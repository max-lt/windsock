//! Snapshots and the journal prune.
//!
//! A snapshot is the index state at its applied frontiers. A proxy with no
//! state, or one that meets a redacted entry, loads the latest snapshot and
//! reads the chains from its frontiers. The journal prune replaces each entry
//! under the frontier of the latest snapshot with its redacted form: the key
//! stays, so no create can take that seq again, and the hash stays, so the
//! chain and `Journal::is_written` still work.
//!
//! A snapshot is sealed as one blob, then cut into parts of at most
//! `snapshot_object` bytes at `snapshots/<time>-<hash>/<n, 6 digits>`. The head
//! `snapshots/<time>-<hash>/head` holds the size and the hash of each part and
//! the frontiers, sealed. The GC writes the head last. A snapshot in one object
//! at `snapshots/<time>-<hash>` still loads.

use bytes::Bytes;
use index::Snapshot;
use journal::{Frontiers, Journal, entry_key};
use remote::{Remote, RemoteError, Sweep};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{Engine, EngineError, Manifest, Result, buffer};

/// Prefix of all snapshot keys: `snapshots/<unix nanos, 20 digits>-<blake3>`, so list order is time order.
pub const SNAPSHOTS_PREFIX: &str = "snapshots/";

/// The most parts that a snapshot head can list.
pub const MAX_SNAPSHOT_PARTS: usize = 4096;

const HEAD: &str = "/head";

/// The size and the hash of one part.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Part {
    len: u64,
    hash: [u8; 32],
}

/// The head of a snapshot in parts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Head {
    parts: Vec<Part>,
    frontiers: Frontiers,
}

/// A snapshot as the remote lists it.
struct Stored {
    /// `snapshots/<time>-<hash>`.
    base: String,
    time: u64,
    hash: [u8; 32],
    form: Form,
}

#[derive(Clone, Copy, PartialEq)]
enum Form {
    /// One object at the base key.
    Single,
    /// Parts and a head under the base key.
    Parts,
}

impl Stored {
    /// The key that names this snapshot: the object or the head.
    fn key(&self) -> String {
        match self.form {
            Form::Single => self.base.clone(),
            Form::Parts => format!("{}{HEAD}", self.base),
        }
    }
}

fn part_key(base: &str, n: usize) -> String {
    format!("{base}/{n:06}")
}

/// The snapshots in the listing, oldest first. Part keys are skipped.
fn stored(keys: &[String]) -> Vec<Stored> {
    keys.iter()
        .filter_map(|key| {
            let (base, form) = match key.strip_suffix(HEAD) {
                Some(base) => (base, Form::Parts),
                None if !key[SNAPSHOTS_PREFIX.len().min(key.len())..].contains('/') => {
                    (key.as_str(), Form::Single)
                }
                None => return None,
            };
            let (time, hash) = parse_key(base)?;
            Some(Stored {
                base: base.to_string(),
                time,
                hash,
                form,
            })
        })
        .collect()
}

/// The largest snapshot a proxy loads. The remote is not trusted with the size of the buffer.
pub const MAX_SNAPSHOT: u64 = 16 * 1024 * 1024 * 1024;

/// Why no snapshot loads: each skipped key with its cause.
#[derive(Debug, Default)]
pub(crate) struct NoSnapshot(Vec<String>);

impl NoSnapshot {
    /// True when the remote has no snapshot at all.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for NoSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("no snapshot in the remote");
        }
        write!(f, "no snapshot loads: {}", self.0.join("; "))
    }
}

/// The write time and the hash in a snapshot key.
fn parse_key(key: &str) -> Option<(u64, [u8; 32])> {
    let (time, hash) = key.strip_prefix(SNAPSHOTS_PREFIX)?.split_once('-')?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hash, &mut bytes).ok()?;
    Some((time.parse().ok()?, bytes))
}

impl<R: Remote + 'static> Engine<R> {
    /// Syncs, then writes a snapshot of the applied state. Returns the key of its head.
    pub async fn snapshot(&self) -> Result<String> {
        self.sync().await?;

        let snapshot = self.index().snapshot()?;
        let plain = snapshot.encode();
        let time = buffer::unix_nanos();
        let sealer = self.keys.sealer();
        let sealed = sealer.seal(seal::Kind::Snapshot, &time.to_le_bytes(), &plain);
        let base = format!("{SNAPSHOTS_PREFIX}{time:020}-{}", blake3::hash(&sealed));

        let size = self.config.snapshot_object.max(1) as usize;
        let mut parts = Vec::new();
        for (n, bytes) in sealed.chunks(size).enumerate() {
            self.remote
                .put(&part_key(&base, n), Bytes::copy_from_slice(bytes))
                .await?;
            parts.push(Part {
                len: bytes.len() as u64,
                hash: *blake3::hash(bytes).as_bytes(),
            });
        }

        // The head goes last: a listed head names parts that exist.
        let head = Head {
            parts,
            frontiers: snapshot.frontiers,
        };
        let plain = postcard::to_allocvec(&head).expect("a head always serializes");
        let key = format!("{base}{HEAD}");
        let sealed = sealer.seal(seal::Kind::SnapshotHead, key.as_bytes(), &plain);
        self.remote.put(&key, Bytes::from(sealed)).await?;

        info!(key, parts = head.parts.len(), "wrote a snapshot");
        Ok(key)
    }

    /// Write time of the newest snapshot, from its key.
    pub(crate) async fn latest_snapshot_time(&self) -> Result<Option<u64>> {
        let keys = self.remote.list(SNAPSHOTS_PREFIX).await?;
        Ok(stored(&keys).last().map(|snapshot| snapshot.time))
    }

    /// The head of a snapshot in parts, opened and checked against the cap.
    async fn read_head(&self, base: &str) -> Result<std::result::Result<Head, String>> {
        let key = format!("{base}{HEAD}");
        let read = self.remote.get(&key).await;
        let read = read.map_err(|e| EngineError::Corrupt(format!("{key}: {e}")))?;
        let Some(sealed) = read else {
            return Ok(Err("the head is gone".to_string()));
        };
        let plain = match self
            .keys
            .sealer()
            .open(seal::Kind::SnapshotHead, key.as_bytes(), &sealed)
        {
            Ok(plain) => plain,
            Err(e) => return Ok(Err(format!("the head does not open: {e}"))),
        };
        let head: Head = match postcard::from_bytes(&plain) {
            Ok(head) => head,
            Err(e) => return Ok(Err(format!("the head does not decode: {e}"))),
        };
        if head.parts.len() > MAX_SNAPSHOT_PARTS {
            return Ok(Err(format!(
                "the head lists {} parts, over the cap of {MAX_SNAPSHOT_PARTS}",
                head.parts.len()
            )));
        }
        let total = head
            .parts
            .iter()
            .try_fold(0u64, |sum, part| sum.checked_add(part.len));
        if total.is_none_or(|total| total > MAX_SNAPSHOT) {
            return Err(EngineError::Corrupt(format!(
                "{key}: the snapshot is over the cap of {MAX_SNAPSHOT} bytes"
            )));
        }
        let listed = self
            .remote
            .list(&format!("{base}/"))
            .await?
            .len()
            .saturating_sub(1);
        if listed != head.parts.len() {
            return Ok(Err(format!(
                "the head lists {} parts, the remote has {listed}",
                head.parts.len()
            )));
        }
        Ok(Ok(head))
    }

    /// The sealed blob of a snapshot in parts. Every part must match its size and hash.
    async fn read_parts(&self, base: &str) -> Result<std::result::Result<Vec<u8>, String>> {
        let head = match self.read_head(base).await? {
            Ok(head) => head,
            Err(cause) => return Ok(Err(cause)),
        };
        let mut sealed = Vec::new();
        for (n, part) in head.parts.iter().enumerate() {
            let key = part_key(base, n);
            let Some(bytes) = self.read_snapshot(&key).await? else {
                return Ok(Err(format!("{key} is gone")));
            };
            if bytes.len() as u64 != part.len {
                return Ok(Err(format!(
                    "{key} has {} bytes, the head says {}",
                    bytes.len(),
                    part.len
                )));
            }
            if blake3::hash(&bytes).as_bytes() != &part.hash {
                return Ok(Err(format!("{key} does not match its hash in the head")));
            }
            sealed.extend_from_slice(&bytes);
        }
        Ok(Ok(sealed))
    }

    /// The newest snapshot that reads back intact, with its write time.
    pub(crate) async fn latest_snapshot(
        &self,
    ) -> Result<std::result::Result<(Snapshot, u64), NoSnapshot>> {
        let mut skipped = NoSnapshot::default();
        let keys = self.remote.list(SNAPSHOTS_PREFIX).await?;
        for snapshot in stored(&keys).iter().rev() {
            let (time, hash) = (snapshot.time, snapshot.hash);
            let key = snapshot.key();
            let mut skip = |cause: String| {
                warn!(key, cause, "skipped a snapshot");
                skipped.0.push(format!("{key}: {cause}"));
            };
            let read = match snapshot.form {
                Form::Single => self
                    .read_snapshot(&key)
                    .await?
                    .ok_or_else(|| "it is gone".to_string()),
                Form::Parts => self.read_parts(&snapshot.base).await?,
            };
            let sealed = match read {
                Ok(sealed) => sealed,
                Err(cause) => {
                    skip(cause);
                    continue;
                }
            };
            if blake3::hash(&sealed).as_bytes() != &hash {
                skip(format!(
                    "{} bytes that do not match the key hash",
                    sealed.len()
                ));
                continue;
            }
            let plain =
                match self
                    .keys
                    .sealer()
                    .open(seal::Kind::Snapshot, &time.to_le_bytes(), &sealed)
                {
                    Ok(plain) => plain,
                    Err(e) => {
                        skip(format!("it does not open: {e}"));
                        continue;
                    }
                };

            match Snapshot::decode(blake3::hash(&plain).as_bytes(), &plain) {
                Ok(snapshot) => return Ok(Ok((snapshot, time))),
                Err(e) => skip(format!("it does not decode: {e}")),
            }
        }

        Ok(Err(skipped))
    }

    /// The whole snapshot at `key`, read in ranges of `snapshot_part`. `None` if it is gone.
    async fn read_snapshot(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let failed = |e: RemoteError| EngineError::Corrupt(format!("{key}: {e}"));
        let over_cap = || {
            EngineError::Corrupt(format!(
                "{key}: the snapshot is over the cap of {MAX_SNAPSHOT} bytes"
            ))
        };
        // A range at the cap fails with the size of a smaller object. It stays under
        // i64::MAX, because some stores parse a range as a signed number.
        let len = match self
            .remote
            .get_range(key, MAX_SNAPSHOT..MAX_SNAPSHOT + 1)
            .await
        {
            Err(RemoteError::InvalidRange { len, .. }) => len,
            Ok(None) => return Ok(None),
            Ok(Some(_)) => return Err(over_cap()),
            Err(e) => return Err(failed(e)),
        };
        if len > MAX_SNAPSHOT {
            return Err(over_cap());
        }

        let part = self.config.snapshot_part.max(1);
        // The size comes from the remote: memory grows with the bytes that arrive.
        let mut sealed = Vec::new();
        while (sealed.len() as u64) < len {
            let start = sealed.len() as u64;
            let end = (start + part).min(len);
            let Some(bytes) = self
                .remote
                .get_range(key, start..end)
                .await
                .map_err(failed)?
            else {
                return Ok(None);
            };
            if bytes.len() as u64 != end - start {
                return Err(EngineError::Corrupt(format!(
                    "{key}: a ranged read gave {} bytes, not {}",
                    bytes.len(),
                    end - start
                )));
            }
            sealed.extend_from_slice(&bytes);
        }

        Ok(Some(sealed))
    }

    /// Replaces the index with the latest snapshot. Returns why when none loads.
    pub(crate) async fn bootstrap(
        &self,
        journal: &mut Journal<R>,
    ) -> Result<std::result::Result<(), NoSnapshot>> {
        let snapshot = match self.latest_snapshot().await? {
            Ok((snapshot, _)) => snapshot,
            Err(none) => return Ok(Err(none)),
        };

        self.index().load(&snapshot)?;

        for (id, bytes) in &snapshot.manifests {
            match Manifest::decode(*id, bytes) {
                Ok(manifest) => self.record_chunks(&manifest)?,
                Err(e) => warn!(manifest_id = %id, %e, "skipped a snapshot manifest"),
            }
        }

        self.index().persist()?;
        journal.reset(self.index().frontiers()?);
        info!(chains = snapshot.frontiers.len(), "loaded a snapshot");
        Ok(Ok(()))
    }

    /// Replaces every entry under the frontier of the newest snapshot that loads in full with its
    /// redacted form. Returns the number of entries replaced, and the write time of that snapshot.
    pub(crate) async fn prune_journal(&self) -> Result<(usize, Option<u64>)> {
        // A head can name parts that no longer read back: only a full load proves the snapshot.
        let Ok((snapshot, time)) = self.latest_snapshot().await? else {
            return Ok((0, None));
        };
        let frontiers = snapshot.frontiers;

        let mut redacted = 0;

        for (node, frontier) in &frontiers {
            let from = self.index().redacted_below(*node)?;

            for seq in from..frontier.next_seq {
                let key = entry_key(*node, seq);
                let Some(bytes) = self.remote.get(&key).await? else {
                    continue;
                };
                let without_actions = journal::redact_wire(&bytes)
                    .map_err(|e| EngineError::Corrupt(format!("{key}: {e:?}")))?;
                let Some(bytes) = without_actions else {
                    continue;
                };

                self.remote.put(&key, Bytes::from(bytes)).await?;
                redacted += 1;
            }

            self.index().set_redacted_below(*node, frontier.next_seq)?;
        }

        Ok((redacted, Some(time)))
    }
}

impl<R: Sweep + 'static> Engine<R> {
    /// Deletes each snapshot older than `loaded`, the snapshot that this run loaded in full,
    /// when a newer snapshot is older than H: a load that started before had H to finish.
    /// Returns the number deleted.
    pub(crate) async fn delete_old_snapshots(&self, loaded: Option<u64>) -> Result<usize> {
        let keys = self.remote.list(SNAPSHOTS_PREFIX).await?;
        let snapshots = stored(&keys);
        let horizon = self.config.gc_horizon.as_nanos() as u64;
        let now = buffer::unix_nanos();
        let mut deleted = 0;

        for pair in snapshots.windows(2) {
            let (old, newer) = (&pair[0], &pair[1]);
            if loaded.is_none_or(|loaded| old.time >= loaded)
                || now < newer.time.saturating_add(horizon)
            {
                break;
            }
            // The head goes first: a listing never shows a head with missing parts.
            self.remote.delete(&old.key()).await?;
            if old.form == Form::Parts {
                for key in self.remote.list(&format!("{}/", old.base)).await? {
                    self.remote.delete(&key).await?;
                }
            }
            info!(key = old.key(), "deleted an old snapshot");
            deleted += 1;
        }

        deleted += self.delete_parts_with_no_head(&keys, now, horizon).await?;
        Ok(deleted)
    }

    /// Deletes the parts of a snapshot with no head once its write time is older than H:
    /// a write that crashed before its head, or a delete that stopped after it.
    async fn delete_parts_with_no_head(
        &self,
        keys: &[String],
        now: u64,
        horizon: u64,
    ) -> Result<usize> {
        let heads: std::collections::BTreeSet<&str> = keys
            .iter()
            .filter_map(|key| key.strip_suffix(HEAD))
            .collect();
        let mut orphans = std::collections::BTreeSet::new();
        for key in keys {
            let Some((base, _)) = key.rsplit_once('/') else {
                continue;
            };
            let Some((time, _)) = parse_key(base) else {
                continue;
            };
            if !heads.contains(base) && now >= time.saturating_add(horizon) {
                orphans.insert(base);
            }
        }

        for base in &orphans {
            for key in keys
                .iter()
                .filter(|key| key.starts_with(&format!("{base}/")))
            {
                self.remote.delete(key).await?;
            }
            info!(base, "deleted the parts of a snapshot with no head");
        }
        Ok(orphans.len())
    }
}
