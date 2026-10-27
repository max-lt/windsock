//! Snapshots and the journal prune.
//!
//! A snapshot is the index state at its applied frontiers. A proxy with no
//! state, or one that meets a redacted entry, loads the latest snapshot and
//! reads the chains from its frontiers. The journal prune replaces each entry
//! under the frontier of the latest snapshot with its redacted form: the key
//! stays, so no create can take that seq again, and the hash stays, so the
//! chain and `Journal::is_written` still work.

use bytes::Bytes;
use index::Snapshot;
use journal::{Journal, entry_key};
use remote::{Remote, RemoteError};
use tracing::{info, warn};

use crate::{Engine, EngineError, Manifest, Result, buffer};

/// Prefix of all snapshot keys: `snapshots/<unix nanos, 20 digits>-<blake3>`, so list order is time order.
pub const SNAPSHOTS_PREFIX: &str = "snapshots/";

/// The largest snapshot a proxy loads. The remote is not trusted with the size of the buffer.
pub const MAX_SNAPSHOT: u64 = 16 * 1024 * 1024 * 1024;

/// Why no snapshot loads: each skipped key with its cause.
#[derive(Debug, Default)]
pub(crate) struct NoSnapshot(Vec<String>);

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
    /// Syncs, then writes a snapshot of the applied state. Returns its key.
    pub async fn snapshot(&self) -> Result<String> {
        self.sync().await?;

        let plain = self.index().snapshot()?.encode();
        let time = buffer::unix_nanos();
        let sealed = self
            .keys
            .sealer()
            .seal(seal::Kind::Snapshot, &time.to_le_bytes(), &plain);
        let hash = blake3::hash(&sealed);
        let key = format!("{SNAPSHOTS_PREFIX}{time:020}-{hash}");
        self.remote.put(&key, Bytes::from(sealed)).await?;

        info!(key, "wrote a snapshot");
        Ok(key)
    }

    /// Write time of the newest snapshot, from its key.
    pub(crate) async fn latest_snapshot_time(&self) -> Result<Option<u64>> {
        let keys = self.remote.list(SNAPSHOTS_PREFIX).await?;
        Ok(keys
            .iter()
            .rev()
            .find_map(|key| parse_key(key))
            .map(|(time, _)| time))
    }

    /// The newest snapshot that reads back intact.
    pub(crate) async fn latest_snapshot(
        &self,
    ) -> Result<std::result::Result<Snapshot, NoSnapshot>> {
        let mut skipped = NoSnapshot::default();
        for key in self.remote.list(SNAPSHOTS_PREFIX).await?.iter().rev() {
            let Some((time, hash)) = parse_key(key) else {
                continue;
            };
            let mut skip = |cause: String| {
                warn!(key, cause, "skipped a snapshot");
                skipped.0.push(format!("{key}: {cause}"));
            };
            let Some(sealed) = self.read_snapshot(key).await? else {
                skip("it is gone".to_string());
                continue;
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
                Ok(snapshot) => return Ok(Ok(snapshot)),
                Err(e) => skip(format!("it does not decode: {e}")),
            }
        }

        Ok(Err(skipped))
    }

    /// The whole snapshot at `key`, read in ranges of `snapshot_part`. `None` if it is gone.
    async fn read_snapshot(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let failed = |e: RemoteError| EngineError::Corrupt(format!("{key}: {e}"));
        // A range past any object fails with the object size.
        let len = match self.remote.get_range(key, u64::MAX - 1..u64::MAX).await {
            Err(RemoteError::InvalidRange { len, .. }) => len,
            Ok(None) => return Ok(None),
            Ok(Some(_)) => return Err(EngineError::Corrupt(format!("{key}: no size"))),
            Err(e) => return Err(failed(e)),
        };
        if len > MAX_SNAPSHOT {
            return Err(EngineError::Corrupt(format!(
                "{key}: the snapshot has {len} bytes, over the cap of {MAX_SNAPSHOT} bytes"
            )));
        }

        let part = self.config.snapshot_part.max(1);
        let mut sealed = Vec::with_capacity(len as usize);
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
            Ok(snapshot) => snapshot,
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

    /// Replaces every entry under the frontier of the latest snapshot with its
    /// redacted form. Returns the number of entries replaced.
    pub(crate) async fn prune_journal(&self) -> Result<usize> {
        let Ok(snapshot) = self.latest_snapshot().await? else {
            return Ok(0);
        };

        let mut redacted = 0;

        for (node, frontier) in &snapshot.frontiers {
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

        Ok(redacted)
    }
}
