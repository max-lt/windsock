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
use journal::{Entry, Journal, entry_key};
use remote::Remote;
use tracing::{info, warn};

use crate::{Engine, EngineError, Manifest, Result, buffer};

/// Prefix of all snapshot keys: `snapshots/<unix nanos, 20 digits>-<blake3>`, so list order is time order.
pub const SNAPSHOTS_PREFIX: &str = "snapshots/";

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

        let bytes = self.index().snapshot()?.encode(&self.key, &keys::random());
        let hash = blake3::hash(&bytes);
        let key = format!("{SNAPSHOTS_PREFIX}{:020}-{hash}", buffer::unix_nanos());
        self.remote.put(&key, Bytes::from(bytes)).await?;

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
    pub(crate) async fn latest_snapshot(&self) -> Result<Option<Snapshot>> {
        for key in self.remote.list(SNAPSHOTS_PREFIX).await?.iter().rev() {
            let Some((_, hash)) = parse_key(key) else {
                continue;
            };
            let Some(bytes) = self.remote.get(key).await? else {
                continue;
            };

            match Snapshot::decode(&self.key, &hash, &bytes) {
                Ok(snapshot) => return Ok(Some(snapshot)),
                Err(e) => warn!(key, %e, "skipped a bad snapshot"),
            }
        }

        Ok(None)
    }

    /// Replaces the index with the latest snapshot. Returns `false` when there is none.
    pub(crate) async fn bootstrap(&self, journal: &mut Journal<R>) -> Result<bool> {
        let Some(snapshot) = self.latest_snapshot().await? else {
            return Ok(false);
        };

        self.index().load(&snapshot)?;

        for (id, bytes) in &snapshot.manifests {
            match Manifest::decode(&self.key, *id, bytes) {
                Ok(manifest) => self.record_chunks(&manifest)?,
                Err(e) => warn!(manifest_id = %id, %e, "skipped a snapshot manifest"),
            }
        }

        self.index().persist()?;
        journal.reset(self.index().frontiers()?);
        info!(chains = snapshot.frontiers.len(), "loaded a snapshot");
        Ok(true)
    }

    /// Replaces every entry under the frontier of the latest snapshot with its
    /// redacted form. Returns the number of entries replaced.
    pub(crate) async fn prune_journal(&self) -> Result<usize> {
        let Some(snapshot) = self.latest_snapshot().await? else {
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
                let entry = Entry::decode(&self.key, &bytes)
                    .map_err(|e| EngineError::Corrupt(format!("{key}: {e}")))?;

                if entry.actions.is_none() {
                    continue;
                }

                let bytes = entry.redacted().encode(&self.key, &keys::random());
                self.remote.put(&key, Bytes::from(bytes)).await?;
                redacted += 1;
            }

            self.index().set_redacted_below(*node, frontier.next_seq)?;
        }

        Ok(redacted)
    }
}
