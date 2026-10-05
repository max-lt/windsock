//! Reading the other chains, and the manifests and chunk locations they name.

use super::*;

/// A miss does not sync again sooner than this after the last sync.
const SYNC_DEBOUNCE: Duration = Duration::from_secs(1);

impl<R: Remote + 'static> Engine<R> {
    /// Reads the new entries of every chain and applies them. Returns the number applied.
    pub async fn sync(&self) -> Result<SyncReport> {
        let mut journal = self.journal.lock().await;
        self.sync_locked(&mut journal).await
    }

    pub(crate) async fn sync_locked(&self, journal: &mut Journal<R>) -> Result<SyncReport> {
        let started = Instant::now();
        *self
            .last_sync
            .lock()
            .expect("no panic while the lock is held") = Some(started);

        let mut entries = journal.sync_all().await?;

        // Entries under the latest snapshot can be redacted: read from the snapshot instead.
        if entries.iter().any(|entry| entry.actions.is_none()) {
            if !self.bootstrap(journal).await? {
                return Err(EngineError::Corrupt(
                    "redacted entries and no snapshot".to_string(),
                ));
            }
            entries = journal.sync_all().await?;
        }

        let mut report = SyncReport {
            broken: journal.broken().keys().copied().collect(),
            ..SyncReport::default()
        };

        if !entries.is_empty() {
            self.ingest(&entries).await?;
            report.applied = self.index().apply(entries)?;
            debug!(applied = report.applied, "synced");
        }

        // GC rule 1 needs every chain: a broken one can hide a condemn.
        if report.broken.is_empty() {
            *self
                .fresh_sync
                .lock()
                .expect("no panic while the lock is held") = Some(started);
        }

        Ok(report)
    }

    /// GC rule 1: dedup only against what a complete sync younger than H/2 found.
    /// Returns `false` when no such sync exists: the flush then writes every chunk.
    pub(crate) async fn ensure_fresh_sync(&self) -> Result<bool> {
        let mut journal = self.journal.lock().await;
        let fresh = || {
            self.fresh_sync
                .lock()
                .expect("no panic while the lock is held")
                .is_some_and(|started| started.elapsed() < self.config.gc_horizon / 2)
        };

        if fresh() {
            return Ok(true);
        }

        let report = self.sync_locked(&mut journal).await?;
        if !report.broken.is_empty() {
            warn!(broken = ?report.broken, "flush without dedup: a chain is broken");
        }

        Ok(fresh())
    }

    pub(crate) fn plan_is_stale(&self, planned_at: u64) -> bool {
        let half = (self.config.gc_horizon / 2).as_nanos() as u64;
        buffer::unix_nanos() >= planned_at.saturating_add(half)
    }

    /// Runs `op`. On a missing bucket or key, syncs once and runs it again,
    /// unless a sync ran in the last second.
    pub(crate) async fn retry_after_sync<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        match op().await {
            Err(EngineError::NoSuchBucket(_) | EngineError::NoSuchKey { .. })
                if self.sync_if_due().await? =>
            {
                op().await
            }
            result => result,
        }
    }

    pub(crate) async fn sync_if_due(&self) -> Result<bool> {
        let mut journal = self.journal.lock().await;
        let due = self
            .last_sync
            .lock()
            .expect("no panic while the lock is held")
            .is_none_or(|last| last.elapsed() >= SYNC_DEBOUNCE);

        if !due {
            return Ok(false);
        }

        self.sync_locked(&mut journal).await?;
        Ok(true)
    }

    /// Stores the manifests that entries carry or name, and the chunk locations they give.
    /// The data is in the remote before the entry, so this can run before the entries apply.
    pub(crate) async fn ingest(&self, entries: &[Entry]) -> Result<()> {
        for action in entries.iter().flat_map(|e| e.actions.iter().flatten()) {
            let Action::Put {
                manifest_id,
                inline_manifest,
                ..
            } = action
            else {
                continue;
            };

            // A bad manifest breaks reads of one key, not the sync of every chain.
            let manifest = match self
                .entry_manifest(*manifest_id, inline_manifest.as_deref())
                .await
            {
                Ok(manifest) => manifest,
                Err(EngineError::Corrupt(reason)) => {
                    warn!(%manifest_id, reason, "skipped a manifest");
                    continue;
                }
                Err(e) => return Err(e),
            };

            self.record_chunks(&manifest)?;
        }

        Ok(())
    }

    /// Records the chunk locations of a manifest, for dedup.
    pub(crate) fn record_chunks(&self, manifest: &Manifest) -> Result<()> {
        let seen_at = buffer::unix_nanos() / 1_000_000_000;
        let index = self.index();

        for chunk in &manifest.chunks {
            if index.chunk(chunk.entry.chunk_id)?.is_some() {
                continue;
            }
            let location = ChunkLocation {
                pack: chunk.pack,
                entry: chunk.entry,
                seen_at,
            };
            index.put_chunk(chunk.entry.chunk_id, &location)?;
        }

        Ok(())
    }
}
