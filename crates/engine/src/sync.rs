//! Reading the other chains, and the manifests and chunk locations they name.

use super::*;

/// A miss does not sync again sooner than this after the last sync.
const SYNC_DEBOUNCE: Duration = Duration::from_secs(1);

/// A sync that stops before the index applies its entries, on an error or a drop of its future,
/// moves the journal back to the applied frontiers: the next sync reads those entries again.
pub(crate) struct Unapplied<'a, R: Remote + 'static> {
    pub(crate) engine: &'a Engine<R>,
    pub(crate) journal: &'a mut Journal<R>,
    pub(crate) applied: bool,
}

impl<R: Remote + 'static> Drop for Unapplied<'_, R> {
    fn drop(&mut self) {
        if !self.applied {
            self.engine.reset_journal(self.journal);
        }
    }
}

impl<R: Remote + 'static> Engine<R> {
    /// Reads the new entries of every chain and applies them. Returns the number applied.
    pub async fn sync(&self) -> Result<SyncReport> {
        let mut journal = self.journal.lock().await;
        self.sync_locked(&mut journal).await
    }

    pub(crate) async fn sync_locked(&self, journal: &mut Journal<R>) -> Result<SyncReport> {
        let started = Stamp::now();
        *self
            .last_sync
            .lock()
            .expect("no panic while the lock is held") = Some(started.mono());

        let mut cut = Unapplied {
            engine: self,
            journal,
            applied: false,
        };
        let entries = self.read_entries(cut.journal).await?;
        let journal = &mut *cut.journal;

        let mut report = SyncReport {
            broken: journal.broken().keys().copied().collect(),
            broken_causes: journal
                .broken()
                .iter()
                .map(|(node, cause)| format!("chain of node {node}: {cause}"))
                .collect(),
            skipped: journal.skipped(),
            ..SyncReport::default()
        };

        // The index keeps the entries it cannot apply yet: a reset would add them twice.
        if !entries.is_empty() {
            report.applied = self.index().apply(entries)?;
            debug!(applied = report.applied, "synced");
        }
        cut.applied = true;
        drop(cut);

        // GC rule 1 needs every chain: a broken one can hide a condemn.
        if report.broken.is_empty() {
            *self
                .fresh_sync
                .lock()
                .expect("no panic while the lock is held") = Some(started);
        }

        Ok(report)
    }

    /// Moves the journal back to the frontiers that the index applied.
    pub(crate) fn reset_journal(&self, journal: &mut Journal<R>) {
        match self.index().frontiers() {
            Ok(frontiers) => journal.reset(frontiers),
            Err(e) => warn!(%e, "the journal stays past entries that the index did not get"),
        }
    }

    /// The new entries of every chain, with their manifests and chunk locations recorded.
    async fn read_entries(&self, journal: &mut Journal<R>) -> Result<Vec<Entry>> {
        let mut entries = journal.sync_all().await?;

        // Entries under the latest snapshot can be redacted: read from the snapshot instead. A GC
        // can write a newer snapshot and redact up to it during the load: load again then.
        for _ in 0..3 {
            if !entries.iter().any(|entry| entry.actions.is_none()) {
                break;
            }
            match self.bootstrap(journal).await? {
                Ok(()) => entries = journal.sync_all().await?,
                // A snapshot that does not load: the error names its keys for the operator.
                Err(none) if !none.is_empty() => {
                    return Err(EngineError::Corrupt(format!("redacted entries and {none}")));
                }
                Err(_) => break,
            }
        }
        // A redacted entry that no snapshot covers breaks its chain only.
        let redacted: BTreeMap<NodeId, u64> = entries
            .iter()
            .filter(|entry| entry.actions.is_none())
            .map(|entry| (entry.node, entry.seq))
            .rev()
            .collect();
        if !redacted.is_empty() {
            let frontiers = self.index().frontiers()?;
            for (node, seq) in &redacted {
                let frontier = frontiers
                    .get(node)
                    .copied()
                    .unwrap_or(journal::Frontier::GENESIS);
                journal.give_up(*node, frontier, journal::ChainError::Redacted { seq: *seq });
            }
            entries.retain(|entry| !redacted.contains_key(&entry.node));
        }

        if !entries.is_empty() {
            self.ingest(&entries).await?;
        }
        Ok(entries)
    }

    /// GC rule 1: dedup only against what a complete sync younger than H/2 found.
    /// Returns `false` when no such sync exists: the flush then writes every chunk.
    pub(crate) async fn ensure_fresh_sync(&self) -> Result<bool> {
        let mut journal = self.journal.lock().await;
        let fresh = || {
            self.fresh_sync
                .lock()
                .expect("no panic while the lock is held")
                .is_some_and(|started| !started.older_than(self.config.gc_horizon / 2))
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

    pub(crate) fn plan_is_stale(&self, planned: Stamp) -> bool {
        planned.older_than(self.config.gc_horizon / 2)
    }

    /// Runs `op`. On a missing bucket or key, or a failed precondition, syncs once and runs it
    /// again, unless a sync ran in the last second: a proxy behind gives a false answer.
    pub(crate) async fn retry_after_sync<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        match op().await {
            Err(
                EngineError::NoSuchBucket(_)
                | EngineError::NoSuchKey { .. }
                | EngineError::PreconditionFailed { .. },
            ) if self.sync_if_due().await? => op().await,
            result => result,
        }
    }

    pub(crate) async fn sync_if_due(&self) -> Result<bool> {
        let mut journal = self.journal.lock().await;
        let due = self
            .last_sync
            .lock()
            .expect("no panic while the lock is held")
            .is_none_or(|last| {
                journal::monotonic_nanos().saturating_sub(last) >= SYNC_DEBOUNCE.as_nanos() as u64
            });

        if !due {
            return Ok(false);
        }

        self.sync_locked(&mut journal).await?;
        Ok(true)
    }

    /// Stores the manifests that entries carry or name, and the chunk locations they give.
    /// The data is in the remote before the entry, so this can run before the entries apply.
    pub(crate) async fn ingest(&self, entries: &[Entry]) -> Result<()> {
        self.note_other_gc(entries);
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

    /// Notes another node that wrote a condemn in the last H: it runs a GC too.
    fn note_other_gc(&self, entries: &[Entry]) {
        let horizon = self.config.gc_horizon.as_nanos() as u64;
        let now = buffer::unix_nanos();
        let other = entries.iter().rfind(|entry| {
            entry.node != self.node
                && now.saturating_sub(entry.hlc) < horizon
                && entry
                    .actions
                    .iter()
                    .flatten()
                    .any(|action| matches!(action, Action::Condemn { .. }))
        });
        if let Some(entry) = other {
            *self
                .other_gc_node
                .lock()
                .expect("no panic while the lock is held") = Some(entry.node);
        }
    }

    /// Another node that wrote a condemn in the last H, as far as the syncs of this process saw.
    pub fn other_gc_node(&self) -> Option<NodeId> {
        *self
            .other_gc_node
            .lock()
            .expect("no panic while the lock is held")
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
