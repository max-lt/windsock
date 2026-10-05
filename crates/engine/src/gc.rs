//! GC: condemn dead packs and manifests, delete them a horizon later.
//!
//! The rules come from the model in `protocol-check/src/gc.rs`. Rule 3 lives
//! here: an object is deleted only when a sync that started at least H after
//! its condemn still finds it dead. Rules 1 and 2 live in the flush.

use std::collections::BTreeSet;

use journal::Action;
use model::{ObjectId, PackId};
use remote::Sweep;
use tracing::{info, warn};

use crate::{
    Engine, EngineError, MANIFESTS_PREFIX, PACKS_PREFIX, Result, buffer, manifest_key, pack_key,
};

/// What one GC run did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    pub condemned_packs: usize,
    pub condemned_manifests: usize,
    pub deleted_packs: usize,
    pub deleted_manifests: usize,
    /// Keys whose old versions or old delete left the index.
    pub pruned_keys: usize,
    /// The stable HLC is more than R ahead of the GC clock: the clock assumption does not hold.
    pub prune_refused: bool,
    pub snapshot_written: bool,
    /// Journal entries replaced by their redacted form.
    pub redacted_entries: usize,
}

/// Dead objects of one kind, split by what the GC does with them now.
struct Dead<T> {
    to_condemn: Vec<T>,
    to_delete: Vec<T>,
}

impl<R: Sweep + 'static> Engine<R> {
    /// Runs the GC once. Run it on one proxy only: two runners are safe, but cost twice.
    pub async fn gc(&self) -> Result<GcReport> {
        let started = buffer::unix_nanos();
        // A broken chain can hold puts of packs that look dead, and it pins the stable HLC.
        let sync = self.sync().await?;
        if !sync.broken.is_empty() {
            warn!(broken = ?sync.broken, "gc refused: a chain is broken");
            return Err(EngineError::BrokenChains(sync.broken));
        }

        let horizon = self.config.gc_horizon.as_nanos() as u64;
        let retention = self.config.retention.as_nanos() as u64;
        let live_manifests = self
            .index()
            .live_manifests(started.saturating_sub(retention))?;
        let live_packs = self.packs_of(&live_manifests).await?;

        let packs = self
            .dead(PACKS_PREFIX, &live_packs, started, horizon, |index, id| {
                index.condemned_pack(id)
            })
            .await?;
        let manifests = self
            .dead(
                MANIFESTS_PREFIX,
                &live_manifests,
                started,
                horizon,
                |index, id| index.condemned_manifest(id),
            )
            .await?;

        let mut report = GcReport {
            condemned_packs: packs.to_condemn.len(),
            condemned_manifests: manifests.to_condemn.len(),
            ..GcReport::default()
        };

        if !packs.to_condemn.is_empty() || !manifests.to_condemn.is_empty() {
            self.condemn(packs.to_condemn, manifests.to_condemn).await?;
        }

        for id in packs.to_delete {
            self.remote.delete(&pack_key(id)).await?;
            report.deleted_packs += 1;
        }

        for id in manifests.to_delete {
            self.remote.delete(&manifest_key(id)).await?;
            report.deleted_manifests += 1;
        }

        // The prune assumes no proxy clock is more than R behind the others.
        let stable = self.index().stable_hlc()?;
        let now = buffer::unix_nanos();
        if stable > now.saturating_add(retention) {
            warn!(
                stable,
                started, "version prune refused: the stable HLC is far ahead of this clock"
            );
            report.prune_refused = true;
        } else {
            report.pruned_keys = self
                .index()
                .prune_versions(stable.saturating_sub(retention))?;
        }

        let interval = self.config.snapshot_interval.as_nanos() as u64;
        let latest = self.latest_snapshot_time().await?;
        if latest.is_none_or(|time| buffer::unix_nanos() >= time.saturating_add(interval)) {
            self.snapshot().await?;
            report.snapshot_written = true;
        }
        report.redacted_entries = self.prune_journal().await?;

        info!(?report, "gc run");
        Ok(report)
    }

    /// Packs that the manifests use. A manifest that cannot be read stops the run:
    /// without it, the GC cannot know which packs are live.
    async fn packs_of(&self, manifests: &BTreeSet<ObjectId>) -> Result<BTreeSet<PackId>> {
        let mut packs = BTreeSet::new();

        for id in manifests {
            let manifest = self.manifest(*id).await.inspect_err(|e| {
                warn!(manifest_id = %id, %e, "gc stopped: a live manifest cannot be read");
            })?;
            packs.extend(manifest.chunks.iter().map(|chunk| chunk.pack));
        }

        Ok(packs)
    }

    /// Objects under `prefix` that no live object uses. A dead object without a
    /// condemn gets one; a condemn older than the horizon at `started` allows the delete.
    async fn dead<T>(
        &self,
        prefix: &str,
        live: &BTreeSet<T>,
        started: u64,
        horizon: u64,
        condemned_at: impl Fn(&index::Index, T) -> std::result::Result<Option<u64>, index::IndexError>,
    ) -> Result<Dead<T>>
    where
        T: Copy + Ord + std::str::FromStr,
    {
        let mut dead = Dead {
            to_condemn: Vec::new(),
            to_delete: Vec::new(),
        };

        for key in self.remote.list(prefix).await? {
            let Some(id) = key.strip_prefix(prefix).and_then(|s| s.parse::<T>().ok()) else {
                continue;
            };

            if live.contains(&id) {
                continue;
            }

            match condemned_at(&self.index(), id)? {
                None => dead.to_condemn.push(id),
                Some(at) if started >= at.saturating_add(horizon) => dead.to_delete.push(id),
                Some(_) => {}
            }
        }

        Ok(dead)
    }

    async fn condemn(&self, packs: Vec<PackId>, manifests: Vec<ObjectId>) -> Result<()> {
        let action = Action::Condemn { packs, manifests };
        let mut journal = self.journal.lock().await;
        let seen = self.index().seen(self.node)?;
        let entry = journal
            .append(vec![action], seen)
            .await
            .map_err(EngineError::from)?;
        self.apply_own(&mut journal, entry).await
    }
}
