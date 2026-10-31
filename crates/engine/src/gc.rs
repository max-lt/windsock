//! GC: condemn dead packs and manifests, delete them a horizon later.
//!
//! The rules come from the model in `protocol-check/src/gc.rs`. Rule 3 lives
//! here: an object is deleted only when a sync that started at least H after
//! its condemn still finds it dead. Rules 1 and 2 live in the flush.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use journal::Action;
use model::{ObjectId, PackId};
use remote::Sweep;
use tracing::{error, info, warn};

use crate::{
    Engine, EngineError, MANIFESTS_PREFIX, PACKS_PREFIX, Result, buffer, manifest_key, pack_key,
};

/// Chains that one Retire entry retires: 500 links of at most 74 bytes fit in the 64 KiB header.
const RETIRE_BATCH: usize = 500;

/// The monotonic time at which this process first saw each object that waits for a delete. The
/// wall clock of the GC host alone can step ahead: a delete also waits H on this clock.
#[derive(Default)]
pub(crate) struct Waits {
    first: Mutex<BTreeMap<String, u64>>,
}

impl Waits {
    /// Monotonic nanoseconds since this process first saw `key`.
    pub(crate) fn elapsed(&self, key: &str) -> u64 {
        let now = journal::monotonic_nanos();
        let mut first = self.first.lock().expect("no panic while the lock is held");
        now.saturating_sub(*first.entry(key.to_string()).or_insert(now))
    }

    /// Forgets the keys under `prefix` that are not in `kept`.
    pub(crate) fn keep(&self, prefix: &str, kept: &BTreeSet<String>) {
        let mut first = self.first.lock().expect("no panic while the lock is held");
        first.retain(|key, _| !key.starts_with(prefix) || kept.contains(key));
    }

    /// The objects that still wait for `horizon`, and the longest wait so far.
    fn waiting(&self, horizon: u64) -> (usize, u64) {
        let now = journal::monotonic_nanos();
        let first = self.first.lock().expect("no panic while the lock is held");
        let waits = first
            .values()
            .map(|at| now.saturating_sub(*at))
            .filter(|waited| *waited < horizon);
        waits.fold((0, 0), |(count, oldest), waited| {
            (count + 1, oldest.max(waited))
        })
    }
}

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
    /// Old snapshots deleted with all their parts.
    pub deleted_snapshots: usize,
    /// Chains that this run retired.
    pub retired_chains: usize,
    /// Retired chains that the stable HLC of this run leaves out.
    pub stable_skipped: usize,
}

/// Dead objects of one kind, split by what this run does with them.
struct Dead<T> {
    to_condemn: Vec<T>,
    to_delete: Vec<T>,
}

impl<R: Sweep + 'static> Engine<R> {
    /// Runs the GC once. Run it on one proxy only: the model check covers one runner.
    pub async fn gc(&self) -> Result<GcReport> {
        let started = buffer::unix_nanos();
        // A condemn entry is a write: it waits for the wall clock as a flush does.
        self.check_clock()?;
        // A broken chain can hold puts of packs that look dead, and it pins the stable HLC.
        self.journal.lock().await.audit_next_sync();
        let sync = self.sync().await?;
        if let Some(node) = self.other_gc_node() {
            warn!(%node, "another node ran the GC in the last horizon: run the GC on one node only");
        }
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
            // The monotonic wait starts at the condemn.
            let keys = packs.to_condemn.iter().map(|id| pack_key(*id));
            let keys = keys.chain(manifests.to_condemn.iter().map(|id| manifest_key(*id)));
            for key in keys {
                self.gc_waits.elapsed(&key);
            }
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
        let quiet = self.config.retire_quiet().as_nanos() as u64;
        let (stable, left_out) = self.index().stable(quiet)?;
        report.stable_skipped = left_out;
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
        let now = buffer::unix_nanos();
        // A snapshot time ahead of this clock comes from a clock that is ahead: write anyway.
        if latest.is_none_or(|time| now >= time.saturating_add(interval) || time > now) {
            match self.snapshot().await {
                Ok(_) => report.snapshot_written = true,
                // The previous snapshot stays, and the prune goes on under it.
                Err(e @ EngineError::SnapshotTooLarge { .. }) => {
                    error!(%e, "no new snapshot: no proxy could load it");
                }
                Err(e) => return Err(e),
            }
        }
        if self.config.retire_chains {
            report.retired_chains = self.retire_quiet_chains(started).await?;
        }
        let (redacted, loaded) = self.prune_journal().await?;
        report.redacted_entries = redacted;
        report.deleted_snapshots = self.delete_old_snapshots(loaded).await?;

        let (waiting, oldest) = self.gc_waits.waiting(horizon);
        info!(
            waiting,
            oldest_secs = oldest / 1_000_000_000,
            "deletes that wait for H on the monotonic clock"
        );
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

        let mut condemned = BTreeSet::new();
        for key in self.remote.list(prefix).await? {
            let Some(id) = key.strip_prefix(prefix).and_then(|s| s.parse::<T>().ok()) else {
                continue;
            };

            if live.contains(&id) {
                continue;
            }

            let Some(at) = condemned_at(&self.index(), id)? else {
                dead.to_condemn.push(id);
                continue;
            };
            let waited = self.gc_waits.elapsed(&key);
            if started >= at.saturating_add(horizon) && waited >= horizon {
                dead.to_delete.push(id);
            }
            condemned.insert(key);
        }
        self.gc_waits.keep(prefix, &condemned);

        Ok(dead)
    }

    /// Retires each other chain with no entry for the quiet time at `now`. An entry retires at
    /// most RETIRE_BATCH chains and lists only them in its seen: its header stays small, also
    /// when the full seen is over the header limit.
    async fn retire_quiet_chains(&self, now: u64) -> Result<usize> {
        let quiet = self.config.retire_quiet().as_nanos() as u64;
        let mut retired: BTreeMap<model::NodeId, u64> = BTreeMap::new();
        for mark in self.index().retire_marks()? {
            let upto = retired.entry(mark.node).or_default();
            *upto = (*upto).max(mark.upto);
        }
        let quiet_chains: Vec<_> = self
            .index()
            .frontiers()?
            .into_iter()
            .filter(|(node, frontier)| {
                *node != self.node
                    && frontier.next_seq > 0
                    && retired.get(node).copied().unwrap_or(0) < frontier.next_seq
                    && frontier.last_hlc.saturating_add(quiet) <= now
            })
            .collect();
        for batch in quiet_chains.chunks(RETIRE_BATCH) {
            let mut seen = journal::Seen::new();
            let mut actions = Vec::new();
            for (node, frontier) in batch {
                let link = journal::Link {
                    seq: frontier.next_seq - 1,
                    hash: frontier.last_hash,
                };
                seen.insert(*node, link);
                actions.push(Action::Retire {
                    node: *node,
                    upto: frontier.next_seq,
                });
            }
            let mut journal = self.journal.lock().await;
            let entry = journal
                .append(actions, seen)
                .await
                .map_err(EngineError::from)?;
            self.apply_own(&mut journal, entry).await?;
            info!(
                chains = batch.len(),
                "retired chains with no entry for the quiet time"
            );
        }
        Ok(quiet_chains.len())
    }

    /// Writes the condemn in entries of at most `max_entry_actions` bytes: one large entry
    /// would be over the reply limit of a reader.
    async fn condemn(&self, packs: Vec<PackId>, manifests: Vec<ObjectId>) -> Result<()> {
        // An ID takes 32 bytes; the action, its tags and the list lengths take less than 16.
        let per_entry = (self.config.max_entry_actions.saturating_sub(16) / 32).max(1) as usize;
        let mut packs = packs.as_slice();
        let mut manifests = manifests.as_slice();

        while !packs.is_empty() || !manifests.is_empty() {
            let (these_packs, rest) = packs.split_at(packs.len().min(per_entry));
            packs = rest;
            let room = per_entry - these_packs.len();
            let (these_manifests, rest) = manifests.split_at(manifests.len().min(room));
            manifests = rest;

            let action = Action::Condemn {
                packs: these_packs.to_vec(),
                manifests: these_manifests.to_vec(),
            };
            let mut journal = self.journal.lock().await;
            let seen = self.index().seen(self.node)?;
            let entry = journal
                .append(vec![action], seen)
                .await
                .map_err(EngineError::from)?;
            self.apply_own(&mut journal, entry).await?;
        }
        Ok(())
    }
}
