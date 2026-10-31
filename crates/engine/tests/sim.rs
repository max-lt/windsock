//! Deterministic simulation: 3 proxies on one remote, a manual wall clock, and random steps from
//! one seed. A failed run prints its seed: run it again with `SIM_SEED=<seed>`.
//!
//! The oracle: for each key, the acked write with the highest (ack HLC, node) wins on every proxy
//! after a final flush and sync. A write may be missing only after a quarantine on its proxy.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::sim::Point;
use engine::{Config, Engine, EngineError, ListEntry, ListQuery, RepoKey, WriteMode};
use remote::{MemoryRemote, Remote, RemoteError, Sweep};
use tempfile::TempDir;

const BUCKET: &str = "bkt";
const KEYS: u64 = 8;
const OTHER_BUCKETS: [&str; 2] = ["one", "two"];
const STEPS: u64 = 60;
const SECOND: u64 = 1_000_000_000;
/// The points after which a flush can crash.
const POINTS: [Point; 7] = [
    Point::SegmentRead,
    Point::Plan,
    Point::PackUpload,
    Point::Intent,
    Point::Commit,
    Point::Apply,
    Point::Release,
];
/// A fixed start time, so a seed gives the same HLCs on every run.
const START: u64 = 1_800_000_000 * SECOND;

thread_local! {
    /// The seed of the run in progress on this thread, for the panic message.
    static CURRENT_SEED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Threads that run seeds at once: each has its own runtime and manual clock.
const THREADS: u64 = 8;

/// SplitMix64: a small generator with no crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// What the next matching write to the remote does.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// Fails and stores nothing.
    Refuse,
    /// Stores, then fails: the answer is lost.
    LoseAnswer,
    /// Stores while the host sleeps for H/2: the plan of the flush is stale at its commit.
    Slow,
}

/// A memory remote that fails the next write under a prefix.
#[derive(Default)]
struct SimRemote {
    inner: MemoryRemote,
    next: Mutex<Option<(&'static str, Fault)>>,
}

impl SimRemote {
    fn take(&self, key: &str) -> Option<Fault> {
        let mut next = self.next.lock().unwrap();
        match *next {
            Some((prefix, fault)) if key.starts_with(prefix) => {
                *next = None;
                Some(fault)
            }
            _ => None,
        }
    }

    fn injected() -> RemoteError {
        RemoteError::Service {
            status: 503,
            code: "SlowDown".into(),
            message: "injected".into(),
        }
    }
}

#[async_trait::async_trait]
impl Remote for SimRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        match self.take(key) {
            Some(Fault::Refuse) => Err(Self::injected()),
            Some(Fault::LoseAnswer) => {
                self.inner.put(key, data).await?;
                Err(Self::injected())
            }
            Some(Fault::Slow) => {
                journal::suspend_manual((config().gc_horizon / 2).as_nanos() as u64);
                self.inner.put(key, data).await
            }
            None => self.inner.put(key, data).await,
        }
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        match self.take(key) {
            Some(Fault::Refuse) => Err(Self::injected()),
            Some(Fault::LoseAnswer) => {
                self.inner.create(key, data).await?;
                Err(Self::injected())
            }
            Some(Fault::Slow) => {
                journal::suspend_manual((config().gc_horizon / 2).as_nanos() as u64);
                self.inner.create(key, data).await
            }
            None => self.inner.create(key, data).await,
        }
    }

    async fn get(&self, key: &str, max_len: u64) -> Result<Option<Bytes>, RemoteError> {
        self.inner.get(key, max_len).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        self.inner.list(prefix).await
    }
}

#[async_trait::async_trait]
impl Sweep for SimRemote {
    async fn delete(&self, key: &str) -> Result<(), RemoteError> {
        self.inner.delete(key).await
    }
}

/// The remote as one proxy sees it: an outage refuses each of its writes.
struct ProxyRemote {
    shared: Arc<SimRemote>,
    outage: Arc<AtomicBool>,
}

impl ProxyRemote {
    fn check(&self) -> Result<(), RemoteError> {
        match self.outage.load(Ordering::SeqCst) {
            true => Err(SimRemote::injected()),
            false => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl Remote for ProxyRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.check()?;
        self.shared.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.check()?;
        self.shared.create(key, data).await
    }

    async fn get(&self, key: &str, max_len: u64) -> Result<Option<Bytes>, RemoteError> {
        self.shared.get(key, max_len).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        self.shared.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        self.shared.list(prefix).await
    }
}

#[async_trait::async_trait]
impl Sweep for ProxyRemote {
    async fn delete(&self, key: &str) -> Result<(), RemoteError> {
        self.check()?;
        self.shared.delete(key).await
    }
}

/// What one seed exercised.
#[derive(Default)]
struct Stats {
    /// blake3 of the step log: two runs of one seed must give the same.
    log_hash: [u8; 32],
    quarantine: bool,
    /// A start failed again with the quarantine still held.
    held_restart: bool,
    crashes: BTreeSet<Point>,
    lost_index: bool,
    stale_index: bool,
    suspend: bool,
    tombstone_prune: bool,
    deleted_pack: bool,
    intent_quarantined: bool,
    young_kept: bool,
    stale_plan: bool,
    marker_fault: bool,
    far_ahead: bool,
    /// The wall clocks stepped back more than R with writes in a buffer.
    step_back: bool,
    /// A spooled put crashed at one of its steps.
    spool_crash: bool,
    /// A power loss changed the data of an unacked put under a valid head, or cut its record.
    power_loss_data: u64,
    power_loss_cut: u64,
    /// Starts refused on the quarantine, and records there with data that does not match.
    refused_starts: u64,
    corrupt_quarantined: u64,
    keyless: bool,
    slow_stale_plan: bool,
    /// Chunks that a flush found stored and did not upload again.
    dedup_hits: u64,
}

/// One acked write: its rank and what a reader must see if it wins.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Acked {
    hlc: u64,
    node: [u8; 32],
    /// The data of a put, `None` for a delete.
    value: Option<Vec<u8>>,
    proxy: usize,
    /// The operator dropped it from the quarantine: it never applies.
    dropped: bool,
}

struct Proxy {
    seed: u8,
    dir: TempDir,
    engine: Option<Engine<ProxyRemote>>,
    node: [u8; 32],
    /// The last ack HLC that this proxy gave: the next one must be higher.
    last_ack: u64,
    outage: Arc<AtomicBool>,
    /// An older copy of the index directory, for a crash that restores it.
    stale_index: Option<TempDir>,
    /// How far the wall clock of this proxy is ahead of the shared time.
    offset: u64,
    /// Time that passed while this host was suspended: its monotonic clock did not count it.
    suspended: u64,
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        match entry.file_type().unwrap().is_dir() {
            true => copy_tree(&entry.path(), &target),
            false => {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }
}

fn config() -> Config {
    Config {
        gc_horizon: Duration::from_secs(120),
        retention: Duration::from_secs(600),
        late_margin: Duration::from_secs(60),
        snapshot_interval: Duration::from_secs(3600),
        ..Config::default()
    }
}

struct Sim {
    rng: Rng,
    /// Power losses draw from their own stream, so the other steps of a seed stay as they were.
    loss: Rng,
    remote: Arc<SimRemote>,
    proxies: Vec<Proxy>,
    now: u64,
    keys: BTreeMap<String, Vec<Acked>>,
    buckets: BTreeMap<String, Vec<Acked>>,
    log: Vec<String>,
    stats: Stats,
    /// The latest HLC that a clock more than R ahead gave: until the clock of proxy 0 is
    /// within R of it, its chain is broken there and a GC or a snapshot may fail.
    far_until: u64,
    /// The nodes whose clock ran more than R ahead: their chains may be broken elsewhere.
    far_nodes: BTreeSet<[u8; 32]>,
    /// The highest bound that a version prune of the GC could use: (stable HLC - R).
    prune_bound: u64,
    /// The highest wall clock of any proxy so far: no HLC is above it, also after a step back.
    highest_clock: u64,
    /// The keys of a chain that a writer with no repo key put, and the node of that chain.
    keyless: Option<(Vec<String>, [u8; 32])>,
    /// The HLC of the latest keyless entry: no clock may reach it.
    keyless_hlc: u64,
    /// The largest clock offset of the run: an HLC from it stays in the journal.
    max_offset: u64,
    /// Real time since the start: it never steps back, unlike the wall clocks.
    elapsed: u64,
}

impl Sim {
    /// Time goes on for every host.
    fn pass(&mut self, by: u64) {
        self.now += by;
        self.elapsed += by;
        self.note_clocks();
    }

    /// Keeps the highest wall clock of the proxies, and the latest far HLC.
    fn note_clocks(&mut self) {
        let r = config().retention.as_nanos() as u64;
        for proxy in &mut self.proxies {
            let clock = self.now + proxy.offset;
            self.highest_clock = self.highest_clock.max(clock);
            if proxy.offset > r {
                self.far_until = self.far_until.max(clock);
                self.far_nodes.insert(proxy.node);
            }
        }
    }

    /// A GC or snapshot error that a clock more than R ahead explains: proxy 0 waits for its
    /// own wall clock, or proxy 0 reads a chain of a far node as more than R ahead.
    fn far_ahead_explains(&self, e: &EngineError) -> bool {
        let r = config().retention.as_nanos() as u64;
        let wall = self.now + self.proxies[0].offset;
        if matches!(e, EngineError::ClockAhead { .. }) {
            let clock = self.proxies[0]
                .engine
                .as_ref()
                .map_or(0, |engine| engine.last_hlc());
            return clock > wall.saturating_add(r);
        }
        let ahead = wall.saturating_add(r) < self.far_until;
        // A chain reads as more than R ahead when its node ran far ahead, or when its clock is
        // more than R past this wall clock after a step back.
        let far = |node: &model::NodeId| {
            let past_wall = self.proxies.iter().any(|proxy| {
                let clock = proxy.engine.as_ref().map_or(0, |engine| engine.last_hlc());
                proxy.node == *node.as_bytes() && proxy.last_ack.max(clock) > wall.saturating_add(r)
            });
            self.far_nodes.contains(node.as_bytes()) && ahead || past_wall
        };
        match e {
            EngineError::BrokenChains(nodes) => nodes.iter().all(far),
            _ => ahead && e.to_string().contains("more than the retention ahead"),
        }
    }

    /// The wall and the monotonic clock of proxy `i`. Each host has its own monotonic clock:
    /// a wall step or a suspend of one host does not move the others.
    fn clocks(&self, i: usize) {
        let proxy = &self.proxies[i];
        journal::set_manual_wall(Some(self.now + proxy.offset));
        journal::set_manual_monotonic(self.elapsed - proxy.suspended);
    }

    async fn try_open(&self, i: usize) -> Result<Engine<ProxyRemote>, EngineError> {
        self.clocks(i);
        let proxy = &self.proxies[i];
        let remote = Arc::new(ProxyRemote {
            shared: self.remote.clone(),
            outage: proxy.outage.clone(),
        });
        Engine::open(
            proxy.dir.path(),
            remote,
            SigningKey::from_bytes(&[proxy.seed; 32]),
            RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
            config(),
        )
        .await
    }

    /// The record segments in the quarantine of proxy `i`, by name, with their bytes.
    fn held_segments(&self, i: usize) -> BTreeMap<String, Vec<u8>> {
        let quarantine = self.proxies[i].dir.path().join("quarantine");
        let Ok(entries) = std::fs::read_dir(quarantine) else {
            return BTreeMap::new();
        };
        entries
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|e| e == "log"))
            .map(|path| {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read(&path).unwrap())
            })
            .collect()
    }

    async fn open(&mut self, i: usize) -> Result<(), String> {
        loop {
            match self.try_open(i).await {
                Ok(engine) => {
                    self.proxies[i].engine = Some(engine);
                    return Ok(());
                }
                Err(EngineError::Quarantined(e)) => {
                    self.stats.refused_starts += 1;
                    self.operator(i, &e).await?
                }
                // A remote error at open: the supervisor starts the proxy again.
                Err(e) if e.to_string().contains("injected") => {
                    self.log.push(format!("p{i} open failed: {e}"));
                }
                Err(e) => return Err(format!("p{i} open: {e}")),
            }
        }
    }

    /// A start refused on the quarantine: maybe a supervisor restart first, then the operator
    /// reads the late writes, drops them, and empties the quarantine.
    async fn operator(&mut self, i: usize, refusal: &str) -> Result<(), String> {
        let held = self.held_segments(i);
        if held.is_empty() {
            return Err(format!(
                "p{i}: a quarantine refusal with no segment held: {refusal}"
            ));
        }
        // The supervisor starts the proxy again before the operator acts: the held quarantine
        // must block the start and stay as it is.
        if self.rng.chance(30) {
            let wait = self.rng.below(120 * SECOND);
            self.pass(wait);
            self.stats.held_restart = true;
            let again = self.try_open(i).await;
            if !matches!(again, Err(EngineError::Quarantined(_))) {
                return Err(format!(
                    "p{i}: a start on a held quarantine: {:?}",
                    again.err()
                ));
            }
            if self.held_segments(i) != held {
                return Err(format!("p{i}: a start changed a held quarantine"));
            }
        }
        let dir = self.proxies[i].dir.path().to_path_buf();
        let writes = engine::quarantined_writes(&dir)
            .await
            .map_err(|e| format!("p{i} quarantine: {e}"))?;
        self.log
            .push(format!("p{i} quarantine at open: {writes:?}"));
        // A record with bad data comes from a power loss before its fsync: never acked.
        let (corrupt, writes): (Vec<_>, Vec<_>) = writes.into_iter().partition(|w| w.corrupt);
        if let Some(acked) = corrupt.iter().find(|w| self.was_acked(i, &w.target, w.hlc)) {
            return Err(format!(
                "p{i}: an acked write is in the quarantine with bad data: {acked:?}"
            ));
        }
        self.stats.corrupt_quarantined += corrupt.len() as u64;
        self.stats.quarantine |= !writes.is_empty();
        // A write is late when its HLC is under the clock less (R - M). A clock is a wall clock or
        // an HLC that it saw, and no HLC passed the highest wall clock of the run by more than its
        // ticks, far under a second: a write at or above this bound was young.
        self.note_clocks();
        let late_limit = (config().retention - config().late_margin).as_nanos() as u64;
        let bound = (self.highest_clock + SECOND).saturating_sub(late_limit);
        if let Some(young) = writes.iter().find(|w| w.hlc >= bound) {
            let tail: Vec<_> = self.log.iter().rev().take(40).rev().cloned().collect();
            return Err(format!(
                "p{i}: a young write is in the quarantine: {young:?}, bound {bound}\n{}",
                tail.join("\n")
            ));
        }
        let intent = std::fs::read_dir(dir.join("quarantine")).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("intent")
        });
        self.stats.intent_quarantined |= intent;
        let newest = writes.iter().map(|w| w.hlc).max().unwrap_or(0);
        self.stats.young_kept |= self.acked_after(i, newest);
        for write in writes {
            self.drop_acked(i, &write.target, write.hlc)?;
        }
        std::fs::remove_dir_all(dir.join("quarantine")).unwrap();
        Ok(())
    }

    /// True when proxy `i` acked a write after `hlc` that the operator did not drop.
    fn acked_after(&self, i: usize, hlc: u64) -> bool {
        self.keys
            .values()
            .chain(self.buckets.values())
            .flatten()
            .any(|a| a.proxy == i && a.hlc > hlc && !a.dropped)
    }

    /// True when proxy `i` acked a write to `target` at `hlc`.
    fn was_acked(&self, i: usize, target: &str, hlc: u64) -> bool {
        let (writes, name) = match target.split_once('/') {
            Some((_, key)) => (&self.keys, key),
            None => (&self.buckets, target),
        };
        writes
            .get(name)
            .is_some_and(|acked| acked.iter().any(|a| a.proxy == i && a.hlc == hlc))
    }

    /// Marks the acked write of proxy `i` to `target` at `hlc` as dropped by the operator.
    fn drop_acked(&mut self, i: usize, target: &str, hlc: u64) -> Result<(), String> {
        let (writes, name) = match target.split_once('/') {
            Some((_, key)) => (&mut self.keys, key),
            None => (&mut self.buckets, target),
        };
        let acked = writes
            .get_mut(name)
            .and_then(|acked| acked.iter_mut().find(|a| a.proxy == i && a.hlc == hlc));
        match acked {
            Some(acked) => {
                acked.dropped = true;
                Ok(())
            }
            None => Err(format!(
                "p{i}: the quarantine holds {target} at {hlc}, never acked"
            )),
        }
    }

    /// Drops the engine of proxy `i` as a kill would, maybe with its index directory, and opens
    /// it again.
    async fn crash(&mut self, i: usize) -> Result<(), String> {
        self.proxies[i].engine = None;
        let index = self.proxies[i].dir.path().join("index");
        match self.rng.below(8) {
            0 | 1 if index.exists() => {
                std::fs::remove_dir_all(&index).unwrap();
                self.stats.lost_index = true;
            }
            // An older copy of the index comes back, as from a backup.
            2 if self.proxies[i].stale_index.is_some() => {
                let stale = self.proxies[i].stale_index.take().expect("checked above");
                std::fs::remove_dir_all(&index).unwrap();
                copy_tree(stale.path(), &index);
                self.stats.stale_index = true;
            }
            3 => {
                let copy = tempfile::tempdir().unwrap();
                copy_tree(&index, copy.path());
                self.proxies[i].stale_index = Some(copy);
            }
            _ => {}
        }
        self.open(i).await
    }

    /// The engine of proxy `i`, with the wall clock of that proxy for the call.
    fn engine(&self, i: usize) -> &Engine<ProxyRemote> {
        self.clocks(i);
        self.proxies[i].engine.as_ref().expect("the proxy is open")
    }

    /// Records an ack of proxy `i` at `hlc` and checks that its acks rise.
    fn acked(&mut self, i: usize, hlc: u64) -> Result<(), String> {
        self.log.push(format!("p{i} ack {hlc}"));
        let proxy = &mut self.proxies[i];
        if hlc <= proxy.last_ack {
            // The last steps show how the ack went down.
            let tail: Vec<_> = self.log.iter().rev().take(25).rev().cloned().collect();
            let tail = tail.join("\n");
            return Err(format!(
                "p{i}: ack HLC {hlc} is not above the last one {}\n{tail}",
                proxy.last_ack
            ));
        }
        proxy.last_ack = hlc;
        Ok(())
    }

    fn quarantine(&mut self, i: usize, e: &EngineError) {
        if matches!(e, EngineError::Quarantined(_)) {
            self.log.push(format!("p{i} quarantine: {e}"));
        }
    }

    /// A writer with bucket rights and no repo key puts a chain far ahead, or the operator
    /// removes the one it put.
    async fn keyless_step(&mut self) {
        if let Some((keys, _)) = self.keyless.take() {
            for key in keys {
                self.remote.delete(&key).await.unwrap();
            }
            return;
        }
        let seed = 100 + self.rng.below(100) as u8;
        // Garbage at seq 0, or seq 1 with no seq 0: no key is needed for these.
        let shape = self.rng.below(3);
        if shape > 0 {
            let node = model::NodeId::from_bytes(
                SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .to_bytes(),
            );
            let keys = vec![journal::entry_key(node, shape - 1), journal::node_key(node)];
            let garbage = Bytes::from_static(b"x");
            self.remote.inner.put(&keys[0], garbage).await.unwrap();
            self.remote.inner.put(&keys[1], Bytes::new()).await.unwrap();
            self.keyless = Some((keys, *node.as_bytes()));
            self.stats.keyless = true;
            return;
        }
        let other = RepoKey::from_hex(&"09".repeat(32)).unwrap().keys();
        let hlc = self.now + 10 * config().retention.as_nanos() as u64;
        let entry = journal::Entry::sign(
            &SigningKey::from_bytes(&[seed; 32]),
            0,
            [0; 32],
            hlc,
            BTreeMap::new(),
            vec![journal::Action::Delete {
                bucket: BUCKET.into(),
                key: "k0".into(),
                hlc,
            }],
            other.sealer(),
        );
        let keys = vec![entry.remote_key(), journal::node_key(entry.node)];
        self.remote
            .inner
            .put(&keys[0], Bytes::from(entry.to_wire()))
            .await
            .unwrap();
        self.remote.inner.put(&keys[1], Bytes::new()).await.unwrap();
        self.keyless = Some((keys, *entry.node.as_bytes()));
        self.keyless_hlc = self.keyless_hlc.max(hlc);
        self.stats.keyless = true;
    }

    /// A GC run on proxy 0. An error fails the run, unless a fault for it is in place.
    async fn gc(&mut self) -> Result<(), String> {
        let armed = self.remote.next.lock().unwrap().is_some();
        let r = self.engine(0).gc().await;
        self.log.push(format!("gc {r:?}"));
        let hit = armed && self.remote.next.lock().unwrap().is_none();
        // A chain from a writer with no repo key stops every GC run, and the refusal names it.
        if let Some((_, node)) = &self.keyless {
            match &r {
                Err(EngineError::BrokenChains(nodes))
                    if nodes.iter().any(|n| n.as_bytes() == node) => {}
                Err(EngineError::Quarantined(_)) => {}
                Err(e) if hit || self.far_ahead_explains(e) => {}
                other => return Err(format!("gc with a keyless chain: {other:?}")),
            }
            return Ok(());
        }
        match r {
            Ok(report) => {
                // The stable HLC is at most the highest clock of the proxies so far.
                self.note_clocks();
                let bound = self.highest_clock - config().retention.as_nanos() as u64;
                self.prune_bound = self.prune_bound.max(bound);
                self.stats.tombstone_prune |= report.pruned_keys > 0;
                self.stats.deleted_pack |= report.deleted_packs > 0;
                Ok(())
            }
            Err(EngineError::Quarantined(_)) => Ok(()),
            Err(e) if hit || self.far_ahead_explains(&e) => Ok(()),
            Err(e) => {
                let tail: Vec<_> = self.log.iter().rev().take(40).rev().cloned().collect();
                let causes = self
                    .engine(0)
                    .sync()
                    .await
                    .map(|report| report.broken_causes);
                Err(format!("gc: {e}\ncauses {causes:?}\n{}", tail.join("\n")))
            }
        }
    }

    /// A flush of proxy `i` that crashes after one of its local steps.
    async fn crash_in_flush(&mut self, i: usize) -> Result<(), String> {
        let point = POINTS[self.rng.below(POINTS.len() as u64) as usize];
        engine::sim::arm_crash(Some(point));
        let result = self.engine(i).flush().await;
        engine::sim::arm_crash(None);
        self.log
            .push(format!("p{i} crash flush {point:?}: {result:?}"));
        match result {
            Err(EngineError::SimCrash(point)) => {
                self.stats.crashes.insert(point);
                self.crash(i).await
            }
            Err(e) => {
                self.quarantine(i, &e);
                Ok(())
            }
            Ok(()) => Ok(()),
        }
    }

    /// The writes of one proxy fail for longer than R - M. Clients go on with acks there, and
    /// another proxy deletes keys and runs the GC. Then the remote works again.
    async fn outage(&mut self) -> Result<(), String> {
        let o = 1 + self.rng.below(2) as usize;
        let other = 3 - o;
        self.proxies[o].outage.store(true, Ordering::SeqCst);
        for _ in 0..8 {
            self.pass(80 * SECOND);
            self.put(o).await?;
            self.delete(other).await?;
            if let Err(e) = self.engine(other).flush().await {
                self.quarantine(other, &e);
            }
            let r = self.engine(o).flush().await;
            self.log.push(format!("p{o} outage flush {r:?}"));
            self.gc().await?;
        }
        self.proxies[o].outage.store(false, Ordering::SeqCst);
        if let Err(e) = self.engine(o).flush().await {
            self.quarantine(o, &e);
        }
        self.crash(o).await
    }

    async fn put(&mut self, i: usize) -> Result<(), String> {
        let key = format!("k{}", self.rng.below(KEYS));
        if self.rng.chance(2) {
            return self.spooled_put(i, key).await;
        }
        // Now and then one of a few large values: a later flush can dedup its chunks.
        let value = match self.rng.chance(30) {
            true => {
                let pick = self.rng.below(4) as u8;
                vec![pick; 64 * 1024]
            }
            false => self.rng.next().to_le_bytes().to_vec(),
        };
        // The open after a power loss needs the remote: in an outage it would fail for ever.
        let outage = self.proxies[i].outage.load(Ordering::SeqCst);
        let power_loss = !outage && self.loss.chance(3);
        engine::sim::arm_crash(power_loss.then_some(Point::Appended));
        let result = self
            .engine(i)
            .put(
                BUCKET,
                &key,
                Bytes::from(value.clone()),
                BTreeMap::new(),
                WriteMode::Overwrite,
            )
            .await;
        engine::sim::arm_crash(None);
        if let Err(EngineError::SimCrash(Point::Appended)) = result {
            return self.power_loss(i, &key, &value).await;
        }
        match result {
            Ok(info) => {
                self.log
                    .push(format!("p{i} put {key} at {}", info.last_modified));
                self.acked(i, info.last_modified)?;
                let node = self.proxies[i].node;
                self.keys.entry(key).or_default().push(Acked {
                    hlc: info.last_modified,
                    node,
                    value: Some(value),
                    proxy: i,
                    dropped: false,
                });
            }
            Err(e) => self.quarantine(i, &e),
        }
        Ok(())
    }

    /// A power loss after a put reached the active segment with no fsync and no ack: part of its
    /// record is lost. Half the time its data changes under a valid head, else the file ends
    /// inside the record. Then the proxy starts again.
    async fn power_loss(&mut self, i: usize, key: &str, value: &[u8]) -> Result<(), String> {
        self.proxies[i].engine = None;
        let buffer = self.proxies[i].dir.path().join("buffer");
        let last = std::fs::read_dir(&buffer)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|e| e == "log"))
            .max()
            .expect("the put is in a segment");
        let mut content = std::fs::read(&last).unwrap();
        let at = content
            .windows(value.len())
            .rposition(|window| window == value)
            .expect("the put is in the last segment");
        let changed = self.loss.chance(50);
        match changed {
            true => {
                content[at + value.len() / 2] ^= 1;
                self.stats.power_loss_data += 1;
            }
            false => {
                content.truncate(at + self.loss.below(value.len() as u64) as usize);
                self.stats.power_loss_cut += 1;
            }
        }
        std::fs::write(&last, &content).unwrap();
        self.log.push(format!(
            "p{i} power loss on the put of {key}: data changed {changed}"
        ));
        self.open(i).await
    }

    /// A put that streams its body through a spool file, now and then with a crash at one of its
    /// steps. After a crash the proxy starts again, and the put counts as acked when its value is
    /// the buffered head of the key: it was durable before the crash.
    async fn spooled_put(&mut self, i: usize, key: String) -> Result<(), String> {
        let mut value = vec![0u8; (1 << 20) + 1];
        for piece in value.chunks_mut(8) {
            let bytes = self.rng.next().to_le_bytes();
            piece.copy_from_slice(&bytes[..piece.len()]);
        }
        let points = [
            Point::SpoolData,
            Point::SpoolHead,
            Point::SpoolNext,
            Point::SpoolDirSync,
            Point::SpoolRename,
            Point::SpoolAck,
        ];
        // The open after a crash needs the remote: in an outage it would fail for ever.
        let outage = self.proxies[i].outage.load(Ordering::SeqCst);
        let point = (!outage && self.rng.chance(50))
            .then(|| points[self.rng.below(points.len() as u64) as usize]);
        engine::sim::arm_crash(point);
        let result = async {
            let engine = self.engine(i);
            let mut spool = engine
                .begin_put(BUCKET, &key, BTreeMap::new(), WriteMode::Overwrite)
                .await?;
            for piece in value.chunks(1 << 20) {
                engine.spool_write(&mut spool, piece).await?;
            }
            engine.finish_put(spool).await
        }
        .await;
        engine::sim::arm_crash(None);
        self.log.push(format!(
            "p{i} spooled put {key} {point:?}: {:?}",
            result.as_ref().map(|r| r.last_modified)
        ));
        let hlc = match result {
            Ok(info) => info.last_modified,
            Err(EngineError::SimCrash(_)) => {
                self.stats.spool_crash = true;
                self.proxies[i].engine = None;
                // The drop of the spool removes its file: a stray one shows that the open clears it.
                let spool = self.proxies[i].dir.path().join("buffer/spool");
                std::fs::write(spool.join("stray"), b"x").unwrap();
                self.open(i).await?;
                if std::fs::read_dir(&spool).unwrap().next().is_some() {
                    return Err(format!("p{i}: the open left a file in the spool"));
                }
                let hash = *blake3::hash(&value).as_bytes();
                match self.engine(i).head(BUCKET, &key).await {
                    Ok(info) if info.content_hash == hash => info.last_modified,
                    _ => return Ok(()),
                }
            }
            Err(e) => {
                self.quarantine(i, &e);
                return Ok(());
            }
        };
        self.acked(i, hlc)?;
        let node = self.proxies[i].node;
        self.keys.entry(key).or_default().push(Acked {
            hlc,
            node,
            value: Some(value),
            proxy: i,
            dropped: false,
        });
        Ok(())
    }

    async fn delete(&mut self, i: usize) -> Result<(), String> {
        let key = format!("k{}", self.rng.below(KEYS));
        match self.engine(i).delete(BUCKET, &key).await {
            Ok(()) => {
                let hlc = self.engine(i).last_hlc();
                self.acked(i, hlc)?;
                let node = self.proxies[i].node;
                self.keys.entry(key).or_default().push(Acked {
                    hlc,
                    node,
                    value: None,
                    proxy: i,
                    dropped: false,
                });
            }
            Err(e) => self.quarantine(i, &e),
        }
        Ok(())
    }

    async fn step(&mut self) -> Result<(), String> {
        let i = self.rng.below(3) as usize;
        let roll = self.rng.below(100);
        self.log
            .push(format!("step p{i} roll {roll} now {}", self.now));
        // Time goes on between two steps.
        let by = self.rng.below(3 * SECOND);
        self.pass(by);

        match roll {
            0..=27 => self.put(i).await?,
            28..=37 => self.delete(i).await?,
            38..=39 => self.outage().await?,
            40..=45 => {
                let name = OTHER_BUCKETS[self.rng.below(2) as usize];
                let create = self.rng.chance(50);
                let result = match create {
                    true => self.engine(i).create_bucket(name, None).await,
                    false => self.engine(i).delete_bucket(name).await,
                };
                match result {
                    Ok(()) => {
                        let hlc = self.engine(i).last_hlc();
                        self.acked(i, hlc)?;
                        let node = self.proxies[i].node;
                        self.buckets
                            .entry(name.to_string())
                            .or_default()
                            .push(Acked {
                                hlc,
                                node,
                                value: create.then(Vec::new),
                                proxy: i,
                                dropped: false,
                            });
                    }
                    // A create of a bucket that exists, or a delete of one that is gone.
                    Err(e) => self.quarantine(i, &e),
                }
            }
            46..=60 => {
                let r = self.engine(i).flush().await;
                self.log.push(format!("p{i} flush {r:?}"));
                if let Err(e) = r {
                    self.stats.stale_plan |= matches!(e, EngineError::StalePlan);
                    self.quarantine(i, &e);
                }
            }
            61 => {
                // A slow pack upload: the host sleeps between the plan and the commit.
                *self.remote.next.lock().unwrap() = Some(("packs/", Fault::Slow));
                let before = self.now;
                let r = self.engine(i).flush().await;
                self.log.push(format!("p{i} slow flush {r:?}"));
                // The shared time follows the wall clock that the sleep moved on. The sleeping
                // host did not count it on its monotonic clock.
                let wall = journal::wall_clock_nanos();
                let slept = wall
                    .saturating_sub(self.proxies[i].offset)
                    .saturating_sub(before);
                self.pass(slept);
                self.proxies[i].suspended += slept;
                if let Err(e) = r {
                    let stale = matches!(e, EngineError::StalePlan);
                    self.stats.stale_plan |= stale;
                    self.stats.slow_stale_plan |= stale;
                    self.quarantine(i, &e);
                }
                *self.remote.next.lock().unwrap() = None;
            }
            62..=72 => {
                let _ = self.engine(i).sync().await;
            }
            73..=76 => self.gc().await?,
            77..=78 => {
                let armed = self.remote.next.lock().unwrap().is_some();
                let r = self.engine(0).snapshot().await;
                // The key holds a random nonce: the log keeps only the result.
                self.log
                    .push(format!("snapshot {:?}", r.as_ref().map(|_| ())));
                let hit = armed && self.remote.next.lock().unwrap().is_none();
                match r {
                    Ok(_) | Err(EngineError::Quarantined(_)) => {}
                    Err(e) if hit || self.far_ahead_explains(&e) => {}
                    Err(e) => return Err(format!("snapshot: {e}")),
                }
            }
            79..=81 => self.crash(i).await?,
            82..=84 => self.crash_in_flush(i).await?,
            89 => {
                // A host suspend: the wall clock moves on, the monotonic clock does not.
                let pause = self.rng.below(300 * SECOND);
                self.pass(pause);
                self.proxies[i].suspended += pause;
                self.stats.suspend = true;
            }
            85 => {
                // One proxy runs ahead past M, and now and then past R: the others then see
                // its new entries as a broken chain until their clocks catch up.
                let m = config().late_margin.as_nanos() as u64;
                let r = config().retention.as_nanos() as u64;
                self.proxies[i].offset = match self.rng.chance(20) {
                    true => {
                        self.stats.far_ahead = true;
                        r + self.rng.below(m)
                    }
                    false => m + self.rng.below(m),
                };
                self.max_offset = self.max_offset.max(self.proxies[i].offset);
                self.note_clocks();
            }
            86 => {
                self.proxies[i].offset = self.rng.below(config().late_margin.as_nanos() as u64);
            }
            87..=88 if self.rng.chance(5) => {
                // A host boots with a wall clock more than R behind, writes in its buffer: no
                // ack goes down, and writes wait for the wall clock.
                let r = config().retention.as_nanos() as u64;
                let step = r + self.rng.below(r);
                self.proxies[i].engine = None;
                self.now = self.now.saturating_sub(step);
                self.open(i).await?;
                self.stats.step_back = true;
            }
            87..=88 => {
                // A step of the wall clock, back or ahead, inside the bound R - M.
                let step = self.rng.below(120 * SECOND);
                self.now = match self.rng.chance(50) {
                    true => self.now + step,
                    false => self.now.saturating_sub(step),
                };
            }
            90 => self.keyless_step().await,
            _ => {
                let prefix = ["log/", "packs/", "manifests/", "snapshots/", "nodes/"]
                    [self.rng.below(5) as usize];
                let fault = match self.rng.chance(50) {
                    true => Fault::Refuse,
                    false => Fault::LoseAnswer,
                };
                *self.remote.next.lock().unwrap() = Some((prefix, fault));
                let result = self.engine(i).flush().await;
                let used = self.remote.next.lock().unwrap().is_none();
                self.stats.marker_fault |= prefix == "nodes/" && used && result.is_err();
                if let Err(e) = result {
                    self.quarantine(i, &e);
                }
            }
        }
        Ok(())
    }

    /// The winner of each name among the acked writes that the operator did not drop.
    fn winners(writes: &BTreeMap<String, Vec<Acked>>) -> BTreeMap<String, Option<Acked>> {
        writes
            .iter()
            .map(|(name, acked)| {
                let kept = acked.iter().filter(|a| !a.dropped);
                (name.clone(), kept.max_by_key(|a| (a.hlc, a.node)).cloned())
            })
            .collect()
    }

    async fn settle(&mut self) -> Result<(), String> {
        *self.remote.next.lock().unwrap() = None;
        // The operator removes a chain of a writer with no repo key.
        if self.keyless.is_some() {
            self.keyless_step().await;
        }
        // Clocks come back, and time passes every HLC that ran ahead.
        for proxy in &mut self.proxies {
            proxy.offset = 0;
        }
        self.pass(self.max_offset);
        for i in 0..3 {
            if self.proxies[i].engine.is_none() {
                self.open(i).await?;
            }
        }
        // After steps back of the wall clocks, a clock can still be more than R ahead: time passes
        // until every proxy can sign again.
        let r = config().retention.as_nanos() as u64;
        let highest = (0..3).map(|i| self.engine(i).last_hlc()).max().unwrap_or(0);
        // A minute more: the last flushes sign entries just above the highest clock.
        self.pass(highest.saturating_sub(self.now + r) + 60 * SECOND);
        for i in 0..3 {
            self.proxies[i].outage.store(false, Ordering::SeqCst);
            // A quarantined proxy needs a restart to move its late writes aside.
            if self.engine(i).is_quarantined() {
                self.proxies[i].engine = None;
                self.open(i).await?;
            }
            // Writes that grew late during an outage go to the quarantine at a restart. The flush
            // syncs first, and newer entries of other nodes can make more writes late: restart
            // again, as an operator would.
            let mut restarts = 0;
            while let Err(e) = self.engine(i).flush().await {
                if !matches!(e, EngineError::Quarantined(_)) || restarts == 5 {
                    let tail: Vec<_> = self.log.iter().rev().take(8).rev().cloned().collect();
                    return Err(format!("p{i} final flush: {e}\n{}", tail.join("\n")));
                }
                restarts += 1;
                self.proxies[i].engine = None;
                self.open(i).await?;
            }
        }
        for _ in 0..2 {
            for i in 0..3 {
                let report = self
                    .engine(i)
                    .sync()
                    .await
                    .map_err(|e| format!("p{i} final sync: {e}"))?;
                if !report.broken.is_empty() {
                    return Err(format!("p{i}: broken chains {:?}", report.broken_causes));
                }
            }
        }
        Ok(())
    }

    /// The versions of `key` on each proxy. A version is an acked write that the operator did
    /// not drop. The last such write of each proxy, at or above the highest bound that a
    /// version prune could use, is on every proxy. A key may be gone only when its winner is a delete under that bound. The
    /// head and the conflicts are the same everywhere.
    fn check_versions(&self, key: &str, winner: Option<&Acked>) -> Result<(), String> {
        let acked: BTreeSet<(u64, [u8; 32])> = self
            .keys
            .get(key)
            .into_iter()
            .flatten()
            .filter(|a| !a.dropped)
            .map(|a| (a.hlc, a.node))
            .collect();
        let bound = self.prune_bound;
        // The buffer keeps only the last write of a proxy to a key before a flush, so an
        // earlier one can never be a version. The last one of each proxy always is.
        let mut last = BTreeMap::new();
        for write in self.keys.get(key).into_iter().flatten() {
            let newer = last
                .get(&write.node)
                .is_none_or(|(hlc, _)| write.hlc > *hlc);
            if newer {
                last.insert(write.node, (write.hlc, write.dropped));
            }
        }
        let kept: BTreeSet<_> = last
            .into_iter()
            .filter(|(_, (hlc, dropped))| !dropped && *hlc >= bound)
            .map(|(node, (hlc, _))| (hlc, node))
            .collect();
        let mut conflicts = Vec::new();
        for i in 0..3 {
            let state = self.engine(i).versions(BUCKET, key);
            let state = state.map_err(|e| format!("p{i} versions {key}: {e}"))?;
            conflicts.push(state.as_ref().map(|s| s.conflicts()).unwrap_or_default());
            let held: BTreeSet<(u64, [u8; 32])> = state
                .into_iter()
                .flat_map(|s| s.versions)
                .map(|v| (v.hlc, *v.node.as_bytes()))
                .collect();
            if let Some(phantom) = held.difference(&acked).next() {
                return Err(format!("p{i} {key}: version {phantom:?} was never acked"));
            }
            if held.is_empty() {
                let old_delete = winner.is_some_and(|w| w.value.is_none() && w.hlc < bound);
                if !old_delete && winner.is_some() {
                    return Err(format!("p{i} {key}: no version, the winner is {winner:?}"));
                }
                continue;
            }
            if let Some(lost) = kept.difference(&held).next() {
                return Err(format!(
                    "p{i} {key}: version {lost:?} at or above the prune bound {bound} is gone"
                ));
            }
            let head = held.last().copied();
            if head != winner.map(|w| (w.hlc, w.node)) {
                return Err(format!(
                    "p{i} {key}: head {head:?}, the winner is {winner:?}"
                ));
            }
        }
        if conflicts.iter().any(|c| c != &conflicts[0]) {
            return Err(format!("{key}: conflicts differ: {conflicts:?}"));
        }
        Ok(())
    }

    /// Every proxy lists the keys whose winner is a put, each at the HLC of that put.
    async fn check_lists(&self) -> Result<(), String> {
        let expected: Vec<(String, u64)> = Self::winners(&self.keys)
            .into_iter()
            .filter_map(|(key, w)| w.filter(|w| w.value.is_some()).map(|w| (key, w.hlc)))
            .collect();
        for i in 0..3 {
            let query = ListQuery {
                prefix: "",
                delimiter: None,
                after: None,
                max_keys: 1000,
            };
            let page = self.engine(i).list_page(BUCKET, &query).await;
            let page = page.map_err(|e| format!("p{i} list: {e}"))?;
            let listed: Vec<(String, u64)> = page
                .entries
                .into_iter()
                .filter_map(|entry| match entry {
                    ListEntry::Object(info) => Some((info.key, info.last_modified)),
                    ListEntry::CommonPrefix(_) => None,
                })
                .collect();
            if listed != expected {
                return Err(format!("p{i} lists {listed:?}, expected {expected:?}"));
            }
        }
        Ok(())
    }

    async fn check(&self) -> Result<(), String> {
        for i in 0..3 {
            let clock = self.engine(i).last_hlc();
            if self.keyless_hlc > 0 && clock >= self.keyless_hlc {
                return Err(format!("p{i}: the clock took a keyless HLC: {clock}"));
            }
        }
        for (key, winner) in Self::winners(&self.keys) {
            let expected = winner.as_ref().and_then(|w| w.value.clone());
            let mut seen = Vec::new();
            for i in 0..3 {
                let got = match self.engine(i).get(BUCKET, &key, None).await {
                    Ok(object) => {
                        let hlc = winner.as_ref().map(|w| w.hlc);
                        if Some(object.info.last_modified) != hlc {
                            return Err(format!(
                                "p{i} {key}: Last-Modified {}, the winner is {winner:?}",
                                object.info.last_modified
                            ));
                        }
                        Some(object.data.to_vec())
                    }
                    Err(EngineError::NoSuchKey { .. }) => None,
                    Err(e) => {
                        let versions = self.engine(i).versions(BUCKET, &key).ok().flatten();
                        let acked = self.keys.get(&key);
                        return Err(format!(
                            "p{i} get {key}: {e}\nversions {versions:?}\nacked {acked:?}"
                        ));
                    }
                };
                seen.push(got);
            }
            if seen.iter().any(|s| s != &seen[0]) {
                return Err(format!("{key}: proxies differ: {seen:?}"));
            }
            self.check_versions(&key, winner.as_ref())?;
            if seen[0] != expected {
                return Err(format!(
                    "{key}: read {:?}, the winner is {winner:?}",
                    seen[0]
                ));
            }
        }

        self.check_lists().await?;

        let winners = Self::winners(&self.buckets);
        let mut names = Vec::new();
        for i in 0..3 {
            let buckets = self
                .engine(i)
                .list_buckets()
                .await
                .map_err(|e| e.to_string())?;
            let listed: BTreeSet<String> = buckets.into_iter().map(|b| b.name).collect();
            names.push(listed);
        }
        if names.iter().any(|n| n != &names[0]) {
            return Err(format!("bucket lists differ: {names:?}"));
        }
        for (name, winner) in winners {
            let exists = names[0].contains(&name);
            let expected = winner.as_ref().is_some_and(|w| w.value.is_some());
            if exists != expected {
                return Err(format!(
                    "bucket {name}: exists {exists}, the winner is {winner:?}"
                ));
            }
        }
        Ok(())
    }
}

async fn run(seed: u64) -> Result<Stats, String> {
    CURRENT_SEED.with(|current| current.set(seed));
    // A seed must not see an armed crash point of the seed before it. Each call sets the
    // clocks of its proxy, so no clock carries over.
    engine::sim::arm_crash(None);
    let now = START;
    let dedup_before = engine::sim::dedup_hits();
    journal::set_manual_wall(Some(now));
    let remote = Arc::new(SimRemote::default());
    let mut sim = Sim {
        rng: Rng(seed),
        loss: Rng(seed ^ 0x9e37_79b9_7f4a_7c15),
        remote,
        proxies: Vec::new(),
        now,
        keys: BTreeMap::new(),
        buckets: BTreeMap::new(),
        log: Vec::new(),
        stats: Stats::default(),
        far_until: 0,
        far_nodes: BTreeSet::new(),
        prune_bound: 0,
        highest_clock: 0,
        keyless: None,
        keyless_hlc: 0,
        max_offset: 0,
        elapsed: SECOND,
    };
    for seed in 1..=3u8 {
        let key = SigningKey::from_bytes(&[seed; 32]);
        sim.proxies.push(Proxy {
            seed,
            dir: tempfile::tempdir().unwrap(),
            engine: None,
            node: key.verifying_key().to_bytes(),
            last_ack: 0,
            outage: Arc::new(AtomicBool::new(false)),
            stale_index: None,
            offset: 0,
            suspended: 0,
        });
    }
    for i in 0..3 {
        sim.open(i).await?;
    }
    sim.engine(0)
        .create_bucket(BUCKET, None)
        .await
        .map_err(|e| e.to_string())?;
    sim.engine(0).flush().await.map_err(|e| e.to_string())?;
    sim.pass(SECOND);
    for i in 1..3 {
        sim.engine(i).sync().await.map_err(|e| e.to_string())?;
    }

    for _ in 0..STEPS {
        sim.step().await?;
    }
    sim.settle().await?;
    sim.check().await?;
    sim.stats.dedup_hits = engine::sim::dedup_hits() - dedup_before;
    sim.stats.log_hash = *blake3::hash(sim.log.join("\n").as_bytes()).as_bytes();
    Ok(sim.stats)
}

/// What a set of seeds exercised.
#[derive(Debug, Default)]
struct Totals {
    seeds: u64,
    quarantine: u64,
    held_restart: u64,
    lost_index: u64,
    stale_index: u64,
    suspend: u64,
    tombstone_prune: u64,
    deleted_pack: u64,
    intent_quarantined: u64,
    young_kept: u64,
    stale_plan: u64,
    marker_fault: u64,
    far_ahead: u64,
    step_back: u64,
    spool_crash: u64,
    power_loss_data: u64,
    power_loss_cut: u64,
    refused_starts: u64,
    corrupt_quarantined: u64,
    keyless: u64,
    slow_stale_plan: u64,
    dedup_hits: u64,
    crashes: BTreeMap<Point, u64>,
}

impl Totals {
    fn add(&mut self, stats: &Stats) {
        self.seeds += 1;
        self.quarantine += u64::from(stats.quarantine);
        self.held_restart += u64::from(stats.held_restart);
        self.lost_index += u64::from(stats.lost_index);
        self.stale_index += u64::from(stats.stale_index);
        self.suspend += u64::from(stats.suspend);
        self.tombstone_prune += u64::from(stats.tombstone_prune);
        self.deleted_pack += u64::from(stats.deleted_pack);
        self.intent_quarantined += u64::from(stats.intent_quarantined);
        self.young_kept += u64::from(stats.young_kept);
        self.stale_plan += u64::from(stats.stale_plan);
        self.marker_fault += u64::from(stats.marker_fault);
        self.far_ahead += u64::from(stats.far_ahead);
        self.step_back += u64::from(stats.step_back);
        self.spool_crash += u64::from(stats.spool_crash);
        self.power_loss_data += stats.power_loss_data;
        self.power_loss_cut += stats.power_loss_cut;
        self.refused_starts += stats.refused_starts;
        self.corrupt_quarantined += stats.corrupt_quarantined;
        self.slow_stale_plan += u64::from(stats.slow_stale_plan);
        self.keyless += u64::from(stats.keyless);
        self.dedup_hits += stats.dedup_hits;
        for point in &stats.crashes {
            *self.crashes.entry(*point).or_default() += 1;
        }
    }

    /// Fails when a branch that the oracle must check never ran.
    fn assert_every_branch_ran(&self) {
        assert!(self.quarantine > 0, "no seed had a quarantine: {self:?}");
        assert!(
            self.held_restart > 0,
            "no seed restarted on a held quarantine: {self:?}"
        );
        assert!(self.lost_index > 0, "no seed lost an index: {self:?}");
        assert!(
            self.stale_index > 0,
            "no seed restored an older index: {self:?}"
        );
        let branches = [
            ("a host suspend", self.suspend),
            ("a tombstone prune", self.tombstone_prune),
            ("a deleted pack", self.deleted_pack),
            ("an intent in the quarantine", self.intent_quarantined),
            ("a young write kept at a quarantine", self.young_kept),
            ("a StalePlan", self.stale_plan),
            ("a failed marker write", self.marker_fault),
            ("a clock more than R ahead", self.far_ahead),
            ("a wall step back over R with a buffer", self.step_back),
            ("a spooled put that crashed", self.spool_crash),
            (
                "a power loss with bad data under a valid head",
                self.power_loss_data,
            ),
            ("a power loss that cut a record", self.power_loss_cut),
            (
                "a record with bad data in the quarantine",
                self.corrupt_quarantined,
            ),
            ("a StalePlan after a slow upload", self.slow_stale_plan),
            ("a chain from a writer with no repo key", self.keyless),
            ("a dedup hit", self.dedup_hits),
        ];
        for (branch, count) in branches {
            assert!(count > 0, "no seed had {branch}: {self:?}");
        }
        for point in POINTS {
            assert!(
                self.crashes.contains_key(&point),
                "no crash after {point:?}: {self:?}"
            );
        }
    }
}

/// Runs `seeds` on [`THREADS`] threads, each with a current-thread runtime. Panics with the
/// failed seeds. Returns what the seeds exercised.
fn run_seeds(seeds: Range<u64>) -> Totals {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("sim seed {}", CURRENT_SEED.with(std::cell::Cell::get));
        previous(info);
    }));
    let failed = Arc::new(Mutex::new(Vec::new()));
    let totals = Arc::new(Mutex::new(Totals::default()));
    let threads: Vec<_> = (0..THREADS)
        .map(|t| {
            let seeds = seeds.clone();
            let failed = failed.clone();
            let totals = totals.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                for seed in seeds.filter(|seed| seed % THREADS == t) {
                    match runtime.block_on(run(seed)) {
                        Ok(stats) => totals.lock().unwrap().add(&stats),
                        Err(e) => {
                            eprintln!("sim seed {seed} failed: {e}");
                            failed.lock().unwrap().push(seed);
                        }
                    }
                }
            })
        })
        .collect();
    let panicked: Vec<_> = threads.into_iter().filter_map(|t| t.join().err()).collect();
    let failed = failed.lock().unwrap().clone();
    assert!(
        panicked.is_empty() && failed.is_empty(),
        "failed seeds: {failed:?}"
    );
    let totals = std::mem::take(&mut *totals.lock().unwrap());
    eprintln!("sim totals: {totals:?}");
    totals
}

/// Seeds of a normal test run. One seed opens fjall about 6 times, about 3 s on macOS, so 1,000
/// seeds take 26 minutes there: the ignored test runs 20,000.
const NORMAL_SEEDS: u64 = 64;

/// One seed from SIM_SEED, else SIM_SEEDS seeds from 0, else the normal seeds.
#[test]
fn test_simulation_of_three_proxies() {
    match std::env::var("SIM_SEED").ok().and_then(|s| s.parse().ok()) {
        Some(seed) => {
            run_seeds(seed..seed + 1);
        }
        None => {
            let count = std::env::var("SIM_SEEDS").ok().and_then(|s| s.parse().ok());
            run_seeds(0..count.unwrap_or(NORMAL_SEEDS)).assert_every_branch_ran();
        }
    }
}

#[test]
#[ignore]
fn test_simulation_of_three_proxies_20000_seeds() {
    run_seeds(1000..21_000).assert_every_branch_ran();
}

/// The scenario that a pinned seed must still reach, as a count of its totals.
type Reached = fn(&Totals) -> u64;

/// Seeds that found a fault, run in every test run, each with the scenario that it reached then.
/// A change of the random draws can move a seed off its scenario: the test then fails, and the
/// scenario needs a new seed.
const REGRESSION_SEEDS: &[(u64, &str, Reached)] = &[
    // A proxy lost its index; the snapshot did not hold its newest own entry, and the next ack
    // went under an earlier one.
    (50, "lost_index", |t| t.lost_index),
    // The commit found a write late by the clock, the open did not, and the proxy refused the
    // commit at every start.
    (10, "held_restart", |t| t.held_restart),
    // An empty segment stopped the quarantine move; a late intent stayed in the buffer.
    (32, "intent_quarantined", |t| t.intent_quarantined),
    (40, "quarantine", |t| t.quarantine),
    // A remote error at open, with the supervisor starting the proxy again.
    (61, "refused_starts", |t| t.refused_starts),
    // A first entry reached the remote with a lost answer and no node marker; the GC did not see
    // the chain and deleted its pack.
    (598, "marker_fault", |t| t.marker_fault),
    // A clock more than R ahead caps the acks.
    (615, "far_ahead", |t| t.far_ahead),
    (919, "far_ahead", |t| t.far_ahead),
    // The version list oracle.
    (382, "corrupt_quarantined", |t| t.corrupt_quarantined),
    (454, "held_restart", |t| t.held_restart),
    (506, "step_back", |t| t.step_back),
    (638, "power_loss_cut", |t| t.power_loss_cut),
    (869, "keyless", |t| t.keyless),
    (926, "tombstone_prune", |t| t.tombstone_prune),
    (999, "keyless", |t| t.keyless),
    // A late write in the quarantine after a step back of the shared wall clock.
    (482, "step_back and quarantine", |t| {
        t.step_back.min(t.quarantine)
    }),
    (687, "step_back and quarantine", |t| {
        t.step_back.min(t.quarantine)
    }),
];

#[test]
fn test_simulation_regression_seeds() {
    for &(seed, scenario, reached) in REGRESSION_SEEDS {
        let totals = run_seeds(seed..seed + 1);
        assert!(
            reached(&totals) > 0,
            "seed {seed} no longer reaches {scenario}"
        );
    }
}

/// A seed gives the same run on a new thread and on a thread that an earlier seed left in any
/// state: manual clocks, a suspend, an armed crash point.
#[test]
fn test_seed_alone_and_after_other_seeds_gives_the_same_run() {
    let runtime = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    };
    let result = |stats: Stats| (stats.log_hash, stats.dedup_hits);
    let after = std::thread::spawn(move || {
        journal::set_manual_wall(Some(START + 7 * 3600 * SECOND));
        journal::suspend_manual(3600 * SECOND);
        journal::set_manual_monotonic(u64::MAX / 2);
        engine::sim::arm_crash(Some(Point::Commit));
        result(runtime().block_on(run(3)).unwrap())
    })
    .join()
    .unwrap();
    let alone = std::thread::spawn(move || result(runtime().block_on(run(3)).unwrap()))
        .join()
        .unwrap();

    assert_eq!(alone, after);
}
