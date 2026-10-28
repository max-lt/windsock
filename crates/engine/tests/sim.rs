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

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        self.inner.get(key).await
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

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        self.shared.get(key).await
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
    remote: Arc<SimRemote>,
    proxies: Vec<Proxy>,
    now: u64,
    keys: BTreeMap<String, Vec<Acked>>,
    buckets: BTreeMap<String, Vec<Acked>>,
    log: Vec<String>,
    stats: Stats,
    /// A clock ran more than R ahead: a GC or a snapshot may then fail on a broken chain.
    faulty: bool,
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
    }

    /// The wall and the monotonic clock of proxy `i`. Each host has its own monotonic clock:
    /// a wall step or a suspend of one host does not move the others.
    fn clocks(&self, i: usize) {
        let proxy = &self.proxies[i];
        journal::set_manual_wall(Some(self.now + proxy.offset));
        journal::set_manual_monotonic(self.elapsed - proxy.suspended);
    }

    async fn open(&mut self, i: usize) -> Result<(), String> {
        self.clocks(i);
        let proxy = &mut self.proxies[i];
        let remote = Arc::new(ProxyRemote {
            shared: self.remote.clone(),
            outage: proxy.outage.clone(),
        });
        let result = Engine::open(
            proxy.dir.path(),
            remote,
            SigningKey::from_bytes(&[proxy.seed; 32]),
            RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
            config(),
        )
        .await;
        match result {
            Ok(engine) => {
                proxy.engine = Some(engine);
                Ok(())
            }
            Err(EngineError::Quarantined(_)) => {
                let dir = proxy.dir.path().to_path_buf();
                // The supervisor starts the proxy again before the operator acts: a held
                // quarantine must block the start and stay as it is.
                if self.rng.chance(30) {
                    let wait = self.rng.below(120 * SECOND);
                    self.pass(wait);
                    self.stats.held_restart = true;
                    return Box::pin(self.open(i)).await;
                }
                // The operator reads the late writes, drops them, and starts the proxy again.
                let held = engine::quarantined_writes(&dir)
                    .await
                    .map_err(|e| format!("p{i} quarantine: {e}"))?;
                self.log.push(format!("p{i} quarantine at open: {held:?}"));
                self.stats.quarantine = true;
                // A write is late when its HLC is under the clock less (R - M), and the clock of
                // the open is at most R ahead of its wall clock.
                let wall = self.now + self.proxies[i].offset;
                let bound = wall + config().late_margin.as_nanos() as u64;
                if let Some(young) = held.iter().find(|w| w.hlc >= bound) {
                    return Err(format!(
                        "p{i}: a young write is in the quarantine: {young:?}"
                    ));
                }
                let intent = std::fs::read_dir(dir.join("quarantine")).unwrap().any(|e| {
                    e.unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with("intent")
                });
                self.stats.intent_quarantined |= intent;
                let newest = held.iter().map(|w| w.hlc).max().unwrap_or(0);
                self.stats.young_kept |= self.acked_after(i, newest);
                for write in held {
                    self.drop_acked(i, &write.target, write.hlc)?;
                }
                std::fs::remove_dir_all(dir.join("quarantine")).unwrap();
                Box::pin(self.open(i)).await
            }
            // A remote error at open: the supervisor starts the proxy again.
            Err(e) if e.to_string().contains("injected") => {
                self.log.push(format!("p{i} open failed: {e}"));
                Box::pin(self.open(i)).await
            }
            Err(e) => Err(format!("p{i} open: {e}")),
        }
    }

    /// True when proxy `i` acked a write after `hlc` that the operator did not drop.
    fn acked_after(&self, i: usize, hlc: u64) -> bool {
        self.keys
            .values()
            .chain(self.buckets.values())
            .flatten()
            .any(|a| a.proxy == i && a.hlc > hlc && !a.dropped)
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

    /// A GC run on proxy 0. An error fails the run, unless a fault for it is in place.
    async fn gc(&mut self) -> Result<(), String> {
        let armed = self.remote.next.lock().unwrap().is_some();
        let r = self.engine(0).gc().await;
        self.log.push(format!("gc {r:?}"));
        let hit = armed && self.remote.next.lock().unwrap().is_none();
        match r {
            Ok(report) => {
                self.stats.tombstone_prune |= report.pruned_keys > 0;
                self.stats.deleted_pack |= report.deleted_packs > 0;
                Ok(())
            }
            Err(EngineError::Quarantined(_)) => Ok(()),
            Err(_) if self.faulty || hit => Ok(()),
            Err(e) => Err(format!("gc: {e}")),
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
        // Now and then one of a few large values: a later flush can dedup its chunks.
        let value = match self.rng.chance(30) {
            true => {
                let pick = self.rng.below(4) as u8;
                vec![pick; 64 * 1024]
            }
            false => self.rng.next().to_le_bytes().to_vec(),
        };
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
                    Err(_) if self.faulty || hit => {}
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
                        self.faulty = true;
                        r + self.rng.below(m)
                    }
                    false => m + self.rng.below(m),
                };
                self.max_offset = self.max_offset.max(self.proxies[i].offset);
            }
            86 => {
                self.proxies[i].offset = self.rng.below(config().late_margin.as_nanos() as u64);
            }
            87..=88 => {
                // A step of the wall clock, back or ahead, inside the bound R - M.
                let step = self.rng.below(120 * SECOND);
                self.now = match self.rng.chance(50) {
                    true => self.now + step,
                    false => self.now.saturating_sub(step),
                };
            }
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
            let mut versions = Vec::new();
            let mut conflicts = Vec::new();
            for i in 0..3 {
                let state = self.engine(i).versions(BUCKET, &key);
                let state = state.map_err(|e| format!("p{i} versions {key}: {e}"))?;
                conflicts.push(state.as_ref().map(|s| s.conflicts()).unwrap_or_default());
                let ranks: BTreeSet<_> = state
                    .into_iter()
                    .flat_map(|s| s.versions)
                    .map(|v| (v.hlc, v.node))
                    .collect();
                versions.push(ranks);
            }
            // The version prune is local: it drops known versions below its bound, and keeps
            // the head and the conflicts. A proxy holds fewer versions, never other ones. A key
            // whose head is an old delete goes as a whole.
            if expected.is_none() {
                let kept: Vec<usize> = (0..3).filter(|&i| !versions[i].is_empty()).collect();
                versions = kept.iter().map(|&i| versions[i].clone()).collect();
                conflicts = kept.iter().map(|&i| conflicts[i].clone()).collect();
            }
            let all: BTreeSet<_> = versions.iter().flatten().copied().collect();
            let longest = versions.iter().map(BTreeSet::len).max().unwrap_or(0);
            let heads: Vec<_> = versions.iter().map(|v| v.last()).collect();
            if all.len() != longest
                || heads.iter().any(|h| h != &heads[0])
                || conflicts.iter().any(|c| c != &conflicts[0])
            {
                return Err(format!(
                    "{key}: version lists differ: {versions:?}, conflicts {conflicts:?}"
                ));
            }
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
    // A seed must not see the clocks of the seed before it on this thread.
    journal::reset_manual_clock();
    let now = START;
    let dedup_before = engine::sim::dedup_hits();
    journal::set_manual_wall(Some(now));
    let remote = Arc::new(SimRemote::default());
    let mut sim = Sim {
        rng: Rng(seed),
        remote,
        proxies: Vec::new(),
        now,
        keys: BTreeMap::new(),
        buckets: BTreeMap::new(),
        log: Vec::new(),
        stats: Stats::default(),
        faulty: false,
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
        self.slow_stale_plan += u64::from(stats.slow_stale_plan);
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
            ("a StalePlan after a slow upload", self.slow_stale_plan),
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

/// Seeds that found a fault, run in every test run.
/// - 522: an intent entry reached the remote with a lost answer, the clock stepped back, and after
///   a reopen the next own entry had a lower HLC.
/// - 50: a proxy lost its index; the snapshot did not hold its newest own entry, and the next ack
///   went under an earlier one.
/// - 10: the commit found a write late by the clock, the open did not, and the proxy refused the
///   commit at every start.
/// - 32, 35, 40: an empty segment stopped the quarantine move; a late intent stayed in the buffer.
/// - 61: a remote error at open, with the supervisor starting the proxy again.
/// - 598: a first entry reached the remote with a lost answer and no node marker; the GC did not
///   see the chain and deleted its pack.
const REGRESSION_SEEDS: &[u64] = &[
    522, 50, 10, 32, 35, 40, 61, 598, 382, 454, 506, 638, 869, 926, 999,
];

#[test]
fn test_simulation_regression_seeds() {
    for &seed in REGRESSION_SEEDS {
        run_seeds(seed..seed + 1);
    }
}

/// One seed gives the same run alone and after other seeds on the same thread.
#[test]
fn test_seed_alone_and_after_other_seeds_gives_the_same_run() {
    let runtime = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    };
    let after = std::thread::spawn(move || {
        let runtime = runtime();
        for seed in 0..3 {
            runtime.block_on(run(seed)).unwrap();
        }
        runtime.block_on(run(3)).unwrap().log_hash
    })
    .join()
    .unwrap();
    let alone = std::thread::spawn(move || runtime().block_on(run(3)).unwrap().log_hash)
        .join()
        .unwrap();

    assert_eq!(alone, after);
}
