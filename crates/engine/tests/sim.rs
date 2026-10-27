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
use engine::{Config, Engine, EngineError, RepoKey, WriteMode};
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
    quarantine: bool,
    /// A start failed again with the quarantine still held.
    held_restart: bool,
    crashes: BTreeSet<Point>,
    lost_index: bool,
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
}

impl Sim {
    async fn open(&mut self, i: usize) -> Result<(), String> {
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
                    self.now += self.rng.below(120 * SECOND);
                    journal::set_manual_wall(Some(self.now));
                    self.stats.held_restart = true;
                    return Box::pin(self.open(i)).await;
                }
                // The operator reads the late writes, drops them, and starts the proxy again.
                let held = engine::quarantined_writes(&dir)
                    .await
                    .map_err(|e| format!("p{i} quarantine: {e}"))?;
                self.log.push(format!("p{i} quarantine at open: {held:?}"));
                self.stats.quarantine = true;
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
        if self.rng.chance(25) {
            std::fs::remove_dir_all(self.proxies[i].dir.path().join("index")).unwrap();
            self.stats.lost_index = true;
        }
        self.open(i).await
    }

    fn engine(&self, i: usize) -> &Engine<ProxyRemote> {
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
            self.now += 80 * SECOND;
            journal::set_manual_wall(Some(self.now));
            self.put(o).await?;
            self.delete(other).await?;
            if let Err(e) = self.engine(other).flush().await {
                self.quarantine(other, &e);
            }
            let r = self.engine(o).flush().await;
            self.log.push(format!("p{o} outage flush {r:?}"));
            let r = self.engine(0).gc().await;
            self.log.push(format!("outage gc {r:?}"));
        }
        self.proxies[o].outage.store(false, Ordering::SeqCst);
        if let Err(e) = self.engine(o).flush().await {
            self.quarantine(o, &e);
        }
        self.crash(o).await
    }

    async fn put(&mut self, i: usize) -> Result<(), String> {
        let key = format!("k{}", self.rng.below(KEYS));
        let value = self.rng.next().to_le_bytes().to_vec();
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
        self.now += self.rng.below(3 * SECOND);
        journal::set_manual_wall(Some(self.now));

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
                    self.quarantine(i, &e);
                }
            }
            61..=72 => {
                let _ = self.engine(i).sync().await;
            }
            73..=76 => {
                let r = self.engine(0).gc().await;
                self.log.push(format!("gc {r:?}"));
            }
            77..=78 => {
                let _ = self.engine(0).snapshot().await;
            }
            79..=81 => self.crash(i).await?,
            82..=84 => self.crash_in_flush(i).await?,
            85..=89 => {
                // A step of the wall clock, back or ahead, inside the bound R - M.
                let step = self.rng.below(120 * SECOND);
                self.now = match self.rng.chance(50) {
                    true => self.now + step,
                    false => self.now.saturating_sub(step),
                };
                journal::set_manual_wall(Some(self.now));
            }
            _ => {
                let prefix =
                    ["log/", "packs/", "manifests/", "snapshots/"][self.rng.below(4) as usize];
                let fault = match self.rng.chance(50) {
                    true => Fault::Refuse,
                    false => Fault::LoseAnswer,
                };
                *self.remote.next.lock().unwrap() = Some((prefix, fault));
                if let Err(e) = self.engine(i).flush().await {
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

    async fn check(&self) -> Result<(), String> {
        for (key, winner) in Self::winners(&self.keys) {
            let expected = winner.as_ref().and_then(|w| w.value.clone());
            let mut seen = Vec::new();
            for i in 0..3 {
                let got = match self.engine(i).get(BUCKET, &key, None).await {
                    Ok(object) => Some(object.data.to_vec()),
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
            if seen[0] != expected {
                return Err(format!(
                    "{key}: read {:?}, the winner is {winner:?}",
                    seen[0]
                ));
            }
        }

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
    let mut now = START;
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
    now += SECOND;
    journal::set_manual_wall(Some(now));
    sim.now = now;
    for i in 1..3 {
        sim.engine(i).sync().await.map_err(|e| e.to_string())?;
    }

    for _ in 0..STEPS {
        sim.step().await?;
    }
    sim.settle().await?;
    sim.check().await?;
    Ok(sim.stats)
}

/// What a set of seeds exercised.
#[derive(Debug, Default)]
struct Totals {
    seeds: u64,
    quarantine: u64,
    held_restart: u64,
    lost_index: u64,
    crashes: BTreeMap<Point, u64>,
}

impl Totals {
    fn add(&mut self, stats: &Stats) {
        self.seeds += 1;
        self.quarantine += u64::from(stats.quarantine);
        self.held_restart += u64::from(stats.held_restart);
        self.lost_index += u64::from(stats.lost_index);
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
const REGRESSION_SEEDS: &[u64] = &[522, 50, 10, 32, 35, 40, 61, 598];

#[test]
fn test_simulation_regression_seeds() {
    for &seed in REGRESSION_SEEDS {
        run_seeds(seed..seed + 1);
    }
}
