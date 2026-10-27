//! Deterministic simulation: 3 proxies on one remote, a manual wall clock, and random steps from
//! one seed. A failed run prints its seed: run it again with `SIM_SEED=<seed>`.
//!
//! The oracle: for each key, the acked write with the highest (ack HLC, node) wins on every proxy
//! after a final flush and sync. A write may be missing only after a quarantine on its proxy.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, EngineError, RepoKey, WriteMode};
use remote::{MemoryRemote, Remote, RemoteError, Sweep};
use tempfile::TempDir;

const BUCKET: &str = "bkt";
const KEYS: u64 = 8;
const OTHER_BUCKETS: [&str; 2] = ["one", "two"];
const STEPS: u64 = 60;
const SECOND: u64 = 1_000_000_000;
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

/// One acked write: its rank and what a reader must see if it wins.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Acked {
    hlc: u64,
    node: [u8; 32],
    /// The data of a put, `None` for a delete.
    value: Option<Vec<u8>>,
    proxy: usize,
}

struct Proxy {
    seed: u8,
    dir: TempDir,
    engine: Option<Engine<SimRemote>>,
    node: [u8; 32],
    /// The last ack HLC that this proxy gave: the next one must be higher.
    last_ack: u64,
    /// A quarantine happened on this proxy: its late writes may be missing.
    quarantined: bool,
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
}

impl Sim {
    async fn open(&mut self, i: usize) -> Result<(), String> {
        let proxy = &mut self.proxies[i];
        let result = Engine::open(
            proxy.dir.path(),
            self.remote.clone(),
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
            Err(EngineError::Quarantined(keys)) => {
                // The operator drops the late writes, then starts the proxy again.
                self.log.push(format!("p{i} quarantine at open: {keys}"));
                proxy.quarantined = true;
                std::fs::remove_dir_all(proxy.dir.path().join("quarantine")).unwrap();
                Box::pin(self.open(i)).await
            }
            Err(e) => Err(format!("p{i} open: {e}")),
        }
    }

    fn engine(&self, i: usize) -> &Engine<SimRemote> {
        self.proxies[i].engine.as_ref().expect("the proxy is open")
    }

    /// Records an ack of proxy `i` at `hlc` and checks that its acks rise.
    fn acked(&mut self, i: usize, hlc: u64) -> Result<(), String> {
        let proxy = &mut self.proxies[i];
        if hlc <= proxy.last_ack {
            return Err(format!(
                "p{i}: ack HLC {hlc} is not above the last one {}",
                proxy.last_ack
            ));
        }
        proxy.last_ack = hlc;
        Ok(())
    }

    fn quarantine(&mut self, i: usize, e: &EngineError) {
        if matches!(e, EngineError::Quarantined(_)) {
            self.log.push(format!("p{i} quarantine: {e}"));
            self.proxies[i].quarantined = true;
        }
    }

    async fn step(&mut self) -> Result<(), String> {
        let i = self.rng.below(3) as usize;
        let roll = self.rng.below(100);
        // Time goes on between two steps.
        self.now += self.rng.below(3 * SECOND);
        journal::set_manual_wall(Some(self.now));

        match roll {
            0..=29 => {
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
                        self.acked(i, info.last_modified)?;
                        let node = self.proxies[i].node;
                        self.keys.entry(key).or_default().push(Acked {
                            hlc: info.last_modified,
                            node,
                            value: Some(value),
                            proxy: i,
                        });
                    }
                    Err(e) => self.quarantine(i, &e),
                }
            }
            30..=39 => {
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
                        });
                    }
                    Err(e) => self.quarantine(i, &e),
                }
            }
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
                            });
                    }
                    // A create of a bucket that exists, or a delete of one that is gone.
                    Err(e) => self.quarantine(i, &e),
                }
            }
            46..=60 => {
                if let Err(e) = self.engine(i).flush().await {
                    self.quarantine(i, &e);
                }
            }
            61..=72 => {
                let _ = self.engine(i).sync().await;
            }
            73..=76 => {
                let _ = self.engine(0).gc().await;
            }
            77..=78 => {
                let _ = self.engine(0).snapshot().await;
            }
            79..=84 => {
                // A crash: the buffer stays on disk and replays at the next open.
                self.proxies[i].engine = None;
                self.open(i).await?;
            }
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

    /// The winner of each name, and whether it may be missing after a quarantine.
    fn winners(&self, writes: &BTreeMap<String, Vec<Acked>>) -> BTreeMap<String, (Acked, bool)> {
        writes
            .iter()
            .map(|(name, acked)| {
                let winner = acked
                    .iter()
                    .max_by_key(|a| (a.hlc, a.node))
                    .expect("a name has writes")
                    .clone();
                let may_miss = acked.iter().any(|a| self.proxies[a.proxy].quarantined);
                (name.clone(), (winner, may_miss))
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
            // A quarantined proxy needs a restart to move its late writes aside.
            if self.engine(i).is_quarantined() {
                self.proxies[i].engine = None;
                self.open(i).await?;
            }
            self.engine(i)
                .flush()
                .await
                .map_err(|e| format!("p{i} final flush: {e}"))?;
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
        for (key, (winner, may_miss)) in self.winners(&self.keys) {
            let mut seen = Vec::new();
            for i in 0..3 {
                let got = match self.engine(i).get(BUCKET, &key, None).await {
                    Ok(object) => Some(object.data.to_vec()),
                    Err(EngineError::NoSuchKey { .. }) => None,
                    Err(e) => return Err(format!("p{i} get {key}: {e}")),
                };
                seen.push(got);
            }
            if seen.iter().any(|s| s != &seen[0]) {
                return Err(format!("{key}: proxies differ: {seen:?}"));
            }
            if seen[0] != winner.value && !may_miss {
                return Err(format!(
                    "{key}: read {:?}, the winner is {:?} from p{} at {}",
                    seen[0], winner.value, winner.proxy, winner.hlc
                ));
            }
        }

        let winners = self.winners(&self.buckets);
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
        for (name, (winner, may_miss)) in winners {
            let exists = names[0].contains(&name);
            if exists != winner.value.is_some() && !may_miss {
                return Err(format!(
                    "bucket {name}: exists {exists}, the winner is {winner:?}"
                ));
            }
        }
        Ok(())
    }
}

async fn run(seed: u64) -> Result<(), String> {
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
    };
    for seed in 1..=3u8 {
        let key = SigningKey::from_bytes(&[seed; 32]);
        sim.proxies.push(Proxy {
            seed,
            dir: tempfile::tempdir().unwrap(),
            engine: None,
            node: key.verifying_key().to_bytes(),
            last_ack: 0,
            quarantined: false,
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
    sim.check().await
}

/// Runs `seeds` on [`THREADS`] threads, each with a current-thread runtime. Panics with the
/// failed seeds.
fn run_seeds(seeds: Range<u64>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("sim seed {}", CURRENT_SEED.with(std::cell::Cell::get));
        previous(info);
    }));
    let failed = Arc::new(Mutex::new(Vec::new()));
    let threads: Vec<_> = (0..THREADS)
        .map(|t| {
            let seeds = seeds.clone();
            let failed = failed.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                for seed in seeds.filter(|seed| seed % THREADS == t) {
                    if let Err(e) = runtime.block_on(run(seed)) {
                        eprintln!("sim seed {seed} failed: {e}");
                        failed.lock().unwrap().push(seed);
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
}

/// Seeds of a normal test run. One seed opens fjall about 6 times, about 3 s on macOS, so 1,000
/// seeds take 26 minutes there: the ignored test runs 20,000.
const NORMAL_SEEDS: u64 = 64;

/// One seed from SIM_SEED, else the normal seeds.
#[test]
fn test_simulation_of_three_proxies() {
    match std::env::var("SIM_SEED").ok().and_then(|s| s.parse().ok()) {
        Some(seed) => run_seeds(seed..seed + 1),
        None => run_seeds(0..NORMAL_SEEDS),
    }
}

#[test]
#[ignore]
fn test_simulation_of_three_proxies_20000_seeds() {
    run_seeds(1000..21_000);
}

/// Seeds that found a fault, run in every test run.
#[test]
fn test_simulation_regression_seeds() {
    // 522: an entry in the intent reached the remote with a lost answer, the clock stepped back,
    // and after a reopen the next own entry had a lower HLC.
    for seed in [522] {
        run_seeds(seed..seed + 1);
    }
}
