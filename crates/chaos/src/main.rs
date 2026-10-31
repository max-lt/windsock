//! Chaos soak: 3 windsockd processes on one directory remote, mixed S3 traffic, kills, restarts,
//! a full disk and a stop longer than H. At the end every proxy must read, for each key, the
//! same value, and one that the acks allow.
//!
//! macOS, needs hdiutil, rsync and lsof:
//!
//! ```bash
//! cargo build --release -p windsockd -p chaos
//! ./target/release/windsock-chaos --minutes 10 --work /tmp/ws-chaos
//! ```
//!
//! It prints one line per phase and a result. It exits 1 when a check fails.

mod model;
mod proxy;
mod s3;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustix::process::Signal;
use tokio::sync::Mutex;

use model::{Model, Rng, Value, digest};
use proxy::{BUCKET, HORIZON, Proxy};
use s3::Outcome;

const WORKERS: u64 = 6;
/// The keys of each worker that get large objects: several read pieces, so GETs read ahead.
const BIG_KEYS: u64 = 4;
const BIG_SIZES: [usize; 2] = [12 << 20, 24 << 20];
/// Log lines that a soak must never show.
const ALARMS: [&str; 6] = [
    "chain is broken",
    "Gap",
    "Changed",
    "panicked",
    "broken chains",
    "differs from the copy",
];

struct Args {
    minutes: f64,
    work: PathBuf,
    image_mb: u64,
    seed: u64,
    bin: PathBuf,
}

fn args() -> Result<Args, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut args = Args {
        minutes: 10.0,
        work: PathBuf::from("/tmp/ws-chaos"),
        image_mb: 64,
        seed: 1,
        bin: root.join("target/release/windsockd"),
    };
    let mut items = std::env::args().skip(1);
    while let Some(name) = items.next() {
        let value = items.next().ok_or(format!("{name} needs a value"))?;
        let number = || value.parse::<u64>().map_err(|e| format!("{name}: {e}"));
        match name.as_str() {
            "--minutes" => args.minutes = value.parse().map_err(|e| format!("{name}: {e}"))?,
            "--work" => args.work = PathBuf::from(&value),
            "--image-mb" => args.image_mb = number()?,
            "--seed" => args.seed = number()?,
            "--bin" => args.bin = PathBuf::from(&value),
            _ => {
                return Err(format!(
                    "unknown {name}. Usage: windsock-chaos [--minutes 10] [--work /tmp/ws-chaos] \
                     [--image-mb 64] [--seed 1] [--bin target/release/windsockd]"
                ));
            }
        }
    }
    Ok(args)
}

fn log(text: &str) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    println!("{h:02}:{m:02}:{s:02} UTC {text}");
}

/// Random S3 traffic on random proxies until `stop`, into the model.
async fn worker(
    w: u64,
    proxies: Arc<Vec<Proxy>>,
    model: Arc<Model>,
    stop: Arc<AtomicBool>,
    pressure: Arc<Pressure>,
    seed: u64,
) {
    let mut rng = Rng::new(seed * 100 + w);
    while !stop.load(Ordering::SeqCst) {
        let p = &proxies[rng.below(3) as usize];
        if !p.running() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        }
        let key = format!("w{w}/k{}", rng.below(40));
        let path = format!("/{BUCKET}/{key}");
        let level = pressure.level();
        let big = format!("w{w}/b{}", rng.below(BIG_KEYS));
        let big_path = format!("/{BUCKET}/{big}");
        let write = match rng.weighted(&[40, 20, 10, 10, 5, 15, 3, 5, 4, 2]) {
            0 => {
                let size = *rng.pick(&[0, 1, 100, 4096, 65536, 300_000, 2_000_000]);
                let data = rng.bytes(size);
                let (value, outcome) = (digest(&data), p.s3.put(&path, Bytes::from(data)).await);
                model.record(&key, value, outcome);
                Some(outcome)
            }
            1 => {
                let _ = p.s3.get(&path).await;
                None
            }
            2 => {
                let outcome = p.s3.delete(&path).await;
                model.record(&key, None, outcome);
                Some(outcome)
            }
            3 => {
                let _ = p.s3.list(BUCKET, &format!("w{w}/")).await;
                None
            }
            4 => {
                let count = 1 + rng.below(3);
                let parts: Vec<Bytes> = (0..count)
                    .map(|_| {
                        let size = *rng.pick(&[1, 70_000, 1_100_000, 6_000_000]);
                        Bytes::from(rng.bytes(size))
                    })
                    .collect();
                let whole: Vec<u8> = parts.iter().flat_map(|part| part.to_vec()).collect();
                let outcome = p.s3.multipart(&path, &parts).await;
                if let Some(outcome) = outcome {
                    model.record(&key, digest(&whole), outcome);
                }
                outcome
            }
            5 => {
                let _ = p.s3.get_range(&path, "bytes=10-5000").await;
                None
            }
            6 => {
                let size = *rng.pick(&BIG_SIZES);
                let data = rng.bytes(size);
                let (value, outcome) =
                    (digest(&data), p.s3.put(&big_path, Bytes::from(data)).await);
                model.record(&big, value, outcome);
                Some(outcome)
            }
            7 => {
                let source = match rng.below(2) {
                    0 => big.clone(),
                    _ => format!("w{w}/k{}", rng.below(40)),
                };
                let (outcome, value) = p.s3.copy(&path, &format!("/{BUCKET}/{source}")).await;
                model.record_copy(&key, &source, value, outcome);
                Some(outcome)
            }
            // A cold read with read-ahead, by a client that goes away at a random point.
            8 => {
                let _ =
                    p.s3.get_part(&big_path, rng.below(BIG_SIZES[1] as u64))
                        .await;
                None
            }
            _ => {
                let _ = p.s3.get(&big_path).await;
                None
            }
        };
        pressure.count(level);
        // A refused write is back-pressure: a client that sends again at once only adds load.
        if write == Some(Outcome::Refused) {
            tokio::time::sleep(REFUSED_PAUSE).await;
        }
        tokio::time::sleep(LEVELS[level].1).await;
    }
}

/// The load levels: a name and the pause of each worker between two operations.
const LEVELS: [(&str, Duration); 4] = [
    ("burst", Duration::ZERO),
    ("high", Duration::from_millis(2)),
    ("medium", Duration::from_millis(20)),
    ("quiet", Duration::from_millis(200)),
];
/// The pause of a worker after a refused write.
const REFUSED_PAUSE: Duration = Duration::from_millis(50);

/// The load level of all workers, and the operations at each level.
#[derive(Default)]
struct Pressure {
    level: AtomicU64,
    ops: [AtomicU64; 4],
}

impl Pressure {
    fn level(&self) -> usize {
        self.level.load(Ordering::SeqCst) as usize
    }

    fn count(&self, level: usize) {
        self.ops[level].fetch_add(1, Ordering::SeqCst);
    }
}

/// Moves the load to a random level every 20 to 60 s: a soak at one load tests one regime only.
async fn vary(pressure: Arc<Pressure>, stop: Arc<AtomicBool>, seed: u64) {
    let mut rng = Rng::new(seed + 7);
    while !stop.load(Ordering::SeqCst) {
        let level = rng.below(LEVELS.len() as u64);
        pressure.level.store(level, Ordering::SeqCst);
        log(&format!("load: {}", LEVELS[level as usize].0));
        tokio::time::sleep(rng.secs(20, 60)).await;
    }
}

/// Kills and stops of random proxies, with a restart after each.
async fn faults(
    proxies: Arc<Vec<Proxy>>,
    stop: Arc<AtomicBool>,
    pause: Arc<Mutex<()>>,
    seed: u64,
    counts: Arc<[AtomicU64; 3]>,
) {
    let mut rng = Rng::new(seed);
    while !stop.load(Ordering::SeqCst) {
        tokio::time::sleep(rng.secs(8, 25)).await;
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let p = &proxies[rng.below(3) as usize];
        let (signal, name, slot) = match rng.below(3) {
            0 => (Signal::TERM, "TERM", 1),
            _ => (Signal::KILL, "KILL", 0),
        };
        let _held = pause.lock().await;
        if !p.running() {
            continue;
        }
        log(&format!("fault: {name} p{}", p.n));
        match p.restart(signal, rng.secs(0, 4)).await {
            Ok(()) => counts[slot].fetch_add(1, Ordering::SeqCst),
            Err(e) => {
                log(&format!("restart failed: {e}"));
                counts[2].fetch_add(1, Ordering::SeqCst)
            }
        };
    }
}

/// Memory and open files of each proxy every 30 s.
async fn monitor(
    proxies: Arc<Vec<Proxy>>,
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<String>>>,
) {
    let start = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_secs(30)).await;
        for p in proxies.iter() {
            let Some((rss, fds)) = p.usage() else {
                continue;
            };
            let total: u64 = fds.values().sum();
            let line = format!(
                "{}s p{} rss {rss} MiB fds {total} {fds:?}",
                start.elapsed().as_secs(),
                p.n
            );
            log(&format!("usage: {line}"));
            samples.lock().await.push(line);
        }
    }
}

/// The keys where the proxies differ, or show a value that the acks do not allow. Waits up to
/// 180 s for the proxies to agree.
async fn converge(
    proxies: &[Proxy],
    allowed: &BTreeMap<String, BTreeSet<Value>>,
) -> Vec<(String, Vec<String>)> {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let mut bad = Vec::new();
        for (key, values) in allowed {
            let mut seen = Vec::new();
            for p in proxies {
                let read = match p.s3.get(&format!("/{BUCKET}/{key}")).await {
                    Ok(reply) if reply.ok() => Ok(digest(&reply.body)),
                    Ok(reply) if reply.status == 404 => Ok(None),
                    Ok(reply) => Err(format!("status {}", reply.status)),
                    Err(e) => Err(e),
                };
                seen.push(read);
            }
            let same = seen.iter().all(|read| read == &seen[0]);
            let allowed = matches!(&seen[0], Ok(value) if values.contains(value));
            if !same || !allowed {
                let shown = seen.iter().map(|read| format!("{read:?}")).collect();
                bad.push((key.clone(), shown));
            }
        }
        if bad.is_empty() || Instant::now() > deadline {
            return bad;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// The log lines of each proxy that hold an alarm, at most 3 for each alarm.
fn alarms(proxies: &[Proxy]) -> Vec<String> {
    let mut hits = Vec::new();
    for p in proxies {
        let text = std::fs::read_to_string(&p.log).unwrap_or_default();
        for alarm in ALARMS {
            let found = text.lines().filter(|line| line.contains(alarm)).take(3);
            hits.extend(found.map(|line| format!("p{}: {line}", p.n)));
        }
    }
    hits
}

async fn soak(args: &Args, proxies: Arc<Vec<Proxy>>) -> Result<bool, String> {
    for p in proxies.iter() {
        p.start().await?;
    }
    let created = proxies[0]
        .s3
        .send("PUT", &format!("/{BUCKET}"), "", &[], Bytes::new())
        .await?;
    if !created.ok() {
        return Err(format!("create bucket: status {}", created.status));
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    let model = Arc::new(Model::default());
    let stop = Arc::new(AtomicBool::new(false));
    let pause = Arc::new(Mutex::new(()));
    let counts = Arc::new([AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)]);
    let samples = Arc::new(Mutex::new(Vec::new()));
    let mut tasks = Vec::new();
    let pressure = Arc::new(Pressure::default());
    for w in 0..WORKERS {
        let (proxies, model, stop) = (proxies.clone(), model.clone(), stop.clone());
        let pressure = pressure.clone();
        tasks.push(tokio::spawn(worker(
            w, proxies, model, stop, pressure, args.seed,
        )));
    }
    tasks.push(tokio::spawn(vary(
        pressure.clone(),
        stop.clone(),
        args.seed,
    )));
    let (p, s, l, c) = (proxies.clone(), stop.clone(), pause.clone(), counts.clone());
    tasks.push(tokio::spawn(faults(p, s, l, args.seed, c)));
    let (p, s, m) = (proxies.clone(), stop.clone(), samples.clone());
    tasks.push(tokio::spawn(monitor(p, s, m)));

    let start = Instant::now();
    let total = Duration::from_secs_f64(args.minutes * 60.0);
    tokio::time::sleep(total / 4).await;
    for sub in ["buffer", "index"] {
        log(&format!(
            "phase: p2 with a full disk under data/engine/{sub} for 10 s"
        ));
        let _held = pause.lock().await;
        proxies[2]
            .full_disk(sub, &args.work, args.image_mb, Duration::from_secs(10))
            .await?;
        log(&format!("phase: p2 back from the full {sub} disk"));
    }
    tokio::time::sleep((total / 2).saturating_sub(start.elapsed())).await;
    log(&format!(
        "phase: p1 stops for {} s, longer than H",
        2 * HORIZON
    ));
    {
        let _held = pause.lock().await;
        proxies[1].stop(Signal::TERM).await;
        tokio::time::sleep(Duration::from_secs(2 * HORIZON)).await;
        proxies[1].start().await?;
    }
    log("phase: p1 back");
    tokio::time::sleep(total.saturating_sub(start.elapsed())).await;

    stop.store(true, Ordering::SeqCst);
    for task in tasks {
        let _ = task.await;
    }
    let ops = model.counts();
    let faults: Vec<u64> = counts.iter().map(|c| c.load(Ordering::SeqCst)).collect();
    log(&format!(
        "load stopped: {ops:?}; faults KILL {} TERM {} failed restarts {}",
        faults[0], faults[1], faults[2]
    ));
    tokio::time::sleep(Duration::from_secs(15)).await;

    for p in proxies.iter() {
        if !p.running() {
            p.start().await?;
        }
    }
    let allowed = model.allowed();
    let bad = converge(&proxies, &allowed).await;
    tokio::time::sleep(Duration::from_secs(12)).await;
    let hits = alarms(&proxies);

    println!("RESULT keys {} bad {}", allowed.len(), bad.len());
    for (key, seen) in bad.iter().take(10) {
        println!("RESULT bad {key}: {seen:?}, allowed {:?}", allowed[key]);
    }
    println!("RESULT ops {ops:?}");
    let by_level: Vec<String> = LEVELS
        .iter()
        .zip(&pressure.ops)
        .map(|((name, _), ops)| format!("{name} {}", ops.load(Ordering::SeqCst)))
        .collect();
    println!("RESULT ops by load: {}", by_level.join(", "));
    println!(
        "RESULT faults KILL {} TERM {} failed restarts {}",
        faults[0], faults[1], faults[2]
    );
    for hit in &hits {
        println!("RESULT alarm {hit}");
    }
    for sample in samples.lock().await.iter() {
        println!("RESULT usage {sample}");
    }
    Ok(bad.is_empty() && hits.is_empty())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = match args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let proxies = match proxy::setup(&args.work, &args.bin) {
        Ok(proxies) => Arc::new(proxies),
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let result = soak(&args, proxies.clone()).await;
    for p in proxies.iter() {
        p.stop(Signal::TERM).await;
    }
    match result {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(e) => {
            eprintln!("soak stopped: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
