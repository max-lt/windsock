//! Windsock bench on a local directory remote, through the S3 API.
//!
//! ```text
//! windsock-bench [--runs 5] [--seconds 15] [--rate 500] [--out bench.md] [--dir /tmp]
//! ```
//!
//! Each run uses new directories. The report gives the median, the lowest and
//! the highest value of each measure over the runs, and the load of the machine.

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use chunking::Compression;
use ed25519_dalek::SigningKey;
use engine::{CacheMode, Chunking, Config, Engine, Policy, PrefixPolicy, WriteMode};
use hyper::StatusCode;
use tokio::sync::Semaphore;
use tracing::info;

use support::{CountingRemote, S3Client, Server, load_average, percentile, random_bytes, spread};

type Error = Box<dyn std::error::Error + Send + Sync>;

const BUCKET: &str = "bench";
const MIN_SIZE: usize = 100 * 1024;
const MAX_SIZE: usize = 500 * 1024;
const COLD_SAMPLE: usize = 200;
const CAPACITY_WORKERS: usize = 32;
const REPLAY_BYTES: usize = 512 * 1024 * 1024;

struct Args {
    runs: usize,
    seconds: u64,
    rate: u64,
    out: PathBuf,
    dir: PathBuf,
}

fn args() -> Result<Args, Error> {
    let mut args = Args {
        runs: 5,
        seconds: 15,
        rate: 500,
        out: PathBuf::from("bench.md"),
        dir: std::env::temp_dir(),
    };
    let given: Vec<String> = std::env::args().skip(1).collect();

    for pair in given.chunks(2) {
        let [name, value] = pair else {
            return Err(format!("{} takes a value", pair[0]).into());
        };
        match name.as_str() {
            "--runs" => args.runs = value.parse()?,
            "--seconds" => args.seconds = value.parse()?,
            "--rate" => args.rate = value.parse()?,
            "--out" => args.out = PathBuf::from(value),
            "--dir" => args.dir = PathBuf::from(value),
            other => return Err(format!("unknown option {other}").into()),
        }
    }

    Ok(args)
}

/// Brumal-like WAL objects: sealed, so fixed chunks and no compression.
fn config() -> Config {
    Config {
        policies: vec![PrefixPolicy {
            bucket: BUCKET.into(),
            prefix: "wal/".into(),
            policy: Policy {
                chunking: Chunking::Fixed,
                compression: Compression::None,
                create_only: false,
                cache: CacheMode::ReadWrite,
            },
        }],
        ..Config::default()
    }
}

/// Object `i`: a size between 100 and 500 KB, unique content.
fn object(i: u64) -> Bytes {
    let size = MIN_SIZE + (i.wrapping_mul(2_654_435_761) as usize % (MAX_SIZE - MIN_SIZE));
    Bytes::from(random_bytes(i + 1, size))
}

/// One measure of one run.
type Measures = BTreeMap<String, f64>;

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Puts at `rate` per second for `seconds`. Latency counts from the planned send
/// time, so a queue in the client or the server shows in it.
async fn sustained(
    client: &S3Client,
    rate: u64,
    seconds: u64,
    m: &mut Measures,
) -> Result<Vec<String>, Error> {
    let total = rate * seconds;
    let in_flight = Arc::new(Semaphore::new(512));
    let start = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();

    for i in 0..total {
        let due = start + Duration::from_secs_f64(i as f64 / rate as f64);
        tokio::time::sleep_until(due.into()).await;
        let permit = in_flight.clone().acquire_owned().await?;
        let client = client.clone();
        tasks.spawn(async move {
            let body = object(i);
            let size = body.len();
            let path = format!("/{BUCKET}/wal/obj-{i:08}");
            let result = client.send("PUT", &path, body).await;
            drop(permit);
            (path, size, result, due.elapsed())
        });
    }

    let mut latencies = Vec::new();
    let mut keys = Vec::new();
    let mut errors = 0;
    let mut bytes = 0;
    while let Some(done) = tasks.join_next().await {
        let (path, size, result, latency) = done?;
        match result {
            Ok((StatusCode::OK, _)) => {
                latencies.push(latency);
                keys.push(path);
                bytes += size;
            }
            _ => errors += 1,
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    latencies.sort();

    m.insert(
        "put.rate_achieved_per_s".into(),
        keys.len() as f64 / elapsed,
    );
    m.insert("put.mb_per_s".into(), bytes as f64 / elapsed / 1e6);
    m.insert(
        "put.latency_p50_ms".into(),
        millis(percentile(&latencies, 50.0)),
    );
    m.insert(
        "put.latency_p99_ms".into(),
        millis(percentile(&latencies, 99.0)),
    );
    m.insert(
        "put.latency_max_ms".into(),
        millis(percentile(&latencies, 100.0)),
    );
    m.insert("put.errors".into(), errors as f64);
    Ok(keys)
}

/// Closed loop: workers put back to back. The rate the server can take.
async fn capacity(client: &S3Client, seconds: u64, m: &mut Measures) -> Result<(), Error> {
    let start = Instant::now();
    let stop = start + Duration::from_secs(seconds);
    let mut workers = tokio::task::JoinSet::new();

    for w in 0..CAPACITY_WORKERS as u64 {
        let client = client.clone();
        workers.spawn(async move {
            let mut latencies = Vec::new();
            let mut n = 0u64;
            while Instant::now() < stop {
                let i = 1_000_000_000 + w * 10_000_000 + n;
                let sent = Instant::now();
                let path = format!("/{BUCKET}/wal/cap-{i}");
                if let Ok((StatusCode::OK, _)) = client.send("PUT", &path, object(i)).await {
                    latencies.push(sent.elapsed());
                }
                n += 1;
            }
            latencies
        });
    }

    let mut latencies = Vec::new();
    while let Some(done) = workers.join_next().await {
        latencies.extend(done?);
    }
    latencies.sort();

    m.insert(
        "capacity.rate_per_s".into(),
        latencies.len() as f64 / start.elapsed().as_secs_f64(),
    );
    m.insert(
        "capacity.latency_p50_ms".into(),
        millis(percentile(&latencies, 50.0)),
    );
    m.insert(
        "capacity.latency_p99_ms".into(),
        millis(percentile(&latencies, 99.0)),
    );
    Ok(())
}

/// GETs of `keys` on a proxy with an empty cache, then again from its cache.
async fn reads(
    client: &S3Client,
    remote: &CountingRemote,
    keys: &[String],
    m: &mut Measures,
) -> Result<(), Error> {
    for (name, label) in [("cold", "from the remote"), ("warm", "from the cache")] {
        let reads_before = remote.counts.reads();
        let mut latencies = Vec::new();

        for key in keys {
            let sent = Instant::now();
            let (status, _) = client.send("GET", key, Bytes::new()).await?;
            if status != StatusCode::OK {
                return Err(format!("GET {key} {label}: {status}").into());
            }
            latencies.push(sent.elapsed());
        }
        latencies.sort();

        let remote_reads = (remote.counts.reads() - reads_before) as f64 / keys.len() as f64;
        let prefix = if name == "cold" {
            "read.cold"
        } else {
            "read.warm"
        };
        m.insert(
            format!("{prefix}.latency_p50_ms"),
            millis(percentile(&latencies, 50.0)),
        );
        m.insert(
            format!("{prefix}.latency_p99_ms"),
            millis(percentile(&latencies, 99.0)),
        );
        m.insert(format!("{prefix}.remote_reads_per_get"), remote_reads);
    }
    Ok(())
}

/// Opens an engine whose buffer holds `REPLAY_BYTES` of writes that never flushed.
async fn replay(dir: &Path, m: &mut Measures) -> Result<(), Error> {
    let remote = Arc::new(CountingRemote::open(&dir.join("replay-remote"))?);
    let engine_dir = dir.join("replay-engine");
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let engine = Engine::open(&engine_dir, remote.clone(), key.clone(), config()).await?;
    engine.create_bucket(BUCKET, None).await?;

    let mut written = 0;
    let mut i = 0u64;
    while written < REPLAY_BYTES {
        let body = object(i);
        written += body.len();
        engine
            .put(
                BUCKET,
                &format!("wal/r-{i}"),
                body,
                BTreeMap::new(),
                WriteMode::Overwrite,
            )
            .await?;
        i += 1;
    }
    drop(engine);

    let start = Instant::now();
    let reopened = Engine::open(&engine_dir, remote, key, config()).await?;
    let elapsed = start.elapsed().as_secs_f64();
    drop(reopened);

    m.insert("replay.mb".into(), written as f64 / 1e6);
    m.insert("replay.seconds".into(), elapsed);
    m.insert("replay.mb_per_s".into(), written as f64 / 1e6 / elapsed);
    Ok(())
}

async fn run(args: &Args, n: usize) -> Result<(Measures, String), Error> {
    let load_before = load_average();
    let work = tempfile::tempdir_in(&args.dir)?;
    let remote = Arc::new(CountingRemote::open(&work.path().join("remote"))?);
    let writer = Server::start(&work.path().join("a"), remote.clone(), 1, config()).await?;
    let client = S3Client::new(&writer.address);
    let mut m = Measures::new();

    client
        .send("PUT", &format!("/{BUCKET}"), Bytes::new())
        .await?;
    writer.engine.flush().await?;
    let writes_before = remote.counts.writes();

    info!(run = n, "sustained puts");
    let started = Instant::now();
    let keys = sustained(&client, args.rate, args.seconds, &mut m).await?;
    let drain = Instant::now();
    writer.engine.flush().await?;
    m.insert(
        "flush.drain_after_load_s".into(),
        drain.elapsed().as_secs_f64(),
    );
    let writes = (remote.counts.writes() - writes_before) as f64;
    m.insert(
        "remote.writes_per_object".into(),
        writes / keys.len() as f64,
    );
    m.insert(
        "remote.writes_per_hour".into(),
        writes / started.elapsed().as_secs_f64() * 3600.0,
    );
    m.insert(
        "remote.writes_per_hour_without_packs".into(),
        m["put.rate_achieved_per_s"] * 3600.0,
    );

    info!(run = n, "capacity");
    capacity(&client, args.seconds, &mut m).await?;
    writer.stop();

    info!(run = n, "cold and warm reads");
    let reader = Server::start(&work.path().join("b"), remote.clone(), 2, config()).await?;
    reader.engine.sync().await?;
    let step = (keys.len() / COLD_SAMPLE).max(1);
    let sample: Vec<String> = keys
        .iter()
        .step_by(step)
        .take(COLD_SAMPLE)
        .cloned()
        .collect();
    reads(&S3Client::new(&reader.address), &remote, &sample, &mut m).await?;
    reader.stop();

    info!(run = n, "buffer replay");
    replay(work.path(), &mut m).await?;

    Ok((m, format!("{load_before} / {}", load_average())))
}

fn sysctl(name: &str) -> String {
    std::process::Command::new("sysctl")
        .args(["-n", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn report(args: &Args, runs: &[(Measures, String)]) -> String {
    let memory_gb = sysctl("hw.memsize").parse::<f64>().unwrap_or(0.0) / 1e9;
    let mut out = format!(
        "# Windsock bench\n\n\
         - Machine: {}, {} cores, {memory_gb:.0} GB\n\
         - Build: release. Remote: local directory (DirRemote). One engine per proxy, S3 API over TCP on 127.0.0.1.\n\
         - Objects: {}-{} KB, incompressible, fixed chunks, no compression (WAL policy). Body hash signed.\n\
         - Runs: {}. Sustained rate target: {}/s for {} s. Capacity: {CAPACITY_WORKERS} workers for {} s.\n\
         - Cold reads: {COLD_SAMPLE} GETs on a second proxy with an empty cache, then the same GETs again.\n\
         - Replay: Engine::open with {} MB of writes in the buffer.\n\n\
         Load average (1, 5, 15 min) before / after each run:\n\n",
        sysctl("machdep.cpu.brand_string"),
        sysctl("hw.ncpu"),
        MIN_SIZE / 1024,
        MAX_SIZE / 1024,
        args.runs,
        args.rate,
        args.seconds,
        args.seconds,
        REPLAY_BYTES / (1024 * 1024),
    );
    for (i, (_, load)) in runs.iter().enumerate() {
        out.push_str(&format!("- run {}: {load}\n", i + 1));
    }

    out.push_str("\n| Measure | Median | Min | Max |\n|---|---|---|---|\n");
    for name in runs[0].0.keys() {
        let values: Vec<f64> = runs.iter().map(|(m, _)| m[name]).collect();
        let (median, low, high) = spread(values);
        out.push_str(&format!(
            "| {name} | {median:.2} | {low:.2} | {high:.2} |\n"
        ));
    }
    out
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "info,engine=warn,s3api=warn,fjall=warn,lsm_tree=warn",
        ))
        .with_writer(std::io::stderr)
        .init();
    let args = args()?;
    let mut runs = Vec::new();

    for n in 1..=args.runs {
        let result = run(&args, n).await?;
        info!(run = n, load = %result.1, "run done");
        runs.push(result);
    }

    std::fs::write(&args.out, report(&args, &runs))?;
    info!(out = %args.out.display(), "report written");
    Ok(())
}
