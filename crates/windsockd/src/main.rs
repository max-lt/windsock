//! The Windsock daemon: the S3 API on a local port, over an engine and a remote.
//!
//! ```text
//! windsockd init <dir>      write <dir>/windsock.toml for one local proxy
//! windsockd run <config>    serve until SIGINT or SIGTERM, then flush the buffer
//! ```

mod config;
mod listener;

use std::io::IsTerminal;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use engine::Engine;
use remote::{DirRemote, Sweep};
use s3remote::{Retry, S3Config, S3Remote};
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use config::{Config, RemoteConfig};
use listener::{LimitedListener, connection_limit, soft_fd_limit};

const CONFIG_FILE: &str = "windsock.toml";
const NODE_KEY_FILE: &str = "node.key";

/// The buffer flushes on shutdown within this time; what remains replays at the next start.
const SHUTDOWN_FLUSH_LIMIT: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,fjall=warn,lsm_tree=warn")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["init", dir] => init(Path::new(dir)),
        ["run", path] => run(&Config::load(Path::new(path))?).await,
        _ => bail!("usage: windsockd init <dir> | windsockd run <config>"),
    }
}

/// Writes a new file only, readable by its owner only: it holds secrets.
fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn init(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(CONFIG_FILE);
    let text = toml::to_string(&Config::local()?).context("cannot write the configuration")?;
    write_secret(&path, text.as_bytes())?;

    info!(config = %path.display(), "wrote a configuration; the S3 access key and secret are in it");
    Ok(())
}

/// The node identity, made on the first start.
fn node_key(data_dir: &Path) -> Result<SigningKey> {
    let path = data_dir.join(NODE_KEY_FILE);

    if !path.exists() {
        write_secret(&path, hex::encode(config::random_bytes::<32>()?).as_bytes())?;
        info!(path = %path.display(), "made a new node key");
    }

    let text = std::fs::read_to_string(&path)?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut bytes)
        .with_context(|| format!("{} is not a hex key", path.display()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Below this, a slow flush can take longer than half the horizon and never commit.
const SHORT_HORIZON_SECS: u64 = 3600;

async fn run(config: &Config) -> Result<()> {
    if config.gc.horizon_secs < SHORT_HORIZON_SECS {
        warn!(
            horizon_secs = config.gc.horizon_secs,
            "gc.horizon_secs is under one hour: a flush that plans and uploads for longer than \
             half of it fails with StalePlan and never commits"
        );
    }
    std::fs::create_dir_all(&config.data_dir)?;
    let key = node_key(&config.data_dir)?;

    match &config.remote {
        RemoteConfig::Dir { path } => {
            info!(remote = %path.display(), "remote is a local directory");
            serve(config, Arc::new(DirRemote::open(path)?), key).await
        }
        RemoteConfig::S3 {
            endpoint,
            bucket,
            prefix,
            region,
            access_key,
            secret_key,
            ca_file,
        } => {
            info!(%endpoint, %bucket, "remote is an S3 bucket");
            let ca_pem = match ca_file {
                Some(path) => Some(
                    std::fs::read(path)
                        .with_context(|| format!("cannot read {}", path.display()))?,
                ),
                None => None,
            };
            let remote = S3Remote::new(S3Config {
                endpoint: endpoint.clone(),
                bucket: bucket.clone(),
                prefix: prefix.clone(),
                region: region.clone(),
                access_key: access_key.clone(),
                secret_key: secret_key.clone(),
                retry: Retry::default(),
                ca_pem,
            })?;
            serve(config, Arc::new(remote), key).await
        }
    }
}

/// Runs `task` every `every`, until the handle is aborted.
fn every<F, Fut>(every: Duration, name: &'static str, task: F) -> JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), String>> + Send,
{
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            if let Err(e) = task().await {
                warn!(task = name, %e, "background task failed");
            }
        }
    })
}

async fn shutdown_signal() {
    let mut terminate = signal(SignalKind::terminate()).expect("a Unix process can watch SIGTERM");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("SIGINT: stopping"),
        _ = terminate.recv() => info!("SIGTERM: stopping"),
    }
}

async fn serve<R: Sweep + 'static>(config: &Config, remote: Arc<R>, key: SigningKey) -> Result<()> {
    let engine = Engine::open(config.data_dir.join("engine"), remote, key, config.engine()).await?;
    let engine = Arc::new(engine);
    info!(node = %engine.node(), "engine open");

    let mut background = vec![engine.spawn_flusher()];
    let syncer = engine.clone();
    background.push(every(
        Duration::from_secs(config.sync_interval_secs),
        "sync",
        move || {
            let engine = syncer.clone();
            async move { engine.sync().await.map(|_| ()).map_err(|e| e.to_string()) }
        },
    ));
    if config.gc.enabled {
        info!(
            interval_secs = config.gc.interval_secs,
            "this proxy runs the GC"
        );
        let collector = engine.clone();
        background.push(every(
            Duration::from_secs(config.gc.interval_secs),
            "gc",
            move || {
                let engine = collector.clone();
                async move { engine.gc().await.map(|_| ()).map_err(|e| e.to_string()) }
            },
        ));
    }

    let s3 = s3api::S3Config::new(config.keys(), config.data_dir.join("uploads"));
    let router = s3api::router(engine.clone(), s3);
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen))?;
    let soft = soft_fd_limit();
    let safe = connection_limit(soft);
    let max_connections = config.max_connections.unwrap_or(safe);
    if max_connections > safe {
        warn!(
            max_connections,
            soft_fd_limit = soft,
            safe,
            "max_connections leaves too few descriptors to the engine: under load, a flush can fail"
        );
    }
    info!(address = %listener.local_addr()?, max_connections, "listening");

    axum::serve(LimitedListener::new(listener, max_connections), router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // A flush cut by the abort is safe: its intent file finishes it at the next flush.
    for task in background {
        task.abort();
    }

    match tokio::time::timeout(SHUTDOWN_FLUSH_LIMIT, engine.flush()).await {
        Ok(Ok(())) => info!("buffer flushed: stopped"),
        Ok(Err(e)) => warn!(%e, "final flush failed: the buffer replays at the next start"),
        Err(_) => warn!("final flush timed out: the buffer replays at the next start"),
    }

    Ok(())
}
