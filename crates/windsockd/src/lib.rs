//! The Windsock daemon as a library. The `windsockd` binary calls [`run`]. A process that keeps
//! the S3 keys itself, such as a console, calls [`serve_with`] with its [`KeyStore`].

mod admin;
pub mod config;
mod disk;
mod listener;
mod node;
pub mod quarantine;

use std::collections::HashMap;
use std::future::IntoFuture;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use engine::{Engine, RepoKey};
use remote::{DirRemote, Startup, Sweep, Verdict};
use s3remote::{Retry, S3Config, S3Remote};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

pub use config::{Config, KeySource};
pub use engine::{BucketInfo, CacheState, EngineError, ObjectInfo};
pub use model::NodeId;
pub use node::{MAX_PAGE, Node, NodeStatus, Page};
pub use s3api::KeyStore;

use config::RemoteConfig;
use listener::{
    ConnectionActivity, LimitedListener, Timeouts, check_connections, connection_limit,
    raise_fd_limit, track_requests,
};

const CONFIG_FILE: &str = "windsock.toml";
const NODE_KEY_FILE: &str = "node.key";
const REPO_KEY_FILE: &str = "repo.key";

/// Pause between two final flushes while the remote fails.
const SHUTDOWN_RETRY: Duration = Duration::from_secs(5);
/// At most one warning in this time while the final flush fails.
const SHUTDOWN_WARN_EVERY: Duration = Duration::from_secs(60);
/// The expiry runs this often, so an upload lives at most this long past `uploads_expire_secs`.
const UPLOADS_EXPIRE_EVERY: Duration = Duration::from_secs(3600);

/// Serves with the [[keys]] of `config` until SIGINT or SIGTERM, then flushes the buffer.
pub async fn run(config: &Config) -> Result<()> {
    config.check_keys(KeySource::Config)?;
    let serving = Serving {
        keys: Arc::new(s3api::StaticKeys::new(config.keys())),
        shutdown: Box::pin(shutdown_signal()),
        on_open: Box::new(drop),
    };
    start(config, Mode::Serve(serving)).await
}

/// Serves with the keys of `keys` until `shutdown` returns, then flushes the buffer. A SIGINT or
/// SIGTERM after `shutdown` stops at once. `config` must have no [[keys]] entry. `on_open` gets
/// the [`Node`] once the engine is open, before the S3 port listens. When the serve returns, or its future
/// is dropped, its tasks stop and each Node call gets `EngineError::Stopped`: drop the Node too,
/// as it holds the engine, and a new serve of the same `data_dir` opens once both are gone.
pub async fn serve_with(
    config: &Config,
    keys: Arc<dyn KeyStore>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    on_open: impl FnOnce(Node) + Send + 'static,
) -> Result<()> {
    config.check_keys(KeySource::Store)?;
    let serving = Serving {
        keys,
        shutdown: Box::pin(shutdown),
        on_open: Box::new(on_open),
    };
    start(config, Mode::Serve(serving)).await
}

/// Sets the cache limit of the daemon that runs with `config`, through its admin socket. 0
/// empties the cache. A restart goes back to `cache_bytes`.
pub async fn cache_trim(config: &Config, bytes: u64) -> Result<()> {
    admin::cache_trim(&config.data_dir, bytes).await
}

/// Checks the storage contract of the remote of `config` once.
pub async fn diagnose(config: &Config) -> Result<()> {
    start(config, Mode::Diagnose).await
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

/// Writes `dir/windsock.toml` for one local proxy, with a new key pair and a new repository key.
pub fn init(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(CONFIG_FILE);
    let text = toml::to_string(&Config::local()?).context("cannot write the configuration")?;
    write_secret(&path, text.as_bytes())?;
    info!(config = %path.display(), "wrote a configuration; the S3 access key and secret are in it");

    let key_path = dir.join(REPO_KEY_FILE);
    write_secret(
        &key_path,
        Zeroizing::new(RepoKey::generate()?.to_hex()).as_bytes(),
    )?;
    warn!(
        repo_key = %key_path.display(),
        "wrote a new repository key. Keep a copy away from the remote: without it, nobody can \
         read the data. Give every other proxy of this remote the same file"
    );
    Ok(())
}

/// The secret of the remote. A missing file is an error: a new key could not read the data.
fn repo_key(path: &Path) -> Result<RepoKey> {
    refuse_if_others_can_read(path)?;
    let text = Zeroizing::new(std::fs::read_to_string(path).with_context(|| {
        format!(
            "cannot read the repository key {}. Copy it from another proxy of this remote: a new \
             key cannot read the data",
            path.display()
        )
    })?);
    RepoKey::from_hex(&text).with_context(|| format!("{} is not a repository key", path.display()))
}

/// Refuses a secret file that other users can read, as ssh does.
fn refuse_if_others_can_read(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(metadata) = std::fs::metadata(path)
        && metadata.permissions().mode() & 0o077 != 0
    {
        bail!(
            "{} can be read by other users. Run: chmod 600 {}",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

/// Where the node key of this start comes from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyOrigin {
    Made,
    Read,
}

/// The node identity, made on the first start.
fn node_key(data_dir: &Path) -> Result<(SigningKey, KeyOrigin)> {
    let path = data_dir.join(NODE_KEY_FILE);

    let mut origin = KeyOrigin::Read;
    if !path.exists() {
        write_secret(
            &path,
            Zeroizing::new(hex::encode(config::random_bytes::<32>()?)).as_bytes(),
        )?;
        info!(path = %path.display(), "made a new node key");
        origin = KeyOrigin::Made;
    }

    refuse_if_others_can_read(&path)?;
    let text = Zeroizing::new(
        std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?,
    );
    let mut bytes = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(text.trim(), bytes.as_mut())
        .with_context(|| format!("{} is not a hex key", path.display()))?;
    Ok((SigningKey::from_bytes(&bytes), origin))
}

/// A new node key on a remote with chains makes one more chain for ever: a data_dir that does not
/// persist makes one at each start. A new proxy of a cluster gets one by design, so only a WARN.
async fn warn_new_identity<R: remote::Remote + ?Sized>(remote: &R) {
    match remote.list(engine::NODES_PREFIX).await {
        Ok(nodes) if !nodes.is_empty() => warn!(
            chains = nodes.len(),
            "a new node identity on a remote with {} chains; data_dir must persist across \
             restarts",
            nodes.len()
        ),
        Ok(_) => {}
        Err(e) => warn!(%e, "cannot list the node markers of the remote"),
    }
}

/// Below this, a slow flush can take longer than half the horizon and never commit.
const SHORT_HORIZON_SECS: u64 = 3600;

/// The first stop request: the daemon drains, then flushes the buffer.
type Shutdown = Pin<Box<dyn Future<Output = ()> + Send>>;

/// How the daemon serves S3.
struct Serving {
    keys: Arc<dyn KeyStore>,
    shutdown: Shutdown,
    /// Gets the node once the engine is open.
    on_open: Box<dyn FnOnce(Node) + Send>,
}

/// What `windsockd` does with the remote of a configuration.
enum Mode {
    Serve(Serving),
    /// Check the storage contract once, then exit.
    Diagnose,
}

/// The connection limit, after a raise of the soft descriptor limit. Refuses a limit that the
/// descriptors cannot hold.
fn connections(config: &Config) -> Result<usize> {
    let soft = raise_fd_limit();
    let safe = connection_limit(soft).map_err(anyhow::Error::msg)?;
    match config.max_connections {
        Some(max) => check_connections(max, soft).map_err(anyhow::Error::msg),
        None => Ok(safe),
    }
}

async fn start(config: &Config, mode: Mode) -> Result<()> {
    if matches!(mode, Mode::Serve(..)) {
        connections(config)?;
    }
    match &config.remote {
        RemoteConfig::Dir { path } => {
            info!(remote = %path.display(), "remote is a local directory");
            let store = format!("directory {}", path.display());
            act(config, Arc::new(DirRemote::open(path)?), &store, mode).await
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
                secret_key: secret_key.expose().to_string(),
                retry: Retry::default(),
                ca_pem,
            })?;
            let store = format!("S3 endpoint {endpoint}, bucket {bucket}");
            act(config, Arc::new(remote), &store, mode).await
        }
    }
}

async fn act<R: Sweep + 'static>(
    config: &Config,
    remote: Arc<R>,
    store: &str,
    mode: Mode,
) -> Result<()> {
    match mode {
        Mode::Serve(serving) => serve(config, remote, store, serving).await,
        Mode::Diagnose => probe_contract(&*remote, store).await,
    }
}

async fn probe_contract(remote: &impl Sweep, store: &str) -> Result<()> {
    match remote::probe(remote).await {
        Ok(Verdict::Conformant) => {
            info!(
                store,
                "ok storage contract (create, reject-create, read-after-write, \
                 list-after-write, ranged read)"
            );
            Ok(())
        }
        Ok(Verdict::Violation(reason)) => {
            bail!("the {store} does not keep the storage contract: {reason}")
        }
        Err(error) => Err(anyhow::Error::new(error))
            .with_context(|| format!("could not check the storage contract of the {store}")),
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

async fn serve<R: Sweep + 'static>(
    config: &Config,
    remote: Arc<R>,
    store: &str,
    serving: Serving,
) -> Result<()> {
    let Serving {
        keys,
        shutdown,
        on_open,
    } = serving;
    if config.gc.horizon_secs < SHORT_HORIZON_SECS {
        warn!(
            horizon_secs = config.gc.horizon_secs,
            "gc.horizon_secs is under one hour: a flush that plans and uploads for longer than \
             half of it fails with StalePlan and never commits"
        );
    }
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("cannot make {}", config.data_dir.display()))?;
    let (key, origin) = node_key(&config.data_dir)?;

    match remote::check_before_serving(&*remote).await {
        Startup::Conformant => info!(store, "the remote keeps the storage contract"),
        Startup::Unverified(error) => warn!(
            store,
            %error,
            attempts = remote::STARTUP_ATTEMPTS,
            "could not check the storage contract: starting anyway"
        ),
        Startup::Violation(reason) => bail!(
            "the {store} does not keep the storage contract, so Windsock cannot run on it \
             safely: {reason}"
        ),
    }
    if origin == KeyOrigin::Made {
        warn_new_identity(&*remote).await;
    }

    let engine_dir = config.data_dir.join("engine");
    let engine = Engine::open(
        &engine_dir,
        remote,
        key,
        repo_key(&config.repo_key)?.keys(),
        config.engine(),
    )
    .await
    .with_context(|| format!("cannot open the engine in {}", engine_dir.display()))?;
    let engine = Arc::new(engine);
    info!(node = %engine.node(), "engine open");

    let (serving, ended) = tokio::sync::oneshot::channel::<()>();
    let mut running = Running {
        tasks: vec![engine.spawn_flusher()],
        socket: None,
        stopped: Arc::new(AtomicBool::new(false)),
        _serving: serving,
    };
    let syncer = engine.clone();
    running.tasks.push(every(
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
        if engine.sync().await.is_ok()
            && let Some(node) = engine.other_gc_node()
        {
            warn!(%node, "another node ran the GC in the last horizon: run the GC on one node only");
        }
        let collector = engine.clone();
        running.tasks.push(every(
            Duration::from_secs(config.gc.interval_secs),
            "gc",
            move || {
                let engine = collector.clone();
                async move { engine.gc().await.map(|_| ()).map_err(|e| e.to_string()) }
            },
        ));
    }

    let mut s3 = s3api::S3Config::new(HashMap::new(), config.data_dir.join("uploads"));
    s3.keys = keys;
    s3.uploads = Arc::new(s3api::Uploads::new(
        config.data_dir.join("uploads"),
        config.engine.parts_limit_bytes,
    ));
    let parts = s3
        .uploads
        .start()
        .await
        .context("cannot read the multipart uploads")?;
    s3.uploads
        .settle(&engine)
        .await
        .context("cannot end a complete that a crash stopped")?;
    if parts > 0 {
        info!(bytes = parts, "multipart parts wait for a complete");
    }
    let limits = node::Limits {
        buffer: config.engine.buffer_limit_bytes,
        parts: config.engine.parts_limit_bytes,
        gc_enabled: config.gc.enabled,
    };
    let socket = admin::prepare(&config.data_dir)?;
    running.socket = socket.clone();
    let node = Node::new(
        engine.clone(),
        s3.uploads.clone(),
        limits,
        socket.is_some(),
        running.stopped.clone(),
    );
    if let Some(socket) = &socket {
        running.tasks.push(tokio::spawn(admin::serve(
            admin::bind(socket)?,
            node.clone(),
        )));
    }
    on_open(node);
    let expirer = s3.uploads.clone();
    let max_age = Duration::from_secs(config.uploads_expire_secs);
    running
        .tasks
        .push(every(UPLOADS_EXPIRE_EVERY, "uploads expire", move || {
            let uploads = expirer.clone();
            async move {
                let (count, bytes) = uploads.expire(max_age).await.map_err(|e| e.to_string())?;
                if count > 0 {
                    info!(count, bytes, "removed expired multipart uploads");
                }
                Ok(())
            }
        }));
    let usage = engine
        .local_usage()
        .await
        .context("cannot measure the local disk")?;
    let limits = disk::Limits {
        cache: config.engine.cache_bytes,
        buffer: config.engine.buffer_limit_bytes,
        parts: config.engine.parts_limit_bytes,
    };
    disk::check(&config.data_dir, usage, s3.uploads.held(), limits);
    let router = s3api::router(engine.clone(), s3).layer(axum::middleware::from_fn(track_requests));
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen))?;
    let max_connections = connections(config)?;
    info!(address = %listener.local_addr()?, max_connections, "listening");

    let timeouts = Timeouts {
        idle: Duration::from_secs(config.idle_timeout_secs),
        upload: Duration::from_secs(config.request_timeout_secs),
    };
    let listener = LimitedListener::new(listener, max_connections, timeouts);
    let draining = Arc::new(Notify::new());
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<ConnectionActivity>(),
    )
    // axum runs this future in its own task: it must end with the serve, or it keeps the engine.
    .with_graceful_shutdown(until_ended(
        drain_then_flush(engine.clone(), draining.clone(), shutdown),
        ended,
    ))
    .into_future();
    let second_signal = async {
        draining.notified().await;
        shutdown_signal().await;
    };

    let outcome = tokio::select! {
        result = server => match result {
            Ok(()) => stopped_after_flush(&engine).await,
            Err(e) => Err(e.into()),
        },
        () = second_signal => {
            let bytes = engine.buffered_bytes().await;
            warn!(bytes, "second signal: stopped before the remote has the buffer; it flushes at the next start");
            Ok(())
        }
        () = index_poisoned(&engine) => {
            error!(
                "the local index refuses every call after a failed write, often a full disk: \
                 stopping. The buffer is on disk and flushes at the next start"
            );
            Err(anyhow::anyhow!("the local index refuses every call: stopped"))
        }
    };

    drop(running);
    outcome
}

/// The background tasks of a serve and its admin socket. Dropped on every return, also an early
/// error or an abort of the serve future: the tasks stop, so the engine is free, and each Node of
/// this serve gets EngineError::Stopped.
struct Running {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    socket: Option<PathBuf>,
    stopped: Arc<AtomicBool>,
    /// Its drop ends the shutdown future that axum holds in a task of its own.
    _serving: tokio::sync::oneshot::Sender<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        // A flush cut by the abort is safe: its intent file finishes it at the next flush.
        for task in &self.tasks {
            task.abort();
        }
        if let Some(socket) = &self.socket
            && let Err(e) = std::fs::remove_file(socket)
        {
            warn!(%e, socket = %socket.display(), "cannot remove the admin socket");
        }
    }
}

/// The end of a drain: an error when buffered writes did not reach the remote.
async fn stopped_after_flush<R: Sweep + 'static>(engine: &Engine<R>) -> Result<()> {
    let bytes = engine.buffered_bytes().await;
    if bytes > 0 {
        bail!(
            "stopped with {bytes} buffered bytes that are not in the remote: the next start moves \
             the late writes to quarantine"
        );
    }
    info!("buffer flushed: stopped");
    Ok(())
}

/// Returns once a failed index write poisons the index: only a restart opens it again.
async fn index_poisoned<R: Sweep + 'static>(engine: &Engine<R>) {
    while !engine.index_is_poisoned() {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// At `shutdown`, refuses new writes and flushes the buffer. The server keeps serving reads, and
/// 503 for writes, until the remote has every buffered write.
/// Runs `task` until `ended` resolves, which the drop of its sender does.
async fn until_ended(task: impl Future<Output = ()>, ended: tokio::sync::oneshot::Receiver<()>) {
    tokio::select! {
        () = task => {}
        _ = ended => {}
    }
}

async fn drain_then_flush<R: Sweep + 'static>(
    engine: Arc<Engine<R>>,
    draining: Arc<Notify>,
    shutdown: Shutdown,
) {
    shutdown.await;
    engine.drain();
    draining.notify_one();
    let bytes = engine.buffered_bytes().await;
    info!(
        bytes,
        "draining: new writes get 503, the buffer goes to the remote; a second signal stops at once"
    );
    flush_until_empty(&engine).await;
}

/// Flushes until the remote has every buffered write. A failed flush waits, then tries again.
async fn flush_until_empty<R: Sweep + 'static>(engine: &Engine<R>) {
    let mut warned: Option<Instant> = None;

    loop {
        match engine.flush().await {
            Ok(()) if engine.buffered_bytes().await == 0 => return,
            Ok(()) => {}
            // A retry fails again: the next start moves the late writes to quarantine.
            Err(e) if engine.is_quarantined() => {
                error!(%e, "final flush stopped: buffered writes are older than the late limit");
                return;
            }
            Err(e) if warned.is_none_or(|at| at.elapsed() >= SHUTDOWN_WARN_EVERY) => {
                warned = Some(Instant::now());
                let bytes = engine.buffered_bytes().await;
                warn!(%e, bytes, "final flush failed: trying again");
            }
            Err(_) => {}
        }
        tokio::time::sleep(SHUTDOWN_RETRY).await;
    }
}
