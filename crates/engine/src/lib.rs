//! Object operations over a remote, with a local write-back buffer.
//!
//! A write is acknowledged once it is fsynced in the local buffer. The flusher
//! uploads buffered writes within a bounded delay: packs and large manifests
//! first, then one journal entry for the whole batch (group commit). Reads see
//! buffered writes before the flush.

mod buckets;
mod buffer;
mod config;
mod flush;
mod gc;
mod list;
mod manifest;
mod plan;
mod read;
pub mod sim;
mod snapshot;
mod sync;
mod write;

use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use cache::{CacheError, ChunkCache};
use ed25519_dalek::SigningKey;
use index::{ChunkLocation, Index, IndexError};
use journal::{Action, Commit, Entry, HybridClock, Journal, JournalError};
pub use list::{ListAfter, ListEntry, ListPage, ListQuery};
use model::{ChunkId, NodeId, ObjectId, PackId};
use pack::{Pack, PackEntry, PackError};
pub use read::{ObjectReader, READ_STEP};
use remote::{Remote, RemoteError};
pub use seal::{Keys, RepoKey};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use buffer::{Buffer, BufferedObject, BufferedPut, Durability, Head, Intent, Op, SegmentReader};
use plan::{Nonces, Planner};

pub use buffer::{QuarantineReader, QuarantinedRecord, QuarantinedWrite};
pub use config::{CacheMode, Chunking, Config, Policy, PrefixPolicy};
pub use gc::GcReport;
pub use index::MAX_OPEN_FILES as INDEX_MAX_OPEN_FILES;
pub use index::ObjectState;
pub use manifest::{ChunkRef, INLINE_MAX, MANIFESTS_PREFIX, Manifest, manifest_id, manifest_key};
pub use snapshot::{MAX_SNAPSHOT, MAX_SNAPSHOT_PARTS, SNAPSHOTS_PREFIX};

/// Prefix of all pack keys.
pub const PACKS_PREFIX: &str = "packs/";

const INDEX_DIR: &str = "index";
const BUFFER_DIR: &str = "buffer";
const ORPHANS_FILE: &str = "snapshot-orphans";
const QUARANTINE_DIR: &str = "quarantine";
const CACHE_DIR: &str = "cache";

/// A known value, sealed under the repository key: it tells whether a key is the key of a remote.
pub const KEY_CHECK_KEY: &str = "repo/key-check";
const KEY_CHECK: &str = "windsock repository key check";
/// The largest actions of one entry that a proxy writes. Half of the 1 GiB that a reader takes in
/// one reply, so every proxy reads every entry whatever its own setting.
pub const MAX_ENTRY_ACTIONS: u64 = 512 * 1024 * 1024;
/// The remote format of this build: journal actions carry their ack HLC.
const REMOTE_FORMAT: u32 = 3;

pub fn pack_key(id: PackId) -> String {
    format!("{PACKS_PREFIX}{id}")
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("invalid bucket name: {0:?}")]
    InvalidBucketName(String),
    #[error("invalid key: {0:?}")]
    InvalidKey(String),
    #[error("no such bucket: {0}")]
    NoSuchBucket(String),
    #[error("no such key: {bucket}/{key}")]
    NoSuchKey { bucket: String, key: String },
    #[error("bucket already exists: {0}")]
    BucketAlreadyExists(String),
    #[error("bucket is not empty: {0}")]
    BucketNotEmpty(String),
    #[error("key already exists: {bucket}/{key}")]
    PreconditionFailed { bucket: String, key: String },
    #[error("range {start}..{end} is outside the object ({size} bytes)")]
    InvalidRange { start: u64, end: u64, size: u64 },
    #[error("the proxy is stopping and takes no new write")]
    Draining,
    #[error("local buffer is full ({limit} bytes)")]
    BufferFull { limit: u64 },
    #[error(
        "the clock of this proxy is more than the retention ahead of its wall clock: writes \
         resume in {wait_secs} s"
    )]
    ClockAhead { wait_secs: u64 },
    #[error("configuration: {0}")]
    Config(String),
    /// A crash point of the simulation test fired: drop the engine.
    #[cfg(feature = "sim")]
    #[error("simulated crash after {0:?}")]
    SimCrash(sim::Point),
    #[error("buffered writes older than the late limit are in quarantine: {0}")]
    Quarantined(String),
    #[error("the object has {size} bytes, over the limit of {limit} bytes")]
    ObjectTooLarge { size: u64, limit: u64 },
    #[error("the key and metadata take {size} bytes, over the limit of {limit} bytes")]
    MetadataTooLarge { size: u64, limit: u64 },
    #[error(
        "the snapshot has {size} bytes in {parts} parts, over the cap of {} bytes or {} parts",
        snapshot::MAX_SNAPSHOT,
        snapshot::MAX_SNAPSHOT_PARTS
    )]
    SnapshotTooLarge { size: u64, parts: usize },
    #[error("the buffer fsync failed, so the write is not stored")]
    WriteLost,
    #[error("the buffer did not recover from a failed fsync. Restart the proxy")]
    BufferBroken,
    #[error("{0} commits lost the seq to another process with this identity")]
    Contended(u32),
    #[error("the flush plan is older than half the GC horizon: plan again")]
    StalePlan,
    #[error("broken chains: {0:?}")]
    BrokenChains(Vec<NodeId>),
    #[error("repo.key is not the key of this remote: {0}")]
    WrongRepoKey(String),
    #[error("corrupt data: {0}")]
    Corrupt(String),
    #[error(transparent)]
    Remote(#[from] RemoteError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Pack(#[from] PackError),
    #[error(transparent)]
    Cache(#[from] CacheError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, EngineError>;

/// What a put requires of the current object. Each check is strict through one proxy; across
/// proxies a race becomes a conflict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteMode {
    Overwrite,
    /// `If-None-Match: *`: no current object.
    CreateOnly,
    /// `If-Match: *`: a current object.
    IfExists,
    /// `If-Match`: a current object with one of these content hashes.
    IfMatch(Vec<[u8; 32]>),
}

/// Bytes on the local disk, by use. Only the cache can shrink.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocalUsage {
    pub index: u64,
    pub cache: u64,
    pub buffer: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectInfo {
    pub key: String,
    pub size: u64,
    /// blake3 of the data.
    pub content_hash: [u8; 32],
    pub metadata: BTreeMap<String, String>,
    /// Unix nanoseconds: acknowledgement time while buffered, entry HLC once flushed.
    pub last_modified: u64,
    /// Another proxy wrote this key without knowing the version a reader gets.
    pub conflicted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub info: ObjectInfo,
    /// The requested range of the data.
    pub data: Bytes,
}

/// What one sync did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub applied: usize,
    /// Chains that could not be read past their frontier. The other chains synced.
    pub broken: Vec<NodeId>,
    /// For each broken chain: its node, the seq and the cause.
    pub broken_causes: Vec<String>,
    /// Chains with no valid first entry that this sync did not read: a writer with no
    /// repository key made them. The open and GC audits read them.
    pub skipped: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketInfo {
    pub name: String,
    pub owner: Option<String>,
    /// Unix nanoseconds of the create: acknowledgement time while buffered, entry HLC once flushed.
    pub created: u64,
}

/// The current state of one key, from the buffer first, then the index.
enum Current {
    Absent,
    Buffered(BufferedPut),
    Stored {
        manifest_id: ObjectId,
        hlc: u64,
        conflicted: bool,
    },
}

impl Current {
    fn exists(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

pub struct Engine<R> {
    remote: Arc<R>,
    config: Config,
    node: NodeId,
    buffer_dir: PathBuf,
    journal: tokio::sync::Mutex<Journal<R>>,
    /// The HLC of acks and entries: max(wall clock, last one issued or seen) + 1.
    clock: Arc<HybridClock>,
    index: Mutex<Index>,
    buffer: tokio::sync::Mutex<Buffer>,
    cache: Option<ChunkCache>,
    /// The repository keys: chunk IDs, the FastCDC seed, and the seal of remote objects.
    keys: Keys,
    /// One flush at a time.
    flushing: tokio::sync::Mutex<()>,
    /// One buffer fsync at a time. The writes that arrive during an fsync share the next one.
    syncing: tokio::sync::Mutex<()>,
    /// Monotonic nanoseconds at the start of the last sync.
    last_sync: Mutex<Option<u64>>,
    /// Start of the last sync that succeeded: GC rule 1 for dedup.
    fresh_sync: Mutex<Option<Stamp>>,
    /// The plan time of the last intent that this process wrote.
    own_plan: Mutex<Option<Stamp>>,
    flush_wanted: Notify,
    /// Set at shutdown: the buffer takes no new write, so a last flush empties it.
    draining: AtomicBool,
    /// A buffered write is older than R at flush: no write and no flush until a restart.
    quarantined: AtomicBool,
    /// The last buffer append failed: logged once until an append works.
    buffer_failing: AtomicBool,
    /// The clock was more than R ahead of the wall clock at the last check: logged once.
    clock_ahead: AtomicBool,
    /// The highest own HLC that the open found, and where: the operator sees what holds the clock.
    own_high: Mutex<(u64, &'static str)>,
    /// When this process first saw each object that waits for a GC delete.
    gc_waits: gc::Waits,
    /// Snapshot bases with parts and no head, and when this node first listed each one
    /// (unix nanos of this node). Kept in `orphans_file`, so a restart keeps the count.
    orphans_seen: Mutex<BTreeMap<String, u64>>,
    orphans_file: PathBuf,
    /// Another node that wrote a condemn in the last H: a second GC runner.
    other_gc_node: Mutex<Option<NodeId>>,
}

/// The writes that the quarantine of the engine directory `dir` holds: what an operator decides
/// on before the next start.
pub async fn quarantined_writes(dir: impl AsRef<Path>) -> Result<Vec<QuarantinedWrite>> {
    buffer::read_quarantine(&dir.as_ref().join(QUARANTINE_DIR)).await
}

/// The quarantine directory of the engine directory `dir`.
pub fn quarantine_dir(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join(QUARANTINE_DIR)
}

/// Refuses to open with a quarantine. A buffered write older than the late limit, R - M, moves
/// to the quarantine, and the open fails: its commit could rank under a delete that a prune
/// already removed, and bring the key back. The young writes stay in the buffer.
async fn quarantine_at_open(
    dir: &Path,
    buffer_dir: &Path,
    buffer: &Buffer,
    now: u64,
    late_limit: Duration,
) -> Result<()> {
    let quarantine = dir.join(QUARANTINE_DIR);
    let limit = now.saturating_sub(late_limit.as_nanos() as u64);
    if buffer.oldest_time().is_some_and(|oldest| oldest < limit) {
        buffer::quarantine_late(buffer_dir, &quarantine, limit).await?;
        let keys = held_writes(&quarantine).await?;
        error!(keys, path = %quarantine.display(), "buffered writes older than the late limit: moved to quarantine");
        return Err(refusal(&quarantine, &keys));
    }
    Ok(())
}

/// Refuses to start while the quarantine directory holds a record segment. Another file holds
/// no write: it gives a WARN. A directory that does not read can hold writes: it fails the start.
async fn refuse_held_quarantine(quarantine: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(quarantine) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(EngineError::Quarantined(format!(
                "{} does not read: {e}. It can hold writes that were never committed",
                quarantine.display()
            )));
        }
    };
    let mut held = false;
    for entry in entries {
        let path = entry?.path();
        match path.extension().is_some_and(|e| e == "log") {
            true => held = true,
            false if is_intent(&path) => {}
            false => {
                warn!(path = %path.display(), "a file in the quarantine that holds no write: ignored")
            }
        }
    }
    if held {
        let keys = held_writes(quarantine).await?;
        return Err(refusal(quarantine, &keys));
    }
    Ok(())
}

/// An intent moved with the late records of its flush: the plan only, never a write.
fn is_intent(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "intent" || name.starts_with("intent."))
}

/// Each write in the quarantine as `target (ack HLC n)`: what the operator decides on.
async fn held_writes(quarantine: &Path) -> Result<String> {
    let writes = buffer::read_quarantine(quarantine).await?;
    let named: Vec<String> = writes
        .iter()
        .map(|write| format!("{} (ack HLC {})", write.target, write.hlc))
        .collect();
    if named.is_empty() {
        return Ok("an interrupted flush (intent file only)".to_string());
    }
    Ok(named.join(", "))
}

fn refusal(quarantine: &Path, keys: &str) -> EngineError {
    EngineError::Quarantined(format!(
        "{keys}: {} holds writes that were never committed. Decide for each key, then empty \
         the directory and start again",
        quarantine.display()
    ))
}

/// A time on both clocks. The GC measures H on the wall clock, and a monotonic clock does not
/// count a host suspend, so an age is the larger of the two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stamp {
    mono: u64,
    wall: u64,
}

impl Stamp {
    pub(crate) fn now() -> Self {
        Self {
            mono: journal::monotonic_nanos(),
            wall: buffer::unix_nanos(),
        }
    }

    pub(crate) fn mono(&self) -> u64 {
        self.mono
    }

    /// True when `age` passed since this stamp, on either clock.
    pub(crate) fn older_than(&self, age: Duration) -> bool {
        let age = age.as_nanos() as u64;
        let now = Self::now();
        now.mono.saturating_sub(self.mono) >= age || now.wall.saturating_sub(self.wall) >= age
    }
}

/// The rules that every proxy of one remote must share, kept in the key check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RepoRules {
    horizon_ns: u64,
    retention_ns: u64,
    late_margin_ns: u64,
}

impl RepoRules {
    fn text(&self) -> String {
        format!(
            "horizon_ns {}\nretention_ns {}\nlate_margin_ns {}",
            self.horizon_ns, self.retention_ns, self.late_margin_ns
        )
    }

    /// The rules in the names and the unit of the configuration.
    fn settings(&self) -> String {
        let secs = |ns: u64| match ns % 1_000_000_000 {
            0 => (ns / 1_000_000_000).to_string(),
            _ => format!("{}", ns as f64 / 1e9),
        };
        format!(
            "gc.horizon_secs = {}, gc.retention_secs = {}, gc.late_margin_secs = {}",
            secs(self.horizon_ns),
            secs(self.retention_ns),
            secs(self.late_margin_ns)
        )
    }

    fn parse<'a>(mut lines: impl Iterator<Item = &'a str>) -> Option<Self> {
        let mut value = |name: &str| {
            lines
                .next()?
                .strip_prefix(name)?
                .strip_prefix(' ')?
                .parse()
                .ok()
        };
        let horizon_ns = value("horizon_ns")?;
        let retention_ns = value("retention_ns")?;
        let late_margin_ns = value("late_margin_ns")?;
        Some(Self {
            horizon_ns,
            retention_ns,
            late_margin_ns,
        })
    }
}

impl<R: Remote + 'static> Engine<R> {
    /// Opens the engine state in `dir` and replays the writes a previous process
    /// buffered. The node identity is the public key of `signing_key`.
    pub async fn open(
        dir: impl AsRef<Path>,
        remote: Arc<R>,
        signing_key: SigningKey,
        keys: Keys,
        config: Config,
    ) -> Result<Self> {
        if config.max_entry_actions > MAX_ENTRY_ACTIONS {
            return Err(EngineError::Config(format!(
                "max_entry_actions ({}) is above {MAX_ENTRY_ACTIONS}: other proxies could not read \
                 the entries",
                config.max_entry_actions
            )));
        }
        if config.retention <= config.late_margin {
            return Err(EngineError::Config(format!(
                "the retention ({:?}) must be above the late margin ({:?})",
                config.retention, config.late_margin
            )));
        }
        let dir = dir.as_ref();
        // Before any remote call: a move later in the open could put a write next to one that
        // the operator has not decided on yet, and the operator must see it with the remote down.
        refuse_held_quarantine(&dir.join(QUARANTINE_DIR)).await?;
        let index = Index::open(dir.join(INDEX_DIR))?;
        let journal = Journal::new(
            remote.clone(),
            signing_key,
            keys.sealer().clone(),
            index.frontiers()?,
        );
        let buffer_dir = dir.join(BUFFER_DIR);
        let buffer = Buffer::open(&buffer_dir, config.pack_target as u64).await?;
        // The wall clock can step back across a restart: an ack never goes under an earlier
        // one, so own values move the clock with no cap. Values of other nodes stop at R ahead.
        let mut journal = journal;
        journal.set_max_ahead(config.retention);
        let clock = journal.clock();
        let ahead = config.retention.as_nanos() as u64;
        let own = journal.node();
        let mut own_high = (0, "none");
        for (node, frontier) in index.frontiers()? {
            if node == own {
                own_high = own_high.max((frontier.last_hlc, "the own chain"));
            } else {
                clock.witness_at_most(frontier.last_hlc, ahead);
            }
        }
        own_high = own_high.max((buffer.latest_time(), "a buffer record"));
        // An entry in the intent can be in the remote with no apply: the next one must rise.
        if let Some(intent) = buffer::read_intent(&buffer_dir).await? {
            own_high = own_high.max((intent.entry.hlc, "the intent"));
        }
        clock.witness(own_high.0);
        let cache = match config.cache_bytes {
            0 => None,
            bytes => Some(ChunkCache::open(dir.join(CACHE_DIR), bytes, keys.clone()).await?),
        };

        if !buffer.is_empty() {
            info!(bytes = buffer.bytes(), "replayed buffered writes");
        }

        let engine = Self {
            node: journal.node(),
            keys,
            remote,
            config,
            buffer_dir,
            journal: tokio::sync::Mutex::new(journal),
            clock,
            index: Mutex::new(index),
            buffer: tokio::sync::Mutex::new(buffer),
            cache,
            flushing: tokio::sync::Mutex::new(()),
            syncing: tokio::sync::Mutex::new(()),
            last_sync: Mutex::new(None),
            fresh_sync: Mutex::new(None),
            own_plan: Mutex::new(None),
            flush_wanted: Notify::new(),
            draining: AtomicBool::new(false),
            quarantined: AtomicBool::new(false),
            buffer_failing: AtomicBool::new(false),
            clock_ahead: AtomicBool::new(false),
            own_high: Mutex::new(own_high),
            gc_waits: gc::Waits::default(),
            orphans_seen: Mutex::new(snapshot::read_orphans(&dir.join(ORPHANS_FILE))),
            orphans_file: dir.join(ORPHANS_FILE),
            other_gc_node: Mutex::new(None),
        };

        engine.check_repo_key().await?;

        // A proxy with no state starts from the latest snapshot, not from every chain.
        // On failure, the first sync that meets a redacted entry loads it.
        if engine.index().frontiers()?.is_empty() {
            let mut journal = engine.journal.lock().await;
            match engine.bootstrap(&mut journal).await {
                Ok(Ok(())) => {}
                Ok(Err(none)) if none.is_empty() => {}
                Ok(Err(none)) => warn!(%none, "no snapshot loaded at open"),
                Err(e) => warn!(%e, "no snapshot loaded at open"),
            }
        }

        // The index is a cache: lost, behind after a power loss, or a restored copy, it can miss
        // the newest own entries. One full sync reads every chain, the own one included, through
        // the checks of a normal read, so the clock passes them before the first ack.
        let report = engine.sync().await?;
        let chain = engine.journal.lock().await.frontier(engine.node).last_hlc;
        {
            let mut high = engine
                .own_high
                .lock()
                .expect("no panic while the lock is held");
            *high = (*high).max((chain, "the own chain"));
        }
        // This sync does not count for the debounce of a sync on a miss.
        *engine
            .last_sync
            .lock()
            .expect("no panic while the lock is held") = None;
        if report.broken.contains(&engine.node) {
            let cause = report.broken_causes.join("; ");
            error!(cause, "the own chain does not read: no start");
            return Err(EngineError::Corrupt(format!(
                "the own chain is broken, so this proxy cannot order its acks: {cause}"
            )));
        }

        // Last, once the clock passed every HLC that the open found. The commit measures an ack
        // against its entry HLC: the clock, not the wall clock. An intent in the remote applies
        // first and frees its segments. An intent that is late and not in the remote never
        // commits: it goes to the quarantine with its records.
        if let Err(e) = engine.recover().await {
            if !matches!(e, EngineError::Quarantined(_)) {
                return Err(e);
            }
            buffer::quarantine_intent(&engine.buffer_dir, &dir.join(QUARANTINE_DIR)).await?;
        }
        let now = engine.clock.last().max(buffer::unix_nanos());
        {
            let buffer = engine.buffer.lock().await;
            quarantine_at_open(
                dir,
                &engine.buffer_dir,
                &buffer,
                now,
                engine.config.late_limit(),
            )
            .await?;
        }

        Ok(engine)
    }

    /// Opens the key check of the remote, or writes it when the remote has none. A proxy with
    /// another key would write a chain that the other proxies cannot read.
    async fn check_repo_key(&self) -> Result<()> {
        let sealer = self.keys.sealer();
        let ours = RepoRules {
            horizon_ns: self.config.gc_horizon.as_nanos() as u64,
            retention_ns: self.config.retention.as_nanos() as u64,
            late_margin_ns: self.config.late_margin.as_nanos() as u64,
        };
        let text = format!("{KEY_CHECK}\nformat {REMOTE_FORMAT}\n{}", ours.text());
        let check = sealer.seal(seal::Kind::KeyCheck, KEY_CHECK.as_bytes(), text.as_bytes());

        // A journal with no key check is not encrypted, or another tool wrote it.
        if self.remote.get(KEY_CHECK_KEY).await?.is_none()
            && !self.remote.list(journal::LOG_PREFIX).await?.is_empty()
        {
            return Err(EngineError::WrongRepoKey(format!(
                "the remote has a journal and no {KEY_CHECK_KEY}: it was written without \
                 encryption, so this build cannot read it"
            )));
        }

        // Create-only: of two first opens, one writes its rules and the other compares to them.
        match self.remote.create(KEY_CHECK_KEY, Bytes::from(check)).await {
            Ok(()) => return Ok(()),
            Err(RemoteError::AlreadyExists(_)) => {}
            Err(e) => return Err(e.into()),
        }

        let Some(stored) = self.remote.get(KEY_CHECK_KEY).await? else {
            return Err(EngineError::WrongRepoKey(format!(
                "{KEY_CHECK_KEY} is gone"
            )));
        };
        // The AEAD tag proves the key. The text gives the format and the rules.
        let plain = sealer
            .open(seal::Kind::KeyCheck, KEY_CHECK.as_bytes(), &stored)
            .map_err(|e| EngineError::WrongRepoKey(e.to_string()))?;
        let text = std::str::from_utf8(&plain).unwrap_or("");
        let mut lines = text.lines();
        let found = match (lines.next(), lines.next()) {
            (Some(KEY_CHECK), None) => 1,
            (Some(KEY_CHECK), Some(line)) => line
                .strip_prefix("format ")
                .and_then(|n| n.parse().ok())
                .unwrap_or(0),
            _ => 0,
        };
        if found != REMOTE_FORMAT {
            return Err(EngineError::Corrupt(format!(
                "{KEY_CHECK_KEY}: the remote has format {found}, this build reads format \
                 {REMOTE_FORMAT}"
            )));
        }

        let rest: Vec<&str> = lines.collect();
        let Some(theirs) = RepoRules::parse(rest.iter().copied()) else {
            return Err(EngineError::Config(format!(
                "{KEY_CHECK_KEY}: this remote was written by an older build; create a new remote"
            )));
        };
        // The exact text: a later build that adds a rule, or another number form, is refused.
        if rest.join("\n") != theirs.text() {
            return Err(EngineError::Config(format!(
                "{KEY_CHECK_KEY}: the rules are not in the form that this build writes: a later \
                 build wrote them; run that build"
            )));
        }
        if theirs != ours {
            return Err(EngineError::Config(format!(
                "the remote holds {}; this proxy has {}. Every proxy of a remote needs the \
                 same values",
                theirs.settings(),
                ours.settings()
            )));
        }
        Ok(())
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    fn index(&self) -> std::sync::MutexGuard<'_, Index> {
        self.index
            .lock()
            .expect("no panic while the index lock is held")
    }
}
