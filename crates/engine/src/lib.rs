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
mod snapshot;
mod sync;
mod write;

use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use cache::{CacheError, ChunkCache};
use ed25519_dalek::SigningKey;
use index::{ChunkLocation, Index, IndexError};
use journal::{Action, Commit, Entry, Journal, JournalError};
pub use list::{ListAfter, ListEntry, ListPage, ListQuery};
use model::{ChunkId, NodeId, ObjectId, PackId};
use pack::{Pack, PackEntry, PackError};
use remote::{Remote, RemoteError};
pub use seal::{Keys, RepoKey};
use subtle::ConstantTimeEq;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use buffer::{Buffer, BufferedObject, BufferedPut, Durability, Head, Intent, Op, SegmentReader};
use plan::{Fetch, Nonces, Planner};

pub use config::{CacheMode, Chunking, Config, Policy, PrefixPolicy};
pub use gc::GcReport;
pub use index::ObjectState;
pub use manifest::{ChunkRef, INLINE_MAX, MANIFESTS_PREFIX, Manifest, manifest_id, manifest_key};
pub use snapshot::{MAX_SNAPSHOT, SNAPSHOTS_PREFIX};

/// Prefix of all pack keys.
pub const PACKS_PREFIX: &str = "packs/";

const INDEX_DIR: &str = "index";
const BUFFER_DIR: &str = "buffer";
const CACHE_DIR: &str = "cache";

/// A known value, sealed under the repository key: it tells whether a key is the key of a remote.
pub const KEY_CHECK_KEY: &str = "repo/key-check";
const KEY_CHECK: &str = "windsock repository key check";

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

/// What a put does when the key exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteMode {
    Overwrite,
    /// `If-None-Match: *`. Strict through one proxy; across proxies a race becomes a conflict.
    CreateOnly,
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
    index: Mutex<Index>,
    buffer: tokio::sync::Mutex<Buffer>,
    cache: Option<ChunkCache>,
    /// The repository keys: chunk IDs, the FastCDC seed, and the seal of remote objects.
    keys: Keys,
    /// One flush at a time.
    flushing: tokio::sync::Mutex<()>,
    /// One buffer fsync at a time. The writes that arrive during an fsync share the next one.
    syncing: tokio::sync::Mutex<()>,
    last_sync: Mutex<Option<Instant>>,
    /// Start of the last sync that succeeded: GC rule 1 for dedup.
    fresh_sync: Mutex<Option<Instant>>,
    flush_wanted: Notify,
    /// Set at shutdown: the buffer takes no new write, so a last flush empties it.
    draining: AtomicBool,
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
        let dir = dir.as_ref();
        let index = Index::open(dir.join(INDEX_DIR))?;
        let journal = Journal::new(
            remote.clone(),
            signing_key,
            keys.sealer().clone(),
            index.frontiers()?,
        );
        let buffer_dir = dir.join(BUFFER_DIR);
        let buffer = Buffer::open(&buffer_dir, config.pack_target as u64).await?;
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
            index: Mutex::new(index),
            buffer: tokio::sync::Mutex::new(buffer),
            cache,
            flushing: tokio::sync::Mutex::new(()),
            syncing: tokio::sync::Mutex::new(()),
            last_sync: Mutex::new(None),
            fresh_sync: Mutex::new(None),
            flush_wanted: Notify::new(),
            draining: AtomicBool::new(false),
        };

        engine.check_repo_key().await?;

        // A proxy with no state starts from the latest snapshot, not from every chain.
        // On failure, the first sync that meets a redacted entry loads it.
        if engine.index().frontiers()?.is_empty() {
            let mut journal = engine.journal.lock().await;
            if let Err(e) = engine.bootstrap(&mut journal).await {
                warn!(%e, "no snapshot loaded at open");
            }
        }

        Ok(engine)
    }

    /// Opens the key check of the remote, or writes it when the remote has none. A proxy with
    /// another key would write a chain that the other proxies cannot read.
    async fn check_repo_key(&self) -> Result<()> {
        let sealer = self.keys.sealer();
        let check = sealer.seal(
            seal::Kind::KeyCheck,
            KEY_CHECK.as_bytes(),
            KEY_CHECK.as_bytes(),
        );

        // A journal with no key check comes from a build before the seal, or from another tool.
        if self.remote.get(KEY_CHECK_KEY).await?.is_none()
            && !self.remote.list(journal::LOG_PREFIX).await?.is_empty()
        {
            return Err(EngineError::WrongRepoKey(format!(
                "the remote has a journal and no {KEY_CHECK_KEY}: it was written without \
                 encryption, so this build cannot read it"
            )));
        }

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
        match sealer.open(seal::Kind::KeyCheck, KEY_CHECK.as_bytes(), &stored) {
            Ok(plain) if bool::from(plain.as_slice().ct_eq(KEY_CHECK.as_bytes())) => Ok(()),
            Ok(_) => Err(EngineError::WrongRepoKey(format!(
                "{KEY_CHECK_KEY} is changed"
            ))),
            Err(e) => Err(EngineError::WrongRepoKey(e.to_string())),
        }
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
