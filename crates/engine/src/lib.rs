//! Object operations over a remote, with a local write-back buffer.
//!
//! A write is acknowledged once it is fsynced in the local buffer. The flusher
//! uploads buffered writes within a bounded delay: packs and large manifests
//! first, then one journal entry for the whole batch (group commit). Reads see
//! buffered writes before the flush.

mod buffer;
mod config;
mod gc;
mod manifest;
mod plan;
mod snapshot;

use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use index::{ChunkLocation, Index, IndexError};
use journal::{Action, Commit, Entry, Journal, JournalError};
use model::{ChunkId, NodeId, ObjectId, PackId};
use pack::{Pack, PackError};
use remote::{Remote, RemoteError};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use buffer::{Buffer, BufferedObject, BufferedPut, Head, Intent, Op, SegmentReader};
use plan::{Nonces, Planner};

pub use config::{Chunking, Config, Policy, PrefixPolicy};
pub use gc::GcReport;
pub use index::ObjectState;
pub use manifest::{ChunkRef, INLINE_MAX, MANIFESTS_PREFIX, Manifest, manifest_id, manifest_key};
pub use snapshot::SNAPSHOTS_PREFIX;

/// Prefix of all pack keys.
pub const PACKS_PREFIX: &str = "packs/";

/// A miss does not sync again sooner than this after the last sync.
const SYNC_DEBOUNCE: Duration = Duration::from_secs(1);

/// Upper bound on the buffered data that one journal entry covers.
const SEGMENTS_PER_ENTRY: usize = 16;

/// Commits that lose the seq to another process before a flush gives up.
const MAX_COMMIT_ATTEMPTS: u32 = 8;

const INDEX_DIR: &str = "index";
const BUFFER_DIR: &str = "buffer";

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
    #[error("local buffer is full ({limit} bytes)")]
    BufferFull { limit: u64 },
    #[error("{0} commits lost the seq to another process with this identity")]
    Contended(u32),
    #[error("the flush plan is older than half the GC horizon: plan again")]
    StalePlan,
    #[error("broken chains: {0:?}")]
    BrokenChains(Vec<NodeId>),
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

/// A flushed record, in buffer order.
enum Planned {
    /// The n-th object given to the planner.
    Put {
        bucket: String,
        key: String,
        object: usize,
    },
    Other(Action),
}

pub struct Engine<R> {
    remote: Arc<R>,
    config: Config,
    node: NodeId,
    buffer_dir: PathBuf,
    journal: tokio::sync::Mutex<Journal<R>>,
    index: Mutex<Index>,
    buffer: tokio::sync::Mutex<Buffer>,
    /// One flush at a time.
    flushing: tokio::sync::Mutex<()>,
    last_sync: Mutex<Option<Instant>>,
    /// Start of the last sync that succeeded: GC rule 1 for dedup.
    fresh_sync: Mutex<Option<Instant>>,
    flush_wanted: Notify,
}

impl<R: Remote + 'static> Engine<R> {
    /// Opens the engine state in `dir` and replays the writes a previous process
    /// buffered. The node identity is the public key of `signing_key`.
    pub async fn open(
        dir: impl AsRef<Path>,
        remote: Arc<R>,
        signing_key: SigningKey,
        config: Config,
    ) -> Result<Self> {
        let dir = dir.as_ref();
        let index = Index::open(dir.join(INDEX_DIR))?;
        let journal = Journal::new(remote.clone(), signing_key, index.frontiers()?);
        let buffer_dir = dir.join(BUFFER_DIR);
        let buffer = Buffer::open(&buffer_dir, config.pack_target as u64).await?;

        if !buffer.is_empty() {
            info!(bytes = buffer.bytes(), "replayed buffered writes");
        }

        let engine = Self {
            node: journal.node(),
            remote,
            config,
            buffer_dir,
            journal: tokio::sync::Mutex::new(journal),
            index: Mutex::new(index),
            buffer: tokio::sync::Mutex::new(buffer),
            flushing: tokio::sync::Mutex::new(()),
            last_sync: Mutex::new(None),
            fresh_sync: Mutex::new(None),
            flush_wanted: Notify::new(),
        };

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

    pub fn node(&self) -> NodeId {
        self.node
    }

    fn index(&self) -> std::sync::MutexGuard<'_, Index> {
        self.index
            .lock()
            .expect("no panic while the index lock is held")
    }

    // ------------------------------------------------------------------
    // Buckets
    // ------------------------------------------------------------------

    pub async fn create_bucket(&self, name: &str, owner: Option<String>) -> Result<()> {
        check_bucket_name(name)?;
        let mut buffer = self.buffer.lock().await;

        if self.bucket_in(&buffer, name)?.is_some() {
            return Err(EngineError::BucketAlreadyExists(name.to_string()));
        }

        let op = Op::CreateBucket {
            bucket: name.to_string(),
            owner,
        };
        self.append(&mut buffer, op, &[]).await
    }

    /// Deletes an empty bucket. Emptiness is checked against what this proxy knows.
    pub async fn delete_bucket(&self, name: &str) -> Result<()> {
        self.retry_after_sync(|| self.delete_bucket_once(name))
            .await
    }

    async fn delete_bucket_once(&self, name: &str) -> Result<()> {
        let mut buffer = self.buffer.lock().await;
        self.require_bucket(&buffer, name)?;

        let has_objects = self
            .keys_in(&buffer, name, "")?
            .into_iter()
            .any(|(_, current)| current.exists());

        if has_objects {
            return Err(EngineError::BucketNotEmpty(name.to_string()));
        }

        let op = Op::DeleteBucket {
            bucket: name.to_string(),
        };
        self.append(&mut buffer, op, &[]).await
    }

    pub async fn bucket(&self, name: &str) -> Result<BucketInfo> {
        self.retry_after_sync(|| async move {
            let buffer = self.buffer.lock().await;
            self.require_bucket(&buffer, name)
        })
        .await
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketInfo>> {
        let buffer = self.buffer.lock().await;
        let mut buckets: BTreeMap<String, Option<String>> = self
            .index()
            .buckets()?
            .into_iter()
            .map(|(name, state)| (name, state.owner))
            .collect();

        for (name, state) in buffer.buckets() {
            if state.exists {
                buckets.insert(name.to_string(), state.owner.clone());
            } else {
                buckets.remove(name);
            }
        }

        Ok(buckets
            .into_iter()
            .map(|(name, owner)| BucketInfo { name, owner })
            .collect())
    }

    fn bucket_in(&self, buffer: &Buffer, name: &str) -> Result<Option<BucketInfo>> {
        if let Some(state) = buffer.bucket(name) {
            return Ok(state.exists.then(|| BucketInfo {
                name: name.to_string(),
                owner: state.owner.clone(),
            }));
        }

        Ok(self
            .index()
            .bucket(name)?
            .filter(|state| state.exists)
            .map(|state| BucketInfo {
                name: name.to_string(),
                owner: state.owner,
            }))
    }

    fn require_bucket(&self, buffer: &Buffer, name: &str) -> Result<BucketInfo> {
        self.bucket_in(buffer, name)?
            .ok_or_else(|| EngineError::NoSuchBucket(name.to_string()))
    }

    // ------------------------------------------------------------------
    // Writes
    // ------------------------------------------------------------------

    /// Stores an object. Returns once the write survives a crash of this proxy.
    pub async fn put(
        &self,
        bucket: &str,
        key: &str,
        data: Bytes,
        metadata: BTreeMap<String, String>,
        mode: WriteMode,
    ) -> Result<ObjectInfo> {
        check_key(key)?;
        let policy = self.config.policy(bucket, key);
        let create_only = mode == WriteMode::CreateOnly || policy.create_only;
        let content_hash = *blake3::hash(&data).as_bytes();
        let (data, metadata) = (&data, &metadata);

        self.retry_after_sync(|| async move {
            let mut buffer = self.buffer.lock().await;
            self.require_bucket(&buffer, bucket)?;

            if create_only && self.current(&buffer, bucket, key)?.exists() {
                return Err(EngineError::PreconditionFailed {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }

            let time = buffer::unix_nanos();
            let op = Op::Put {
                bucket: bucket.to_string(),
                key: key.to_string(),
                metadata: metadata.clone(),
                content_hash,
            };
            self.append_at(&mut buffer, time, op, data).await?;

            Ok(ObjectInfo {
                key: key.to_string(),
                size: data.len() as u64,
                content_hash,
                metadata: metadata.clone(),
                last_modified: time,
                conflicted: false,
            })
        })
        .await
    }

    /// Deletes a key. A missing key is not an error, as in S3.
    pub async fn delete(&self, bucket: &str, key: &str) -> Result<()> {
        check_key(key)?;

        self.retry_after_sync(|| async move {
            let mut buffer = self.buffer.lock().await;
            self.require_bucket(&buffer, bucket)?;

            let op = Op::Delete {
                bucket: bucket.to_string(),
                key: key.to_string(),
            };
            self.append(&mut buffer, op, &[]).await
        })
        .await
    }

    async fn append(&self, buffer: &mut Buffer, op: Op, data: &[u8]) -> Result<()> {
        self.append_at(buffer, buffer::unix_nanos(), op, data).await
    }

    async fn append_at(&self, buffer: &mut Buffer, time: u64, op: Op, data: &[u8]) -> Result<()> {
        let limit = self.config.buffer_limit;

        if buffer.bytes() + data.len() as u64 > limit {
            return Err(EngineError::BufferFull { limit });
        }

        buffer.append(Head { time, op }, data).await?;

        if buffer.bytes() >= self.config.pack_target as u64 {
            self.flush_wanted.notify_one();
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Reads
    // ------------------------------------------------------------------

    /// Reads `range` of an object, or all of it.
    pub async fn get(&self, bucket: &str, key: &str, range: Option<Range<u64>>) -> Result<Object> {
        self.retry_after_sync(|| self.get_once(bucket, key, range.clone()))
            .await
    }

    pub async fn head(&self, bucket: &str, key: &str) -> Result<ObjectInfo> {
        self.retry_after_sync(|| async move {
            let current = {
                let buffer = self.buffer.lock().await;
                self.require_bucket(&buffer, bucket)?;
                self.current(&buffer, bucket, key)?
            };
            self.info(bucket, key, current).await
        })
        .await
    }

    /// Every key of `bucket` under `prefix` that exists, in key order.
    pub async fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<ObjectInfo>> {
        self.retry_after_sync(|| async move {
            let keys = {
                let buffer = self.buffer.lock().await;
                self.require_bucket(&buffer, bucket)?;
                self.keys_in(&buffer, bucket, prefix)?
            };

            let mut out = Vec::with_capacity(keys.len());
            for (key, current) in keys {
                if current.exists() {
                    out.push(self.info(bucket, &key, current).await?);
                }
            }
            Ok(out)
        })
        .await
    }

    /// Every journaled version of a key. Buffered writes are not versions yet.
    pub fn versions(&self, bucket: &str, key: &str) -> Result<Option<ObjectState>> {
        Ok(self.index().object(bucket, key)?)
    }

    async fn get_once(&self, bucket: &str, key: &str, range: Option<Range<u64>>) -> Result<Object> {
        loop {
            let current = {
                let buffer = self.buffer.lock().await;
                self.require_bucket(&buffer, bucket)?;
                self.current(&buffer, bucket, key)?
            };

            match current {
                Current::Absent => return Err(no_such_key(bucket, key)),
                Current::Buffered(put) => {
                    let range = check_range(range.clone(), put.size)?;
                    let Some(data) = buffer::read_put(&self.buffer_dir, &put, range).await? else {
                        // A flush released the segment: the write is in the index now.
                        continue;
                    };
                    return Ok(Object {
                        info: buffered_info(key, put),
                        data: Bytes::from(data),
                    });
                }
                Current::Stored {
                    manifest_id,
                    hlc,
                    conflicted,
                } => {
                    let manifest = self.manifest(manifest_id).await?;
                    let range = check_range(range, manifest.size)?;
                    let data = self.read_range(&manifest, range).await?;
                    return Ok(Object {
                        info: stored_info(key, manifest, hlc, conflicted),
                        data: Bytes::from(data),
                    });
                }
            }
        }
    }

    fn current(&self, buffer: &Buffer, bucket: &str, key: &str) -> Result<Current> {
        match buffer.object(bucket, key) {
            Some(BufferedObject::Put(put)) => return Ok(Current::Buffered(put.clone())),
            Some(BufferedObject::Delete { .. }) => return Ok(Current::Absent),
            None => {}
        }

        let state = self.index().object(bucket, key)?;
        Ok(state.map_or(Current::Absent, |state| stored(&state)))
    }

    /// The current state of every key of `bucket` under `prefix`, deleted ones included.
    fn keys_in(
        &self,
        buffer: &Buffer,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<(String, Current)>> {
        let mut keys: BTreeMap<String, Current> = self
            .index()
            .list(bucket, prefix)?
            .into_iter()
            .map(|(key, state)| (key, stored(&state)))
            .collect();

        for (key, object) in buffer.objects(bucket, prefix) {
            let current = match object {
                BufferedObject::Put(put) => Current::Buffered(put.clone()),
                BufferedObject::Delete { .. } => Current::Absent,
            };
            keys.insert(key.to_string(), current);
        }

        Ok(keys.into_iter().collect())
    }

    async fn info(&self, bucket: &str, key: &str, current: Current) -> Result<ObjectInfo> {
        match current {
            Current::Absent => Err(no_such_key(bucket, key)),
            Current::Buffered(put) => Ok(buffered_info(key, put)),
            Current::Stored {
                manifest_id,
                hlc,
                conflicted,
            } => {
                let manifest = self.manifest(manifest_id).await?;
                Ok(stored_info(key, manifest, hlc, conflicted))
            }
        }
    }

    /// The manifest from the index, or from the remote on a miss.
    async fn manifest(&self, id: ObjectId) -> Result<Manifest> {
        if let Some(bytes) = self.index().manifest(id)? {
            return Manifest::decode(id, &bytes);
        }

        let Some(bytes) = self.remote.get(&manifest_key(id)).await? else {
            return Err(EngineError::Corrupt(format!("manifest {id} is missing")));
        };

        let manifest = Manifest::decode(id, &bytes)?;
        self.index().put_manifest(id, &bytes)?;
        Ok(manifest)
    }

    async fn entry_manifest(&self, id: ObjectId, inline: Option<&[u8]>) -> Result<Manifest> {
        let Some(bytes) = inline else {
            return self.manifest(id).await;
        };

        let manifest = Manifest::decode(id, bytes)?;
        self.index().put_manifest(id, bytes)?;
        Ok(manifest)
    }

    async fn read_range(&self, manifest: &Manifest, range: Range<u64>) -> Result<Vec<u8>> {
        let len = (range.end - range.start) as usize;
        let (fetches, skip) = plan::plan_read(&manifest.chunks, range);
        let mut raw = Vec::new();

        for fetch in fetches {
            let key = pack_key(fetch.pack);
            let Some(bytes) = self.remote.get_range(&key, fetch.range.clone()).await? else {
                return Err(EngineError::Corrupt(format!(
                    "pack {} is missing",
                    fetch.pack
                )));
            };

            for entry in &fetch.entries {
                let start = (entry.offset - fetch.range.start) as usize;
                let stored = &bytes[start..start + entry.stored_len as usize];
                raw.extend(pack::read_chunk(entry, stored)?);
            }
        }

        let skip = skip as usize;
        Ok(raw[skip..skip + len].to_vec())
    }

    // ------------------------------------------------------------------
    // Sync
    // ------------------------------------------------------------------

    /// Reads the new entries of every chain and applies them. Returns the number applied.
    pub async fn sync(&self) -> Result<SyncReport> {
        let mut journal = self.journal.lock().await;
        self.sync_locked(&mut journal).await
    }

    async fn sync_locked(&self, journal: &mut Journal<R>) -> Result<SyncReport> {
        let started = Instant::now();
        *self
            .last_sync
            .lock()
            .expect("no panic while the lock is held") = Some(started);

        let mut entries = journal.sync_all().await?;

        // Entries under the latest snapshot can be redacted: read from the snapshot instead.
        if entries.iter().any(|entry| entry.actions.is_none()) {
            if !self.bootstrap(journal).await? {
                return Err(EngineError::Corrupt(
                    "redacted entries and no snapshot".to_string(),
                ));
            }
            entries = journal.sync_all().await?;
        }

        let mut report = SyncReport {
            broken: journal.broken().keys().copied().collect(),
            ..SyncReport::default()
        };

        if !entries.is_empty() {
            self.ingest(&entries).await?;
            report.applied = self.index().apply(entries)?;
            debug!(applied = report.applied, "synced");
        }

        // GC rule 1 needs every chain: a broken one can hide a condemn.
        if report.broken.is_empty() {
            *self
                .fresh_sync
                .lock()
                .expect("no panic while the lock is held") = Some(started);
        }

        Ok(report)
    }

    /// GC rule 1: dedup only against what a complete sync younger than H/2 found.
    /// Returns `false` when no such sync exists: the flush then writes every chunk.
    async fn ensure_fresh_sync(&self) -> Result<bool> {
        let mut journal = self.journal.lock().await;
        let fresh = || {
            self.fresh_sync
                .lock()
                .expect("no panic while the lock is held")
                .is_some_and(|started| started.elapsed() < self.config.gc_horizon / 2)
        };

        if fresh() {
            return Ok(true);
        }

        let report = self.sync_locked(&mut journal).await?;
        if !report.broken.is_empty() {
            warn!(broken = ?report.broken, "flush without dedup: a chain is broken");
        }

        Ok(fresh())
    }

    fn plan_is_stale(&self, planned_at: u64) -> bool {
        let half = (self.config.gc_horizon / 2).as_nanos() as u64;
        buffer::unix_nanos() >= planned_at.saturating_add(half)
    }

    /// Runs `op`. On a missing bucket or key, syncs once and runs it again,
    /// unless a sync ran in the last second.
    async fn retry_after_sync<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        match op().await {
            Err(EngineError::NoSuchBucket(_) | EngineError::NoSuchKey { .. })
                if self.sync_if_due().await? =>
            {
                op().await
            }
            result => result,
        }
    }

    async fn sync_if_due(&self) -> Result<bool> {
        let mut journal = self.journal.lock().await;
        let due = self
            .last_sync
            .lock()
            .expect("no panic while the lock is held")
            .is_none_or(|last| last.elapsed() >= SYNC_DEBOUNCE);

        if !due {
            return Ok(false);
        }

        self.sync_locked(&mut journal).await?;
        Ok(true)
    }

    /// Stores the manifests that entries carry or name, and the chunk locations they give.
    /// The data is in the remote before the entry, so this can run before the entries apply.
    async fn ingest(&self, entries: &[Entry]) -> Result<()> {
        for action in entries.iter().flat_map(|e| e.actions.iter().flatten()) {
            let Action::Put {
                manifest_id,
                inline_manifest,
                ..
            } = action
            else {
                continue;
            };

            // A bad manifest breaks reads of one key, not the sync of every chain.
            let manifest = match self
                .entry_manifest(*manifest_id, inline_manifest.as_deref())
                .await
            {
                Ok(manifest) => manifest,
                Err(EngineError::Corrupt(reason)) => {
                    warn!(%manifest_id, reason, "skipped a manifest");
                    continue;
                }
                Err(e) => return Err(e),
            };

            self.record_chunks(&manifest)?;
        }

        Ok(())
    }

    /// Records the chunk locations of a manifest, for dedup.
    fn record_chunks(&self, manifest: &Manifest) -> Result<()> {
        let seen_at = buffer::unix_nanos() / 1_000_000_000;
        let index = self.index();

        for chunk in &manifest.chunks {
            if index.chunk(chunk.entry.chunk_id)?.is_some() {
                continue;
            }
            let location = ChunkLocation {
                pack: chunk.pack,
                entry: chunk.entry,
                seen_at,
            };
            index.put_chunk(chunk.entry.chunk_id, &location)?;
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Flush
    // ------------------------------------------------------------------

    /// Uploads every buffered write and commits it to the journal.
    pub async fn flush(&self) -> Result<()> {
        let _flushing = self.flushing.lock().await;
        self.recover().await?;

        let sealed = self.buffer.lock().await.seal().await?;

        for batch in sealed.chunks(SEGMENTS_PER_ENTRY) {
            self.flush_segments(batch).await?;
        }

        Ok(())
    }

    /// Flushes every `flush_delay`, or sooner once a pack worth of data is buffered.
    pub fn spawn_flusher(self: &Arc<Self>) -> JoinHandle<()> {
        let engine = Arc::clone(self);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(engine.config.flush_delay) => {}
                    () = engine.flush_wanted.notified() => {}
                }

                if let Err(e) = engine.flush().await {
                    warn!(%e, "flush failed");
                    // Without a pause, a full buffer retries on every put while the remote is down.
                    tokio::time::sleep(engine.config.flush_delay).await;
                }
            }
        })
    }

    /// Finishes the commit of a flush that a crash or an error interrupted.
    /// GC rule 2: an old plan is only looked for in the remote, never written.
    async fn recover(&self) -> Result<()> {
        let Some(intent) = buffer::read_intent(&self.buffer_dir).await? else {
            return Ok(());
        };

        let mut journal = self.journal.lock().await;
        let written = if self.plan_is_stale(intent.planned_at) {
            journal.is_written(&intent.entry).await?
        } else {
            journal.commit(&intent.entry).await? == Commit::Written
        };

        if written {
            info!(seq = intent.entry.seq, "recovered an interrupted flush");
            self.apply_own(&mut journal, intent.entry).await?;
            self.buffer.lock().await.release(&intent.segments).await?;
        } else {
            warn!(
                seq = intent.entry.seq,
                "interrupted flush is not in the remote: flushing again"
            );
        }

        buffer::remove_intent(&self.buffer_dir).await
    }

    async fn flush_segments(&self, segments: &[u64]) -> Result<()> {
        let dedup = self.ensure_fresh_sync().await?;
        let planned_at = buffer::unix_nanos();
        let seed = blake3::Hasher::new()
            .update(self.node.as_bytes())
            .update(&buffer::unix_nanos().to_le_bytes())
            .finalize();
        let nonces = Nonces::new(*seed.as_bytes());
        let mut planner = Planner::new(
            self.config.pack_target,
            self.config.own_pack_threshold,
            nonces,
        );
        let mut planned = Vec::new();
        let mut objects = 0;

        for &seq in segments {
            let path = buffer::segment_path(&self.buffer_dir, seq);
            let mut reader = SegmentReader::open(&path).await?;

            while let Some(record) = reader.next(&path).await? {
                let next = match record.head.op {
                    Op::Put {
                        bucket,
                        key,
                        metadata,
                        content_hash,
                    } => {
                        let policy = self.config.policy(&bucket, &key);
                        let closed =
                            planner.add(&record.data, content_hash, metadata, policy, |id| {
                                if !dedup {
                                    return Ok(None);
                                }
                                self.stored_chunk(id)
                            })?;
                        self.upload_packs(closed).await?;
                        objects += 1;
                        Planned::Put {
                            bucket,
                            key,
                            object: objects - 1,
                        }
                    }
                    Op::Delete { bucket, key } => Planned::Other(Action::Delete { bucket, key }),
                    Op::CreateBucket { bucket, owner } => {
                        Planned::Other(Action::CreateBucket { bucket, owner })
                    }
                    Op::DeleteBucket { bucket } => Planned::Other(Action::DeleteBucket { bucket }),
                };
                planned.push(next);
            }
        }

        let (last, manifests) = planner.finish();
        self.upload_packs(last.into_iter().collect()).await?;

        let mut actions = Vec::with_capacity(planned.len());
        for next in planned {
            actions.push(match next {
                Planned::Put {
                    bucket,
                    key,
                    object,
                } => {
                    self.manifest_action(bucket, key, &manifests[object])
                        .await?
                }
                Planned::Other(action) => action,
            });
        }

        let mut journal = self.journal.lock().await;
        let entry = self
            .commit(&mut journal, actions, segments, planned_at)
            .await?;
        debug!(seq = entry.seq, segments = segments.len(), "flushed");
        self.apply_own(&mut journal, entry).await?;
        drop(journal);

        self.buffer.lock().await.release(segments).await?;
        buffer::remove_intent(&self.buffer_dir).await
    }

    fn stored_chunk(&self, id: ChunkId) -> Result<Option<ChunkRef>> {
        Ok(self.index().chunk(id)?.map(|location| ChunkRef {
            pack: location.pack,
            entry: location.entry,
        }))
    }

    async fn upload_packs(&self, packs: Vec<Pack>) -> Result<()> {
        for pack in packs {
            debug!(pack = %pack.id, bytes = pack.bytes.len(), "uploading pack");
            self.remote
                .put(&pack_key(pack.id), Bytes::from(pack.bytes))
                .await?;
        }

        Ok(())
    }

    /// The put action of a manifest. A large manifest goes to the remote first.
    async fn manifest_action(
        &self,
        bucket: String,
        key: String,
        manifest: &Manifest,
    ) -> Result<Action> {
        let bytes = manifest.encode();
        let manifest_id = manifest_id(&bytes);

        let inline_manifest = if bytes.len() <= INLINE_MAX {
            Some(bytes)
        } else {
            self.remote
                .put(&manifest_key(manifest_id), Bytes::from(bytes.clone()))
                .await?;
            self.index().put_manifest(manifest_id, &bytes)?;
            None
        };

        Ok(Action::Put {
            bucket,
            key,
            manifest_id,
            inline_manifest,
        })
    }

    /// Writes the intent, then the entry. A crash in between leaves the intent for `recover`.
    async fn commit(
        &self,
        journal: &mut Journal<R>,
        actions: Vec<Action>,
        segments: &[u64],
        planned_at: u64,
    ) -> Result<Entry> {
        for _ in 0..MAX_COMMIT_ATTEMPTS {
            // GC rule 2: a dedup decision older than H/2 can name a pack that the GC deleted.
            if self.plan_is_stale(planned_at) {
                return Err(EngineError::StalePlan);
            }

            let seen = self.index().seen(self.node)?;
            let intent = Intent {
                entry: journal.prepare(actions.clone(), seen),
                segments: segments.to_vec(),
                planned_at,
            };
            buffer::write_intent(&self.buffer_dir, &intent).await?;

            match journal.commit(&intent.entry).await? {
                Commit::Written => return Ok(intent.entry),
                Commit::SeqTaken => continue,
            }
        }

        Err(EngineError::Contended(MAX_COMMIT_ATTEMPTS))
    }

    /// Applies an own entry, with the own-chain entries the commit read, and
    /// persists the index: the buffer may drop the writes after this.
    async fn apply_own(&self, journal: &mut Journal<R>, entry: Entry) -> Result<()> {
        let mut entries = journal.take_stashed();
        // A pruned copy of the entry can come back from the remote: keep the whole one.
        entries.retain(|stashed| (stashed.node, stashed.seq) != (entry.node, entry.seq));

        // Another process with this identity wrote entries that are now pruned.
        if entries.iter().any(|stashed| stashed.actions.is_none()) {
            if !self.bootstrap(journal).await? {
                return Err(EngineError::Corrupt(
                    "redacted entries and no snapshot".to_string(),
                ));
            }
            entries.clear();
        }

        entries.push(entry);

        self.ingest(&entries).await?;
        let mut index = self.index();
        index.apply(entries)?;
        index.persist()?;
        Ok(())
    }
}

fn stored(state: &ObjectState) -> Current {
    match (state.head(), state.current()) {
        (Some(head), Some(manifest_id)) => Current::Stored {
            manifest_id,
            hlc: head.hlc,
            conflicted: state.is_conflicted(),
        },
        _ => Current::Absent,
    }
}

fn no_such_key(bucket: &str, key: &str) -> EngineError {
    EngineError::NoSuchKey {
        bucket: bucket.to_string(),
        key: key.to_string(),
    }
}

fn buffered_info(key: &str, put: BufferedPut) -> ObjectInfo {
    ObjectInfo {
        key: key.to_string(),
        size: put.size,
        content_hash: put.content_hash,
        metadata: put.metadata,
        last_modified: put.time,
        conflicted: false,
    }
}

fn stored_info(key: &str, manifest: Manifest, hlc: u64, conflicted: bool) -> ObjectInfo {
    ObjectInfo {
        key: key.to_string(),
        size: manifest.size,
        content_hash: manifest.content_hash,
        metadata: manifest.metadata,
        last_modified: hlc,
        conflicted,
    }
}

fn check_range(range: Option<Range<u64>>, size: u64) -> Result<Range<u64>> {
    let range = range.unwrap_or(0..size);

    if range.start > range.end || range.end > size {
        return Err(EngineError::InvalidRange {
            start: range.start,
            end: range.end,
            size,
        });
    }

    Ok(range)
}

/// S3 rules: 3 to 63 bytes of lowercase letters, digits, dots and hyphens,
/// starting and ending with a letter or a digit.
fn check_bucket_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let valid = (3..=63).contains(&bytes.len())
        && bytes.iter().all(|b| edge(b) || *b == b'.' || *b == b'-')
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge);

    if !valid {
        return Err(EngineError::InvalidBucketName(name.to_string()));
    }

    Ok(())
}

/// S3 rules: 1 to 1024 bytes of UTF-8.
fn check_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 1024 {
        return Err(EngineError::InvalidKey(key.to_string()));
    }

    Ok(())
}
