//! Materialized view of the journal, in Fjall.
//!
//! The index applies entries in causal order: an entry waits until the entries
//! in its `seen` are applied. Frontiers of applied entries are persisted, so a
//! restart reads only the new entries. Pending entries are not persisted: a
//! restart reads them again.

mod snapshot;
mod state;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use journal::{Action, Entry, EntryHash, Frontier, Frontiers, Seen};
use model::{ChunkId, NodeId, ObjectId, PackId};
use pack::PackEntry;
use serde::{Deserialize, Serialize};
use tracing::debug;

pub use snapshot::Snapshot;
pub use state::{BucketState, EntryRef, ObjectState, Pruned, Version, knew};

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error(transparent)]
    Storage(#[from] fjall::Error),
    #[error("corrupt index record: {0}")]
    Corrupt(#[from] postcard::Error),
    #[error("entry {seq} of node {node} links to an entry with another hash")]
    LinkMismatch { node: NodeId, seq: u64 },
    #[error("entry {seq} of node {node} is redacted: load a snapshot that covers it")]
    Redacted { node: NodeId, seq: u64 },
    #[error("the {what} has format {found}, this build reads format {expected}")]
    Format {
        what: &'static str,
        found: u32,
        expected: u32,
    },
}

type Result<T> = std::result::Result<T, IndexError>;

fn corrupt() -> IndexError {
    IndexError::Corrupt(postcard::Error::DeserializeBadEncoding)
}

/// Where a chunk lives in the remote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkLocation {
    pub pack: PackId,
    pub entry: PackEntry,
    /// Unix time when this location was last confirmed, for a future GC horizon.
    pub seen_at: u64,
}

/// The chunk locations of an index, apart from its lock.
#[derive(Clone)]
pub struct ChunkLocations(Keyspace);

impl ChunkLocations {
    pub fn get(&self, id: ChunkId) -> Result<Option<ChunkLocation>> {
        Ok(match self.0.get(id.as_bytes())? {
            Some(value) => Some(postcard::from_bytes(&value)?),
            None => None,
        })
    }
}

enum Readiness {
    Ready,
    Wait,
    AlreadyApplied,
}

pub struct Index {
    db: Database,
    frontiers: Keyspace,
    entries: Keyspace,
    objects: Keyspace,
    buckets: Keyspace,
    chunks: Keyspace,
    /// `pack | chunk`: the chunks to forget when a pack is condemned.
    pack_chunks: Keyspace,
    manifests: Keyspace,
    /// `tag | id` to the lowest HLC of a condemn: the same for every apply order.
    condemned: Keyspace,
    /// Node to the first seq not yet checked by the journal prune. Local progress only.
    redacted: Keyspace,
    /// `retired node | writer | seq` of each valid Retire action, to its point and entry HLC.
    retired: Keyspace,
    /// Entries that wait for a dependency, by node and seq: a sync can read one again.
    pending: BTreeMap<(NodeId, u64), Entry>,
    _temp: Option<tempfile::TempDir>,
}

fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("index records always serialize")
}

fn entry_key(node: NodeId, seq: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(node.as_bytes());
    key[32..].copy_from_slice(&seq.to_be_bytes());
    key
}

const PACK_TAG: u8 = b'p';
const MANIFEST_TAG: u8 = b'm';

fn condemn_key(tag: u8, id: &[u8; 32]) -> [u8; 33] {
    let mut key = [0u8; 33];
    key[0] = tag;
    key[1..].copy_from_slice(id);
    key
}

/// The entries of `node` below `upto` are retired by the entry `seq` of `by`, at `hlc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetireMark {
    pub node: NodeId,
    pub by: NodeId,
    pub seq: u64,
    pub upto: u64,
    pub hlc: u64,
}

impl RetireMark {
    fn key(&self) -> [u8; 72] {
        let mut key = [0u8; 72];
        key[..32].copy_from_slice(self.node.as_bytes());
        key[32..64].copy_from_slice(self.by.as_bytes());
        key[64..].copy_from_slice(&self.seq.to_be_bytes());
        key
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let id = |range: std::ops::Range<usize>| -> Result<NodeId> {
            let bytes: [u8; 32] = key
                .get(range)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(corrupt)?;
            Ok(NodeId::from_bytes(bytes))
        };
        let seq: [u8; 8] = key
            .get(64..72)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(corrupt)?;
        let (upto, hlc) = postcard::from_bytes(value)?;
        Ok(Self {
            node: id(0..32)?,
            by: id(32..64)?,
            seq: u64::from_be_bytes(seq),
            upto,
            hlc,
        })
    }
}

fn pack_chunk_key(pack: PackId, chunk: ChunkId) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(pack.as_bytes());
    key[32..].copy_from_slice(chunk.as_bytes());
    key
}

/// `[bucket length][bucket][key]`: a prefix scan on a bucket cannot leak into another.
fn object_key(bucket: &str, key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + bucket.len() + key.len());
    out.push(u8::try_from(bucket.len()).expect("S3 bucket names have at most 63 bytes"));
    out.extend_from_slice(bucket.as_bytes());
    out.extend_from_slice(key.as_bytes());
    out
}

/// The most table files that the index keeps open. The fjall default is 900 on Linux, more than
/// the 256 descriptors that windsockd keeps out of the S3 connection limit.
pub const MAX_OPEN_FILES: usize = 128;

/// Keys that a load removes in one batch. Small in tests, so a test index takes several.
const CLEAR_BATCH: usize = if cfg!(test) { 2 } else { 65_536 };

/// The state format of this build: versions ordered by their ack HLC.
const FORMAT: u32 = 2;
const FORMAT_KEY: &str = "format";

impl Index {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::builder(path)
            .max_cached_files(Some(MAX_OPEN_FILES))
            .open()?;
        Self::with_database(db, None)
    }

    /// An index in a temporary directory, removed on drop.
    pub fn open_temporary() -> Result<Self> {
        let dir = tempfile::tempdir().map_err(fjall::Error::from)?;
        let db = Database::builder(dir.path()).temporary(true).open()?;
        Self::with_database(db, Some(dir))
    }

    fn with_database(db: Database, temp: Option<tempfile::TempDir>) -> Result<Self> {
        let meta = db.keyspace("meta", KeyspaceCreateOptions::default)?;
        let frontiers = db.keyspace("frontiers", KeyspaceCreateOptions::default)?;
        let found = match meta.get(FORMAT_KEY)? {
            Some(value) => postcard::from_bytes(&value)?,
            // An index with state and no format key comes from format 1.
            None if !frontiers.is_empty()? => 1,
            None => {
                meta.insert(FORMAT_KEY, encode(&FORMAT))?;
                FORMAT
            }
        };
        if found != FORMAT {
            return Err(IndexError::Format {
                what: "local index",
                found,
                expected: FORMAT,
            });
        }

        Ok(Self {
            frontiers,
            entries: db.keyspace("entries", KeyspaceCreateOptions::default)?,
            objects: db.keyspace("objects", KeyspaceCreateOptions::default)?,
            buckets: db.keyspace("buckets", KeyspaceCreateOptions::default)?,
            chunks: db.keyspace("chunks", KeyspaceCreateOptions::default)?,
            pack_chunks: db.keyspace("pack_chunks", KeyspaceCreateOptions::default)?,
            manifests: db.keyspace("manifests", KeyspaceCreateOptions::default)?,
            condemned: db.keyspace("condemned", KeyspaceCreateOptions::default)?,
            redacted: db.keyspace("redacted", KeyspaceCreateOptions::default)?,
            retired: db.keyspace("retired", KeyspaceCreateOptions::default)?,
            db,
            pending: BTreeMap::new(),
            _temp: temp,
        })
    }

    /// Bytes that the store takes on disk.
    pub fn disk_bytes(&self) -> Result<u64> {
        Ok(self.db.disk_space()?)
    }

    /// True when a failed write made the store refuse every call until a restart.
    pub fn is_poisoned(&self) -> bool {
        matches!(
            self.db.persist(PersistMode::Buffer),
            Err(fjall::Error::Poisoned)
        )
    }

    /// Flushes every applied entry to disk.
    pub fn persist(&self) -> Result<()> {
        self.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    /// Frontier of applied entries, per node. Feed it to a new journal.
    pub fn frontiers(&self) -> Result<Frontiers> {
        let mut frontiers = Frontiers::new();

        for guard in self.frontiers.iter() {
            let (key, value) = guard.into_inner()?;
            let node = NodeId::from_bytes(
                key[..]
                    .try_into()
                    .map_err(|_| IndexError::Corrupt(postcard::Error::DeserializeBadEncoding))?,
            );
            frontiers.insert(node, postcard::from_bytes(&value)?);
        }

        Ok(frontiers)
    }

    pub fn frontier(&self, node: NodeId) -> Result<Frontier> {
        Ok(match self.frontiers.get(node.as_bytes())? {
            Some(value) => postcard::from_bytes(&value)?,
            None => Frontier::GENESIS,
        })
    }

    /// What this node has applied from the other chains: the `seen` of its next entry.
    pub fn seen(&self, own: NodeId) -> Result<Seen> {
        let mut seen = journal::seen_from(&self.frontiers()?, own);
        // A chain at its highest retired point is known through the Retire entry, which a later
        // entry reaches by its own links: leave it out, so the header stays small. A chain that
        // wrote past that point is listed again.
        let mut retired: BTreeMap<NodeId, u64> = BTreeMap::new();
        for mark in self.retire_marks()? {
            let upto = retired.entry(mark.node).or_default();
            *upto = (*upto).max(mark.upto);
        }
        seen.retain(|node, link| retired.get(node) != Some(&(link.seq + 1)));
        Ok(seen)
    }

    /// Applies every entry whose causal dependencies are applied, and keeps the
    /// others pending. Returns the number of entries applied.
    pub fn apply(&mut self, entries: Vec<Entry>) -> Result<usize> {
        for entry in entries {
            self.pending.entry((entry.node, entry.seq)).or_insert(entry);
        }
        let mut applied = 0;

        loop {
            let mut progress = false;
            let waiting: Vec<_> = self.pending.keys().copied().collect();

            for key in waiting {
                match self.readiness(&self.pending[&key])? {
                    Readiness::Wait => {}
                    Readiness::AlreadyApplied => {
                        self.pending.remove(&key);
                    }
                    Readiness::Ready => {
                        let entry = self.pending.remove(&key).expect("a key of the map");
                        self.apply_one(&entry)?;
                        applied += 1;
                        progress = true;
                    }
                }
            }

            if !progress {
                break;
            }
        }

        if !self.pending.is_empty() {
            debug!(
                pending = self.pending.len(),
                "entries wait for their dependencies"
            );
        }

        Ok(applied)
    }

    /// Entries read but not applied, because a dependency is missing.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    fn readiness(&self, entry: &Entry) -> Result<Readiness> {
        let own = self.frontier(entry.node)?;

        if own.next_seq > entry.seq {
            return Ok(Readiness::AlreadyApplied);
        }

        if own.next_seq < entry.seq {
            return Ok(Readiness::Wait);
        }

        if entry.actions.is_none() {
            return Err(IndexError::Redacted {
                node: entry.node,
                seq: entry.seq,
            });
        }

        for (node, link) in &entry.seen {
            let applied = self.frontier(*node)?;

            if applied.next_seq <= link.seq {
                return Ok(Readiness::Wait);
            }

            let matches = match self.entries.get(entry_key(*node, link.seq))? {
                Some(hash) => hash[..] == link.hash[..],
                // Below a loaded snapshot only the last hash of each chain is known.
                None if link.seq + 1 == applied.next_seq => applied.last_hash == link.hash,
                None => true,
            };

            if !matches {
                return Err(IndexError::LinkMismatch {
                    node: entry.node,
                    seq: entry.seq,
                });
            }
        }

        Ok(Readiness::Ready)
    }

    fn apply_one(&self, entry: &Entry) -> Result<()> {
        let mut batch = self.db.batch();

        for action in entry.actions.iter().flatten() {
            match action {
                Action::Put {
                    bucket,
                    key,
                    manifest_id,
                    hlc,
                    ..
                } => {
                    self.record_version(&mut batch, entry, *hlc, bucket, key, Some(*manifest_id))?
                }
                Action::Delete { bucket, key, hlc } => {
                    self.record_version(&mut batch, entry, *hlc, bucket, key, None)?
                }
                Action::CreateBucket { bucket, owner, hlc } => {
                    self.record_bucket(&mut batch, entry, *hlc, bucket, Some(owner.clone()))?
                }
                Action::DeleteBucket { bucket, hlc } => {
                    self.record_bucket(&mut batch, entry, *hlc, bucket, None)?
                }
                Action::Condemn { packs, manifests } => {
                    for pack in packs {
                        self.record_condemn(&mut batch, entry, PACK_TAG, pack.as_bytes())?;
                        self.forget_pack(&mut batch, *pack)?;
                    }
                    for manifest in manifests {
                        self.record_condemn(&mut batch, entry, MANIFEST_TAG, manifest.as_bytes())?;
                    }
                }
                Action::Retire { node, upto } => {
                    // A writer retires only entries that it applied, never its own chain.
                    let applied = entry.seen.get(node).map_or(0, |link| link.seq + 1);
                    if *node != entry.node && *upto > 0 && *upto <= applied {
                        let mark = RetireMark {
                            node: *node,
                            by: entry.node,
                            seq: entry.seq,
                            upto: *upto,
                            hlc: entry.hlc,
                        };
                        batch.insert(&self.retired, mark.key(), encode(&(mark.upto, mark.hlc)));
                    }
                }
            }
        }

        let hash: EntryHash = entry.hash();
        let frontier = Frontier {
            next_seq: entry.seq + 1,
            last_hash: hash,
            last_hlc: entry.hlc,
        };
        batch.insert(&self.entries, entry_key(entry.node, entry.seq), hash);
        batch.insert(&self.frontiers, entry.node.as_bytes(), encode(&frontier));
        batch.commit()?;

        debug!(node = %entry.node, seq = entry.seq, "applied entry");
        Ok(())
    }

    /// Every valid Retire action that the index applied.
    pub fn retire_marks(&self) -> Result<Vec<RetireMark>> {
        let mut marks = Vec::new();
        for guard in self.retired.iter() {
            let (key, value) = guard.into_inner()?;
            marks.push(RetireMark::decode(&key, &value)?);
        }
        Ok(marks)
    }

    /// The seen of `entry`, with a link for each chain that a Retire reached by its links covers.
    /// Its writer applied that Retire, so it knew the retired entries: the state stays the one of
    /// a full seen, whatever chain the writer left out.
    fn reached_seen(&self, entry: &Entry) -> Result<Seen> {
        let marks = self.retire_marks()?;
        let mut seen = entry.seen.clone();
        // A Retire entry can itself be in a retired chain: go on until no link changes.
        loop {
            let mut changed = false;
            for mark in &marks {
                let reached = (mark.by == entry.node && mark.seq < entry.seq)
                    || seen.get(&mark.by).is_some_and(|link| link.seq >= mark.seq);
                let known = seen.get(&mark.node).map_or(0, |link| link.seq + 1);
                if mark.node == entry.node || !reached || known >= mark.upto {
                    continue;
                }
                let link = journal::Link {
                    seq: mark.upto - 1,
                    hash: [0; 32],
                };
                seen.insert(mark.node, link);
                changed = true;
            }
            if !changed {
                return Ok(seen);
            }
        }
    }

    fn record_version(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        entry: &Entry,
        hlc: u64,
        bucket: &str,
        key: &str,
        manifest_id: Option<ObjectId>,
    ) -> Result<()> {
        let storage_key = object_key(bucket, key);
        let mut state = self.object(bucket, key)?.unwrap_or_default();

        let seen = self.reached_seen(entry)?;
        if state.record_seen(entry, hlc, manifest_id, seen) {
            batch.insert(&self.objects, storage_key, encode(&state));
        }

        Ok(())
    }

    fn record_condemn(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        entry: &Entry,
        tag: u8,
        id: &[u8; 32],
    ) -> Result<()> {
        let key = condemn_key(tag, id);

        if let Some(hlc) = self.condemned_at(key)?
            && hlc <= entry.hlc
        {
            return Ok(());
        }

        batch.insert(&self.condemned, key, entry.hlc.to_be_bytes());
        Ok(())
    }

    /// Removes the chunk locations in `pack`: a writer must not dedup against it again.
    fn forget_pack(&self, batch: &mut fjall::OwnedWriteBatch, pack: PackId) -> Result<()> {
        for guard in self.pack_chunks.prefix(pack.as_bytes()) {
            let (key, _) = guard.into_inner()?;
            let chunk = ChunkId::from_bytes(key[32..].try_into().map_err(|_| corrupt())?);

            if self
                .chunk(chunk)?
                .is_some_and(|location| location.pack == pack)
            {
                batch.remove(&self.chunks, chunk.as_bytes());
            }
            batch.remove(&self.pack_chunks, key);
        }

        Ok(())
    }

    fn condemned_at(&self, key: [u8; 33]) -> Result<Option<u64>> {
        let Some(value) = self.condemned.get(key)? else {
            return Ok(None);
        };

        let bytes: [u8; 8] = value[..].try_into().map_err(|_| corrupt())?;
        Ok(Some(u64::from_be_bytes(bytes)))
    }

    fn record_bucket(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        entry: &Entry,
        hlc: u64,
        bucket: &str,
        create: Option<Option<String>>,
    ) -> Result<()> {
        let current = self.bucket(bucket)?;

        if let Some(state) = BucketState::apply(current.as_ref(), entry, hlc, create) {
            batch.insert(&self.buckets, bucket.as_bytes(), encode(&state));
        }

        Ok(())
    }

    pub fn object(&self, bucket: &str, key: &str) -> Result<Option<ObjectState>> {
        Ok(match self.objects.get(object_key(bucket, key))? {
            Some(value) => Some(postcard::from_bytes(&value)?),
            None => None,
        })
    }

    /// The manifest a reader gets for `key`. `None` when deleted or absent.
    pub fn resolve(&self, bucket: &str, key: &str) -> Result<Option<ObjectId>> {
        Ok(self.object(bucket, key)?.and_then(|state| state.current()))
    }

    /// Every key of `bucket` under `prefix`, in key order, with its state.
    pub fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<(String, ObjectState)>> {
        let scan = object_key(bucket, prefix);
        let skip = 1 + bucket.len();
        let mut out = Vec::new();

        for guard in self.objects.prefix(scan) {
            let (key, value) = guard.into_inner()?;
            let name = String::from_utf8_lossy(&key[skip..]).into_owned();
            out.push((name, postcard::from_bytes(&value)?));
        }

        Ok(out)
    }

    /// The first object of `bucket` under `prefix` whose key is `from` or after it.
    pub fn first_from(
        &self,
        bucket: &str,
        prefix: &str,
        from: &str,
    ) -> Result<Option<(String, ObjectState)>> {
        let scan = object_key(bucket, prefix);
        let start = object_key(bucket, from).max(scan.clone());
        let skip = 1 + bucket.len();

        let Some(guard) = self.objects.range(start..).next() else {
            return Ok(None);
        };
        let (key, value) = guard.into_inner()?;
        if !key.starts_with(&scan) {
            return Ok(None);
        }

        let name = String::from_utf8_lossy(&key[skip..]).into_owned();
        Ok(Some((name, postcard::from_bytes(&value)?)))
    }

    pub fn bucket(&self, name: &str) -> Result<Option<BucketState>> {
        Ok(match self.buckets.get(name.as_bytes())? {
            Some(value) => Some(postcard::from_bytes(&value)?),
            None => None,
        })
    }

    /// Every bucket that exists, in name order.
    pub fn buckets(&self) -> Result<Vec<(String, BucketState)>> {
        let mut out = Vec::new();

        for guard in self.buckets.iter() {
            let (name, value) = guard.into_inner()?;
            let state: BucketState = postcard::from_bytes(&value)?;

            if state.exists {
                out.push((String::from_utf8_lossy(&name).into_owned(), state));
            }
        }

        Ok(out)
    }

    /// Records where a chunk lives. A location in a condemned pack is ignored.
    pub fn put_chunk(&self, id: ChunkId, location: &ChunkLocation) -> Result<()> {
        if self.condemned_pack(location.pack)?.is_some() {
            return Ok(());
        }

        let mut batch = self.db.batch();
        batch.insert(&self.chunks, id.as_bytes(), encode(location));
        batch.insert(&self.pack_chunks, pack_chunk_key(location.pack, id), []);
        batch.commit()?;
        Ok(())
    }

    pub fn chunk(&self, id: ChunkId) -> Result<Option<ChunkLocation>> {
        self.chunk_locations().get(id)
    }

    /// A handle on the chunk locations that a blocking task can own.
    pub fn chunk_locations(&self) -> ChunkLocations {
        ChunkLocations(self.chunks.clone())
    }

    /// Stores the bytes of a manifest. The caller checks them against `id`.
    pub fn put_manifest(&self, id: ObjectId, bytes: &[u8]) -> Result<()> {
        self.manifests.insert(id.as_bytes(), bytes)?;
        Ok(())
    }

    pub fn manifest(&self, id: ObjectId) -> Result<Option<Vec<u8>>> {
        Ok(self
            .manifests
            .get(id.as_bytes())?
            .map(|value| value.to_vec()))
    }

    /// First seq of `node` that the journal prune has not checked yet.
    pub fn redacted_below(&self, node: NodeId) -> Result<u64> {
        let Some(value) = self.redacted.get(node.as_bytes())? else {
            return Ok(0);
        };

        let bytes: [u8; 8] = value[..].try_into().map_err(|_| corrupt())?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn set_redacted_below(&self, node: NodeId, seq: u64) -> Result<()> {
        self.redacted.insert(node.as_bytes(), seq.to_be_bytes())?;
        Ok(())
    }

    /// The applied state. Pending entries are left out: a reader reads them again.
    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut objects = Vec::new();
        let mut manifests = BTreeMap::new();

        for guard in self.objects.iter() {
            let (key, value) = guard.into_inner()?;
            let state: ObjectState = postcard::from_bytes(&value)?;

            for id in state.versions.iter().filter_map(|v| v.manifest_id) {
                if let Some(bytes) = self.manifest(id)? {
                    manifests.insert(id, bytes);
                }
            }
            objects.push((key.to_vec(), state));
        }

        let mut buckets = Vec::new();
        for guard in self.buckets.iter() {
            let (name, value) = guard.into_inner()?;
            buckets.push((
                String::from_utf8_lossy(&name).into_owned(),
                postcard::from_bytes(&value)?,
            ));
        }

        let mut condemned = Vec::new();
        for guard in self.condemned.iter() {
            let (key, value) = guard.into_inner()?;
            let hlc: [u8; 8] = value[..].try_into().map_err(|_| corrupt())?;
            condemned.push((key.to_vec(), u64::from_be_bytes(hlc)));
        }

        Ok(Snapshot {
            frontiers: self.frontiers()?,
            objects,
            buckets,
            condemned,
            manifests: manifests.into_iter().collect(),
            retired: self.retire_marks()?,
        })
    }

    /// Replaces the applied state with `snapshot`. Chunk locations are cleared:
    /// the caller rebuilds them from the manifests.
    pub fn load(&mut self, snapshot: &Snapshot) -> Result<()> {
        // Frontiers first: open loads a snapshot into an index with none. Batches bound the memory.
        for keyspace in [
            &self.frontiers,
            &self.entries,
            &self.objects,
            &self.buckets,
            &self.chunks,
            &self.pack_chunks,
            &self.condemned,
            &self.retired,
        ] {
            let mut clear = self.db.batch();
            let mut keys = 0;
            for guard in keyspace.iter() {
                let (key, _) = guard.into_inner()?;
                clear.remove(keyspace, key);
                keys += 1;
                if keys == CLEAR_BATCH {
                    std::mem::replace(&mut clear, self.db.batch()).commit()?;
                    keys = 0;
                }
            }
            clear.commit()?;
        }

        let mut fill = self.db.batch();
        for (node, frontier) in &snapshot.frontiers {
            fill.insert(&self.frontiers, node.as_bytes(), encode(frontier));
        }
        for (key, state) in &snapshot.objects {
            fill.insert(&self.objects, key.as_slice(), encode(state));
        }
        for (name, state) in &snapshot.buckets {
            fill.insert(&self.buckets, name.as_bytes(), encode(state));
        }
        for (key, hlc) in &snapshot.condemned {
            fill.insert(&self.condemned, key.as_slice(), hlc.to_be_bytes());
        }
        for (id, bytes) in &snapshot.manifests {
            fill.insert(&self.manifests, id.as_bytes(), bytes.as_slice());
        }
        for mark in &snapshot.retired {
            fill.insert(&self.retired, mark.key(), encode(&(mark.upto, mark.hlc)));
        }
        fill.commit()?;

        self.pending.clear();
        Ok(())
    }

    /// HLC of the first condemn of a pack.
    pub fn condemned_pack(&self, id: PackId) -> Result<Option<u64>> {
        self.condemned_at(condemn_key(PACK_TAG, id.as_bytes()))
    }

    /// HLC of the first condemn of a manifest.
    pub fn condemned_manifest(&self, id: ObjectId) -> Result<Option<u64>> {
        self.condemned_at(condemn_key(MANIFEST_TAG, id.as_bytes()))
    }

    /// Manifests that must stay in the remote: see [`ObjectState::live_manifests`].
    /// Pending entries count too: they apply later.
    pub fn live_manifests(&self, recent: u64) -> Result<BTreeSet<ObjectId>> {
        let mut live = BTreeSet::new();

        for guard in self.objects.iter() {
            let (_, value) = guard.into_inner()?;
            let state: ObjectState = postcard::from_bytes(&value)?;
            live.extend(state.live_manifests(recent));
        }

        for action in self
            .pending
            .values()
            .flat_map(|e| e.actions.iter().flatten())
        {
            if let Action::Put { manifest_id, .. } = action {
                live.insert(*manifest_id);
            }
        }

        Ok(live)
    }

    /// The lowest last HLC over the applied chains, and the lowest entry or ack HLC of a pending
    /// entry. A future entry can still carry an ack under it: a buffered write of a proxy with no
    /// chain yet, or a write late by up to `retention - late_margin`. The late write rule of the
    /// engine covers that gap.
    ///
    /// A chain retired at its frontier does not count once its Retire entry is at least `quiet`
    /// above its last HLC, and another entry, of another chain or later in the chain of the Retire,
    /// is at or above the Retire entry: the reader checks the quiet time and trusts no writer.
    pub fn stable_hlc(&self, quiet: u64) -> Result<u64> {
        Ok(self.stable(quiet)?.0)
    }

    /// [`Index::stable_hlc`], and the count of retired chains that it leaves out.
    pub fn stable(&self, quiet: u64) -> Result<(u64, usize)> {
        let frontiers = self.frontiers()?;
        let marks = self.retire_marks()?;
        let skipped = |node: &NodeId, frontier: &Frontier| {
            marks.iter().any(|mark| {
                mark.node == *node
                    && mark.upto == frontier.next_seq
                    && mark.hlc >= frontier.last_hlc.saturating_add(quiet)
                    && frontiers.iter().any(|(other, f)| {
                        other != node
                            && f.last_hlc >= mark.hlc
                            && (*other != mark.by || f.next_seq > mark.seq + 1)
                    })
            })
        };
        let left_out = frontiers.iter().filter(|(n, f)| skipped(n, f)).count();
        let applied = frontiers
            .iter()
            .filter(|(node, frontier)| !skipped(node, frontier))
            .map(|(_, f)| f.last_hlc);
        // A waiting entry can carry acks far under its own HLC.
        let pending = self.pending.values().map(|e| {
            let acks = e.actions.iter().flatten().filter_map(Action::hlc);
            acks.min().unwrap_or(e.hlc).min(e.hlc)
        });

        Ok((applied.chain(pending).min().unwrap_or(0), left_out))
    }

    /// Prunes every key with [`ObjectState::prune`]. Returns the number of keys changed or removed.
    pub fn prune_versions(&self, below: u64) -> Result<usize> {
        let mut batch = self.db.batch();
        let mut changed = 0;

        for guard in self.objects.iter() {
            let (key, value) = guard.into_inner()?;
            let mut state: ObjectState = postcard::from_bytes(&value)?;

            match state.prune(below) {
                Pruned::Unchanged => continue,
                Pruned::Changed => batch.insert(&self.objects, key, encode(&state)),
                Pruned::Gone => batch.remove(&self.objects, key),
            }
            changed += 1;
        }

        batch.commit()?;
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    pub(crate) fn test_sealer() -> seal::Sealer {
        seal::RepoKey::from_hex(&"07".repeat(32))
            .unwrap()
            .keys()
            .sealer()
            .clone()
    }
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use journal::{Journal, Link};
    use remote::MemoryRemote;

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn journal(remote: &Arc<MemoryRemote>, seed: u8) -> Journal<MemoryRemote> {
        Journal::new(remote.clone(), key(seed), test_sealer(), Frontiers::new())
    }

    fn manifest(n: u8) -> ObjectId {
        ObjectId::from_bytes([n; 32])
    }

    /// A rising ack HLC, one second behind the wall clock: under the HLC of the entry.
    fn ack() -> u64 {
        static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
            - 1_000_000_000;
        let next = wall.max(LAST.load(std::sync::atomic::Ordering::SeqCst) + 1);
        LAST.store(next, std::sync::atomic::Ordering::SeqCst);
        next
    }

    fn put(key: &str, n: u8) -> Vec<Action> {
        vec![Action::Put {
            bucket: "b".into(),
            key: key.into(),
            manifest_id: manifest(n),
            inline_manifest: None,
            hlc: ack(),
        }]
    }

    fn put_at(key: &str, n: u8, hlc: u64) -> Action {
        Action::Put {
            bucket: "b".into(),
            key: key.into(),
            manifest_id: manifest(n),
            inline_manifest: None,
            hlc,
        }
    }

    fn create_bucket(name: &str) -> Vec<Action> {
        vec![Action::CreateBucket {
            bucket: name.into(),
            owner: None,
            hlc: ack(),
        }]
    }

    /// Everything a reader can observe.
    type View = (Vec<(String, ObjectState)>, Vec<(String, BucketState)>);

    fn snapshot_view(index: &Index) -> View {
        (index.list("b", "").unwrap(), index.buckets().unwrap())
    }

    #[tokio::test]
    async fn test_applies_puts_and_resolves_the_latest() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut index = Index::open_temporary().unwrap();
        a.append(put("k", 1), Seen::new()).await.unwrap();
        a.append(put("k", 2), Seen::new()).await.unwrap();

        let mut reader = journal(&remote, 9);
        let applied = index.apply(reader.sync_all().await.unwrap()).unwrap();

        assert_eq!(applied, 2);
        assert_eq!(index.resolve("b", "k").unwrap(), Some(manifest(2)));
        assert_eq!(index.object("b", "k").unwrap().unwrap().versions.len(), 2);
        assert_eq!(index.frontier(a.node()).unwrap().next_seq, 2);
    }

    #[tokio::test]
    async fn test_entry_waits_for_what_its_writer_saw() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        let mut index = Index::open_temporary().unwrap();

        // b puts into a bucket it saw a create: a reader must never see the put alone.
        a.append(create_bucket("b"), Seen::new()).await.unwrap();
        b.sync_all().await.unwrap();
        let seen = journal::seen_from(b.frontiers(), b.node());
        b.append(put("k", 1), seen).await.unwrap();

        let mut reader = journal(&remote, 9);
        let from_b = reader.sync_node(b.node()).await.unwrap();
        assert_eq!(index.apply(from_b).unwrap(), 0);
        assert_eq!(index.pending(), 1);
        assert_eq!(index.resolve("b", "k").unwrap(), None);

        let from_a = reader.sync_node(a.node()).await.unwrap();
        assert_eq!(index.apply(from_a).unwrap(), 2);
        assert_eq!(index.pending(), 0);
        assert_eq!(index.resolve("b", "k").unwrap(), Some(manifest(1)));
        assert!(index.bucket("b").unwrap().unwrap().exists);
    }

    #[tokio::test]
    async fn test_entry_read_again_while_it_waits_is_kept_once() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        let mut index = Index::open_temporary().unwrap();
        a.append(create_bucket("b"), Seen::new()).await.unwrap();
        b.sync_all().await.unwrap();
        let seen = journal::seen_from(b.frontiers(), b.node());
        b.append(put("k", 1), seen).await.unwrap();

        let from_b = journal(&remote, 9).sync_node(b.node()).await.unwrap();
        for _ in 0..3 {
            index.apply(from_b.clone()).unwrap();
        }

        assert_eq!(index.pending(), 1);
    }

    #[tokio::test]
    async fn test_rebuild_from_the_journal_equals_incremental_state() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        let mut incremental = Index::open_temporary().unwrap();
        let mut reader = journal(&remote, 9);

        a.append(create_bucket("b"), Seen::new()).await.unwrap();
        a.append(put("x", 1), Seen::new()).await.unwrap();
        incremental.apply(reader.sync_all().await.unwrap()).unwrap();

        b.sync_all().await.unwrap();
        let seen = journal::seen_from(b.frontiers(), b.node());
        b.append(put("x", 2), seen.clone()).await.unwrap();
        b.append(put("y", 3), seen).await.unwrap();
        a.append(put("y", 4), Seen::new()).await.unwrap();
        incremental.apply(reader.sync_all().await.unwrap()).unwrap();

        let mut rebuilt = Index::open_temporary().unwrap();
        let mut fresh = journal(&remote, 8);
        rebuilt.apply(fresh.sync_all().await.unwrap()).unwrap();

        assert_eq!(snapshot_view(&rebuilt), snapshot_view(&incremental));
        assert_eq!(
            rebuilt.frontiers().unwrap(),
            incremental.frontiers().unwrap()
        );
        assert_eq!(incremental.resolve("b", "x").unwrap(), Some(manifest(2)));
        assert!(
            !incremental
                .object("b", "x")
                .unwrap()
                .unwrap()
                .is_conflicted()
        );
        assert!(
            incremental
                .object("b", "y")
                .unwrap()
                .unwrap()
                .is_conflicted()
        );
    }

    #[tokio::test]
    async fn test_concurrent_creates_of_one_key_are_surfaced() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        let mut index = Index::open_temporary().unwrap();
        a.append(put("k", 1), Seen::new()).await.unwrap();
        b.append(put("k", 2), Seen::new()).await.unwrap();

        let mut reader = journal(&remote, 9);
        index.apply(reader.sync_all().await.unwrap()).unwrap();
        let state = index.object("b", "k").unwrap().unwrap();

        assert!(state.is_conflicted());
        assert_eq!(state.versions.len(), 2);
        assert!(
            state.current().is_some(),
            "a reader still gets the LWW winner"
        );
    }

    #[tokio::test]
    async fn test_frontiers_survive_a_reopen() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let dir = tempfile::tempdir().unwrap();
        a.append(put("k", 1), Seen::new()).await.unwrap();

        {
            let mut index = Index::open(dir.path()).unwrap();
            let mut reader = journal(&remote, 9);
            index.apply(reader.sync_all().await.unwrap()).unwrap();
            index.persist().unwrap();
        }

        a.append(put("k", 2), Seen::new()).await.unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        let mut reader = Journal::new(
            remote.clone(),
            key(9),
            test_sealer(),
            index.frontiers().unwrap(),
        );
        let entries = reader.sync_all().await.unwrap();

        assert_eq!(entries.len(), 1, "only the new entry is read");
        assert_eq!(index.apply(entries).unwrap(), 1);
        assert_eq!(index.resolve("b", "k").unwrap(), Some(manifest(2)));
    }

    #[tokio::test]
    async fn test_replayed_entries_are_ignored() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut index = Index::open_temporary().unwrap();
        a.append(put("k", 1), Seen::new()).await.unwrap();

        let mut reader = journal(&remote, 9);
        let entries = reader.sync_all().await.unwrap();
        index.apply(entries.clone()).unwrap();
        let before = snapshot_view(&index);

        assert_eq!(index.apply(entries).unwrap(), 0);
        assert_eq!(snapshot_view(&index), before);
    }

    #[tokio::test]
    async fn test_link_to_a_forged_entry_is_rejected() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut index = Index::open_temporary().unwrap();
        a.append(put("k", 1), Seen::new()).await.unwrap();
        let mut reader = journal(&remote, 9);
        index.apply(reader.sync_all().await.unwrap()).unwrap();

        let forged_link = Seen::from([(
            a.node(),
            journal::Link {
                seq: 0,
                hash: [9u8; 32],
            },
        )]);
        let entry = Entry::sign(
            &key(2),
            0,
            [0u8; 32],
            99,
            forged_link,
            put("k", 2),
            &test_sealer(),
        );

        assert!(matches!(
            index.apply(vec![entry]),
            Err(IndexError::LinkMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn test_delete_hides_the_key_and_keeps_its_history() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut index = Index::open_temporary().unwrap();
        a.append(put("k", 1), Seen::new()).await.unwrap();
        a.append(
            vec![Action::Delete {
                bucket: "b".into(),
                key: "k".into(),
                hlc: ack(),
            }],
            Seen::new(),
        )
        .await
        .unwrap();

        let mut reader = journal(&remote, 9);
        index.apply(reader.sync_all().await.unwrap()).unwrap();

        assert_eq!(index.resolve("b", "k").unwrap(), None);
        assert_eq!(index.object("b", "k").unwrap().unwrap().versions.len(), 2);
        assert_eq!(index.list("b", "").unwrap().len(), 1);
    }

    #[test]
    fn test_list_stays_inside_the_bucket() {
        let index = Index::open_temporary().unwrap();
        let entry = Entry::sign(
            &key(1),
            0,
            [0u8; 32],
            1,
            Seen::new(),
            vec![
                Action::Put {
                    bucket: "b".into(),
                    key: "a/1".into(),
                    manifest_id: manifest(1),
                    inline_manifest: None,
                    hlc: 1,
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "a/2".into(),
                    manifest_id: manifest(2),
                    inline_manifest: None,
                    hlc: 1,
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "c".into(),
                    manifest_id: manifest(3),
                    inline_manifest: None,
                    hlc: 1,
                },
                Action::Put {
                    bucket: "ba".into(),
                    key: "a/3".into(),
                    manifest_id: manifest(4),
                    inline_manifest: None,
                    hlc: 1,
                },
            ],
            &test_sealer(),
        );
        let mut index = index;
        index.apply(vec![entry]).unwrap();

        let keys: Vec<_> = index
            .list("b", "a/")
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();

        assert_eq!(keys, ["a/1", "a/2"]);
        assert_eq!(index.list("b", "").unwrap().len(), 3);
        assert_eq!(index.list("ba", "").unwrap().len(), 1);
    }

    #[test]
    fn test_last_action_on_a_name_in_one_entry_wins() {
        let mut index = Index::open_temporary().unwrap();
        let entry = Entry::sign(
            &key(1),
            0,
            [0u8; 32],
            10,
            Seen::new(),
            vec![
                Action::CreateBucket {
                    bucket: "b".into(),
                    owner: None,
                    hlc: 1,
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "k".into(),
                    manifest_id: manifest(1),
                    inline_manifest: None,
                    hlc: 2,
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "k".into(),
                    manifest_id: manifest(2),
                    inline_manifest: None,
                    hlc: 3,
                },
                Action::DeleteBucket {
                    bucket: "b".into(),
                    hlc: 4,
                },
            ],
            &test_sealer(),
        );

        index.apply(vec![entry]).unwrap();

        assert_eq!(index.resolve("b", "k").unwrap(), Some(manifest(2)));
        assert!(!index.bucket("b").unwrap().unwrap().exists);
    }

    #[test]
    fn test_manifest_roundtrip() {
        let index = Index::open_temporary().unwrap();

        index.put_manifest(manifest(1), b"bytes").unwrap();

        assert_eq!(index.manifest(manifest(1)).unwrap().unwrap(), b"bytes");
        assert_eq!(index.manifest(manifest(2)).unwrap(), None);
    }

    fn location(pack: u8, chunk: ChunkId) -> ChunkLocation {
        ChunkLocation {
            pack: PackId::from_bytes([pack; 32]),
            entry: PackEntry {
                chunk_id: chunk,
                offset: 5,
                stored_len: 10,
                raw_len: 10,
                compression: chunking::Compression::None,
            },
            seen_at: 0,
        }
    }

    fn condemn(seed: u8, hlc: u64, pack: u8) -> Entry {
        let action = Action::Condemn {
            packs: vec![PackId::from_bytes([pack; 32])],
            manifests: vec![manifest(pack)],
        };
        Entry::sign(
            &key(seed),
            0,
            [0u8; 32],
            hlc,
            Seen::new(),
            vec![action],
            &test_sealer(),
        )
    }

    #[test]
    fn test_condemn_forgets_the_chunks_of_the_pack_for_good() {
        let mut index = Index::open_temporary().unwrap();
        let in_condemned = ChunkId::from_bytes([1u8; 32]);
        let elsewhere = ChunkId::from_bytes([2u8; 32]);
        index
            .put_chunk(in_condemned, &location(7, in_condemned))
            .unwrap();
        index.put_chunk(elsewhere, &location(8, elsewhere)).unwrap();

        index.apply(vec![condemn(1, 5, 7)]).unwrap();
        index
            .put_chunk(in_condemned, &location(7, in_condemned))
            .unwrap();

        assert_eq!(index.chunk(in_condemned).unwrap(), None);
        assert!(index.chunk(elsewhere).unwrap().is_some());
        assert_eq!(
            index.condemned_pack(PackId::from_bytes([7u8; 32])).unwrap(),
            Some(5)
        );
        assert_eq!(index.condemned_manifest(manifest(7)).unwrap(), Some(5));
        assert_eq!(
            index.condemned_pack(PackId::from_bytes([8u8; 32])).unwrap(),
            None
        );
    }

    #[test]
    fn test_first_condemn_wins_in_any_order() {
        for order in [[0, 1], [1, 0]] {
            let entries = [condemn(1, 5, 7), condemn(2, 9, 7)];
            let mut index = Index::open_temporary().unwrap();

            for i in order {
                index.apply(vec![entries[i].clone()]).unwrap();
            }

            assert_eq!(
                index.condemned_pack(PackId::from_bytes([7u8; 32])).unwrap(),
                Some(5)
            );
        }
    }

    #[test]
    fn test_live_manifests_include_pending_entries() {
        let mut index = Index::open_temporary().unwrap();
        let waits = Seen::from([(
            NodeId::from_bytes([9u8; 32]),
            journal::Link {
                seq: 0,
                hash: [0u8; 32],
            },
        )]);
        let pending = Entry::sign(&key(1), 0, [0u8; 32], 7, waits, put("k", 3), &test_sealer());
        let applied = Entry::sign(
            &key(2),
            0,
            [0u8; 32],
            20,
            Seen::new(),
            put("j", 4),
            &test_sealer(),
        );

        index.apply(vec![pending, applied]).unwrap();

        assert_eq!(index.pending(), 1);
        assert_eq!(
            index.live_manifests(0).unwrap(),
            BTreeSet::from([manifest(3), manifest(4)])
        );
        assert_eq!(
            index.stable_hlc(u64::MAX).unwrap(),
            7,
            "a pending entry lowers the stable HLC"
        );
    }

    #[test]
    fn test_stable_hlc_is_the_slowest_chain() {
        let mut index = Index::open_temporary().unwrap();
        let slow = Entry::sign(
            &key(1),
            0,
            [0u8; 32],
            10,
            Seen::new(),
            put("a", 1),
            &test_sealer(),
        );
        let fast = Entry::sign(
            &key(2),
            0,
            [0u8; 32],
            30,
            Seen::new(),
            put("b", 2),
            &test_sealer(),
        );

        assert_eq!(index.stable_hlc(u64::MAX).unwrap(), 0);
        index.apply(vec![slow, fast]).unwrap();

        assert_eq!(index.stable_hlc(u64::MAX).unwrap(), 10);
    }

    #[test]
    fn test_prune_versions_removes_keys_deleted_long_ago() {
        let mut index = Index::open_temporary().unwrap();
        let actions = vec![
            put_at("gone", 1, 7),
            put_at("kept", 2, 8),
            Action::Delete {
                bucket: "b".into(),
                key: "gone".into(),
                hlc: 9,
            },
        ];
        let first = Entry::sign(
            &key(1),
            0,
            [0u8; 32],
            10,
            Seen::new(),
            actions,
            &test_sealer(),
        );
        let rewrite = Entry::sign(
            &key(1),
            1,
            first.hash(),
            20,
            Seen::new(),
            vec![put_at("kept", 5, 19)],
            &test_sealer(),
        );
        index.apply(vec![first, rewrite]).unwrap();

        assert_eq!(index.prune_versions(15).unwrap(), 2);

        assert_eq!(index.object("b", "gone").unwrap(), None);
        assert_eq!(
            index.object("b", "kept").unwrap().unwrap().versions.len(),
            1
        );
        assert_eq!(index.resolve("b", "kept").unwrap(), Some(manifest(5)));
        assert_eq!(index.prune_versions(15).unwrap(), 0);
    }

    #[test]
    fn test_index_of_another_format_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = Database::builder(dir.path()).open().unwrap();
            let frontiers = db
                .keyspace("frontiers", KeyspaceCreateOptions::default)
                .unwrap();
            frontiers
                .insert([1u8; 32], encode(&Frontier::GENESIS))
                .unwrap();
        }

        let result = Index::open(dir.path());

        assert!(
            matches!(
                result,
                Err(IndexError::Format {
                    found: 1,
                    expected: 2,
                    ..
                })
            ),
            "{:?}",
            result.err()
        );
    }

    #[test]
    fn test_snapshot_of_another_format_is_refused() {
        let mut bytes = Snapshot {
            frontiers: Frontiers::new(),
            objects: Vec::new(),
            buckets: Vec::new(),
            condemned: Vec::new(),
            manifests: Vec::new(),
            retired: Vec::new(),
        }
        .encode();
        bytes[0] = 1;

        let result = Snapshot::decode(blake3::hash(&bytes).as_bytes(), &bytes);

        let error = result.unwrap_err().to_string();
        assert!(error.contains("snapshot has format 1"), "{error}");
        assert!(error.contains("reads format 3"), "{error}");
    }

    /// A redacted entry has no actions: applying it as empty would lose them silently.
    #[tokio::test]
    async fn test_redacted_entry_is_refused() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let entry = a.append(put("k", 1), Seen::new()).await.unwrap();
        let mut index = Index::open_temporary().unwrap();

        let result = index.apply(vec![entry.redacted()]);

        assert!(matches!(result, Err(IndexError::Redacted { seq: 0, .. })));
        assert_eq!(index.frontier(a.node()).unwrap(), Frontier::GENESIS);
    }

    /// An index with a bucket, two writes, a delete and a condemn from node 1,
    /// and the entries it applied.
    async fn busy_index(remote: &Arc<MemoryRemote>) -> (Index, Vec<Entry>) {
        let mut a = journal(remote, 1);
        let mut entries = vec![
            a.append(create_bucket("b"), Seen::new()).await.unwrap(),
            a.append(put("x", 1), Seen::new()).await.unwrap(),
            a.append(put("y", 2), Seen::new()).await.unwrap(),
        ];
        let delete = vec![Action::Delete {
            bucket: "b".into(),
            key: "x".into(),
            hlc: ack(),
        }];
        entries.push(a.append(delete, Seen::new()).await.unwrap());
        let condemn = vec![Action::Condemn {
            packs: vec![PackId::from_bytes([7u8; 32])],
            manifests: vec![],
        }];
        entries.push(a.append(condemn, Seen::new()).await.unwrap());

        let mut index = Index::open_temporary().unwrap();
        index.put_manifest(manifest(2), b"inline").unwrap();
        index.apply(entries.clone()).unwrap();
        (index, entries)
    }

    #[test]
    fn test_snapshot_format_is_stable() {
        let snapshot = Snapshot {
            frontiers: Frontiers::from([(
                NodeId::from_bytes([1u8; 32]),
                Frontier {
                    next_seq: 3,
                    last_hash: [2u8; 32],
                    last_hlc: 4,
                },
            )]),
            objects: vec![(b"key".to_vec(), ObjectState::default())],
            buckets: vec![],
            condemned: vec![(vec![b'p'; 33], 5)],
            manifests: vec![(manifest(6), b"m".to_vec())],
            retired: vec![RetireMark {
                node: NodeId::from_bytes([7u8; 32]),
                by: NodeId::from_bytes([8u8; 32]),
                seq: 9,
                upto: 10,
                hlc: 11,
            }],
        };

        assert_eq!(
            blake3::hash(&snapshot.encode()).to_string(),
            "c7b3b5387e9032b92d264418c6ab3e86232520255890783a40e43fe0f95728dc"
        );
    }

    #[tokio::test]
    async fn test_loaded_snapshot_gives_the_same_state() {
        let remote = Arc::new(MemoryRemote::default());
        let (source, _) = busy_index(&remote).await;
        let snapshot = source.snapshot().unwrap();
        let bytes = snapshot.encode();
        let decoded = Snapshot::decode(blake3::hash(&bytes).as_bytes(), &bytes).unwrap();

        let mut target = Index::open_temporary().unwrap();
        let stray = Entry::sign(
            &key(5),
            3,
            [0u8; 32],
            1,
            Seen::new(),
            put("z", 9),
            &test_sealer(),
        );
        target.apply(vec![stray]).unwrap();
        target.load(&decoded).unwrap();

        assert_eq!(target.snapshot().unwrap(), snapshot);
        assert_eq!(snapshot_view(&target), snapshot_view(&source));
        assert_eq!(target.pending(), 0);
        assert_eq!(target.manifest(manifest(2)).unwrap().unwrap(), b"inline");
        assert!(
            target
                .condemned_pack(PackId::from_bytes([7u8; 32]))
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_load_over_a_full_index_keeps_only_the_snapshot() {
        let remote = Arc::new(MemoryRemote::default());
        let (source, _) = busy_index(&remote).await;
        let snapshot = source.snapshot().unwrap();
        let (mut target, _) = busy_index(&Arc::new(MemoryRemote::default())).await;
        let empty = Index::open_temporary().unwrap().snapshot().unwrap();

        target.load(&empty).unwrap();
        let cleared = target.snapshot().unwrap();
        target.load(&snapshot).unwrap();

        assert_eq!(cleared, empty);
        assert_eq!(target.snapshot().unwrap(), snapshot);
    }

    #[test]
    fn test_snapshot_decode_rejects_a_wrong_hash() {
        let bytes = Index::open_temporary()
            .unwrap()
            .snapshot()
            .unwrap()
            .encode();

        assert!(Snapshot::decode(&[0u8; 32], &bytes).is_err());
    }

    /// After a load, the index has no hash for the entries under the frontier.
    /// A link to one of them must not wait forever.
    #[tokio::test]
    async fn test_link_below_a_loaded_snapshot_does_not_block() {
        let remote = Arc::new(MemoryRemote::default());
        let (source, entries) = busy_index(&remote).await;
        let mut target = Index::open_temporary().unwrap();
        target.load(&source.snapshot().unwrap()).unwrap();
        let links = |seq: usize| {
            Seen::from([(
                entries[seq].node,
                journal::Link {
                    seq: seq as u64,
                    hash: entries[seq].hash(),
                },
            )])
        };
        let old_link = Entry::sign(
            &key(2),
            0,
            [0u8; 32],
            99,
            links(1),
            put("k", 3),
            &test_sealer(),
        );
        let last_link = Entry::sign(
            &key(3),
            0,
            [0u8; 32],
            99,
            links(4),
            put("j", 4),
            &test_sealer(),
        );

        assert_eq!(target.apply(vec![old_link, last_link]).unwrap(), 2);
        assert_eq!(target.resolve("b", "k").unwrap(), Some(manifest(3)));
    }

    #[tokio::test]
    async fn test_link_to_the_last_entry_of_a_loaded_snapshot_is_checked() {
        let remote = Arc::new(MemoryRemote::default());
        let (source, entries) = busy_index(&remote).await;
        let mut target = Index::open_temporary().unwrap();
        target.load(&source.snapshot().unwrap()).unwrap();
        let forged = Seen::from([(
            entries[4].node,
            journal::Link {
                seq: 4,
                hash: [9u8; 32],
            },
        )]);
        let entry = Entry::sign(
            &key(2),
            0,
            [0u8; 32],
            99,
            forged,
            put("k", 3),
            &test_sealer(),
        );

        assert!(matches!(
            target.apply(vec![entry]),
            Err(IndexError::LinkMismatch { .. })
        ));
    }

    #[test]
    fn test_chunk_location_roundtrip() {
        let index = Index::open_temporary().unwrap();
        let id = ChunkId::from_bytes([1u8; 32]);
        let location = ChunkLocation {
            pack: PackId::from_bytes([2u8; 32]),
            entry: PackEntry {
                chunk_id: id,
                offset: 5,
                stored_len: 10,
                raw_len: 20,
                compression: chunking::Compression::None,
            },
            seen_at: 42,
        };

        index.put_chunk(id, &location).unwrap();

        assert_eq!(index.chunk(id).unwrap(), Some(location));
        assert_eq!(index.chunk(ChunkId::from_bytes([3u8; 32])).unwrap(), None);
    }

    /// A put of k by node 1, a Retire of it by node 3 that applied it, and a later put of k by
    /// node 2 that links node 3 only: the entries in write order.
    async fn retired_history(upto: u64) -> Vec<Entry> {
        retired_history_with(upto, true).await
    }

    /// [`retired_history`], where the second put links the Retire entry only with `link`.
    async fn retired_history_with(upto: u64, link_retire: bool) -> Vec<Entry> {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut gc = journal(&remote, 3);
        let mut b = journal(&remote, 2);
        let first = a.append(put("k", 1), Seen::new()).await.unwrap();
        let link = |e: &Entry| Link {
            seq: e.seq,
            hash: e.hash(),
        };
        let retire = vec![Action::Retire {
            node: first.node,
            upto,
        }];
        let seen = Seen::from([(first.node, link(&first))]);
        let retired = gc.append(retire, seen).await.unwrap();
        let seen = match link_retire {
            true => Seen::from([(retired.node, link(&retired))]),
            false => Seen::new(),
        };
        let second = b.append(put("k", 2), seen).await.unwrap();
        vec![first, retired, second]
    }

    fn conflicted(index: &Index) -> bool {
        index.object("b", "k").unwrap().unwrap().is_conflicted()
    }

    #[tokio::test]
    async fn test_writer_that_reached_a_retire_knew_the_retired_entries() {
        let entries = retired_history(1).await;
        let mut index = Index::open_temporary().unwrap();
        let mut reversed = Index::open_temporary().unwrap();

        index.apply(entries.clone()).unwrap();
        reversed.apply(entries.into_iter().rev().collect()).unwrap();

        assert!(!conflicted(&index));
        assert_eq!(index.resolve("b", "k").unwrap(), Some(manifest(2)));
        assert_eq!(snapshot_view(&reversed), snapshot_view(&index));
    }

    #[tokio::test]
    async fn test_put_after_its_writer_retired_a_chain_knew_that_chain() {
        let remote = Arc::new(MemoryRemote::default());
        let mut x = journal(&remote, 1);
        let mut gc = journal(&remote, 3);
        let first = x.append(put("k", 1), Seen::new()).await.unwrap();
        let link = Link {
            seq: first.seq,
            hash: first.hash(),
        };
        let retire = vec![Action::Retire {
            node: first.node,
            upto: 1,
        }];
        let retired = gc
            .append(retire, Seen::from([(first.node, link)]))
            .await
            .unwrap();
        let second = gc.append(put("k", 2), Seen::new()).await.unwrap();
        let entries = vec![first, retired, second];
        let mut index = Index::open_temporary().unwrap();
        let mut reversed = Index::open_temporary().unwrap();

        index.apply(entries.clone()).unwrap();
        reversed.apply(entries.into_iter().rev().collect()).unwrap();

        assert!(!conflicted(&index));
        assert_eq!(index.resolve("b", "k").unwrap(), Some(manifest(2)));
        assert_eq!(snapshot_view(&reversed), snapshot_view(&index));
    }

    #[tokio::test]
    async fn test_put_that_reached_a_retire_of_a_retiring_chain_knew_both() {
        let remote = Arc::new(MemoryRemote::default());
        let mut x = journal(&remote, 1);
        let mut w = journal(&remote, 2);
        let mut gc1 = journal(&remote, 3);
        let mut gc2 = journal(&remote, 4);
        let link = |e: &Entry| Link {
            seq: e.seq,
            hash: e.hash(),
        };
        let retire = |e: &Entry| {
            vec![Action::Retire {
                node: e.node,
                upto: e.seq + 1,
            }]
        };
        let first = x.append(put("k", 1), Seen::new()).await.unwrap();
        let seen = Seen::from([(first.node, link(&first))]);
        let retired = gc1.append(retire(&first), seen).await.unwrap();
        let seen = Seen::from([(retired.node, link(&retired))]);
        let retired_gc = gc2.append(retire(&retired), seen).await.unwrap();
        let seen = Seen::from([(retired_gc.node, link(&retired_gc))]);
        let second = w.append(put("k", 2), seen).await.unwrap();
        let entries = vec![first, retired, retired_gc, second];
        let mut index = Index::open_temporary().unwrap();
        let mut reversed = Index::open_temporary().unwrap();

        index.apply(entries.clone()).unwrap();
        reversed.apply(entries.into_iter().rev().collect()).unwrap();

        assert!(!conflicted(&index));
        assert_eq!(index.resolve("b", "k").unwrap(), Some(manifest(2)));
        assert_eq!(snapshot_view(&reversed), snapshot_view(&index));
    }

    /// A Retire of an entry that its writer did not apply moves nothing.
    #[tokio::test]
    async fn test_retire_past_what_its_writer_applied_is_ignored() {
        let mut index = Index::open_temporary().unwrap();

        index.apply(retired_history(2).await).unwrap();

        assert!(conflicted(&index));
    }

    /// A writer leaves a chain out while its frontier is the retired point, and lists it again
    /// once the chain wrote past it.
    #[tokio::test]
    async fn test_seen_leaves_a_retired_chain_out_until_it_writes_again() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut gc = journal(&remote, 3);
        let first = a.append(put("k", 1), Seen::new()).await.unwrap();
        let link = Link {
            seq: first.seq,
            hash: first.hash(),
        };
        let retire = vec![Action::Retire {
            node: first.node,
            upto: 1,
        }];
        let retired = gc
            .append(retire, Seen::from([(first.node, link)]))
            .await
            .unwrap();
        let own = NodeId::from_bytes(key(2).verifying_key().to_bytes());
        let mut index = Index::open_temporary().unwrap();
        index.apply(vec![first.clone(), retired.clone()]).unwrap();

        let left_out = index.seen(own).unwrap();
        let again = a.append(put("k", 3), Seen::new()).await.unwrap();
        index.apply(vec![again]).unwrap();
        let back = index.seen(own).unwrap();

        assert!(!left_out.contains_key(&first.node), "{left_out:?}");
        assert!(left_out.contains_key(&retired.node));
        assert_eq!(back.get(&first.node).map(|l| l.seq), Some(1));
    }

    /// Entry `seq` of node `seed` at `hlc`, after `prev`, with `seen` and `actions`.
    fn entry_at(
        seed: u8,
        prev: Option<&Entry>,
        hlc: u64,
        seen: Seen,
        actions: Vec<Action>,
    ) -> Entry {
        let (seq, prev) = prev.map_or((0, [0; 32]), |p| (p.seq + 1, p.hash()));
        Entry::sign(&key(seed), seq, prev, hlc, seen, actions, &test_sealer())
    }

    /// Chain 1 writes at HLC 100. Chain 3 retires it at `retire_hlc`, then writes at `after`.
    /// Chain 2 writes at `other`. Then chain 1 writes again at `again`. The stable HLC with a
    /// quiet time of 50.
    fn stable_with(
        retire_hlc: u64,
        after: Option<u64>,
        other: Option<u64>,
        again: Option<u64>,
    ) -> u64 {
        let quiet = entry_at(1, None, 100, Seen::new(), put("k", 1));
        let link = Link {
            seq: 0,
            hash: quiet.hash(),
        };
        let retire = vec![Action::Retire {
            node: quiet.node,
            upto: 1,
        }];
        let retired = entry_at(
            3,
            None,
            retire_hlc,
            Seen::from([(quiet.node, link)]),
            retire,
        );
        let mut entries = vec![quiet.clone(), retired.clone()];
        if let Some(hlc) = after {
            entries.push(entry_at(3, Some(&retired), hlc, Seen::new(), put("x", 3)));
        }
        if let Some(hlc) = other {
            entries.push(entry_at(2, None, hlc, Seen::new(), put("y", 2)));
        }
        if let Some(hlc) = again {
            entries.push(entry_at(1, Some(&quiet), hlc, Seen::new(), put("k", 4)));
        }
        let mut index = Index::open_temporary().unwrap();
        index.apply(entries).unwrap();
        index.stable_hlc(50).unwrap()
    }

    #[test]
    fn test_stable_hlc_skips_a_chain_retired_after_its_quiet_time() {
        assert_eq!(stable_with(150, None, Some(200), None), 150);
        // A later entry of the writer of the Retire also shows that its HLC is not ahead.
        assert_eq!(stable_with(150, Some(160), None, None), 160);
    }

    #[test]
    fn test_stable_hlc_keeps_a_chain_retired_too_early_or_with_no_later_hlc() {
        assert_eq!(stable_with(149, None, Some(200), None), 100);
        assert_eq!(stable_with(150, None, None, None), 100);
        assert_eq!(stable_with(150, None, Some(149), None), 100);
    }

    #[test]
    fn test_stable_hlc_takes_a_retired_chain_again_once_it_writes() {
        // The Retire is far above the new entry, so only the frontier keeps the chain.
        assert_eq!(stable_with(300, None, Some(400), Some(130)), 130);
    }

    /// Only a writer whose links reach the Retire entry knew the retired entries.
    #[tokio::test]
    async fn test_writer_that_did_not_reach_a_retire_keeps_the_conflict() {
        let mut index = Index::open_temporary().unwrap();

        index.apply(retired_history_with(1, false).await).unwrap();

        assert!(conflicted(&index));
    }

    #[tokio::test]
    async fn test_loaded_snapshot_keeps_the_retired_entries() {
        let entries = retired_history(1).await;
        let mut source = Index::open_temporary().unwrap();
        source.apply(entries[..2].to_vec()).unwrap();
        let snapshot = source.snapshot().unwrap();
        let mut target = Index::open_temporary().unwrap();

        target.load(&snapshot).unwrap();
        target.apply(entries[2..].to_vec()).unwrap();

        assert!(!conflicted(&target));
    }
}
