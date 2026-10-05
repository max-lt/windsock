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
    pending: Vec<Entry>,
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

impl Index {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::builder(path).open()?;
        Self::with_database(db, None)
    }

    /// An index in a temporary directory, removed on drop.
    pub fn open_temporary() -> Result<Self> {
        let dir = tempfile::tempdir().map_err(fjall::Error::from)?;
        let db = Database::builder(dir.path()).temporary(true).open()?;
        Self::with_database(db, Some(dir))
    }

    fn with_database(db: Database, temp: Option<tempfile::TempDir>) -> Result<Self> {
        Ok(Self {
            frontiers: db.keyspace("frontiers", KeyspaceCreateOptions::default)?,
            entries: db.keyspace("entries", KeyspaceCreateOptions::default)?,
            objects: db.keyspace("objects", KeyspaceCreateOptions::default)?,
            buckets: db.keyspace("buckets", KeyspaceCreateOptions::default)?,
            chunks: db.keyspace("chunks", KeyspaceCreateOptions::default)?,
            pack_chunks: db.keyspace("pack_chunks", KeyspaceCreateOptions::default)?,
            manifests: db.keyspace("manifests", KeyspaceCreateOptions::default)?,
            condemned: db.keyspace("condemned", KeyspaceCreateOptions::default)?,
            redacted: db.keyspace("redacted", KeyspaceCreateOptions::default)?,
            db,
            pending: Vec::new(),
            _temp: temp,
        })
    }

    /// Flushes every applied entry to disk.
    pub fn persist(&self) -> Result<()> {
        self.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Frontiers
    // ------------------------------------------------------------------

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
        Ok(journal::seen_from(&self.frontiers()?, own))
    }

    // ------------------------------------------------------------------
    // Apply
    // ------------------------------------------------------------------

    /// Applies every entry whose causal dependencies are applied, and keeps the
    /// others pending. Returns the number of entries applied.
    pub fn apply(&mut self, entries: Vec<Entry>) -> Result<usize> {
        self.pending.extend(entries);
        let mut applied = 0;

        loop {
            let mut progress = false;
            let mut i = 0;

            while i < self.pending.len() {
                match self.readiness(&self.pending[i])? {
                    Readiness::Wait => i += 1,
                    Readiness::AlreadyApplied => {
                        self.pending.remove(i);
                    }
                    Readiness::Ready => {
                        let entry = self.pending.remove(i);
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
                    ..
                } => self.record_version(&mut batch, entry, bucket, key, Some(*manifest_id))?,
                Action::Delete { bucket, key } => {
                    self.record_version(&mut batch, entry, bucket, key, None)?
                }
                Action::CreateBucket { bucket, owner } => {
                    self.record_bucket(&mut batch, entry, bucket, Some(owner.clone()))?
                }
                Action::DeleteBucket { bucket } => {
                    self.record_bucket(&mut batch, entry, bucket, None)?
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

    fn record_version(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        entry: &Entry,
        bucket: &str,
        key: &str,
        manifest_id: Option<ObjectId>,
    ) -> Result<()> {
        let storage_key = object_key(bucket, key);
        let mut state = self.object(bucket, key)?.unwrap_or_default();

        if state.record(entry, manifest_id) {
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
        bucket: &str,
        create: Option<Option<String>>,
    ) -> Result<()> {
        let current = self.bucket(bucket)?;

        if let Some(state) = BucketState::apply(current.as_ref(), entry, create) {
            batch.insert(&self.buckets, bucket.as_bytes(), encode(&state));
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

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

    // ------------------------------------------------------------------
    // Chunk locations
    // ------------------------------------------------------------------

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
        Ok(match self.chunks.get(id.as_bytes())? {
            Some(value) => Some(postcard::from_bytes(&value)?),
            None => None,
        })
    }

    // ------------------------------------------------------------------
    // Manifests
    // ------------------------------------------------------------------

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

    // ------------------------------------------------------------------
    // Snapshots
    // ------------------------------------------------------------------

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
        })
    }

    /// Replaces the applied state with `snapshot`. Chunk locations are cleared:
    /// the caller rebuilds them from the manifests.
    pub fn load(&mut self, snapshot: &Snapshot) -> Result<()> {
        let mut clear = self.db.batch();
        for keyspace in [
            &self.frontiers,
            &self.entries,
            &self.objects,
            &self.buckets,
            &self.chunks,
            &self.pack_chunks,
            &self.condemned,
        ] {
            for guard in keyspace.iter() {
                let (key, _) = guard.into_inner()?;
                clear.remove(keyspace, key);
            }
        }
        clear.commit()?;

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
        fill.commit()?;

        self.pending.clear();
        Ok(())
    }

    // ------------------------------------------------------------------
    // GC
    // ------------------------------------------------------------------

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

        for action in self.pending.iter().flat_map(|e| e.actions.iter().flatten()) {
            if let Action::Put { manifest_id, .. } = action {
                live.insert(*manifest_id);
            }
        }

        Ok(live)
    }

    /// No entry still to apply has a lower HLC: the lowest last HLC over the
    /// applied chains, and the lowest HLC of a pending entry.
    pub fn stable_hlc(&self) -> Result<u64> {
        let frontiers = self.frontiers()?;
        let applied = frontiers.values().map(|f| f.last_hlc);
        let pending = self.pending.iter().map(|e| e.hlc);

        Ok(applied.chain(pending).min().unwrap_or(0))
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
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use journal::Journal;
    use remote::MemoryRemote;

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn journal(remote: &Arc<MemoryRemote>, seed: u8) -> Journal<MemoryRemote> {
        Journal::new(remote.clone(), key(seed), Frontiers::new())
    }

    fn manifest(n: u8) -> ObjectId {
        ObjectId::from_bytes([n; 32])
    }

    fn put(key: &str, n: u8) -> Vec<Action> {
        vec![Action::Put {
            bucket: "b".into(),
            key: key.into(),
            manifest_id: manifest(n),
            inline_manifest: None,
        }]
    }

    fn create_bucket(name: &str) -> Vec<Action> {
        vec![Action::CreateBucket {
            bucket: name.into(),
            owner: None,
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
        let mut reader = Journal::new(remote.clone(), key(9), index.frontiers().unwrap());
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
        let entry = Entry::sign(&key(2), 0, [0u8; 32], 99, forged_link, put("k", 2));

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
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "a/2".into(),
                    manifest_id: manifest(2),
                    inline_manifest: None,
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "c".into(),
                    manifest_id: manifest(3),
                    inline_manifest: None,
                },
                Action::Put {
                    bucket: "ba".into(),
                    key: "a/3".into(),
                    manifest_id: manifest(4),
                    inline_manifest: None,
                },
            ],
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
            1,
            Seen::new(),
            vec![
                Action::CreateBucket {
                    bucket: "b".into(),
                    owner: None,
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "k".into(),
                    manifest_id: manifest(1),
                    inline_manifest: None,
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "k".into(),
                    manifest_id: manifest(2),
                    inline_manifest: None,
                },
                Action::DeleteBucket { bucket: "b".into() },
            ],
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
        Entry::sign(&key(seed), 0, [0u8; 32], hlc, Seen::new(), vec![action])
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
        let pending = Entry::sign(&key(1), 0, [0u8; 32], 7, waits, put("k", 3));
        let applied = Entry::sign(&key(2), 0, [0u8; 32], 20, Seen::new(), put("j", 4));

        index.apply(vec![pending, applied]).unwrap();

        assert_eq!(index.pending(), 1);
        assert_eq!(
            index.live_manifests(0).unwrap(),
            BTreeSet::from([manifest(3), manifest(4)])
        );
        assert_eq!(
            index.stable_hlc().unwrap(),
            7,
            "a pending entry lowers the stable HLC"
        );
    }

    #[test]
    fn test_stable_hlc_is_the_slowest_chain() {
        let mut index = Index::open_temporary().unwrap();
        let slow = Entry::sign(&key(1), 0, [0u8; 32], 10, Seen::new(), put("a", 1));
        let fast = Entry::sign(&key(2), 0, [0u8; 32], 30, Seen::new(), put("b", 2));

        assert_eq!(index.stable_hlc().unwrap(), 0);
        index.apply(vec![slow, fast]).unwrap();

        assert_eq!(index.stable_hlc().unwrap(), 10);
    }

    #[test]
    fn test_prune_versions_removes_keys_deleted_long_ago() {
        let mut index = Index::open_temporary().unwrap();
        let actions = vec![
            put("gone", 1).remove(0),
            put("kept", 2).remove(0),
            Action::Delete {
                bucket: "b".into(),
                key: "gone".into(),
            },
        ];
        let first = Entry::sign(&key(1), 0, [0u8; 32], 10, Seen::new(), actions);
        let rewrite = Entry::sign(&key(1), 1, first.hash(), 20, Seen::new(), put("kept", 5));
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
        };

        assert_eq!(
            blake3::hash(&snapshot.encode()).to_string(),
            "9c6fbf9848442f5b3fbf82aec4b65a4452a57651382f53a7ca8836475899a2b1"
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
        let stray = Entry::sign(&key(5), 3, [0u8; 32], 1, Seen::new(), put("z", 9));
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
        let old_link = Entry::sign(&key(2), 0, [0u8; 32], 99, links(1), put("k", 3));
        let last_link = Entry::sign(&key(3), 0, [0u8; 32], 99, links(4), put("j", 4));

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
        let entry = Entry::sign(&key(2), 0, [0u8; 32], 99, forged, put("k", 3));

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
}
