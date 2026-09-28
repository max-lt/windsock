//! Materialized view of the journal, in Fjall.
//!
//! The index applies entries in causal order: an entry waits until the entries
//! in its `seen` are applied. Frontiers of applied entries are persisted, so a
//! restart reads only the new entries. Pending entries are not persisted: a
//! restart reads them again.

mod state;

use std::path::Path;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use journal::{Action, Entry, EntryHash, Frontier, Frontiers, Seen};
use model::{ChunkId, NodeId, ObjectId, PackId};
use pack::PackEntry;
use serde::{Deserialize, Serialize};
use tracing::debug;

pub use state::{BucketState, EntryRef, ObjectState, Version, knew};

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error(transparent)]
    Storage(#[from] fjall::Error),
    #[error("corrupt index record: {0}")]
    Corrupt(#[from] postcard::Error),
    #[error("entry {seq} of node {node} links to an entry with another hash")]
    LinkMismatch { node: NodeId, seq: u64 },
}

type Result<T> = std::result::Result<T, IndexError>;

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

        for (node, link) in &entry.seen {
            let Some(applied) = self.entries.get(entry_key(*node, link.seq))? else {
                return Ok(Readiness::Wait);
            };

            if applied[..] != link.hash[..] {
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

    pub fn put_chunk(&self, id: ChunkId, location: &ChunkLocation) -> Result<()> {
        self.chunks.insert(id.as_bytes(), encode(location))?;
        Ok(())
    }

    pub fn chunk(&self, id: ChunkId) -> Result<Option<ChunkLocation>> {
        Ok(match self.chunks.get(id.as_bytes())? {
            Some(value) => Some(postcard::from_bytes(&value)?),
            None => None,
        })
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
        }]
    }

    fn create_bucket(name: &str) -> Vec<Action> {
        vec![Action::CreateBucket {
            bucket: name.into(),
            owner: None,
        }]
    }

    /// Everything a reader can observe.
    type Snapshot = (Vec<(String, ObjectState)>, Vec<(String, BucketState)>);

    fn snapshot(index: &Index) -> Snapshot {
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

        assert_eq!(snapshot(&rebuilt), snapshot(&incremental));
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
        let before = snapshot(&index);

        assert_eq!(index.apply(entries).unwrap(), 0);
        assert_eq!(snapshot(&index), before);
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
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "a/2".into(),
                    manifest_id: manifest(2),
                },
                Action::Put {
                    bucket: "b".into(),
                    key: "c".into(),
                    manifest_id: manifest(3),
                },
                Action::Put {
                    bucket: "ba".into(),
                    key: "a/3".into(),
                    manifest_id: manifest(4),
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
