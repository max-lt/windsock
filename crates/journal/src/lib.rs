//! Append-only journal of index mutations, one signed chain per node.
//!
//! Entry `seq` of node `n` lives at `log/<n>/<seq>`, written with a create-only
//! write. One entry per seq, so the chain cannot fork. A reader follows a chain
//! from its frontier up to the first missing seq.
//!
//! `nodes/<n>` is an empty marker, written once, so readers can list the nodes.

mod chain;
mod clock;
mod entry;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use model::NodeId;
use remote::{Remote, RemoteError};
use tracing::{debug, warn};

pub use chain::{ChainError, Frontier};
pub use entry::{Action, Entry, EntryHash, LOG_PREFIX, NODES_PREFIX, entry_key, node_key};

use clock::HybridClock;

/// Appends that lose the seq to another process before `append` gives up.
const MAX_ATTEMPTS: u32 = 8;

/// Frontier of every chain a journal has read.
pub type Frontiers = BTreeMap<NodeId, Frontier>;

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error(transparent)]
    Remote(#[from] RemoteError),
    #[error("chain of node {node}: {source}")]
    Chain { node: NodeId, source: ChainError },
    #[error("{0} appends lost the seq to another process with this identity")]
    Contended(u32),
}

/// Reads all chains of a remote and appends to the chain of one node.
pub struct Journal<R> {
    remote: Arc<R>,
    signing_key: SigningKey,
    node: NodeId,
    clock: HybridClock,
    frontiers: Frontiers,
    registered: bool,
}

impl<R: Remote> Journal<R> {
    /// Opens the journal of the node that owns `signing_key`.
    ///
    /// `frontiers` are the positions saved by an earlier journal. Start from an
    /// empty map to read every chain from its first entry.
    pub fn new(remote: Arc<R>, signing_key: SigningKey, frontiers: Frontiers) -> Self {
        let node = NodeId::from_bytes(signing_key.verifying_key().to_bytes());

        Self {
            remote,
            signing_key,
            node,
            clock: HybridClock::default(),
            frontiers,
            registered: false,
        }
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    pub fn frontiers(&self) -> &Frontiers {
        &self.frontiers
    }

    pub fn frontier(&self, node: NodeId) -> Frontier {
        self.frontiers
            .get(&node)
            .copied()
            .unwrap_or(Frontier::GENESIS)
    }

    /// Appends an action to the own chain. Returns once the entry is in the remote.
    ///
    /// When another process with the same identity took the seq, this reads
    /// what it wrote and retries after it.
    pub async fn append(&mut self, action: Action) -> Result<Entry, JournalError> {
        for _ in 0..MAX_ATTEMPTS {
            let frontier = self.frontier(self.node);
            let entry = Entry::sign(
                &self.signing_key,
                frontier.next_seq,
                frontier.last_hash,
                self.clock.tick(),
                action.clone(),
            );
            let bytes = postcard::to_allocvec(&entry).expect("an entry always serializes");

            match self
                .remote
                .create(&entry.remote_key(), Bytes::from(bytes))
                .await
            {
                Ok(()) => {
                    let next = frontier
                        .extend(self.node, &entry)
                        .expect("a fresh entry extends the frontier it was built from");
                    self.frontiers.insert(self.node, next);
                    self.register().await;
                    debug!(seq = entry.seq, "appended entry");
                    return Ok(entry);
                }
                Err(RemoteError::AlreadyExists(_)) => {
                    warn!(
                        seq = entry.seq,
                        "seq taken by another process with this identity"
                    );
                    self.sync_node(self.node).await?;
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err(JournalError::Contended(MAX_ATTEMPTS))
    }

    /// Reads the chain of `node` from its frontier up to the first missing seq.
    /// Returns the new entries in order. A broken chain leaves the frontier as it was.
    pub async fn sync_node(&mut self, node: NodeId) -> Result<Vec<Entry>, JournalError> {
        let mut frontier = self.frontier(node);
        let mut entries = Vec::new();

        loop {
            let key = entry_key(node, frontier.next_seq);
            let Some(bytes) = self.remote.get(&key).await? else {
                break;
            };

            let entry: Entry = postcard::from_bytes(&bytes).map_err(|_| JournalError::Chain {
                node,
                source: ChainError::Malformed {
                    seq: frontier.next_seq,
                },
            })?;
            frontier = frontier
                .extend(node, &entry)
                .map_err(|source| JournalError::Chain { node, source })?;
            self.clock.witness(entry.hlc);
            entries.push(entry);
        }

        if !entries.is_empty() {
            debug!(%node, count = entries.len(), "read entries");
        }

        self.frontiers.insert(node, frontier);
        Ok(entries)
    }

    /// Syncs every known node and every node with a marker. Returns the new entries.
    pub async fn sync_all(&mut self) -> Result<Vec<Entry>, JournalError> {
        let mut nodes: BTreeSet<NodeId> = self.frontiers.keys().copied().collect();

        for key in self.remote.list(NODES_PREFIX).await? {
            if let Some(node) = key.strip_prefix(NODES_PREFIX).and_then(|s| s.parse().ok()) {
                nodes.insert(node);
            }
        }

        let mut entries = Vec::new();

        for node in nodes {
            entries.extend(self.sync_node(node).await?);
        }

        Ok(entries)
    }

    /// Writes the node marker once. A failure only delays discovery by other proxies.
    async fn register(&mut self) {
        if self.registered {
            return;
        }

        match self.remote.put(&node_key(self.node), Bytes::new()).await {
            Ok(()) => self.registered = true,
            Err(e) => warn!(%e, "failed to write the node marker"),
        }
    }
}

#[cfg(test)]
mod tests {
    use model::ObjectId;
    use remote::MemoryRemote;

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn journal(remote: &Arc<MemoryRemote>, seed: u8) -> Journal<MemoryRemote> {
        Journal::new(remote.clone(), key(seed), Frontiers::new())
    }

    fn put(key: &str) -> Action {
        Action::Put {
            bucket: "b".into(),
            key: key.into(),
            manifest_id: ObjectId::from_bytes([1u8; 32]),
        }
    }

    #[tokio::test]
    async fn test_append_stores_a_signed_entry() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);

        let entry = a.append(put("k")).await.unwrap();

        let stored = remote.get(&entry.remote_key()).await.unwrap().unwrap();
        let decoded: Entry = postcard::from_bytes(&stored).unwrap();
        assert_eq!(decoded, entry);
        assert!(decoded.verify());
        assert_eq!(entry.seq, 0);
        assert_eq!(a.frontier(a.node()).next_seq, 1);
        assert!(remote.get(&node_key(a.node())).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_peer_reads_entries_in_order() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        for k in ["x", "y", "z"] {
            a.append(put(k)).await.unwrap();
        }

        let entries = b.sync_all().await.unwrap();

        assert_eq!(entries.len(), 3);
        assert!(entries.iter().enumerate().all(|(i, e)| e.seq == i as u64));
        assert!(entries.iter().all(|e| e.node == a.node()));
        assert_eq!(b.frontier(a.node()).next_seq, 3);
        assert!(b.sync_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_two_processes_on_one_identity_take_distinct_seqs() {
        let remote = Arc::new(MemoryRemote::default());
        let mut first = journal(&remote, 1);
        let mut zombie = journal(&remote, 1);

        let e0 = first.append(put("from first")).await.unwrap();
        let e1 = zombie.append(put("from zombie")).await.unwrap();
        let e2 = first.append(put("from first again")).await.unwrap();

        assert_eq!((e0.seq, e1.seq, e2.seq), (0, 1, 2));
        assert_eq!(e1.prev, e0.hash());
        assert_eq!(e2.prev, e1.hash());

        let mut reader = journal(&remote, 3);
        let entries = reader.sync_node(first.node()).await.unwrap();
        assert_eq!(entries, vec![e0, e1, e2]);
    }

    #[tokio::test]
    async fn test_restart_with_lost_state_continues_the_chain() {
        let remote = Arc::new(MemoryRemote::default());
        let mut before = journal(&remote, 1);
        before.append(put("x")).await.unwrap();
        before.append(put("y")).await.unwrap();
        drop(before);

        let mut after = journal(&remote, 1);
        let entry = after.append(put("z")).await.unwrap();

        assert_eq!(entry.seq, 2);
        let mut reader = journal(&remote, 2);
        assert_eq!(reader.sync_node(after.node()).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_saved_frontiers_skip_known_entries() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        a.append(put("x")).await.unwrap();
        b.sync_all().await.unwrap();
        let saved = b.frontiers().clone();
        drop(b);

        a.append(put("y")).await.unwrap();
        let mut b = Journal::new(remote.clone(), key(2), saved);
        let entries = b.sync_all().await.unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seq, 1);
    }

    #[tokio::test]
    async fn test_tampered_entry_stops_the_reader() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        a.append(put("x")).await.unwrap();
        let mut forged = a.append(put("y")).await.unwrap();
        forged.action = put("forged");
        let bytes = postcard::to_allocvec(&forged).unwrap();
        remote
            .put(&forged.remote_key(), Bytes::from(bytes))
            .await
            .unwrap();

        let mut b = journal(&remote, 2);
        let result = b.sync_node(a.node()).await;

        assert!(matches!(
            result,
            Err(JournalError::Chain {
                source: ChainError::BadSignature { seq: 1 },
                ..
            })
        ));
        assert_eq!(b.frontier(a.node()), Frontier::GENESIS);
    }

    #[tokio::test]
    async fn test_garbage_entry_stops_the_reader() {
        let remote = Arc::new(MemoryRemote::default());
        let a = journal(&remote, 1);
        remote
            .put(&entry_key(a.node(), 0), Bytes::from_static(b"garbage"))
            .await
            .unwrap();

        let mut b = journal(&remote, 2);
        let result = b.sync_node(a.node()).await;

        assert!(matches!(
            result,
            Err(JournalError::Chain {
                source: ChainError::Malformed { seq: 0 },
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_reader_stops_at_a_gap() {
        let remote = Arc::new(MemoryRemote::default());
        let a = journal(&remote, 1);
        let orphan = Entry::sign(&key(1), 1, [0u8; 32], 5, put("x"));
        let bytes = postcard::to_allocvec(&orphan).unwrap();
        remote
            .put(&orphan.remote_key(), Bytes::from(bytes))
            .await
            .unwrap();

        let mut b = journal(&remote, 2);

        assert!(b.sync_node(a.node()).await.unwrap().is_empty());
        assert_eq!(b.frontier(a.node()), Frontier::GENESIS);
    }

    #[tokio::test]
    async fn test_reader_clock_passes_the_writer_clock() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        a.clock.witness(u64::MAX / 2);
        let from_a = a.append(put("x")).await.unwrap();

        b.sync_all().await.unwrap();
        let from_b = b.append(put("y")).await.unwrap();

        assert!(from_b.hlc > from_a.hlc);
    }
}
