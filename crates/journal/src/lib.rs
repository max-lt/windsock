//! Append-only journal of index mutations, one signed chain per node.
//!
//! Entry `seq` of node `n` lives at `log/<n>/<seq>`, written with a create-only
//! write. One entry per seq, so the chain cannot fork. A reader follows a chain
//! from its frontier up to the first missing seq.
//!
//! Each entry also records the last entry of every other chain its writer had
//! integrated (`seen`). `prev` and `seen` form a causal DAG with no merge
//! entries: the next entry of a node is the join.
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
pub use entry::{
    Action, Entry, EntryHash, LOG_PREFIX, Link, NODES_PREFIX, Seen, entry_key, node_key,
};

use clock::HybridClock;

/// Appends that lose the seq to another process before `append` gives up.
const MAX_ATTEMPTS: u32 = 8;

/// Frontier of every chain a journal has read.
pub type Frontiers = BTreeMap<NodeId, Frontier>;

/// Last entry of every chain in `frontiers`, except the chain of `own`.
pub fn seen_from(frontiers: &Frontiers, own: NodeId) -> Seen {
    frontiers
        .iter()
        .filter(|(node, frontier)| **node != own && frontier.next_seq > 0)
        .map(|(node, frontier)| {
            let link = Link {
                seq: frontier.next_seq - 1,
                hash: frontier.last_hash,
            };
            (*node, link)
        })
        .collect()
}

/// Outcome of [`Journal::commit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    Written,
    /// Another entry holds the seq. Prepare the actions again and retry.
    SeqTaken,
}

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
    /// Own-chain entries read while a commit resolved a taken seq, not yet returned.
    stashed: Vec<Entry>,
    /// Chains that the last sync found broken. The other chains go on.
    broken: BTreeMap<NodeId, ChainError>,
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
            stashed: Vec::new(),
            broken: BTreeMap::new(),
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

    /// Appends actions to the own chain as one entry. Returns once the entry is in the remote.
    ///
    /// `seen` is what the writer has applied from the other chains: build it with
    /// [`seen_from`] on the applied frontiers, not on the read ones.
    ///
    /// When another process with the same identity took the seq, this reads
    /// what it wrote and retries after it.
    pub async fn append(
        &mut self,
        actions: Vec<Action>,
        seen: Seen,
    ) -> Result<Entry, JournalError> {
        for _ in 0..MAX_ATTEMPTS {
            let entry = self.prepare(actions.clone(), seen.clone());

            match self.commit(&entry).await? {
                Commit::Written => return Ok(entry),
                Commit::SeqTaken => continue,
            }
        }

        Err(JournalError::Contended(MAX_ATTEMPTS))
    }

    /// Signs actions as the next entry of the own chain, without writing it.
    pub fn prepare(&self, actions: Vec<Action>, seen: Seen) -> Entry {
        let frontier = self.frontier(self.node);

        Entry::sign(
            &self.signing_key,
            frontier.next_seq,
            frontier.last_hash,
            self.clock.tick(),
            seen,
            actions,
        )
    }

    /// Writes a prepared entry. Safe to call again with the same entry after a
    /// crash or an ambiguous error: an entry already in the remote counts as written.
    pub async fn commit(&mut self, entry: &Entry) -> Result<Commit, JournalError> {
        let bytes = postcard::to_allocvec(entry).expect("an entry always serializes");

        match self
            .remote
            .create(&entry.remote_key(), Bytes::from(bytes))
            .await
        {
            Ok(()) => {
                self.advance_own(entry).await?;
                self.register().await;
                debug!(seq = entry.seq, "appended entry");
                Ok(Commit::Written)
            }
            Err(RemoteError::AlreadyExists(_)) => self.resolve_taken_seq(entry).await,
            Err(e) => Err(e.into()),
        }
    }

    async fn advance_own(&mut self, entry: &Entry) -> Result<(), JournalError> {
        match self.frontier(self.node).extend(self.node, entry) {
            Ok(next) => {
                self.frontiers.insert(self.node, next);
            }
            // The own frontier is behind the entry: a restart lost it.
            Err(_) => {
                let read = self.sync_node(self.node).await?;
                self.stashed.extend(read);
            }
        }

        Ok(())
    }

    /// Checks that a prepared entry is in the remote, without writing it.
    pub async fn is_written(&mut self, entry: &Entry) -> Result<bool, JournalError> {
        let read = self.sync_node(self.node).await?;
        self.stashed.extend(read);

        let stored = self.remote.get(&entry.remote_key()).await?;
        Ok(stored
            .and_then(|bytes| postcard::from_bytes::<Entry>(&bytes).ok())
            .is_some_and(|stored| stored.hash() == entry.hash()))
    }

    async fn resolve_taken_seq(&mut self, entry: &Entry) -> Result<Commit, JournalError> {
        if self.is_written(entry).await? {
            self.register().await;
            return Ok(Commit::Written);
        }

        warn!(
            seq = entry.seq,
            "seq taken by another process with this identity"
        );
        Ok(Commit::SeqTaken)
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

    /// Chains that the last `sync_all` could not read past their frontier, and why.
    pub fn broken(&self) -> &BTreeMap<NodeId, ChainError> {
        &self.broken
    }

    /// Reads again from `frontiers`, as after a snapshot load.
    pub fn reset(&mut self, frontiers: Frontiers) {
        self.frontiers = frontiers;
        self.stashed.clear();
    }

    /// Own-chain entries that a commit read and that no sync returned yet.
    pub fn take_stashed(&mut self) -> Vec<Entry> {
        std::mem::take(&mut self.stashed)
    }

    /// Syncs every known node and every node with a marker. Returns the new
    /// entries, stashed ones first. A broken chain is skipped and listed in
    /// [`Journal::broken`]; a remote error stops the sync.
    pub async fn sync_all(&mut self) -> Result<Vec<Entry>, JournalError> {
        let mut nodes: BTreeSet<NodeId> = self.frontiers.keys().copied().collect();

        for key in self.remote.list(NODES_PREFIX).await? {
            if let Some(node) = key.strip_prefix(NODES_PREFIX).and_then(|s| s.parse().ok()) {
                nodes.insert(node);
            }
        }

        let mut entries = self.take_stashed();

        for node in nodes {
            match self.sync_node(node).await {
                Ok(read) => {
                    self.broken.remove(&node);
                    entries.extend(read);
                }
                // One bad chain must not stop the sync of every chain.
                Err(JournalError::Chain { node, source }) => {
                    warn!(%node, %source, "chain is broken: the other chains go on");
                    self.broken.insert(node, source);
                }
                Err(e) => return Err(e),
            }
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
            inline_manifest: None,
        }
    }

    async fn overwrite(remote: &MemoryRemote, entry: &Entry) {
        let bytes = postcard::to_allocvec(entry).unwrap();
        remote
            .put(&entry.remote_key(), Bytes::from(bytes))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_append_stores_a_signed_entry() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);

        let entry = a.append(vec![put("k")], Seen::new()).await.unwrap();

        let stored = remote.get(&entry.remote_key()).await.unwrap().unwrap();
        let decoded: Entry = postcard::from_bytes(&stored).unwrap();
        assert_eq!(decoded, entry);
        assert!(decoded.signature_is_valid());
        assert_eq!(entry.seq, 0);
        assert!(entry.seen.is_empty());
        assert_eq!(a.frontier(a.node()).next_seq, 1);
        assert!(remote.get(&node_key(a.node())).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_peer_reads_entries_in_order() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        for k in ["x", "y", "z"] {
            a.append(vec![put(k)], Seen::new()).await.unwrap();
        }

        let entries = b.sync_all().await.unwrap();

        assert_eq!(entries.len(), 3);
        assert!(entries.iter().enumerate().all(|(i, e)| e.seq == i as u64));
        assert!(entries.iter().all(|e| e.node == a.node()));
        assert_eq!(b.frontier(a.node()).next_seq, 3);
        assert!(b.sync_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_entry_records_what_the_writer_had_seen() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        a.append(vec![put("x")], Seen::new()).await.unwrap();
        let last_of_a = a.append(vec![put("y")], Seen::new()).await.unwrap();

        b.sync_all().await.unwrap();
        let seen_by_b = seen_from(b.frontiers(), b.node());
        let from_b = b.append(vec![put("z")], seen_by_b).await.unwrap();
        let seen_by_a = seen_from(a.frontiers(), a.node());
        let from_a = a.append(vec![put("w")], seen_by_a).await.unwrap();

        let expected = Link {
            seq: 1,
            hash: last_of_a.hash(),
        };
        assert_eq!(from_b.seen, Seen::from([(a.node(), expected)]));
        assert!(from_a.seen.is_empty(), "a never read b");
    }

    #[tokio::test]
    async fn test_two_processes_on_one_identity_take_distinct_seqs() {
        let remote = Arc::new(MemoryRemote::default());
        let mut first = journal(&remote, 1);
        let mut zombie = journal(&remote, 1);

        let e0 = first
            .append(vec![put("from first")], Seen::new())
            .await
            .unwrap();
        let e1 = zombie
            .append(vec![put("from zombie")], Seen::new())
            .await
            .unwrap();
        let e2 = first
            .append(vec![put("from first again")], Seen::new())
            .await
            .unwrap();

        assert_eq!((e0.seq, e1.seq, e2.seq), (0, 1, 2));
        assert_eq!(e1.prev, e0.hash());
        assert_eq!(e2.prev, e1.hash());

        let mut reader = journal(&remote, 3);
        let entries = reader.sync_node(first.node()).await.unwrap();
        assert_eq!(entries, vec![e0, e1, e2]);
    }

    #[tokio::test]
    async fn test_commit_of_a_written_entry_is_idempotent() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let entry = a.prepare(vec![put("k")], Seen::new());

        assert_eq!(a.commit(&entry).await.unwrap(), Commit::Written);
        assert_eq!(a.commit(&entry).await.unwrap(), Commit::Written);

        let mut reader = journal(&remote, 2);
        assert_eq!(reader.sync_node(a.node()).await.unwrap(), vec![entry]);
        assert_eq!(a.frontier(a.node()).next_seq, 1);
    }

    #[tokio::test]
    async fn test_commit_after_restart_finds_the_written_entry() {
        let remote = Arc::new(MemoryRemote::default());
        let mut before = journal(&remote, 1);
        let entry = before.prepare(vec![put("k")], Seen::new());
        before.commit(&entry).await.unwrap();
        drop(before);

        let mut after = journal(&remote, 1);

        assert_eq!(after.commit(&entry).await.unwrap(), Commit::Written);
        assert_eq!(after.frontier(after.node()).next_seq, 1);
        assert_eq!(after.frontier(after.node()).last_hash, entry.hash());
    }

    #[tokio::test]
    async fn test_prepared_entry_loses_its_seq_to_another_process() {
        let remote = Arc::new(MemoryRemote::default());
        let mut first = journal(&remote, 1);
        let mut zombie = journal(&remote, 1);
        let prepared = first.prepare(vec![put("from first")], Seen::new());
        zombie
            .append(vec![put("from zombie")], Seen::new())
            .await
            .unwrap();

        assert_eq!(first.commit(&prepared).await.unwrap(), Commit::SeqTaken);
        assert_eq!(first.frontier(first.node()).next_seq, 1);

        let retried = first.prepare(vec![put("from first")], Seen::new());
        assert_eq!(retried.seq, 1);
        assert_eq!(first.commit(&retried).await.unwrap(), Commit::Written);
    }

    #[tokio::test]
    async fn test_is_written_finds_only_the_same_entry() {
        let remote = Arc::new(MemoryRemote::default());
        let mut first = journal(&remote, 1);
        let mut zombie = journal(&remote, 1);
        let prepared = first.prepare(vec![put("from first")], Seen::new());

        assert!(!first.is_written(&prepared).await.unwrap());
        zombie
            .append(vec![put("from zombie")], Seen::new())
            .await
            .unwrap();
        assert!(!first.is_written(&prepared).await.unwrap());

        let written = first.append(vec![put("ours")], Seen::new()).await.unwrap();
        assert!(first.is_written(&written).await.unwrap());
    }

    #[tokio::test]
    async fn test_entries_read_by_a_commit_come_back_from_the_next_sync() {
        let remote = Arc::new(MemoryRemote::default());
        let mut first = journal(&remote, 1);
        let mut zombie = journal(&remote, 1);
        let prepared = first.prepare(vec![put("from first")], Seen::new());
        let from_zombie = zombie
            .append(vec![put("from zombie")], Seen::new())
            .await
            .unwrap();
        first.commit(&prepared).await.unwrap();

        let entries = first.sync_all().await.unwrap();

        assert_eq!(entries, vec![from_zombie]);
        assert!(first.sync_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_restart_with_lost_state_continues_the_chain() {
        let remote = Arc::new(MemoryRemote::default());
        let mut before = journal(&remote, 1);
        before.append(vec![put("x")], Seen::new()).await.unwrap();
        before.append(vec![put("y")], Seen::new()).await.unwrap();
        drop(before);

        let mut after = journal(&remote, 1);
        let entry = after.append(vec![put("z")], Seen::new()).await.unwrap();

        assert_eq!(entry.seq, 2);
        let mut reader = journal(&remote, 2);
        assert_eq!(reader.sync_node(after.node()).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_saved_frontiers_skip_known_entries() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        a.append(vec![put("x")], Seen::new()).await.unwrap();
        b.sync_all().await.unwrap();
        let saved = b.frontiers().clone();
        drop(b);

        a.append(vec![put("y")], Seen::new()).await.unwrap();
        let mut b = Journal::new(remote.clone(), key(2), saved);
        let entries = b.sync_all().await.unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seq, 1);
    }

    #[tokio::test]
    async fn test_tampered_entry_stops_the_reader() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        a.append(vec![put("x")], Seen::new()).await.unwrap();
        let mut forged = a.append(vec![put("y")], Seen::new()).await.unwrap();
        forged.actions = Some(vec![put("forged")]);
        overwrite(&remote, &forged).await;

        let mut b = journal(&remote, 2);
        let result = b.sync_node(a.node()).await;

        assert!(matches!(
            result,
            Err(JournalError::Chain {
                source: ChainError::ActionsMismatch { seq: 1 },
                ..
            })
        ));
        assert_eq!(b.frontier(a.node()), Frontier::GENESIS);
    }

    #[tokio::test]
    async fn test_redacted_entry_keeps_the_chain_readable() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        a.append(vec![put("x")], Seen::new()).await.unwrap();
        let secret = a.append(vec![put("secret")], Seen::new()).await.unwrap();
        overwrite(&remote, &secret.redacted()).await;
        a.append(vec![put("z")], Seen::new()).await.unwrap();

        let mut b = journal(&remote, 2);
        let entries = b.sync_node(a.node()).await.unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].actions, None);
        assert_eq!(entries[2].actions, Some(vec![put("z")]));
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
    async fn test_broken_chain_does_not_stop_the_other_chains() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        let mut c = journal(&remote, 3);
        a.append(vec![put("a")], Seen::new()).await.unwrap();
        c.append(vec![put("c0")], Seen::new()).await.unwrap();
        let mut tampered = c.append(vec![put("c1")], Seen::new()).await.unwrap();
        b.append(vec![put("b")], Seen::new()).await.unwrap();
        tampered.actions = Some(vec![put("forged")]);
        overwrite(&remote, &tampered).await;

        let mut reader = journal(&remote, 9);
        let entries = reader.sync_all().await.unwrap();

        let nodes: BTreeSet<_> = entries.iter().map(|e| e.node).collect();
        assert_eq!(nodes, BTreeSet::from([a.node(), b.node()]));
        assert_eq!(
            reader.broken().keys().copied().collect::<Vec<_>>(),
            [c.node()]
        );
        assert_eq!(reader.frontier(c.node()), Frontier::GENESIS);
    }

    #[tokio::test]
    async fn test_fixed_chain_syncs_again() {
        let remote = Arc::new(MemoryRemote::default());
        let mut c = journal(&remote, 3);
        let good = c.append(vec![put("c0")], Seen::new()).await.unwrap();
        let mut tampered = good.clone();
        tampered.actions = Some(vec![put("forged")]);
        overwrite(&remote, &tampered).await;
        let mut reader = journal(&remote, 9);
        assert!(reader.sync_all().await.unwrap().is_empty());
        assert!(reader.broken().contains_key(&c.node()));

        overwrite(&remote, &good).await;
        let entries = reader.sync_all().await.unwrap();

        assert_eq!(entries, vec![good]);
        assert!(reader.broken().is_empty());
    }

    #[tokio::test]
    async fn test_reader_stops_at_a_gap() {
        let remote = Arc::new(MemoryRemote::default());
        let a = journal(&remote, 1);
        let orphan = Entry::sign(&key(1), 1, [0u8; 32], 5, Seen::new(), vec![put("x")]);
        overwrite(&remote, &orphan).await;

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
        let from_a = a.append(vec![put("x")], Seen::new()).await.unwrap();

        b.sync_all().await.unwrap();
        let from_b = b.append(vec![put("y")], Seen::new()).await.unwrap();

        assert!(from_b.hlc > from_a.hlc);
    }
}
