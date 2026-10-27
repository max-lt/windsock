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
use seal::Sealer;
use tracing::{debug, error, warn};

pub use chain::{ChainError, Frontier};
pub use entry::{
    Action, Entry, EntryHash, LOG_PREFIX, Link, NODES_PREFIX, Seen, WireError, entry_key, node_key,
    redact_wire,
};

#[cfg(feature = "sim")]
pub use clock::set_manual_wall;
pub use clock::{HybridClock, wall_clock_nanos};

/// Appends that lose the seq to another process before `append` gives up.
const MAX_ATTEMPTS: u32 = 8;

/// R by default: 24 h in nanoseconds.
const DEFAULT_MAX_AHEAD: u64 = 24 * 3600 * 1_000_000_000;

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
    #[error("the HLC is at the end of its range: a new entry would rank under the old ones")]
    ClockOverflow,
}

/// Reads all chains of a remote and appends to the chain of one node.
pub struct Journal<R> {
    remote: Arc<R>,
    signing_key: SigningKey,
    sealer: Sealer,
    node: NodeId,
    clock: Arc<HybridClock>,
    frontiers: Frontiers,
    /// Own-chain entries read while a commit resolved a taken seq, not yet returned.
    stashed: Vec<Entry>,
    /// Chains that the last sync found broken. The other chains go on.
    broken: BTreeMap<NodeId, ChainError>,
    registered: bool,
    /// The next sync lists each chain and reads its last entry again.
    audit: bool,
    /// Nanoseconds that an entry HLC may be ahead of the wall clock of this reader: R.
    max_ahead: u64,
    /// Entries already logged as too far ahead: one ERROR each.
    reported_ahead: BTreeSet<(NodeId, u64)>,
}

impl<R: Remote> Journal<R> {
    /// Opens the journal of the node that owns `signing_key`.
    ///
    /// `frontiers` are the positions saved by an earlier journal. Start from an
    /// empty map to read every chain from its first entry.
    pub fn new(
        remote: Arc<R>,
        signing_key: SigningKey,
        sealer: Sealer,
        frontiers: Frontiers,
    ) -> Self {
        let node = NodeId::from_bytes(signing_key.verifying_key().to_bytes());

        Self {
            remote,
            signing_key,
            sealer,
            node,
            clock: Arc::new(HybridClock::default()),
            frontiers,
            stashed: Vec::new(),
            broken: BTreeMap::new(),
            registered: false,
            audit: true,
            max_ahead: DEFAULT_MAX_AHEAD,
            reported_ahead: BTreeSet::new(),
        }
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    /// The clock of this node: the entries and the acks of its writes take their HLC from it.
    pub fn clock(&self) -> Arc<HybridClock> {
        self.clock.clone()
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
            let entry = self.prepare(actions.clone(), seen.clone())?;

            match self.commit(&entry).await? {
                Commit::Written => return Ok(entry),
                Commit::SeqTaken => continue,
            }
        }

        Err(JournalError::Contended(MAX_ATTEMPTS))
    }

    /// Signs actions as the next entry of the own chain, without writing it.
    pub fn prepare(&self, actions: Vec<Action>, seen: Seen) -> Result<Entry, JournalError> {
        let frontier = self.frontier(self.node);

        let hlc = self.clock.tick().ok_or(JournalError::ClockOverflow)?;
        Ok(Entry::sign(
            &self.signing_key,
            frontier.next_seq,
            frontier.last_hash,
            hlc,
            seen,
            actions,
            &self.sealer,
        ))
    }

    /// Writes a prepared entry. Safe to call again with the same entry after a
    /// crash or an ambiguous error: an entry already in the remote counts as written.
    pub async fn commit(&mut self, entry: &Entry) -> Result<Commit, JournalError> {
        let bytes = entry.to_wire();

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
            .and_then(|bytes| Entry::from_wire(&bytes, &self.sealer).ok())
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
                // A writer creates seq n before n + 1: a later entry with no entry here is a gap,
                // and the chain would end here for this reader only.
                let next = frontier
                    .next_seq
                    .checked_add(1)
                    .map(|seq| entry_key(node, seq));
                if let Some(next) = next
                    && self.remote.get(&next).await?.is_some()
                {
                    return Err(JournalError::Chain {
                        node,
                        source: ChainError::Gap {
                            seq: frontier.next_seq,
                        },
                    });
                }
                break;
            };

            let seq = frontier.next_seq;
            let entry =
                Entry::from_wire(&bytes, &self.sealer).map_err(|e| JournalError::Chain {
                    node,
                    source: match e {
                        WireError::Malformed => ChainError::Malformed { seq },
                        WireError::ActionsMismatch => ChainError::ActionsMismatch { seq },
                        WireError::Sealed => ChainError::Sealed { seq },
                    },
                })?;
            frontier = frontier
                .extend(node, &entry)
                .map_err(|source| JournalError::Chain { node, source })?;
            // The chain reads again once this clock passes the HLC less R.
            if entry.hlc > clock::limit(self.max_ahead) {
                if self.reported_ahead.insert((node, seq)) {
                    error!(%node, seq, hlc = entry.hlc, "entry HLC more than R ahead of this clock");
                }
                return Err(JournalError::Chain {
                    node,
                    source: ChainError::FutureHlc { seq },
                });
            }
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

    /// Sets how far an entry HLC may be ahead of the wall clock of this reader. Pass R.
    pub fn set_max_ahead(&mut self, max_ahead: std::time::Duration) {
        self.max_ahead = max_ahead.as_nanos() as u64;
    }

    /// Makes the next sync check each chain against a listing. It finds a gap of any length and
    /// a changed copy of the last entry read. It costs one LIST and one GET per chain.
    pub fn audit_next_sync(&mut self) {
        self.audit = true;
    }

    /// The HLC of the last entry of the own chain in the remote, read with one LIST and one GET.
    /// A redacted entry keeps its HLC. `None` for a chain with no entry.
    pub async fn own_tail_hlc(&self) -> Result<Option<u64>, JournalError> {
        let prefix = format!("{LOG_PREFIX}{}/", self.node);
        let last = self
            .remote
            .list(&prefix)
            .await?
            .iter()
            .filter_map(|key| key.strip_prefix(&prefix)?.parse::<u64>().ok())
            .max();
        let Some(seq) = last else {
            return Ok(None);
        };
        let Some(bytes) = self.remote.get(&entry_key(self.node, seq)).await? else {
            return Ok(None);
        };
        let entry = Entry::from_wire(&bytes, &self.sealer).map_err(|_| JournalError::Chain {
            node: self.node,
            source: ChainError::Malformed { seq },
        })?;
        Ok(Some(entry.hlc))
    }

    /// The highest seq in the listing of a chain, and an error when the last entry read changed.
    async fn audit_chain(&self, node: NodeId) -> Result<Option<u64>, JournalError> {
        let prefix = format!("{LOG_PREFIX}{node}/");
        let highest = self
            .remote
            .list(&prefix)
            .await?
            .iter()
            .filter_map(|key| key.strip_prefix(&prefix)?.parse::<u64>().ok())
            .max();

        let frontier = self.frontier(node);
        let Some(last) = frontier.next_seq.checked_sub(1) else {
            return Ok(highest);
        };
        let same = match self.remote.get(&entry_key(node, last)).await? {
            Some(bytes) => Entry::from_wire(&bytes, &self.sealer)
                .is_ok_and(|entry| entry.hash() == frontier.last_hash),
            None => false,
        };
        if !same {
            return Err(JournalError::Chain {
                node,
                source: ChainError::Changed { seq: last },
            });
        }
        Ok(highest)
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
        // The flag stays set until a whole audit runs: a remote error must not skip it.
        let audit = self.audit;
        let mut queue: Vec<NodeId> = nodes.iter().copied().collect();
        let mut known = nodes;

        while let Some(node) = queue.pop() {
            // The listing comes first: each entry in it exists before the reads below.
            let highest = match audit {
                true => self.audit_chain(node).await,
                false => Ok(None),
            };
            let result = match highest {
                Ok(highest) => self.sync_node(node).await.map(|read| (highest, read)),
                Err(e) => Err(e),
            };
            match result {
                Ok((highest, read)) => {
                    // A node that lost its marker is still named in the seen of other entries.
                    for seen in read.iter().flat_map(|entry| entry.seen.keys()) {
                        if known.insert(*seen) {
                            queue.push(*seen);
                        }
                    }
                    entries.extend(read);
                    let next = self.frontier(node).next_seq;
                    match highest {
                        Some(seq) if seq >= next => {
                            let source = ChainError::Gap { seq: next };
                            warn!(%node, %source, "chain is broken: the other chains go on");
                            self.broken.insert(node, source);
                        }
                        // A gap or a changed entry shows only in an audit: the mark stays until one passes.
                        _ if audit => {
                            self.broken.remove(&node);
                        }
                        _ => {}
                    }
                }
                // One bad chain must not stop the sync of every chain.
                Err(JournalError::Chain { node, source }) => {
                    warn!(%node, %source, "chain is broken: the other chains go on");
                    self.broken.insert(node, source);
                }
                Err(e) => return Err(e),
            }
        }

        self.audit = false;
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

    fn node_of(seed: u8) -> NodeId {
        NodeId::from_bytes(key(seed).verifying_key().to_bytes())
    }

    fn journal(remote: &Arc<MemoryRemote>, seed: u8) -> Journal<MemoryRemote> {
        Journal::new(
            remote.clone(),
            key(seed),
            entry::test_sealer(),
            Frontiers::new(),
        )
    }

    fn put(key: &str) -> Action {
        Action::Put {
            bucket: "b".into(),
            key: key.into(),
            manifest_id: ObjectId::from_bytes([1u8; 32]),
            inline_manifest: None,
            hlc: 1,
        }
    }

    async fn overwrite(remote: &MemoryRemote, entry: &Entry) {
        let bytes = entry.to_wire();
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
        let decoded = Entry::from_wire(&stored, &entry::test_sealer()).unwrap();
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
        let entry = a.prepare(vec![put("k")], Seen::new()).unwrap();

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
        let entry = before.prepare(vec![put("k")], Seen::new()).unwrap();
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
        let prepared = first.prepare(vec![put("from first")], Seen::new()).unwrap();
        zombie
            .append(vec![put("from zombie")], Seen::new())
            .await
            .unwrap();

        assert_eq!(first.commit(&prepared).await.unwrap(), Commit::SeqTaken);
        assert_eq!(first.frontier(first.node()).next_seq, 1);

        let retried = first.prepare(vec![put("from first")], Seen::new()).unwrap();
        assert_eq!(retried.seq, 1);
        assert_eq!(first.commit(&retried).await.unwrap(), Commit::Written);
    }

    #[tokio::test]
    async fn test_is_written_finds_only_the_same_entry() {
        let remote = Arc::new(MemoryRemote::default());
        let mut first = journal(&remote, 1);
        let mut zombie = journal(&remote, 1);
        let prepared = first.prepare(vec![put("from first")], Seen::new()).unwrap();

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
        let prepared = first.prepare(vec![put("from first")], Seen::new()).unwrap();
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
        let mut b = Journal::new(remote.clone(), key(2), entry::test_sealer(), saved);
        let entries = b.sync_all().await.unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seq, 1);
    }

    #[tokio::test]
    async fn test_tampered_entry_stops_the_reader() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        a.append(vec![put("x")], Seen::new()).await.unwrap();
        let signed = a.append(vec![put("y")], Seen::new()).await.unwrap();
        let forged = signed.forged(vec![put("forged")], &entry::test_sealer());
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
        let signed = c.append(vec![put("c1")], Seen::new()).await.unwrap();
        b.append(vec![put("b")], Seen::new()).await.unwrap();
        let tampered = signed.forged(vec![put("forged")], &entry::test_sealer());
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
        let tampered = good.forged(vec![put("forged")], &entry::test_sealer());
        overwrite(&remote, &tampered).await;
        let mut reader = journal(&remote, 9);
        assert!(reader.sync_all().await.unwrap().is_empty());
        assert!(reader.broken().contains_key(&c.node()));

        overwrite(&remote, &good).await;
        let entries = reader.sync_all().await.unwrap();
        assert_eq!(entries, vec![good]);
        assert!(
            !reader.broken().is_empty(),
            "the mark stays until an audit passes"
        );
        reader.audit_next_sync();
        reader.sync_all().await.unwrap();

        assert!(reader.broken().is_empty());
    }

    #[tokio::test]
    async fn test_reader_names_a_gap_as_a_broken_chain() {
        let remote = Arc::new(MemoryRemote::default());
        let a = journal(&remote, 1);
        let orphan = Entry::sign(
            &key(1),
            1,
            [0u8; 32],
            5,
            Seen::new(),
            vec![put("x")],
            &entry::test_sealer(),
        );
        overwrite(&remote, &orphan).await;

        let mut b = journal(&remote, 2);

        let result = b.sync_node(a.node()).await;

        assert!(
            matches!(
                result,
                Err(JournalError::Chain {
                    source: ChainError::Gap { seq: 0 },
                    ..
                })
            ),
            "{result:?}"
        );
        assert_eq!(b.frontier(a.node()), Frontier::GENESIS);
    }

    fn wall() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    async fn entry_at(remote: &MemoryRemote, seed: u8, hlc: u64) {
        let entry = Entry::sign(
            &key(seed),
            0,
            [0u8; 32],
            hlc,
            Seen::new(),
            vec![put("k")],
            &entry::test_sealer(),
        );
        overwrite(remote, &entry).await;
    }

    /// R = 2 s: an entry at most R ahead reads, one more ahead is a broken chain until the clock
    /// of the reader passes it, and the clock never takes it.
    #[tokio::test]
    async fn test_entry_more_than_r_ahead_breaks_the_chain_until_the_clock_passes_it() {
        let remote = Arc::new(MemoryRemote::default());
        let r = std::time::Duration::from_secs(2);
        let near = wall() + r.as_nanos() as u64 - 200_000_000;
        entry_at(&remote, 1, near).await;
        let far = wall() + r.as_nanos() as u64 + 1_000_000_000;
        entry_at(&remote, 2, far).await;
        let mut reader = journal(&remote, 9);
        reader.set_max_ahead(r);

        assert_eq!(reader.sync_node(node_of(1)).await.unwrap().len(), 1);
        let result = reader.sync_node(node_of(2)).await;
        assert!(
            matches!(
                result,
                Err(JournalError::Chain {
                    source: ChainError::FutureHlc { seq: 0 },
                    ..
                })
            ),
            "{result:?}"
        );
        assert!(
            reader.clock.tick().unwrap() < far,
            "the clock does not take it"
        );

        std::thread::sleep(std::time::Duration::from_millis(1500));

        assert_eq!(reader.sync_node(node_of(2)).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_reader_clock_passes_the_writer_clock() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        let mut b = journal(&remote, 2);
        a.clock.witness(wall() + 3_600_000_000_000);
        let from_a = a.append(vec![put("x")], Seen::new()).await.unwrap();

        b.sync_all().await.unwrap();
        let from_b = b.append(vec![put("y")], Seen::new()).await.unwrap();

        assert!(from_b.hlc > from_a.hlc);
    }

    #[tokio::test]
    async fn test_reader_with_another_key_names_the_chain_it_cannot_open() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        a.append(vec![put("x")], Seen::new()).await.unwrap();
        let other = seal::RepoKey::from_hex(&"08".repeat(32)).unwrap().keys();
        let mut reader = Journal::new(
            remote.clone(),
            key(9),
            other.sealer().clone(),
            Frontiers::new(),
        );

        let result = reader.sync_node(a.node()).await;

        assert!(matches!(
            result,
            Err(JournalError::Chain {
                source: ChainError::Sealed { seq: 0 },
                ..
            })
        ));
    }
}
