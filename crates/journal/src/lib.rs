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
    redact_wire, seq_of,
};

pub use clock::{HybridClock, monotonic_nanos, wall_clock_nanos};
#[cfg(any(test, feature = "sim"))]
pub use clock::{set_manual_monotonic, set_manual_wall, suspend_manual};

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
    #[error("{0}: the store says the node marker exists, and a read finds no marker")]
    MarkerMissing(String),
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
    /// A sync of this process read the own chain.
    own_read: bool,
    /// Chains whose first entry has no valid MAC: no real entry ever. Only the full audits read
    /// them.
    fake: BTreeSet<NodeId>,
    /// The fake chains that the last sync did not read.
    skipped: usize,
    /// The broken chains that this process logged. A chain logs again after it reads well.
    reported_broken: BTreeSet<NodeId>,
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
            own_read: false,
            fake: BTreeSet::new(),
            skipped: 0,
            reported_broken: BTreeSet::new(),
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
        // A chain needs a rising HLC, and an entry HLC above each ack in it: no cap.
        self.clock.witness(frontier.last_hlc);
        let acks = actions.iter().filter_map(Action::hlc).max();
        self.clock.witness(acks.unwrap_or(0));
        let hlc = self.clock.tick().ok_or(JournalError::ClockOverflow)?;
        if acks.is_some_and(|ack| ack >= hlc) {
            return Err(JournalError::Chain {
                node: self.node,
                source: ChainError::ActionAfterEntry {
                    seq: frontier.next_seq,
                },
            });
        }
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
        // A reader finds a chain through its marker: an entry with no marker is invisible to the
        // GC, which then takes its packs for orphans.
        self.register().await?;
        let bytes = entry.to_wire();

        match self
            .remote
            .create(&entry.remote_key(), Bytes::from(bytes))
            .await
        {
            Ok(()) => {
                self.advance_own(entry).await?;
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
                            later: frontier.next_seq + 1,
                            key: next,
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
                        WireError::BadMac => ChainError::BadMac { seq },
                    },
                })?;
            frontier = frontier
                .extend(node, &entry)
                .map_err(|source| JournalError::Chain { node, source })?;
            // The chain reads again once this clock passes the HLC less R. The own chain passed the
            // signature and MAC checks above: its HLCs are acks of this node, never a forged value.
            if node != self.node && entry.hlc > clock::limit(self.max_ahead) {
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

    /// The chains with no valid first entry that the last sync did not read.
    pub fn skipped(&self) -> usize {
        self.skipped
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

    /// The highest seq in the listing of a chain, and an error when the last entry read changed.
    async fn audit_chain(&self, node: NodeId) -> Result<Option<u64>, JournalError> {
        let frontier = self.frontier(node);
        let highest = self.highest_after(node, frontier.next_seq).await?;

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

    /// The highest seq at or above `next` in the listing of a chain. The listing starts after
    /// the key of `next - 1`, so its cost is the new entries only.
    async fn highest_after(&self, node: NodeId, next: u64) -> Result<Option<u64>, JournalError> {
        const PAGE: usize = 1000;
        let prefix = format!("{LOG_PREFIX}{node}/");
        let mut after = match next.checked_sub(1) {
            Some(last) => entry_key(node, last),
            None => prefix.clone(),
        };
        let mut highest = None;
        loop {
            let keys = self.remote.list_after(&prefix, &after, PAGE).await?;
            for key in &keys {
                match seq_of(&prefix, key) {
                    Some(seq) => highest = highest.max(Some(seq)),
                    None => warn!(key, "a key under the log is not an entry: ignored"),
                }
            }
            match keys.last() {
                Some(last) if keys.len() == PAGE => after = last.clone(),
                _ => return Ok(highest),
            }
        }
    }

    /// Moves the chain of `node` back to `frontier` and marks it broken by `source`: its entries
    /// past `frontier` do not apply, and the next sync reads them again.
    pub fn give_up(&mut self, node: NodeId, frontier: Frontier, source: ChainError) {
        warn!(%node, %source, "chain is broken: the other chains go on");
        self.frontiers.insert(node, frontier);
        self.broken.insert(node, source);
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
        // The own chain with no frontier and no marker still orders the next acks: the first
        // sync of the process reads it.
        if !self.own_read {
            nodes.insert(self.node);
        }

        let mut marked = BTreeSet::new();
        for key in self.remote.list(NODES_PREFIX).await? {
            if let Some(node) = key.strip_prefix(NODES_PREFIX).and_then(|s| s.parse().ok()) {
                marked.insert(node);
            }
        }
        // A fake chain whose marker is gone was removed by the operator: its mark goes too.
        let gone: Vec<NodeId> = self.fake.difference(&marked).copied().collect();
        for node in gone {
            self.fake.remove(&node);
            self.broken.remove(&node);
        }
        nodes.extend(marked);

        let mut entries = self.take_stashed();
        // The flag stays set until a whole audit runs: a remote error must not skip it. A marked
        // chain is audited at each sync, so a proxy with no GC run clears the mark too.
        let mut queue: Vec<NodeId> = nodes.iter().copied().collect();
        let mut known = nodes;

        self.skipped = 0;
        while let Some(node) = queue.pop() {
            if !self.audit && self.fake.contains(&node) {
                self.skipped += 1;
                continue;
            }
            // Between the open and GC audits, a sync audits only the marked chains.
            let audit = self.audit || self.broken.contains_key(&node);
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
                    self.fake.remove(&node);
                    let next = self.frontier(node).next_seq;
                    match highest {
                        Some(seq) if seq >= next => {
                            let source = ChainError::Gap {
                                seq: next,
                                later: seq,
                                key: entry_key(node, seq),
                            };
                            self.mark_broken(node, source);
                        }
                        // A gap or a changed entry shows only in an audit: the mark stays until one passes.
                        _ if audit => {
                            self.broken.remove(&node);
                            self.reported_broken.remove(&node);
                        }
                        _ => {}
                    }
                }
                // One bad chain must not stop the sync of every chain.
                Err(JournalError::Chain { node, source }) => {
                    self.mark_broken(node, source);
                }
                Err(e) => return Err(e),
            }
        }

        self.audit = false;
        self.own_read = true;
        Ok(entries)
    }

    /// Marks a chain as broken, and logs it once per chain. A chain with no valid first entry
    /// needs no repository key to make: a normal sync stops to read it.
    fn mark_broken(&mut self, node: NodeId, source: ChainError) {
        let first = matches!(
            source,
            ChainError::BadMac { seq: 0 }
                | ChainError::Malformed { seq: 0 }
                | ChainError::Gap { seq: 0, .. }
        );
        if first && self.frontier(node) == Frontier::GENESIS && self.fake.insert(node) {
            warn!(
                key = entry_key(node, 0),
                "a chain with no valid first entry: read only at the open and GC audits"
            );
        }
        if self.reported_broken.insert(node) {
            warn!(%node, %source, "chain is broken: the other chains go on");
        }
        self.broken.insert(node, source);
    }

    /// Makes the node marker exist before the first entry of the chain. It is created once, as
    /// every remote object.
    async fn register(&mut self) -> Result<(), JournalError> {
        if self.registered {
            return Ok(());
        }
        let key = node_key(self.node);
        // A store that says the marker exists and then has none gets one more create.
        for _ in 0..2 {
            match self.remote.create(&key, Bytes::new()).await {
                Ok(()) => {}
                Err(RemoteError::AlreadyExists(_)) => match self.remote.get(&key).await? {
                    None => continue,
                    // The marker only says that the node exists: its content is never read.
                    Some(bytes) if !bytes.is_empty() => {
                        warn!(
                            key,
                            "the node marker holds data that this node did not write"
                        );
                    }
                    Some(_) => {}
                },
                Err(e) => return Err(e.into()),
            }
            self.registered = true;
            return Ok(());
        }
        error!(
            key,
            "the store says the node marker exists, and has no marker"
        );
        Err(JournalError::MarkerMissing(key))
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

    /// The clock can sit under the last own entry, for example after an open that capped it at
    /// wall + R. The next entry must still rank above the last one, or the own chain breaks.
    #[tokio::test]
    async fn test_next_entry_rises_above_the_last_own_entry() {
        let remote = Arc::new(MemoryRemote::default());
        let mut writer = journal(&remote, 1);
        let first = writer.append(vec![put("a")], Seen::new()).await.unwrap();
        let far = wall() + 3_600_000_000_000;
        let frontiers = Frontiers::from([(
            first.node,
            Frontier {
                next_seq: 1,
                last_hash: first.hash(),
                last_hlc: far,
            },
        )]);
        let restarted = Journal::new(remote.clone(), key(1), entry::test_sealer(), frontiers);

        let next = restarted.prepare(vec![put("b")], Seen::new()).unwrap();

        assert!(next.hlc > far, "{} is not above {far}", next.hlc);
    }

    /// A writer with bucket rights and no repo key: its own node key, an entry far ahead.
    async fn keyless_entry(remote: &MemoryRemote, redact: bool) -> (NodeId, u64) {
        let other = seal::RepoKey::from_hex(&"09".repeat(32)).unwrap().keys();
        let hlc = wall() + 20 * 3600 * 1_000_000_000;
        let entry = Entry::sign(
            &key(77),
            0,
            [0; 32],
            hlc,
            Seen::new(),
            vec![put("x")],
            other.sealer(),
        );
        let wire = match redact {
            true => redact_wire(&entry.to_wire()).unwrap().unwrap(),
            false => entry.to_wire(),
        };
        remote
            .put(&entry.remote_key(), Bytes::from(wire))
            .await
            .unwrap();
        remote
            .put(&node_key(entry.node), Bytes::new())
            .await
            .unwrap();
        (entry.node, hlc)
    }

    /// An entry from a writer with no repo key breaks its own chain only: the other chains
    /// read, and the clock of the reader does not take its HLC.
    #[tokio::test]
    async fn test_entry_with_no_repo_key_breaks_only_its_chain() {
        for redact in [true, false] {
            let remote = Arc::new(MemoryRemote::default());
            let mut a = journal(&remote, 1);
            let good = a.append(vec![put("a")], Seen::new()).await.unwrap();
            let (forged, hlc) = keyless_entry(&remote, redact).await;
            let mut reader = journal(&remote, 9);

            let entries = reader.sync_all().await.unwrap();

            assert_eq!(entries, vec![good], "redacted {redact}");
            assert!(
                matches!(reader.broken()[&forged], ChainError::BadMac { seq: 0 }),
                "{:?}",
                reader.broken()
            );
            assert!(
                reader.clock.tick().unwrap() < hlc,
                "the clock took the forged HLC"
            );
        }
    }

    /// A remote that counts the log keys that its listings return, and the log listings.
    #[derive(Default)]
    struct Counting {
        inner: MemoryRemote,
        keys: std::sync::atomic::AtomicUsize,
        lists: std::sync::atomic::AtomicUsize,
        gets: std::sync::atomic::AtomicUsize,
    }

    impl Counting {
        fn count(&self, prefix: &str, keys: &[String]) {
            if prefix.starts_with(LOG_PREFIX) {
                let ordering = std::sync::atomic::Ordering::SeqCst;
                self.lists.fetch_add(1, ordering);
                self.keys.fetch_add(keys.len(), ordering);
            }
        }
    }

    #[async_trait::async_trait]
    impl Remote for Counting {
        async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
            self.inner.put(key, data).await
        }

        async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
            self.inner.create(key, data).await
        }

        async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
            if key.starts_with(LOG_PREFIX) {
                self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner.get(key).await
        }

        async fn get_range(
            &self,
            key: &str,
            range: std::ops::Range<u64>,
        ) -> Result<Option<Bytes>, RemoteError> {
            self.inner.get_range(key, range).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
            let keys = self.inner.list(prefix).await?;
            self.count(prefix, &keys);
            Ok(keys)
        }

        async fn list_after(
            &self,
            prefix: &str,
            after: &str,
            limit: usize,
        ) -> Result<Vec<String>, RemoteError> {
            let keys = self.inner.list_after(prefix, after, limit).await?;
            self.count(prefix, &keys);
            Ok(keys)
        }
    }

    /// Chains whose first entry has no valid MAC never held a real entry: a normal sync does not
    /// read them. The full audits of the open and the GC still do.
    #[tokio::test]
    async fn test_fake_chains_cost_nothing_at_a_normal_sync() {
        let remote = Arc::new(Counting::default());
        let mut real = Journal::new(
            remote.clone(),
            key(1),
            entry::test_sealer(),
            Frontiers::new(),
        );
        real.append(vec![put("a")], Seen::new()).await.unwrap();
        for seed in 60..65 {
            let other = seal::RepoKey::from_hex(&"09".repeat(32)).unwrap().keys();
            let fake = Entry::sign(
                &key(seed),
                0,
                [0; 32],
                1,
                Seen::new(),
                vec![put("x")],
                other.sealer(),
            );
            remote
                .inner
                .put(&fake.remote_key(), Bytes::from(fake.to_wire()))
                .await
                .unwrap();
            remote
                .inner
                .put(&node_key(fake.node), Bytes::new())
                .await
                .unwrap();
        }
        let mut reader = Journal::new(
            remote.clone(),
            key(9),
            entry::test_sealer(),
            Frontiers::new(),
        );
        reader.sync_all().await.unwrap();
        assert_eq!(reader.broken().len(), 5);
        let ordering = std::sync::atomic::Ordering::SeqCst;
        remote.gets.store(0, ordering);
        remote.lists.store(0, ordering);

        reader.sync_all().await.unwrap();

        // The real chain and the own chain: the next seq and the gap probe each.
        assert_eq!(remote.gets.load(ordering), 4);
        assert_eq!(remote.lists.load(ordering), 0);
        assert_eq!(reader.skipped(), 5);
        assert_eq!(reader.broken().len(), 5, "the fake chains stay marked");
    }

    /// The own chain is exempt from the FutureHlc check only after the signature and MAC checks:
    /// a far own entry that fails them moves no clock, and its chain is broken and named.
    #[tokio::test]
    async fn test_far_own_entry_with_a_bad_signature_or_mac_moves_no_clock() {
        for tamper in [entry::with_bad_signature, entry::with_bad_mac] {
            let remote = Arc::new(MemoryRemote::default());
            let far = clock::wall_clock_nanos() + 365 * 24 * 3600 * 1_000_000_000;
            let entry = Entry::sign(
                &key(1),
                0,
                [0; 32],
                far,
                Seen::new(),
                vec![put("a")],
                &entry::test_sealer(),
            );
            let entry = tamper(entry);
            remote
                .put(&entry.remote_key(), Bytes::from(entry.to_wire()))
                .await
                .unwrap();
            remote
                .put(&node_key(entry.node), Bytes::new())
                .await
                .unwrap();
            let mut own = Journal::new(
                remote.clone(),
                key(1),
                entry::test_sealer(),
                Frontiers::new(),
            );

            own.sync_all().await.unwrap();

            assert!(own.clock().last() < far, "the clock took a far HLC");
            assert!(own.broken().contains_key(&entry.node));
        }
    }

    /// A chain with garbage at seq 0, or with seq 1 and no seq 0, needs no key either.
    #[tokio::test]
    async fn test_chains_with_no_valid_first_entry_cost_nothing_at_a_normal_sync() {
        let remote = Arc::new(Counting::default());
        let mut real = Journal::new(
            remote.clone(),
            key(1),
            entry::test_sealer(),
            Frontiers::new(),
        );
        real.append(vec![put("a")], Seen::new()).await.unwrap();
        for seed in 60..66 {
            let node = NodeId::from_bytes(key(seed).verifying_key().to_bytes());
            let seq = if seed < 63 { 0 } else { 1 };
            remote
                .inner
                .put(&entry_key(node, seq), Bytes::from_static(b"x"))
                .await
                .unwrap();
            remote
                .inner
                .put(&node_key(node), Bytes::new())
                .await
                .unwrap();
        }
        let mut reader = Journal::new(
            remote.clone(),
            key(9),
            entry::test_sealer(),
            Frontiers::new(),
        );
        reader.sync_all().await.unwrap();
        assert_eq!(reader.broken().len(), 6);
        let ordering = std::sync::atomic::Ordering::SeqCst;
        remote.gets.store(0, ordering);
        remote.lists.store(0, ordering);

        reader.sync_all().await.unwrap();

        assert_eq!(remote.gets.load(ordering), 4);
        assert_eq!(remote.lists.load(ordering), 0);
        assert_eq!(reader.skipped(), 6);
        assert_eq!(reader.broken().len(), 6, "the fake chains stay marked");
    }

    /// The operator removes the objects of a fake chain: the next normal sync drops its mark,
    /// also on a proxy with no GC run.
    #[tokio::test]
    async fn test_fake_chain_mark_goes_with_its_marker() {
        use remote::Sweep;
        let remote = Arc::new(MemoryRemote::default());
        let other = seal::RepoKey::from_hex(&"09".repeat(32)).unwrap().keys();
        let fake = Entry::sign(
            &key(60),
            0,
            [0; 32],
            1,
            Seen::new(),
            vec![put("x")],
            other.sealer(),
        );
        remote
            .put(&fake.remote_key(), Bytes::from(fake.to_wire()))
            .await
            .unwrap();
        remote
            .put(&node_key(fake.node), Bytes::new())
            .await
            .unwrap();
        let mut reader = journal(&remote, 9);
        reader.sync_all().await.unwrap();
        assert!(reader.broken().contains_key(&fake.node));

        remote.delete(&fake.remote_key()).await.unwrap();
        remote.delete(&node_key(fake.node)).await.unwrap();
        reader.sync_all().await.unwrap();

        assert!(reader.broken().is_empty(), "{:?}", reader.broken());
    }

    /// A chain with a real entry that later fails stays audited at each sync: it can be a real
    /// chain that a fault broke.
    #[tokio::test]
    async fn test_real_chain_that_fails_later_is_audited_at_each_sync() {
        let remote = Arc::new(Counting::default());
        let mut real = Journal::new(
            remote.clone(),
            key(1),
            entry::test_sealer(),
            Frontiers::new(),
        );
        let first = real.append(vec![put("a")], Seen::new()).await.unwrap();
        let other = seal::RepoKey::from_hex(&"09".repeat(32)).unwrap().keys();
        let bad = Entry::sign(
            &key(1),
            1,
            first.hash(),
            5,
            Seen::new(),
            vec![put("x")],
            other.sealer(),
        );
        remote
            .inner
            .put(&bad.remote_key(), Bytes::from(bad.to_wire()))
            .await
            .unwrap();
        let mut reader = Journal::new(
            remote.clone(),
            key(9),
            entry::test_sealer(),
            Frontiers::new(),
        );
        reader.sync_all().await.unwrap();
        assert!(reader.broken().contains_key(&first.node));
        let ordering = std::sync::atomic::Ordering::SeqCst;
        remote.lists.store(0, ordering);

        reader.sync_all().await.unwrap();

        assert_eq!(
            remote.lists.load(ordering),
            1,
            "the marked real chain is audited"
        );
        assert_eq!(reader.skipped(), 0);
    }

    /// An audit of a long chain lists the keys after the frontier, not the whole chain.
    #[tokio::test]
    async fn test_audit_lists_only_the_keys_after_the_frontier() {
        let remote = Arc::new(Counting::default());
        let mut writer = Journal::new(
            remote.clone(),
            key(1),
            entry::test_sealer(),
            Frontiers::new(),
        );
        for n in 0..30 {
            writer
                .append(vec![put(&format!("k{n}"))], Seen::new())
                .await
                .unwrap();
        }
        let mut reader = Journal::new(
            remote.clone(),
            key(9),
            entry::test_sealer(),
            Frontiers::new(),
        );
        reader.sync_all().await.unwrap();
        writer.append(vec![put("new")], Seen::new()).await.unwrap();
        remote.keys.store(0, std::sync::atomic::Ordering::SeqCst);

        reader.audit_next_sync();
        reader.sync_all().await.unwrap();

        assert!(remote.keys.load(std::sync::atomic::Ordering::SeqCst) <= 1);
    }

    /// A sync with one marked chain audits that chain only. The full audit is for the open and
    /// the GC.
    #[tokio::test]
    async fn test_sync_audits_only_the_marked_chains() {
        let remote = Arc::new(Counting::default());
        let mut chains = Vec::new();
        for seed in 1..=3 {
            let mut chain = Journal::new(
                remote.clone(),
                key(seed),
                entry::test_sealer(),
                Frontiers::new(),
            );
            chain.append(vec![put("a")], Seen::new()).await.unwrap();
            chains.push(chain);
        }
        let marked = chains[0].node();
        remote
            .inner
            .put(&entry_key(marked, 5), Bytes::from_static(b"not an entry"))
            .await
            .unwrap();
        let mut reader = Journal::new(
            remote.clone(),
            key(9),
            entry::test_sealer(),
            Frontiers::new(),
        );
        reader.sync_all().await.unwrap();
        assert_eq!(
            reader.broken().keys().copied().collect::<Vec<_>>(),
            vec![marked]
        );
        remote.lists.store(0, std::sync::atomic::Ordering::SeqCst);

        reader.sync_all().await.unwrap();

        assert_eq!(remote.lists.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A key under log/<node>/ that is not 20 digits is not an entry: it breaks no chain, and no
    /// error names a key that is not in the bucket.
    #[tokio::test]
    async fn test_log_key_that_is_not_a_canonical_seq_is_ignored() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        a.append(vec![put("a")], Seen::new()).await.unwrap();
        let odd = format!("{LOG_PREFIX}{}/7777", a.node());
        remote.put(&odd, Bytes::from_static(b"x")).await.unwrap();

        let mut fresh = journal(&remote, 1);
        fresh.sync_all().await.unwrap();

        assert!(fresh.broken().is_empty(), "{:?}", fresh.broken());
    }

    /// A gap names the key of the later entry as it is in the bucket.
    #[tokio::test]
    async fn test_gap_names_the_key_that_is_in_the_bucket() {
        let remote = Arc::new(MemoryRemote::default());
        let mut a = journal(&remote, 1);
        a.append(vec![put("a")], Seen::new()).await.unwrap();
        let far = entry_key(a.node(), 999);
        remote.put(&far, Bytes::from_static(b"x")).await.unwrap();

        let mut reader = journal(&remote, 9);
        reader.sync_all().await.unwrap();

        let cause = reader.broken()[&a.node()].to_string();
        assert!(cause.contains(&far), "{cause}");
    }

    /// A node with a lost index and no marker must still read its own chain, or its next acks
    /// rank under its own entries.
    #[tokio::test]
    async fn test_own_chain_is_read_with_no_frontier_and_no_marker() {
        use remote::Sweep;
        let remote = Arc::new(MemoryRemote::default());
        let mut first = journal(&remote, 1);
        let written = first.append(vec![put("a")], Seen::new()).await.unwrap();
        remote.delete(&node_key(first.node())).await.unwrap();

        let mut fresh = journal(&remote, 1);
        let entries = fresh.sync_all().await.unwrap();

        assert_eq!(entries, vec![written]);
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
        // The marked chain is audited at this sync: the mark goes once the chain reads.
        assert_eq!(entries, vec![good]);
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
                    source: ChainError::Gap { seq: 0, .. },
                    ..
                })
            ),
            "{result:?}"
        );
        assert_eq!(b.frontier(a.node()), Frontier::GENESIS);
    }

    fn wall() -> u64 {
        crate::wall_clock_nanos()
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
        set_manual_wall(Some(1_900_000_000_000_000_000));
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

        set_manual_wall(Some(wall() + 1_500_000_000));

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
                source: ChainError::BadMac { seq: 0 },
                ..
            })
        ));
    }
}
