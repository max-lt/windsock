//! Per-key and per-bucket state, and the rules that merge entries into it. No I/O.
//!
//! One key keeps every version it received, ordered by (hlc, node): the first
//! one is what a reader sees. The state is a function of the set of versions,
//! so every proxy reaches the same state whatever the order of application.

use journal::{Entry, Seen};
use model::{NodeId, ObjectId};
use serde::{Deserialize, Serialize};

/// An applied entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntryRef {
    pub node: NodeId,
    pub seq: u64,
}

impl EntryRef {
    pub fn of(entry: &Entry) -> Self {
        Self {
            node: entry.node,
            seq: entry.seq,
        }
    }
}

/// Did the writer of `from`, with `seen` at that time, know `target`?
pub fn knew(from: EntryRef, seen: &Seen, target: EntryRef) -> bool {
    if from.node == target.node {
        return target.seq < from.seq;
    }

    seen.get(&target.node)
        .is_some_and(|link| link.seq >= target.seq)
}

/// One write to a key. `manifest_id` is `None` for a delete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub hlc: u64,
    pub node: NodeId,
    pub seq: u64,
    pub manifest_id: Option<ObjectId>,
    /// What the writer had applied from the other chains.
    pub seen: Seen,
}

impl Version {
    pub fn entry_ref(&self) -> EntryRef {
        EntryRef {
            node: self.node,
            seq: self.seq,
        }
    }

    /// Last writer wins. The HLC rises along a chain, so (hlc, node) is unique.
    fn rank(&self) -> (u64, NodeId) {
        (self.hlc, self.node)
    }
}

/// Every version of one key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectState {
    /// Ordered by rank, highest first.
    pub versions: Vec<Version>,
}

impl ObjectState {
    /// The version a reader sees.
    pub fn head(&self) -> Option<&Version> {
        self.versions.first()
    }

    /// The manifest a reader gets. `None` when the key is deleted or absent.
    pub fn current(&self) -> Option<ObjectId> {
        self.head().and_then(|v| v.manifest_id)
    }

    /// Records the version that `entry` writes. Returns `false` when it was already recorded.
    pub fn record(&mut self, entry: &Entry, manifest_id: Option<ObjectId>) -> bool {
        let version = Version {
            hlc: entry.hlc,
            node: entry.node,
            seq: entry.seq,
            manifest_id,
            seen: entry.seen.clone(),
        };

        if self
            .versions
            .iter()
            .any(|v| v.entry_ref() == version.entry_ref())
        {
            return false;
        }

        self.versions.push(version);
        self.versions.sort_by_key(|v| std::cmp::Reverse(v.rank()));
        true
    }

    /// Versions the head's writer did not know: independent writes that a reader
    /// does not see. A writer that knows a version has a higher HLC, so a write that
    /// knew every side of a conflict becomes the head and ends it.
    pub fn conflicts(&self) -> Vec<EntryRef> {
        let Some(head) = self.head() else {
            return Vec::new();
        };

        self.versions[1..]
            .iter()
            .map(Version::entry_ref)
            .filter(|other| !knew(head.entry_ref(), &head.seen, *other))
            .collect()
    }

    pub fn is_conflicted(&self) -> bool {
        !self.conflicts().is_empty()
    }
}

/// State of one bucket name: the last create or delete wins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketState {
    pub exists: bool,
    pub owner: Option<String>,
    pub hlc: u64,
    pub node: NodeId,
}

impl BucketState {
    /// Applies a create (`Some(owner)`) or a delete (`None`) from `entry`.
    /// Returns `None` when a later write already won.
    pub fn apply(
        current: Option<&Self>,
        entry: &Entry,
        create: Option<Option<String>>,
    ) -> Option<Self> {
        if current.is_some_and(|c| (c.hlc, c.node) >= (entry.hlc, entry.node)) {
            return None;
        }

        Some(Self {
            exists: create.is_some(),
            owner: create.flatten(),
            hlc: entry.hlc,
            node: entry.node,
        })
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use journal::{Action, Link};

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes(key(seed).verifying_key().to_bytes())
    }

    fn manifest(n: u8) -> ObjectId {
        ObjectId::from_bytes([n; 32])
    }

    fn entry(seed: u8, seq: u64, hlc: u64, seen: Seen) -> Entry {
        let action = Action::Put {
            bucket: "b".into(),
            key: "k".into(),
            manifest_id: manifest(seed),
            inline_manifest: None,
        };
        Entry::sign(&key(seed), seq, [0u8; 32], hlc, seen, vec![action])
    }

    fn link(seed: u8, seq: u64) -> (NodeId, Link) {
        (
            node(seed),
            Link {
                seq,
                hash: [0u8; 32],
            },
        )
    }

    /// The same versions in every order give the same state.
    fn states_in_all_orders(entries: &[Entry]) -> Vec<ObjectState> {
        let mut states = Vec::new();

        for start in 0..entries.len() {
            let mut state = ObjectState::default();
            for i in 0..entries.len() {
                let e = &entries[(start + i) % entries.len()];
                state.record(e, Some(manifest(e.node.as_bytes()[0])));
            }
            states.push(state);
        }

        states
    }

    #[test]
    fn test_state_does_not_depend_on_the_order() {
        let a = entry(1, 0, 10, Seen::new());
        let b = entry(2, 0, 20, Seen::new());
        let d = entry(3, 0, 5, Seen::new());
        let c = entry(1, 1, 30, Seen::from([link(2, 0)]));

        let states = states_in_all_orders(&[a, b, d, c]);

        assert!(states.windows(2).all(|w| w[0] == w[1]));
        assert_eq!(states[0].versions.len(), 4);
    }

    #[test]
    fn test_writers_that_did_not_know_each_other_conflict() {
        let a = entry(1, 0, 10, Seen::new());
        let b = entry(2, 0, 20, Seen::new());
        let mut state = ObjectState::default();
        state.record(&a, Some(manifest(1)));
        state.record(&b, Some(manifest(2)));

        assert_eq!(state.conflicts(), vec![EntryRef::of(&a)]);
        assert_eq!(
            state.current(),
            Some(manifest(2)),
            "a reader gets the LWW winner"
        );
    }

    #[test]
    fn test_informed_overwrite_does_not_conflict() {
        let a = entry(1, 0, 10, Seen::new());
        let b = entry(2, 0, 20, Seen::from([link(1, 0)]));
        let mut state = ObjectState::default();
        state.record(&b, Some(manifest(2)));
        state.record(&a, Some(manifest(1)));

        assert!(!state.is_conflicted());
        assert_eq!(state.current(), Some(manifest(2)));
    }

    #[test]
    fn test_write_that_knew_both_sides_ends_the_conflict() {
        let a = entry(1, 0, 10, Seen::new());
        let b = entry(2, 0, 20, Seen::new());
        let resolving = entry(1, 1, 30, Seen::from([link(2, 0)]));
        let mut state = ObjectState::default();
        state.record(&a, Some(manifest(1)));
        state.record(&b, Some(manifest(2)));
        assert!(state.is_conflicted());

        state.record(&resolving, Some(manifest(3)));

        assert!(!state.is_conflicted());
        assert_eq!(state.current(), Some(manifest(3)));
    }

    #[test]
    fn test_write_that_knew_one_side_keeps_the_conflict() {
        let a = entry(1, 0, 10, Seen::new());
        let b = entry(2, 0, 20, Seen::new());
        let partial = entry(1, 1, 30, Seen::new());
        let mut state = ObjectState::default();
        state.record(&a, Some(manifest(1)));
        state.record(&b, Some(manifest(2)));

        state.record(&partial, Some(manifest(3)));

        assert_eq!(state.conflicts(), vec![EntryRef::of(&b)]);
    }

    #[test]
    fn test_delete_is_a_version_without_manifest() {
        let put = entry(1, 0, 10, Seen::new());
        let delete = entry(1, 1, 11, Seen::new());
        let mut state = ObjectState::default();
        state.record(&put, Some(manifest(1)));

        state.record(&delete, None);

        assert_eq!(state.current(), None);
        assert_eq!(state.versions.len(), 2);
        assert!(!state.is_conflicted());
    }

    #[test]
    fn test_same_entry_is_recorded_once() {
        let a = entry(1, 0, 10, Seen::new());
        let mut state = ObjectState::default();

        assert!(state.record(&a, Some(manifest(1))));
        assert!(!state.record(&a, Some(manifest(1))));
        assert_eq!(state.versions.len(), 1);
    }

    #[test]
    fn test_bucket_keeps_the_latest_write() {
        let create = entry(1, 0, 10, Seen::new());
        let delete = entry(2, 0, 20, Seen::new());

        let created = BucketState::apply(None, &create, Some(Some("max".into()))).unwrap();
        let deleted = BucketState::apply(Some(&created), &delete, None).unwrap();
        let stale = BucketState::apply(Some(&deleted), &create, Some(None));

        assert!(created.exists);
        assert_eq!(created.owner.as_deref(), Some("max"));
        assert!(!deleted.exists);
        assert_eq!(stale, None);
    }
}
