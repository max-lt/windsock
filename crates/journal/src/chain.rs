//! Chain validation. No I/O: the journal shell feeds entries to a [`Frontier`].

use model::NodeId;
use serde::{Deserialize, Serialize};

use crate::entry::{Entry, EntryHash};

/// Position of a reader in one node chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontier {
    /// Seq of the next entry to read or write.
    pub next_seq: u64,
    /// Hash of the last entry read. All zero before the first one.
    pub last_hash: EntryHash,
    /// HLC of the last entry read. Zero before the first one.
    pub last_hlc: u64,
}

impl Frontier {
    /// Start of a chain: nothing read yet.
    pub const GENESIS: Self = Self {
        next_seq: 0,
        last_hash: [0u8; 32],
        last_hlc: 0,
    };

    /// Checks that `entry` extends the chain of `node` at this frontier.
    ///
    /// Links to other chains (`seen`) are not checked here: the index resolves
    /// them when it applies the entry.
    pub fn extend(&self, node: NodeId, entry: &Entry) -> Result<Frontier, ChainError> {
        if entry.node != node {
            return Err(ChainError::WrongNode {
                expected: node,
                actual: entry.node,
            });
        }

        if entry.seq != self.next_seq {
            return Err(ChainError::WrongSeq {
                expected: self.next_seq,
                actual: entry.seq,
            });
        }

        if entry.prev != self.last_hash {
            return Err(ChainError::BrokenLink { seq: entry.seq });
        }

        if entry.hlc <= self.last_hlc {
            return Err(ChainError::HlcNotRising {
                seq: entry.seq,
                hlc: entry.hlc,
                previous: self.last_hlc,
            });
        }

        // A link to the own chain could never be satisfied by a causal reader.
        if entry.seen.contains_key(&node) {
            return Err(ChainError::SelfLink { seq: entry.seq });
        }

        if !entry.signature_is_valid() {
            return Err(ChainError::BadSignature { seq: entry.seq });
        }

        if !entry.actions_are_intact() {
            return Err(ChainError::ActionsMismatch { seq: entry.seq });
        }

        Ok(Frontier {
            next_seq: entry.seq + 1,
            last_hash: entry.hash(),
            last_hlc: entry.hlc,
        })
    }
}

/// An entry does not extend the chain it was read from.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("entry {seq} is not a valid entry")]
    Malformed { seq: u64 },
    #[error("entry is from node {actual}, expected {expected}")]
    WrongNode { expected: NodeId, actual: NodeId },
    #[error("entry has seq {actual}, expected {expected}")]
    WrongSeq { expected: u64, actual: u64 },
    #[error("entry {seq} does not link to the previous entry")]
    BrokenLink { seq: u64 },
    #[error("entry {seq} has hlc {hlc}, not above {previous}")]
    HlcNotRising { seq: u64, hlc: u64, previous: u64 },
    #[error("entry {seq} links to its own chain")]
    SelfLink { seq: u64 },
    #[error("entry {seq} has an invalid signature")]
    BadSignature { seq: u64 },
    #[error("entry {seq} carries actions that were not signed")]
    ActionsMismatch { seq: u64 },
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use model::ObjectId;

    use super::*;
    use crate::entry::{Action, Link, Seen};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes(key(seed).verifying_key().to_bytes())
    }

    fn put() -> Action {
        Action::Put {
            bucket: "b".into(),
            key: "k".into(),
            manifest_id: ObjectId::from_bytes([1u8; 32]),
            inline_manifest: None,
        }
    }

    fn sign(seed: u8, seq: u64, prev: EntryHash, hlc: u64) -> Entry {
        Entry::sign(&key(seed), seq, prev, hlc, Seen::new(), vec![put()])
    }

    #[test]
    fn test_chain_of_two_entries_extends() {
        let first = sign(1, 0, [0u8; 32], 10);
        let after_first = Frontier::GENESIS.extend(node(1), &first).unwrap();
        let second = sign(1, 1, first.hash(), 11);
        let after_second = after_first.extend(node(1), &second).unwrap();

        assert_eq!(after_first.next_seq, 1);
        assert_eq!(after_second.next_seq, 2);
        assert_eq!(after_second.last_hash, second.hash());
        assert_eq!(after_second.last_hlc, 11);
    }

    #[test]
    fn test_entry_from_another_node_is_rejected() {
        let entry = sign(2, 0, [0u8; 32], 10);

        assert!(matches!(
            Frontier::GENESIS.extend(node(1), &entry),
            Err(ChainError::WrongNode { .. })
        ));
    }

    #[test]
    fn test_wrong_seq_is_rejected() {
        let entry = sign(1, 1, [0u8; 32], 10);

        assert_eq!(
            Frontier::GENESIS.extend(node(1), &entry),
            Err(ChainError::WrongSeq {
                expected: 0,
                actual: 1
            })
        );
    }

    #[test]
    fn test_broken_link_is_rejected() {
        let first = sign(1, 0, [0u8; 32], 10);
        let frontier = Frontier::GENESIS.extend(node(1), &first).unwrap();
        let second = sign(1, 1, [9u8; 32], 11);

        assert_eq!(
            frontier.extend(node(1), &second),
            Err(ChainError::BrokenLink { seq: 1 })
        );
    }

    #[test]
    fn test_hlc_must_rise() {
        let first = sign(1, 0, [0u8; 32], 10);
        let frontier = Frontier::GENESIS.extend(node(1), &first).unwrap();
        let second = sign(1, 1, first.hash(), 10);

        assert!(matches!(
            frontier.extend(node(1), &second),
            Err(ChainError::HlcNotRising { seq: 1, .. })
        ));
    }

    #[test]
    fn test_link_to_own_chain_is_rejected() {
        let seen = Seen::from([(
            node(1),
            Link {
                seq: 0,
                hash: [0u8; 32],
            },
        )]);
        let entry = Entry::sign(&key(1), 0, [0u8; 32], 10, seen, vec![put()]);

        assert_eq!(
            Frontier::GENESIS.extend(node(1), &entry),
            Err(ChainError::SelfLink { seq: 0 })
        );
    }

    #[test]
    fn test_forged_signature_is_rejected() {
        let mut entry = sign(1, 0, [0u8; 32], 10);
        entry.hlc = 11;

        assert_eq!(
            Frontier::GENESIS.extend(node(1), &entry),
            Err(ChainError::BadSignature { seq: 0 })
        );
    }

    #[test]
    fn test_swapped_actions_are_rejected() {
        let mut entry = sign(1, 0, [0u8; 32], 10);
        entry.actions = Some(vec![Action::Delete {
            bucket: "b".into(),
            key: "k".into(),
        }]);

        assert_eq!(
            Frontier::GENESIS.extend(node(1), &entry),
            Err(ChainError::ActionsMismatch { seq: 0 })
        );
    }

    #[test]
    fn test_redacted_entry_extends_the_chain() {
        let first = sign(1, 0, [0u8; 32], 10);
        let frontier = Frontier::GENESIS.extend(node(1), &first).unwrap();
        let second = sign(1, 1, first.hash(), 11);
        let third = sign(1, 2, second.hash(), 12);

        let after_second = frontier.extend(node(1), &second.redacted()).unwrap();
        let after_third = after_second.extend(node(1), &third).unwrap();

        assert_eq!(after_third.next_seq, 3);
    }
}
