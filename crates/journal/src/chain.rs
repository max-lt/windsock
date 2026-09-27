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

        if !entry.verify() {
            return Err(ChainError::BadSignature { seq: entry.seq });
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
    #[error("entry {seq} has an invalid signature")]
    BadSignature { seq: u64 },
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use model::ObjectId;

    use super::*;
    use crate::entry::Action;

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
        }
    }

    #[test]
    fn test_chain_of_two_entries_extends() {
        let first = Entry::sign(&key(1), 0, [0u8; 32], 10, put());
        let after_first = Frontier::GENESIS.extend(node(1), &first).unwrap();
        let second = Entry::sign(&key(1), 1, first.hash(), 11, put());
        let after_second = after_first.extend(node(1), &second).unwrap();

        assert_eq!(after_first.next_seq, 1);
        assert_eq!(after_second.next_seq, 2);
        assert_eq!(after_second.last_hash, second.hash());
        assert_eq!(after_second.last_hlc, 11);
    }

    #[test]
    fn test_entry_from_another_node_is_rejected() {
        let entry = Entry::sign(&key(2), 0, [0u8; 32], 10, put());

        assert!(matches!(
            Frontier::GENESIS.extend(node(1), &entry),
            Err(ChainError::WrongNode { .. })
        ));
    }

    #[test]
    fn test_wrong_seq_is_rejected() {
        let entry = Entry::sign(&key(1), 1, [0u8; 32], 10, put());

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
        let first = Entry::sign(&key(1), 0, [0u8; 32], 10, put());
        let frontier = Frontier::GENESIS.extend(node(1), &first).unwrap();
        let second = Entry::sign(&key(1), 1, [9u8; 32], 11, put());

        assert_eq!(
            frontier.extend(node(1), &second),
            Err(ChainError::BrokenLink { seq: 1 })
        );
    }

    #[test]
    fn test_hlc_must_rise() {
        let first = Entry::sign(&key(1), 0, [0u8; 32], 10, put());
        let frontier = Frontier::GENESIS.extend(node(1), &first).unwrap();
        let second = Entry::sign(&key(1), 1, first.hash(), 10, put());

        assert!(matches!(
            frontier.extend(node(1), &second),
            Err(ChainError::HlcNotRising { seq: 1, .. })
        ));
    }

    #[test]
    fn test_forged_signature_is_rejected() {
        let mut entry = Entry::sign(&key(1), 0, [0u8; 32], 10, put());
        entry.action = Action::Delete {
            bucket: "b".into(),
            key: "k".into(),
        };

        assert_eq!(
            Frontier::GENESIS.extend(node(1), &entry),
            Err(ChainError::BadSignature { seq: 0 })
        );
    }
}
