//! Signed journal entries and their remote keys.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use model::{NodeId, ObjectId};
use serde::{Deserialize, Serialize};

/// blake3 hash of the signed content of an entry.
pub type EntryHash = [u8; 32];

/// Prefix of all entry keys.
pub const LOG_PREFIX: &str = "log/";

/// Prefix of all node markers.
pub const NODES_PREFIX: &str = "nodes/";

/// A mutation of the index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Put {
        bucket: String,
        key: String,
        manifest_id: ObjectId,
    },
    Delete {
        bucket: String,
        key: String,
    },
    CreateBucket {
        bucket: String,
        owner: Option<String>,
    },
    DeleteBucket {
        bucket: String,
    },
}

/// Last entry of another node that a writer had integrated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub seq: u64,
    pub hash: EntryHash,
}

/// Last entry of every other node that a writer had integrated.
pub type Seen = BTreeMap<NodeId, Link>;

/// One entry of a node chain, signed by the node.
///
/// The signature covers `blake3(action)` and not the action itself, so a purge
/// can drop the action and keep the chain valid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub node: NodeId,
    pub seq: u64,
    /// Hash of the previous entry of the chain. All zero for seq 0.
    pub prev: EntryHash,
    pub hlc: u64,
    /// `prev` and `seen` together form a causal DAG across chains.
    pub seen: Seen,
    pub action_hash: [u8; 32],
    /// `None` once a purge removed the action.
    pub action: Option<Action>,
    /// ed25519 signature over the content hash, in two halves: serde has no `[u8; 64]`.
    signature: ([u8; 32], [u8; 32]),
}

/// The signed part of an entry.
#[derive(Serialize)]
struct Content<'a> {
    node: NodeId,
    seq: u64,
    prev: &'a EntryHash,
    hlc: u64,
    seen: &'a Seen,
    action_hash: &'a [u8; 32],
}

fn action_hash(action: &Action) -> [u8; 32] {
    let bytes = postcard::to_allocvec(action).expect("an action always serializes");
    *blake3::hash(&bytes).as_bytes()
}

fn content_hash(
    node: NodeId,
    seq: u64,
    prev: &EntryHash,
    hlc: u64,
    seen: &Seen,
    action_hash: &[u8; 32],
) -> EntryHash {
    let content = Content {
        node,
        seq,
        prev,
        hlc,
        seen,
        action_hash,
    };
    let bytes = postcard::to_allocvec(&content).expect("an entry always serializes");
    *blake3::hash(&bytes).as_bytes()
}

impl Entry {
    /// Builds and signs an entry. The node is the public key of `key`.
    pub fn sign(
        key: &SigningKey,
        seq: u64,
        prev: EntryHash,
        hlc: u64,
        seen: Seen,
        action: Action,
    ) -> Self {
        let node = NodeId::from_bytes(key.verifying_key().to_bytes());
        let action_hash = action_hash(&action);
        let hash = content_hash(node, seq, &prev, hlc, &seen, &action_hash);
        let signature = key.sign(&hash).to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&signature[..32]);
        s.copy_from_slice(&signature[32..]);

        Self {
            node,
            seq,
            prev,
            hlc,
            seen,
            action_hash,
            action: Some(action),
            signature: (r, s),
        }
    }

    /// Hash of the signed content. The next entry of the chain stores it as `prev`.
    pub fn hash(&self) -> EntryHash {
        content_hash(
            self.node,
            self.seq,
            &self.prev,
            self.hlc,
            &self.seen,
            &self.action_hash,
        )
    }

    /// Checks the signature against the public key in `node`.
    pub fn signature_is_valid(&self) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(self.node.as_bytes()) else {
            return false;
        };

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&self.signature.0);
        signature[32..].copy_from_slice(&self.signature.1);

        verifying_key
            .verify(&self.hash(), &Signature::from_bytes(&signature))
            .is_ok()
    }

    /// Checks that the action, when present, is the one that was signed.
    pub fn action_is_intact(&self) -> bool {
        self.action
            .as_ref()
            .is_none_or(|action| action_hash(action) == self.action_hash)
    }

    /// The same entry without its action. Its hash and signature do not change.
    pub fn redacted(&self) -> Self {
        Self {
            action: None,
            ..self.clone()
        }
    }

    /// Remote key of this entry.
    pub fn remote_key(&self) -> String {
        entry_key(self.node, self.seq)
    }
}

/// Remote key of entry `seq` of `node`. The seq is zero-padded, so list order is numeric order.
pub fn entry_key(node: NodeId, seq: u64) -> String {
    format!("{LOG_PREFIX}{node}/{seq:020}")
}

/// Remote key of the marker that says `node` has a chain.
pub fn node_key(node: NodeId) -> String {
    format!("{NODES_PREFIX}{node}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn put() -> Action {
        Action::Put {
            bucket: "b".into(),
            key: "k".into(),
            manifest_id: ObjectId::from_bytes([1u8; 32]),
        }
    }

    fn seen() -> Seen {
        Seen::from([(
            NodeId::from_bytes([2u8; 32]),
            Link {
                seq: 4,
                hash: [3u8; 32],
            },
        )])
    }

    #[test]
    fn test_signed_entry_verifies() {
        let entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), put());

        assert!(entry.signature_is_valid());
        assert!(entry.action_is_intact());
        assert_eq!(entry.node.as_bytes(), &key().verifying_key().to_bytes());
    }

    #[test]
    fn test_changed_content_fails_verification() {
        let mut entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), put());
        entry.hlc += 1;

        assert!(!entry.signature_is_valid());
    }

    #[test]
    fn test_changed_seen_fails_verification() {
        let mut entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), put());
        entry.seen.clear();

        assert!(!entry.signature_is_valid());
    }

    #[test]
    fn test_changed_action_is_not_intact() {
        let mut entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), put());
        entry.action = Some(Action::Delete {
            bucket: "b".into(),
            key: "k".into(),
        });

        assert!(entry.signature_is_valid());
        assert!(!entry.action_is_intact());
    }

    #[test]
    fn test_redacted_entry_keeps_hash_and_signature() {
        let entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), put());
        let redacted = entry.redacted();

        assert_eq!(redacted.action, None);
        assert_eq!(redacted.hash(), entry.hash());
        assert!(redacted.signature_is_valid());
        assert!(redacted.action_is_intact());
    }

    #[test]
    fn test_entry_roundtrips_through_postcard() {
        let entry = Entry::sign(&key(), 3, [9u8; 32], 42, seen(), put());
        let bytes = postcard::to_allocvec(&entry).unwrap();
        let decoded: Entry = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(decoded, entry);
        assert!(decoded.signature_is_valid());
    }

    #[test]
    fn test_entry_keys_sort_in_seq_order() {
        let node = NodeId::from_bytes([0u8; 32]);
        let keys: Vec<_> = [9, 10, 100, u64::MAX]
            .map(|seq| entry_key(node, seq))
            .to_vec();

        assert!(keys.windows(2).all(|w| w[0] < w[1]));
        assert!(keys[0].starts_with(&format!("log/{node}/")));
    }
}
