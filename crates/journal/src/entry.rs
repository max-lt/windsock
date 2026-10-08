//! Signed journal entries and their remote keys.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use keys::{Nonce, RepoKey};
use model::{NodeId, ObjectId, PackId};
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
        /// The manifest itself, when it is small enough to skip `manifests/<id>`.
        inline_manifest: Option<Vec<u8>>,
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
    /// The GC found these objects dead. Readers stop deduping against the packs.
    Condemn {
        packs: Vec<PackId>,
        manifests: Vec<ObjectId>,
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
/// The signature covers the keyed hash of the actions and not the actions
/// themselves, so a purge can drop them and keep the chain valid. The remote
/// form seals the actions: see [`Entry::encode`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub node: NodeId,
    pub seq: u64,
    /// Hash of the previous entry of the chain. All zero for seq 0.
    pub prev: EntryHash,
    pub hlc: u64,
    /// `prev` and `seen` together form a causal DAG across chains.
    pub seen: Seen,
    pub actions_hash: [u8; 32],
    /// The mutations of this entry, in order. `None` once a purge removed them.
    pub actions: Option<Vec<Action>>,
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
    actions_hash: &'a [u8; 32],
}

/// Keyed, so a reader of the remote cannot test a guess of the actions against it.
fn actions_hash(key: &RepoKey, actions: &[Action]) -> [u8; 32] {
    let bytes = postcard::to_allocvec(actions).expect("actions always serialize");
    key.hash(&bytes)
}

/// The remote form of an entry: the same fields, with the actions sealed.
#[derive(Serialize, Deserialize)]
struct Stored {
    node: NodeId,
    seq: u64,
    prev: EntryHash,
    hlc: u64,
    seen: Seen,
    actions_hash: [u8; 32],
    actions: Option<Vec<u8>>,
    signature: ([u8; 32], [u8; 32]),
}

/// Remote bytes that do not give an entry of this repository.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("not a valid entry")]
    Malformed,
    #[error("the actions do not open: another repository key, or corrupt data")]
    Sealed,
    #[error("the actions are not the signed ones")]
    ActionsMismatch,
}

fn content_hash(
    node: NodeId,
    seq: u64,
    prev: &EntryHash,
    hlc: u64,
    seen: &Seen,
    actions_hash: &[u8; 32],
) -> EntryHash {
    let content = Content {
        node,
        seq,
        prev,
        hlc,
        seen,
        actions_hash,
    };
    let bytes = postcard::to_allocvec(&content).expect("an entry always serializes");
    *blake3::hash(&bytes).as_bytes()
}

impl Entry {
    /// Builds and signs an entry. The node is the public key of `signing_key`.
    pub fn sign(
        signing_key: &SigningKey,
        key: &RepoKey,
        seq: u64,
        prev: EntryHash,
        hlc: u64,
        seen: Seen,
        actions: Vec<Action>,
    ) -> Self {
        let node = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
        let actions_hash = actions_hash(key, &actions);
        let hash = content_hash(node, seq, &prev, hlc, &seen, &actions_hash);
        let signature = signing_key.sign(&hash).to_bytes();
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
            actions_hash,
            actions: Some(actions),
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
            &self.actions_hash,
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

    /// The remote form. The actions are sealed with `nonce`, which must never repeat.
    pub fn encode(&self, key: &RepoKey, nonce: &Nonce) -> Vec<u8> {
        let actions = self.actions.as_ref().map(|actions| {
            let plain = postcard::to_allocvec(actions).expect("actions always serialize");
            key.seal(nonce, &plain)
        });
        let stored = Stored {
            node: self.node,
            seq: self.seq,
            prev: self.prev,
            hlc: self.hlc,
            seen: self.seen.clone(),
            actions_hash: self.actions_hash,
            actions,
            signature: self.signature,
        };
        postcard::to_allocvec(&stored).expect("an entry always serializes")
    }

    /// Reads the remote form. The actions, when present, must open and be the signed ones.
    /// The signature and the chain links are the job of [`crate::Frontier::extend`].
    pub fn decode(key: &RepoKey, bytes: &[u8]) -> Result<Self, DecodeError> {
        let stored: Stored = postcard::from_bytes(bytes).map_err(|_| DecodeError::Malformed)?;
        let actions = match &stored.actions {
            None => None,
            Some(sealed) => {
                let plain = key.open(sealed).map_err(|_| DecodeError::Sealed)?;
                let actions: Vec<Action> =
                    postcard::from_bytes(&plain).map_err(|_| DecodeError::Malformed)?;
                if actions_hash(key, &actions) != stored.actions_hash {
                    return Err(DecodeError::ActionsMismatch);
                }
                Some(actions)
            }
        };

        Ok(Self {
            node: stored.node,
            seq: stored.seq,
            prev: stored.prev,
            hlc: stored.hlc,
            seen: stored.seen,
            actions_hash: stored.actions_hash,
            actions,
            signature: stored.signature,
        })
    }

    /// The same entry without its actions. Its hash and signature do not change.
    pub fn redacted(&self) -> Self {
        Self {
            actions: None,
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

    fn repo() -> RepoKey {
        RepoKey::from_bytes([42u8; 32])
    }

    fn put() -> Action {
        Action::Put {
            bucket: "b".into(),
            key: "k".into(),
            manifest_id: ObjectId::from_bytes([1u8; 32]),
            inline_manifest: None,
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
        let entry = Entry::sign(&key(), &repo(), 0, [0u8; 32], 1, seen(), vec![put()]);

        assert!(entry.signature_is_valid());
        assert_eq!(entry.node.as_bytes(), &key().verifying_key().to_bytes());
    }

    #[test]
    fn test_changed_content_fails_verification() {
        let mut entry = Entry::sign(&key(), &repo(), 0, [0u8; 32], 1, seen(), vec![put()]);
        entry.hlc += 1;

        assert!(!entry.signature_is_valid());
    }

    #[test]
    fn test_changed_seen_fails_verification() {
        let mut entry = Entry::sign(&key(), &repo(), 0, [0u8; 32], 1, seen(), vec![put()]);
        entry.seen.clear();

        assert!(!entry.signature_is_valid());
    }

    #[test]
    fn test_decode_rejects_actions_that_were_not_signed() {
        let mut entry = Entry::sign(&key(), &repo(), 0, [0u8; 32], 1, seen(), vec![put()]);
        entry.actions = Some(vec![Action::Delete {
            bucket: "b".into(),
            key: "k".into(),
        }]);
        let bytes = entry.encode(&repo(), &[1u8; 24]);

        assert!(matches!(
            Entry::decode(&repo(), &bytes),
            Err(DecodeError::ActionsMismatch)
        ));
    }

    #[test]
    fn test_decode_rejects_another_key() {
        let entry = Entry::sign(&key(), &repo(), 0, [0u8; 32], 1, seen(), vec![put()]);
        let bytes = entry.encode(&repo(), &[1u8; 24]);

        assert!(matches!(
            Entry::decode(&RepoKey::from_bytes([43u8; 32]), &bytes),
            Err(DecodeError::Sealed)
        ));
    }

    #[test]
    fn test_remote_form_roundtrip() {
        let entry = Entry::sign(&key(), &repo(), 3, [9u8; 32], 42, seen(), vec![put()]);
        let decoded = Entry::decode(&repo(), &entry.encode(&repo(), &[1u8; 24])).unwrap();

        assert_eq!(decoded, entry);
        assert!(decoded.signature_is_valid());
    }

    #[test]
    fn test_remote_form_hides_the_actions() {
        let action = Action::Delete {
            bucket: "tenant-bucket".into(),
            key: "secret-key".into(),
        };
        let entry = Entry::sign(&key(), &repo(), 0, [0u8; 32], 1, seen(), vec![action]);
        let bytes = entry.encode(&repo(), &[1u8; 24]);

        assert!(!bytes.windows(13).any(|w| w == b"tenant-bucket"));
        assert!(!bytes.windows(10).any(|w| w == b"secret-key"));
    }

    #[test]
    fn test_actions_hash_depends_on_the_key() {
        let entry = Entry::sign(&key(), &repo(), 0, [0u8; 32], 1, seen(), vec![put()]);
        let other = Entry::sign(
            &key(),
            &RepoKey::from_bytes([43u8; 32]),
            0,
            [0u8; 32],
            1,
            seen(),
            vec![put()],
        );

        assert_ne!(entry.actions_hash, other.actions_hash);
    }

    #[test]
    fn test_redacted_entry_keeps_hash_and_signature() {
        let entry = Entry::sign(&key(), &repo(), 0, [0u8; 32], 1, seen(), vec![put()]);
        let redacted = entry.redacted();

        assert_eq!(redacted.actions, None);
        assert_eq!(redacted.hash(), entry.hash());
        assert!(redacted.signature_is_valid());
        assert_eq!(
            Entry::decode(&repo(), &redacted.encode(&repo(), &[1u8; 24])).unwrap(),
            redacted
        );
    }

    #[test]
    fn test_entry_roundtrips_through_postcard() {
        let entry = Entry::sign(&key(), &repo(), 3, [9u8; 32], 42, seen(), vec![put()]);
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
