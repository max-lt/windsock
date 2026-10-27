//! Signed journal entries and their remote keys.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use model::{NodeId, ObjectId, PackId};
use seal::{Kind, Sealer};
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
/// The actions go to the remote sealed with the repository key. The signature covers
/// `blake3(sealed actions)` and not the actions themselves, so a purge can drop them and keep
/// the chain valid.
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
    /// The actions as the remote holds them. `None` once a purge removed them.
    sealed: Option<Vec<u8>>,
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

/// The form of an entry on the remote: the sealed actions, never the clear ones.
#[derive(Serialize, Deserialize)]
struct Wire {
    node: NodeId,
    seq: u64,
    prev: EntryHash,
    hlc: u64,
    seen: Seen,
    actions_hash: [u8; 32],
    sealed: Option<Vec<u8>>,
    signature: ([u8; 32], [u8; 32]),
}

/// An entry from the remote does not read back.
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    Malformed,
    /// The sealed actions are not the ones that were signed.
    ActionsMismatch,
    /// The sealed actions do not open: another repository key, or changed bytes.
    Sealed,
}

fn actions_hash(sealed: &[u8]) -> [u8; 32] {
    *blake3::hash(sealed).as_bytes()
}

/// The associated data of the sealed actions, so they do not open as another entry.
fn seal_context(node: NodeId, seq: u64) -> Vec<u8> {
    [node.as_bytes().as_slice(), &seq.to_le_bytes()].concat()
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
    /// Builds and signs an entry. The node is the public key of `key`.
    pub fn sign(
        key: &SigningKey,
        seq: u64,
        prev: EntryHash,
        hlc: u64,
        seen: Seen,
        actions: Vec<Action>,
        sealer: &Sealer,
    ) -> Self {
        let node = NodeId::from_bytes(key.verifying_key().to_bytes());
        let plain = postcard::to_allocvec(&actions).expect("actions always serialize");
        let sealed = sealer.seal(Kind::Actions, &seal_context(node, seq), &plain);
        let actions_hash = actions_hash(&sealed);
        let hash = content_hash(node, seq, &prev, hlc, &seen, &actions_hash);
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
            actions_hash,
            actions: Some(actions),
            sealed: Some(sealed),
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

    /// Checks that the actions, when present, are the ones that were signed.
    pub fn actions_are_intact(&self) -> bool {
        match (&self.actions, &self.sealed) {
            (None, None) => true,
            (Some(_), Some(sealed)) => actions_hash(sealed) == self.actions_hash,
            _ => false,
        }
    }

    /// The same entry without its actions. Its hash and signature do not change.
    pub fn redacted(&self) -> Self {
        Self {
            actions: None,
            sealed: None,
            ..self.clone()
        }
    }

    /// The bytes that the remote holds for this entry.
    pub fn to_wire(&self) -> Vec<u8> {
        let wire = Wire {
            node: self.node,
            seq: self.seq,
            prev: self.prev,
            hlc: self.hlc,
            seen: self.seen.clone(),
            actions_hash: self.actions_hash,
            sealed: self.sealed.clone(),
            signature: self.signature,
        };
        postcard::to_allocvec(&wire).expect("an entry always serializes")
    }

    /// Reads an entry from the remote and opens its actions.
    pub fn from_wire(bytes: &[u8], sealer: &Sealer) -> Result<Self, WireError> {
        let wire: Wire = postcard::from_bytes(bytes).map_err(|_| WireError::Malformed)?;
        let actions = match &wire.sealed {
            None => None,
            Some(sealed) if actions_hash(sealed) != wire.actions_hash => {
                return Err(WireError::ActionsMismatch);
            }
            Some(sealed) => {
                let context = seal_context(wire.node, wire.seq);
                let plain = sealer
                    .open(Kind::Actions, &context, sealed)
                    .map_err(|_| WireError::Sealed)?;
                Some(postcard::from_bytes(&plain).map_err(|_| WireError::Malformed)?)
            }
        };

        Ok(Self {
            node: wire.node,
            seq: wire.seq,
            prev: wire.prev,
            hlc: wire.hlc,
            seen: wire.seen,
            actions_hash: wire.actions_hash,
            actions,
            sealed: wire.sealed,
            signature: wire.signature,
        })
    }

    /// Remote key of this entry.
    pub fn remote_key(&self) -> String {
        entry_key(self.node, self.seq)
    }
}

/// The remote bytes of an entry without its actions, or `None` when a purge already removed
/// them. Needs no key: the hash and the signature do not change.
pub fn redact_wire(bytes: &[u8]) -> Result<Option<Vec<u8>>, WireError> {
    let mut wire: Wire = postcard::from_bytes(bytes).map_err(|_| WireError::Malformed)?;
    if wire.sealed.take().is_none() {
        return Ok(None);
    }
    Ok(Some(
        postcard::to_allocvec(&wire).expect("an entry always serializes"),
    ))
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
impl Entry {
    /// The same signed entry with other actions sealed in, as a forger would write it.
    pub(crate) fn forged(&self, actions: Vec<Action>, sealer: &Sealer) -> Self {
        let plain = postcard::to_allocvec(&actions).expect("actions always serialize");
        let sealed = sealer.seal(Kind::Actions, &seal_context(self.node, self.seq), &plain);
        Self {
            actions: Some(actions),
            sealed: Some(sealed),
            ..self.clone()
        }
    }
}

/// A fixed repository key for tests.
#[cfg(test)]
pub(crate) fn test_sealer() -> Sealer {
    seal::RepoKey::from_hex(&"07".repeat(32))
        .expect("a constant hex key parses")
        .keys()
        .sealer()
        .clone()
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
        let entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], &test_sealer());

        assert!(entry.signature_is_valid());
        assert!(entry.actions_are_intact());
        assert_eq!(entry.node.as_bytes(), &key().verifying_key().to_bytes());
    }

    #[test]
    fn test_changed_content_fails_verification() {
        let mut entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], &test_sealer());
        entry.hlc += 1;

        assert!(!entry.signature_is_valid());
    }

    #[test]
    fn test_changed_seen_fails_verification() {
        let mut entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], &test_sealer());
        entry.seen.clear();

        assert!(!entry.signature_is_valid());
    }

    #[test]
    fn test_changed_actions_are_not_intact() {
        let entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], &test_sealer());
        let forged = entry.forged(
            vec![Action::Delete {
                bucket: "b".into(),
                key: "k".into(),
            }],
            &test_sealer(),
        );

        assert!(forged.signature_is_valid());
        assert!(!forged.actions_are_intact());
    }

    #[test]
    fn test_changed_clear_actions_do_not_survive_the_wire_form() {
        let mut entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], &test_sealer());
        entry.actions = Some(vec![Action::Delete {
            bucket: "b".into(),
            key: "k".into(),
        }]);

        let read = Entry::from_wire(&entry.to_wire(), &test_sealer()).unwrap();

        assert_eq!(read.actions, Some(vec![put()]));
    }

    #[test]
    fn test_redacted_entry_keeps_hash_and_signature() {
        let entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], &test_sealer());
        let redacted = entry.redacted();

        assert_eq!(redacted.actions, None);
        assert_eq!(redacted.hash(), entry.hash());
        assert!(redacted.signature_is_valid());
        assert!(redacted.actions_are_intact());
    }

    #[test]
    fn test_entry_roundtrips_through_postcard() {
        let entry = Entry::sign(
            &key(),
            3,
            [9u8; 32],
            42,
            seen(),
            vec![put()],
            &test_sealer(),
        );
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

    #[test]
    fn test_wire_form_roundtrips_and_holds_no_clear_action() {
        let entry = Entry::sign(
            &key(),
            3,
            [9u8; 32],
            42,
            seen(),
            vec![put()],
            &test_sealer(),
        );

        let wire = entry.to_wire();

        assert_eq!(Entry::from_wire(&wire, &test_sealer()).unwrap(), entry);
        assert!(!wire.windows(b"bucket".len()).any(|w| w == b"bucket"));
    }

    #[test]
    fn test_wire_form_does_not_open_with_another_key() {
        let entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], &test_sealer());
        let other = seal::RepoKey::from_hex(&"08".repeat(32)).unwrap().keys();

        let result = Entry::from_wire(&entry.to_wire(), other.sealer());

        assert_eq!(result, Err(WireError::Sealed));
    }

    #[test]
    fn test_redacted_wire_form_keeps_the_hash_and_drops_the_actions() {
        let entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], &test_sealer());

        let redacted = redact_wire(&entry.to_wire()).unwrap().unwrap();
        let read = Entry::from_wire(&redacted, &test_sealer()).unwrap();

        assert_eq!(read.actions, None);
        assert_eq!(read.hash(), entry.hash());
        assert!(read.signature_is_valid());
        assert_eq!(redact_wire(&redacted).unwrap(), None);
    }
}
