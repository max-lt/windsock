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
        /// HLC of the ack: the order of the versions of one key. At most the entry HLC.
        hlc: u64,
    },
    Delete {
        bucket: String,
        key: String,
        /// HLC of the ack: the order of the versions of one key. At most the entry HLC.
        hlc: u64,
    },
    CreateBucket {
        bucket: String,
        owner: Option<String>,
        /// HLC of the ack: the order of the writes to one bucket name.
        hlc: u64,
    },
    DeleteBucket {
        bucket: String,
        /// HLC of the ack: the order of the writes to one bucket name.
        hlc: u64,
    },
    /// The GC found these objects dead. Readers stop deduping against the packs.
    Condemn {
        packs: Vec<PackId>,
        manifests: Vec<ObjectId>,
    },
}

impl Action {
    /// The ack HLC of a write to a key or to a bucket name.
    pub fn hlc(&self) -> Option<u64> {
        match self {
            Action::Put { hlc, .. }
            | Action::Delete { hlc, .. }
            | Action::CreateBucket { hlc, .. }
            | Action::DeleteBucket { hlc, .. } => Some(*hlc),
            _ => None,
        }
    }
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
    /// Length of the sealed actions. Signed, so a reader knows it before it reads them.
    pub actions_len: u64,
    /// The mutations of this entry, in order. `None` once a purge removed them.
    pub actions: Option<Vec<Action>>,
    /// The actions as the remote holds them. `None` once a purge removed them.
    sealed: Option<Vec<u8>>,
    /// ed25519 signature over the content hash, in two halves: serde has no `[u8; 64]`.
    signature: ([u8; 32], [u8; 32]),
    /// MAC of the content hash under the repository key. A redaction keeps it.
    mac: [u8; 32],
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
    actions_len: u64,
}

/// The wire bytes after the sealed actions: the signature, then the MAC.
pub const TAIL_LEN: u64 = 96;

/// The signed fields of an entry, in wire order. Postcard writes a nested struct as its fields.
#[derive(Clone, Serialize, Deserialize)]
struct Fields {
    node: NodeId,
    seq: u64,
    prev: EntryHash,
    hlc: u64,
    seen: Seen,
    actions_hash: [u8; 32],
    actions_len: u64,
}

impl Fields {
    fn content_hash(&self) -> EntryHash {
        content_hash(
            self.node,
            self.seq,
            &self.prev,
            self.hlc,
            &self.seen,
            &self.actions_hash,
            self.actions_len,
        )
    }
}

/// The form of an entry on the remote: the sealed actions, never the clear ones.
#[derive(Serialize, Deserialize)]
struct Wire {
    fields: Fields,
    sealed: Option<Vec<u8>>,
    signature: ([u8; 32], [u8; 32]),
    mac: [u8; 32],
}

#[derive(Deserialize)]
struct Tail {
    signature: ([u8; 32], [u8; 32]),
    mac: [u8; 32],
}

fn parse_tail(bytes: &[u8]) -> Result<Tail, WireError> {
    if bytes.len() as u64 != TAIL_LEN {
        return Err(WireError::Malformed);
    }
    postcard::from_bytes(bytes).map_err(|_| WireError::Malformed)
}

fn check_mac(fields: &Fields, mac: &[u8; 32], sealer: &Sealer) -> Result<(), WireError> {
    match sealer.entry_mac_is_valid(&fields.content_hash(), mac) {
        true => Ok(()),
        false => Err(WireError::BadMac),
    }
}

/// The wire bytes of an entry up to its sealed actions, and where the rest of the entry lies.
pub struct EntryHead {
    fields: Fields,
    header_len: u64,
    sealed_len: Option<u64>,
}

impl EntryHead {
    /// Decodes the start of wire bytes, up to the length of the sealed actions.
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let (fields, rest) =
            postcard::take_from_bytes::<Fields>(bytes).map_err(|_| WireError::Malformed)?;
        let (sealed_len, rest) = match rest.split_first() {
            Some((0, rest)) => (None, rest),
            Some((1, rest)) => {
                let (len, rest) =
                    postcard::take_from_bytes::<u64>(rest).map_err(|_| WireError::Malformed)?;
                (Some(len), rest)
            }
            _ => return Err(WireError::Malformed),
        };
        // A length that the signed one does not give: no read of the rest, whatever the MAC.
        if sealed_len.is_some_and(|len| len != fields.actions_len) {
            return Err(WireError::ActionsMismatch);
        }
        Ok(Self {
            fields,
            header_len: (bytes.len() - rest.len()) as u64,
            sealed_len,
        })
    }

    /// The node that the header names.
    pub fn node(&self) -> NodeId {
        self.fields.node
    }

    /// The seq that the header names.
    pub fn seq(&self) -> u64 {
        self.fields.seq
    }

    /// The wire bytes before the sealed actions.
    pub fn header_len(&self) -> u64 {
        self.header_len
    }

    /// The length of the sealed actions, or `None` once a purge removed them.
    pub fn sealed_len(&self) -> Option<u64> {
        self.sealed_len
    }

    /// The length of the whole entry, or `None` when it overflows.
    pub fn wire_len(&self) -> Option<u64> {
        self.header_len
            .checked_add(self.sealed_len.unwrap_or(0))?
            .checked_add(TAIL_LEN)
    }

    /// The wire bytes of the entry with no actions, from this header and its tail: a prune reads
    /// no actions. Postcard writes the same fields to the same bytes.
    pub fn redacted_wire(&self, tail: &[u8]) -> Vec<u8> {
        let mut bytes = postcard::to_allocvec(&self.fields).expect("an entry always serializes");
        bytes.push(0);
        bytes.extend_from_slice(tail);
        bytes
    }

    /// Checks the MAC in `tail`. A writer with no repository key stops here, before its actions.
    pub fn check_tail(&self, tail: &[u8], sealer: &Sealer) -> Result<(), WireError> {
        check_mac(&self.fields, &parse_tail(tail)?.mac, sealer)
    }
}

/// An entry from the remote does not read back.
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    Malformed,
    /// The sealed actions are not the ones that were signed.
    ActionsMismatch,
    /// The sealed actions do not open: another repository key, or changed bytes.
    Sealed,
    /// The MAC under the repository key does not match: a writer with no repository key, or
    /// changed bytes.
    BadMac,
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
    actions_len: u64,
) -> EntryHash {
    let content = Content {
        node,
        seq,
        prev,
        hlc,
        seen,
        actions_hash,
        actions_len,
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
        let actions_len = sealed.len() as u64;
        let hash = content_hash(node, seq, &prev, hlc, &seen, &actions_hash, actions_len);
        let signature = key.sign(&hash).to_bytes();
        let mac = sealer.entry_mac(&hash);
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
            actions_len,
            actions: Some(actions),
            sealed: Some(sealed),
            signature: (r, s),
            mac,
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
            self.actions_len,
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
            (Some(_), Some(sealed)) => {
                sealed.len() as u64 == self.actions_len && actions_hash(sealed) == self.actions_hash
            }
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

    fn fields(&self) -> Fields {
        Fields {
            node: self.node,
            seq: self.seq,
            prev: self.prev,
            hlc: self.hlc,
            seen: self.seen.clone(),
            actions_hash: self.actions_hash,
            actions_len: self.actions_len,
        }
    }

    /// The bytes that the remote holds for this entry.
    pub fn to_wire(&self) -> Vec<u8> {
        let wire = Wire {
            fields: self.fields(),
            sealed: self.sealed.clone(),
            signature: self.signature,
            mac: self.mac,
        };
        postcard::to_allocvec(&wire).expect("an entry always serializes")
    }

    /// Wire bytes with the actions sealed and the MAC that `sealer` gives, from wire bytes whose
    /// `sealed` field holds the plain actions. The fuzz target reaches the code after the MAC and
    /// the seal with it. `None` when the bytes are not a wire entry.
    #[cfg(feature = "fuzz")]
    pub fn fuzz_wire(bytes: &[u8], sealer: &Sealer) -> Option<Vec<u8>> {
        let mut wire: Wire = postcard::from_bytes(bytes).ok()?;
        if let Some(plain) = &wire.sealed {
            let context = seal_context(wire.fields.node, wire.fields.seq);
            let sealed = sealer.seal(Kind::Actions, &context, plain);
            wire.fields.actions_hash = actions_hash(&sealed);
            wire.fields.actions_len = sealed.len() as u64;
            wire.sealed = Some(sealed);
        }
        wire.mac = sealer.entry_mac(&wire.fields.content_hash());
        Some(postcard::to_allocvec(&wire).expect("an entry always serializes"))
    }

    /// The wire bytes before the sealed actions: the part that a reader decodes first.
    pub fn header_len(&self) -> u64 {
        let fields = postcard::to_allocvec(&self.fields()).expect("an entry always serializes");
        let Some(sealed) = &self.sealed else {
            return fields.len() as u64 + 1;
        };
        // Some writes its tag, then the length of the bytes as a varint.
        let len = sealed.len() as u64;
        let varint = (u64::BITS - len.leading_zeros()).div_ceil(7).max(1) as u64;
        fields.len() as u64 + 1 + varint
    }

    /// The length of [`Entry::to_wire`], with no copy of the sealed actions.
    pub fn wire_len(&self) -> u64 {
        let sealed = self.sealed.as_ref().map_or(0, |sealed| sealed.len() as u64);
        self.header_len() + sealed + TAIL_LEN
    }

    /// Reads an entry from the remote and opens its actions.
    pub fn from_wire(bytes: &[u8], sealer: &Sealer) -> Result<Self, WireError> {
        // The checks of a ranged read come first, so both reads give the same error.
        EntryHead::parse(bytes)?;
        let wire: Wire = postcard::from_bytes(bytes).map_err(|_| WireError::Malformed)?;
        Self::checked(wire, sealer)
    }

    /// Reads an entry from the parts of its wire bytes, with the checks of [`Entry::from_wire`].
    pub fn from_parts(
        head: EntryHead,
        sealed: Option<Vec<u8>>,
        tail: &[u8],
        sealer: &Sealer,
    ) -> Result<Self, WireError> {
        if sealed.as_ref().map(|sealed| sealed.len() as u64) != head.sealed_len {
            return Err(WireError::Malformed);
        }
        let tail = parse_tail(tail)?;
        let wire = Wire {
            fields: head.fields,
            sealed,
            signature: tail.signature,
            mac: tail.mac,
        };
        Self::checked(wire, sealer)
    }

    fn checked(wire: Wire, sealer: &Sealer) -> Result<Self, WireError> {
        // The same order as EntryHead::parse: the signed length comes before the MAC.
        let len = wire.sealed.as_ref().map(|sealed| sealed.len() as u64);
        if len.is_some_and(|len| len != wire.fields.actions_len) {
            return Err(WireError::ActionsMismatch);
        }
        // Before any use of the header: a writer with no repository key stops here.
        check_mac(&wire.fields, &wire.mac, sealer)?;
        let fields = wire.fields;
        let actions = match &wire.sealed {
            None => None,
            Some(sealed) if actions_hash(sealed) != fields.actions_hash => {
                return Err(WireError::ActionsMismatch);
            }
            Some(sealed) => {
                let context = seal_context(fields.node, fields.seq);
                let plain = sealer
                    .open(Kind::Actions, &context, sealed)
                    .map_err(|_| WireError::Sealed)?;
                Some(postcard::from_bytes(&plain).map_err(|_| WireError::Malformed)?)
            }
        };

        Ok(Self {
            node: fields.node,
            seq: fields.seq,
            prev: fields.prev,
            hlc: fields.hlc,
            seen: fields.seen,
            actions_hash: fields.actions_hash,
            actions_len: fields.actions_len,
            actions,
            sealed: wire.sealed,
            signature: wire.signature,
            mac: wire.mac,
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

/// The seq of a key under `prefix` (`log/<node>/`): exactly 20 digits, as [`entry_key`] writes.
pub fn seq_of(prefix: &str, key: &str) -> Option<u64> {
    let digits = key.strip_prefix(prefix)?;
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
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

/// The entry with one bit of its signature changed. The MAC stays valid.
#[cfg(test)]
pub(crate) fn with_bad_signature(mut entry: Entry) -> Entry {
    entry.signature.0[0] ^= 1;
    entry
}

/// The entry with one bit of its MAC changed. The signature stays valid.
#[cfg(test)]
pub(crate) fn with_bad_mac(mut entry: Entry) -> Entry {
    entry.mac[0] ^= 1;
    entry
}

/// The header of `entry` with a signed and a wire length of `len`, as a writer with no repository
/// key makes it: the start of an entry of any size.
#[cfg(test)]
pub(crate) fn header_with_sealed_len(entry: &Entry, len: u64) -> Vec<u8> {
    let mut fields = entry.fields();
    fields.actions_len = len;
    header_with_wire_len(&fields, len)
}

/// The real header of `entry` with a wire length of `len` and its signed length, as a replay of a
/// real header and tail makes it.
#[cfg(test)]
pub(crate) fn header_with_replayed_len(entry: &Entry, len: u64) -> Vec<u8> {
    header_with_wire_len(&entry.fields(), len)
}

#[cfg(test)]
fn header_with_wire_len(fields: &Fields, len: u64) -> Vec<u8> {
    let mut bytes = postcard::to_allocvec(fields).expect("an entry always serializes");
    bytes.push(1);
    bytes.extend(postcard::to_allocvec(&len).expect("a length always serializes"));
    bytes
}

/// The longest header that an entry of `node` with `seen` can have: every number at its largest.
pub fn header_bound(node: NodeId, seen: &Seen) -> u64 {
    let fields = Fields {
        node,
        seq: u64::MAX,
        prev: [0; 32],
        hlc: u64::MAX,
        seen: seen.clone(),
        actions_hash: [0; 32],
        actions_len: u64::MAX,
    };
    let fields = postcard::to_allocvec(&fields).expect("an entry always serializes");
    // The Some tag, then the length of the sealed actions as a varint of at most 10 bytes.
    fields.len() as u64 + 1 + 10
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

    #[test]
    fn test_wire_len_is_the_length_of_the_wire_bytes() {
        for size in [0, 10, 200, 20_000] {
            let action = Action::Put {
                bucket: "b".into(),
                key: "k".repeat(size.max(1)),
                manifest_id: ObjectId::from_bytes([1; 32]),
                inline_manifest: None,
                hlc: 1,
            };
            let entry = Entry::sign(
                &key(),
                3,
                [2; 32],
                9,
                Seen::new(),
                vec![action],
                &test_sealer(),
            );

            assert_eq!(entry.wire_len(), entry.to_wire().len() as u64, "{size}");
            let redacted = entry.redacted();
            assert_eq!(redacted.wire_len(), redacted.to_wire().len() as u64);
        }
    }

    /// Pins the bytes that the MAC covers and the key that it uses: a change here makes
    /// every entry in every remote fail its MAC.
    #[test]
    fn test_entry_mac_known_answer() {
        let mut seen = Seen::new();
        seen.insert(
            NodeId::from_bytes([4; 32]),
            Link {
                seq: 5,
                hash: [6; 32],
            },
        );
        let content = content_hash(
            NodeId::from_bytes([1; 32]),
            7,
            &[2; 32],
            42,
            &seen,
            &[3; 32],
            8,
        );
        let mac = test_sealer().entry_mac(&content);

        let hex = |bytes: [u8; 32]| blake3::Hash::from_bytes(bytes).to_hex().to_string();
        assert_eq!(
            hex(content),
            "cfde6288a061158e09a1047a65eacb6bf6ec3c1f7699780467d29a433592bad0"
        );
        assert_eq!(
            hex(mac),
            "f6b1687b5bc050c9cda2a06784764957594ef11b641c106f81bc48376043b40e"
        );
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn put() -> Action {
        Action::Put {
            bucket: "b".into(),
            key: "k".into(),
            manifest_id: ObjectId::from_bytes([1u8; 32]),
            inline_manifest: None,
            hlc: 1,
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
                hlc: 1,
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
            hlc: 1,
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

        // The MAC fails first, before any use of the header or the sealed actions.
        assert_eq!(result, Err(WireError::BadMac));
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

    /// A key holder redacts an entry with no key: the mac stays valid, so readers take it.
    #[test]
    fn test_redacted_wire_form_keeps_a_valid_mac() {
        let entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], &test_sealer());

        let redacted = redact_wire(&entry.to_wire()).unwrap().unwrap();

        assert!(Entry::from_wire(&redacted, &test_sealer()).is_ok());
    }

    /// An entry signed by any node key but with no repository key does not read.
    #[test]
    fn test_entry_from_a_writer_with_no_repo_key_does_not_read() {
        let other = seal::RepoKey::from_hex(&"09".repeat(32)).unwrap().keys();
        let entry = Entry::sign(&key(), 0, [0u8; 32], 1, seen(), vec![put()], other.sealer());
        let redacted = redact_wire(&entry.to_wire()).unwrap().unwrap();

        for wire in [entry.to_wire(), redacted] {
            let read = Entry::from_wire(&wire, &test_sealer());
            assert_eq!(read.err(), Some(WireError::BadMac));
        }
    }

    /// Pins the wire layout of an entry, with fixed field values: the sealed actions hold a
    /// random nonce.
    #[test]
    fn test_entry_wire_form_is_stable() {
        let wire = Wire {
            fields: Fields {
                node: NodeId::from_bytes([1u8; 32]),
                seq: 3,
                prev: [5u8; 32],
                hlc: 7,
                seen: seen(),
                actions_hash: [6u8; 32],
                actions_len: 2,
            },
            sealed: Some(vec![9, 9]),
            signature: ([7u8; 32], [8u8; 32]),
            mac: [4u8; 32],
        };

        let bytes = postcard::to_allocvec(&wire).unwrap();

        assert_eq!(
            blake3::hash(&bytes).to_string(),
            "7dcd0c5e966ba66f06ece9494ae0d790792c0ed9a2d42919c50e5afe08fd2727"
        );
    }

    fn sized(size: usize) -> Entry {
        let action = Action::Put {
            bucket: "b".into(),
            key: "k".repeat(size.max(1)),
            manifest_id: ObjectId::from_bytes([1; 32]),
            inline_manifest: None,
            hlc: 1,
        };
        Entry::sign(&key(), 0, [0; 32], 9, seen(), vec![action], &test_sealer())
    }

    /// The header, the sealed actions and the tail of wire bytes, as a ranged reader cuts them.
    fn cut(wire: &[u8]) -> (EntryHead, Option<Vec<u8>>, Vec<u8>) {
        let head = EntryHead::parse(wire).unwrap();
        let start = head.header_len() as usize;
        let tail = wire.len() - TAIL_LEN as usize;
        let sealed = head.sealed_len().map(|_| wire[start..tail].to_vec());
        (head, sealed, wire[tail..].to_vec())
    }

    #[test]
    fn test_entry_head_finds_the_parts_of_the_wire_bytes() {
        for entry in [sized(1), sized(70_000), sized(1).redacted()] {
            let wire = entry.to_wire();

            let head = EntryHead::parse(&wire).unwrap();

            assert_eq!(head.header_len(), entry.header_len());
            assert_eq!(head.wire_len(), Some(wire.len() as u64));
            let header = &wire[..entry.header_len() as usize];
            assert!(EntryHead::parse(header).is_ok());
            assert_eq!(
                EntryHead::parse(&header[..header.len() - 1]).err(),
                Some(WireError::Malformed)
            );
        }
    }

    #[test]
    fn test_from_parts_reads_as_from_wire() {
        for entry in [sized(1), sized(70_000), sized(1).redacted()] {
            let wire = entry.to_wire();
            let (head, sealed, tail) = cut(&wire);

            head.check_tail(&tail, &test_sealer()).unwrap();
            let read = Entry::from_parts(head, sealed, &tail, &test_sealer()).unwrap();

            assert_eq!(read, Entry::from_wire(&wire, &test_sealer()).unwrap());
        }
    }

    #[test]
    fn test_from_parts_refuses_parts_of_two_entries() {
        let a = sized(100).to_wire();
        let action = sized(100).actions.unwrap();
        let b = Entry::sign(&key(), 0, [0; 32], 10, seen(), action, &test_sealer()).to_wire();
        assert_eq!(a.len(), b.len());
        let (_, b_sealed, b_tail) = cut(&b);
        let sealer = test_sealer();

        let (head, _, _) = cut(&a);
        assert_eq!(
            head.check_tail(&b_tail, &sealer).err(),
            Some(WireError::BadMac)
        );
        let (head, _, tail) = cut(&a);
        let read = Entry::from_parts(head, b_sealed, &tail, &sealer);
        assert_eq!(read.err(), Some(WireError::ActionsMismatch));
        let (head, sealed, tail) = cut(&a);
        let mut short = sealed.unwrap();
        short.pop();
        let read = Entry::from_parts(head, Some(short), &tail, &sealer);
        assert_eq!(read.err(), Some(WireError::Malformed));
        let (head, sealed, tail) = cut(&a);
        let read = Entry::from_parts(head, sealed, &tail[1..], &sealer);
        assert_eq!(read.err(), Some(WireError::Malformed));
    }

    /// The MAC needs only the header and the tail: a writer with no repository key stops there.
    #[test]
    fn test_check_tail_refuses_a_writer_with_no_repo_key() {
        let other = seal::RepoKey::from_hex(&"09".repeat(32)).unwrap().keys();
        let entry = Entry::sign(&key(), 0, [0; 32], 1, seen(), vec![put()], other.sealer());
        let (head, _, tail) = cut(&entry.to_wire());

        assert_eq!(
            head.check_tail(&tail, &test_sealer()).err(),
            Some(WireError::BadMac)
        );
    }
}
