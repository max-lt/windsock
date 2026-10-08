//! The repository key: keyed hashes and sealed objects.
//!
//! A sealed object is `nonce | ciphertext | tag`, with XChaCha20-Poly1305. The
//! derivation contexts and the layout are part of the storage format.

use std::fmt;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use model::KeyId;

const HASH_CONTEXT: &str = "windsock 2026-10-08 hash key";
const SEAL_CONTEXT: &str = "windsock 2026-10-08 seal key";
const ID_CONTEXT: &str = "windsock 2026-10-08 key id";

/// Bytes that a seal adds: the nonce in front, the tag at the end.
pub const SEAL_OVERHEAD: usize = NONCE_LEN + 16;

const NONCE_LEN: usize = 24;

/// A seal nonce. It must never repeat under one key.
pub type Nonce = [u8; NONCE_LEN];

/// A sealed object does not open: wrong key, or changed bytes.
#[derive(Debug, thiserror::Error)]
#[error("sealed object does not open: wrong key or corrupt data")]
pub struct SealError;

/// The secret of one remote. Every proxy of the remote holds the same key.
pub struct RepoKey {
    hash_key: [u8; 32],
    cipher: XChaCha20Poly1305,
    id: KeyId,
}

impl RepoKey {
    pub fn from_bytes(secret: [u8; 32]) -> Self {
        let seal_key = blake3::derive_key(SEAL_CONTEXT, &secret);

        Self {
            hash_key: blake3::derive_key(HASH_CONTEXT, &secret),
            cipher: XChaCha20Poly1305::new(&seal_key.into()),
            id: KeyId::from_bytes(blake3::derive_key(ID_CONTEXT, &secret)),
        }
    }

    pub fn id(&self) -> KeyId {
        self.id
    }

    /// blake3 of `data`, keyed: without the key, nobody can compute it.
    pub fn hash(&self, data: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.hash_key, data).as_bytes()
    }

    pub fn seal(&self, nonce: &Nonce, plain: &[u8]) -> Vec<u8> {
        let ciphertext = self
            .cipher
            .encrypt(&XNonce::from(*nonce), plain)
            .expect("a sealed object is smaller than 256 GiB");
        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(nonce);
        sealed.extend(ciphertext);
        sealed
    }

    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < SEAL_OVERHEAD {
            return Err(SealError);
        }

        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce: Nonce = nonce.try_into().expect("the split is NONCE_LEN long");
        self.cipher
            .decrypt(&XNonce::from(nonce), ciphertext)
            .map_err(|_| SealError)
    }
}

/// Shows the key ID only: the secret must not reach a log.
impl fmt::Debug for RepoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepoKey({})", self.id)
    }
}

/// Random bytes from the operating system.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the operating system gives random bytes");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> RepoKey {
        RepoKey::from_bytes([seed; 32])
    }

    #[test]
    fn test_seal_roundtrip() {
        let sealed = key(1).seal(&[2u8; 24], b"windsock");

        assert_eq!(sealed.len(), b"windsock".len() + SEAL_OVERHEAD);
        assert_eq!(key(1).open(&sealed).unwrap(), b"windsock");
    }

    #[test]
    fn test_sealed_object_hides_the_data() {
        let sealed = key(1).seal(&[2u8; 24], b"windsock windsock");

        assert!(!sealed.windows(8).any(|w| w == b"windsock"));
    }

    #[test]
    fn test_open_rejects_another_key() {
        let sealed = key(1).seal(&[2u8; 24], b"windsock");

        assert!(key(2).open(&sealed).is_err());
    }

    #[test]
    fn test_open_rejects_a_changed_byte() {
        let mut sealed = key(1).seal(&[2u8; 24], b"windsock");
        sealed[NONCE_LEN + 3] ^= 1;

        assert!(key(1).open(&sealed).is_err());
    }

    #[test]
    fn test_open_rejects_a_changed_nonce() {
        let mut sealed = key(1).seal(&[2u8; 24], b"windsock");
        sealed[0] ^= 1;

        assert!(key(1).open(&sealed).is_err());
    }

    #[test]
    fn test_open_rejects_a_short_object() {
        assert!(key(1).open(&[0u8; SEAL_OVERHEAD - 1]).is_err());
    }

    #[test]
    fn test_hash_depends_on_the_key() {
        assert_ne!(key(1).hash(b"windsock"), key(2).hash(b"windsock"));
        assert_ne!(
            &key(1).hash(b"windsock"),
            blake3::hash(b"windsock").as_bytes()
        );
    }

    #[test]
    fn test_debug_hides_the_secret() {
        let text = format!("{:?}", key(1));

        assert_eq!(text, format!("RepoKey({})", key(1).id()));
    }

    #[test]
    fn test_random_bytes_differ() {
        assert_ne!(random::<16>(), random::<16>());
    }

    #[test]
    fn test_key_format_is_stable() {
        let key = key(7);

        assert_eq!(
            key.id().to_string(),
            "cf6c5932a89dd6a9708c2e963c6c7c3884ac32278959333c7329a21a22ad2733"
        );
        assert_eq!(
            hex::encode(key.hash(b"windsock")),
            "9a0fa304ef07e0878ae8520c5152ab9206be5f118fb4aa5f104689e59597ede1"
        );
        assert_eq!(
            hex::encode(key.seal(&[9u8; 24], b"windsock")),
            "090909090909090909090909090909090909090909090909a30cb0122131e3a71508dfe97de17c4a921ebac780e6fdf2"
        );
    }
}
