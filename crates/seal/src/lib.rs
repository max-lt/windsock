//! The repository secret and what it keys: chunk IDs, the FastCDC seed, and the seal of every
//! object that goes to the remote.
//!
//! All proxies of one remote share the secret. A reader of the remote without it cannot read
//! the data or test whether a known chunk is stored.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use model::ChunkId;
use zeroize::Zeroize;

/// Format of a sealed blob: `VERSION | key_id[4] | nonce[24] | ciphertext | tag[16]`.
const VERSION: u8 = 1;
const KEY_ID_LEN: usize = 4;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 1 + KEY_ID_LEN + NONCE_LEN;

/// Bytes that a seal adds to its input.
pub const OVERHEAD: usize = HEADER_LEN + 16;

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("the repository key is not 64 hex characters")]
    BadKey,
    #[error("no random bytes from the system: {0}")]
    Random(String),
    #[error("a sealed blob is too short or has an unknown format")]
    Format,
    #[error("a sealed blob uses key {0}, and this proxy does not have it")]
    UnknownKey(String),
    #[error("a sealed blob does not open: wrong key, wrong object, or changed bytes")]
    Open,
}

/// The secret of one remote. Its loss makes all data of the remote unreadable.
pub struct RepoKey([u8; 32]);

impl Drop for RepoKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for RepoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RepoKey(..)")
    }
}

impl RepoKey {
    pub fn generate() -> Result<Self, SealError> {
        let mut bytes = [0u8; 32];
        getrandom(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn from_hex(text: &str) -> Result<Self, SealError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(text.trim(), &mut bytes).map_err(|_| SealError::BadKey)?;
        Ok(Self(bytes))
    }

    /// The key file content. Zeroize it after use.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn keys(&self) -> Keys {
        let chunk_id = blake3::derive_key("windsock 2026-10-26 chunk id", &self.0);
        let mut seal = blake3::derive_key("windsock 2026-10-26 seal", &self.0);
        let id = blake3::derive_key("windsock 2026-10-26 seal key id", &seal);
        let cipher = XChaCha20Poly1305::new(&seal.into());
        seal.zeroize();
        Keys {
            chunk_id,
            sealer: Sealer {
                cipher,
                key_id: id[..KEY_ID_LEN]
                    .try_into()
                    .expect("a hash has more than 4 bytes"),
            },
        }
    }
}

fn getrandom(bytes: &mut [u8]) -> Result<(), SealError> {
    use chacha20poly1305::aead::rand_core::RngCore;
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|e| SealError::Random(e.to_string()))
}

/// The keys that one repository secret gives. The cipher zeroizes its own key on drop.
#[derive(Clone)]
pub struct Keys {
    chunk_id: [u8; 32],
    sealer: Sealer,
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.chunk_id.zeroize();
    }
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys(..)")
    }
}

impl Keys {
    /// The ID of a chunk: keyed, so only a holder of the secret can compute it.
    pub fn chunk_id(&self, raw: &[u8]) -> ChunkId {
        ChunkId::from_bytes(*blake3::keyed_hash(&self.chunk_id, raw).as_bytes())
    }

    /// A secret FastCDC seed, so chunk sizes do not show the structure of an object.
    pub fn cdc_seed(&self) -> u64 {
        let mut seed = blake3::derive_key("windsock 2026-10-26 fastcdc seed", &self.chunk_id);
        let value = u64::from_le_bytes(seed[..8].try_into().expect("a hash has more than 8 bytes"));
        seed.zeroize();
        value
    }

    pub fn sealer(&self) -> &Sealer {
        &self.sealer
    }
}

/// What a sealed blob holds. It goes into the associated data with the identity of the object,
/// so a blob of one object does not open as another one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    PackChunk = 1,
    PackFooter = 2,
    Manifest = 3,
    Actions = 4,
    Snapshot = 5,
    KeyCheck = 6,
}

#[derive(Clone)]
pub struct Sealer {
    cipher: XChaCha20Poly1305,
    key_id: [u8; KEY_ID_LEN],
}

impl Sealer {
    /// Seals `plain` for the object `context` of kind `kind`, with a new random nonce.
    pub fn seal(&self, kind: Kind, context: &[u8], plain: &[u8]) -> Vec<u8> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad = associated_data(kind, context);
        let sealed = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .expect("XChaCha20-Poly1305 encrypts any input under 256 GiB");

        let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
        out.push(VERSION);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        out
    }

    /// Opens a blob that [`Sealer::seal`] made for the same `kind` and `context`.
    pub fn open(&self, kind: Kind, context: &[u8], blob: &[u8]) -> Result<Vec<u8>, SealError> {
        if blob.len() < OVERHEAD || blob[0] != VERSION {
            return Err(SealError::Format);
        }
        let key_id = &blob[1..1 + KEY_ID_LEN];
        if key_id != self.key_id {
            return Err(SealError::UnknownKey(hex::encode(key_id)));
        }

        let nonce = XNonce::from_slice(&blob[1 + KEY_ID_LEN..HEADER_LEN]);
        let aad = associated_data(kind, context);
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &blob[HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::Open)
    }
}

fn associated_data(kind: Kind, context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + context.len());
    aad.push(kind as u8);
    aad.extend_from_slice(context);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(byte: u8) -> Keys {
        RepoKey::from_hex(&hex::encode([byte; 32])).unwrap().keys()
    }

    #[test]
    fn test_seal_then_open_returns_the_input() {
        let sealer = keys(1).sealer().clone();

        let blob = sealer.seal(Kind::Manifest, b"id", b"plain");

        assert_eq!(blob.len(), b"plain".len() + OVERHEAD);
        assert_eq!(sealer.open(Kind::Manifest, b"id", &blob).unwrap(), b"plain");
    }

    #[test]
    fn test_two_seals_of_one_input_differ() {
        let sealer = keys(1).sealer().clone();

        assert_ne!(
            sealer.seal(Kind::Manifest, b"id", b"plain"),
            sealer.seal(Kind::Manifest, b"id", b"plain")
        );
    }

    #[test]
    fn test_blob_does_not_open_as_another_object_or_kind() {
        let sealer = keys(1).sealer().clone();
        let blob = sealer.seal(Kind::Manifest, b"id", b"plain");

        assert!(matches!(
            sealer.open(Kind::Manifest, b"other", &blob),
            Err(SealError::Open)
        ));
        assert!(matches!(
            sealer.open(Kind::Snapshot, b"id", &blob),
            Err(SealError::Open)
        ));
    }

    #[test]
    fn test_changed_byte_does_not_open() {
        let sealer = keys(1).sealer().clone();
        let mut blob = sealer.seal(Kind::Actions, b"", b"plain");
        let last = blob.len() - 1;
        blob[last] ^= 1;

        assert!(matches!(
            sealer.open(Kind::Actions, b"", &blob),
            Err(SealError::Open)
        ));
    }

    #[test]
    fn test_blob_of_another_key_names_its_key() {
        let blob = keys(1).sealer().seal(Kind::Actions, b"", b"plain");

        let result = keys(2).sealer().open(Kind::Actions, b"", &blob);

        assert!(matches!(result, Err(SealError::UnknownKey(_))));
    }

    #[test]
    fn test_chunk_id_depends_on_the_key() {
        assert_eq!(keys(1).chunk_id(b"data"), keys(1).chunk_id(b"data"));
        assert_ne!(keys(1).chunk_id(b"data"), keys(2).chunk_id(b"data"));
        assert_ne!(
            keys(1).chunk_id(b"data").as_bytes(),
            blake3::hash(b"data").as_bytes()
        );
        assert_ne!(keys(1).cdc_seed(), keys(2).cdc_seed());
    }

    #[test]
    fn test_key_file_roundtrips_and_rejects_bad_text() {
        let key = RepoKey::generate().unwrap();

        assert_eq!(
            RepoKey::from_hex(&key.to_hex()).unwrap().to_hex(),
            key.to_hex()
        );
        assert!(RepoKey::from_hex("not hex").is_err());
        assert_eq!(format!("{key:?}"), "RepoKey(..)");
        assert_eq!(format!("{:?}", key.keys()), "Keys(..)");
    }

    #[test]
    fn test_seal_roundtrips_at_every_size_limit() {
        let sealer = keys(1).sealer().clone();
        for len in [
            0,
            1,
            255,
            256,
            64 * 1024,
            256 * 1024 - 1,
            256 * 1024,
            256 * 1024 + 1,
            9 << 20,
        ] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

            let blob = sealer.seal(Kind::PackChunk, b"id", &plain);

            assert_eq!(blob.len(), len + OVERHEAD);
            assert_eq!(
                sealer.open(Kind::PackChunk, b"id", &blob).unwrap(),
                plain,
                "{len}"
            );
        }
    }

    #[test]
    fn test_nonce_does_not_repeat_over_many_seals() {
        let sealer = keys(1).sealer().clone();
        let count = 20_000;

        let nonces: std::collections::HashSet<Vec<u8>> = (0..count)
            .map(|_| sealer.seal(Kind::Actions, b"", b"same")[1 + KEY_ID_LEN..HEADER_LEN].to_vec())
            .collect();

        assert_eq!(nonces.len(), count);
    }
}
