//! Manifest format: an object as a list of chunks in packs.
//!
//! Layout: `VERSION | sealed postcard(Manifest)`. The ObjectId is the blake3 hash of these
//! bytes. The seal nonce is the manifest nonce then zero. The nonce makes it unique per write:
//! the GC deletes `manifests/<id>`, so the same key must never be written again.

use std::collections::BTreeMap;

use keys::RepoKey;
use model::{ObjectId, PackId};
use pack::PackEntry;
use serde::{Deserialize, Serialize};

use crate::EngineError;

const VERSION: u8 = 3;

/// Prefix of the manifests that are too large to inline in a journal entry.
pub const MANIFESTS_PREFIX: &str = "manifests/";

/// Manifests up to this size travel inside the journal entry.
pub const INLINE_MAX: usize = 4096;

/// One chunk of an object and where it is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    pub pack: PackId,
    pub entry: PackEntry,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub nonce: [u8; 16],
    pub size: u64,
    /// blake3 of the object data. Known at put time, so it can serve as a stable ETag.
    pub content_hash: [u8; 32],
    pub metadata: BTreeMap<String, String>,
    /// In object order.
    pub chunks: Vec<ChunkRef>,
}

impl Manifest {
    pub fn encode(&self, key: &RepoKey) -> Vec<u8> {
        let plain = postcard::to_allocvec(self).expect("a manifest always serializes");
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&self.nonce);
        let mut bytes = vec![VERSION];
        bytes.extend(key.seal(&nonce, &plain));
        bytes
    }

    /// Checks `bytes` against `id` and decodes them.
    pub fn decode(key: &RepoKey, id: ObjectId, bytes: &[u8]) -> Result<Self, EngineError> {
        if manifest_id(bytes) != id {
            return Err(EngineError::Corrupt(format!(
                "manifest {id}: hash mismatch"
            )));
        }

        let Some((&VERSION, body)) = bytes.split_first() else {
            return Err(EngineError::Corrupt(format!(
                "manifest {id}: unsupported version"
            )));
        };

        let plain = key
            .open(body)
            .map_err(|e| EngineError::Corrupt(format!("manifest {id}: {e}")))?;
        let manifest: Self = postcard::from_bytes(&plain)
            .map_err(|e| EngineError::Corrupt(format!("manifest {id}: {e}")))?;
        let chunk_bytes: u64 = manifest
            .chunks
            .iter()
            .map(|c| u64::from(c.entry.raw_len))
            .sum();

        if chunk_bytes != manifest.size {
            return Err(EngineError::Corrupt(format!(
                "manifest {id}: chunks do not cover the object"
            )));
        }

        Ok(manifest)
    }
}

pub fn manifest_id(bytes: &[u8]) -> ObjectId {
    ObjectId::from_bytes(*blake3::hash(bytes).as_bytes())
}

pub fn manifest_key(id: ObjectId) -> String {
    format!("{MANIFESTS_PREFIX}{id}")
}

#[cfg(test)]
mod tests {
    use chunking::Compression;
    use model::ChunkId;

    use super::*;

    fn key() -> RepoKey {
        RepoKey::from_bytes([7u8; 32])
    }

    fn sample() -> Manifest {
        let entry = |n: u8, offset: u64| PackEntry {
            chunk_id: ChunkId::from_bytes([n; 32]),
            offset,
            stored_len: 7,
            raw_len: 10,
            compression: Compression::Zstd,
        };

        Manifest {
            nonce: [6u8; 16],
            size: 20,
            content_hash: [3u8; 32],
            metadata: BTreeMap::from([("content-type".into(), "text/plain".into())]),
            chunks: vec![
                ChunkRef {
                    pack: PackId::from_bytes([1u8; 32]),
                    entry: entry(4, 5),
                },
                ChunkRef {
                    pack: PackId::from_bytes([2u8; 32]),
                    entry: entry(5, 12),
                },
            ],
        }
    }

    #[test]
    fn test_manifest_roundtrip() {
        let bytes = sample().encode(&key());

        assert_eq!(
            Manifest::decode(&key(), manifest_id(&bytes), &bytes).unwrap(),
            sample()
        );
    }

    #[test]
    fn test_manifest_format_is_stable() {
        assert_eq!(
            manifest_id(&sample().encode(&key())).to_string(),
            "02f2fd2104337e8c56f92d9e040824a7fc96e5e10ee14d2659de7e7fea68fb27"
        );
    }

    #[test]
    fn test_manifest_hides_metadata_and_chunk_ids() {
        let bytes = sample().encode(&key());

        assert!(!bytes.windows(10).any(|w| w == b"text/plain"));
        assert!(!bytes.windows(32).any(|w| w == [4u8; 32]));
    }

    #[test]
    fn test_decode_rejects_another_key() {
        let bytes = sample().encode(&key());
        let other = RepoKey::from_bytes([8u8; 32]);

        assert!(matches!(
            Manifest::decode(&other, manifest_id(&bytes), &bytes),
            Err(EngineError::Corrupt(_))
        ));
    }

    #[test]
    fn test_decode_rejects_hash_mismatch() {
        let bytes = sample().encode(&key());
        let other = manifest_id(b"other");

        assert!(matches!(
            Manifest::decode(&key(), other, &bytes),
            Err(EngineError::Corrupt(_))
        ));
    }

    #[test]
    fn test_decode_rejects_unknown_version() {
        let mut bytes = sample().encode(&key());
        bytes[0] = VERSION + 1;

        assert!(matches!(
            Manifest::decode(&key(), manifest_id(&bytes), &bytes),
            Err(EngineError::Corrupt(_))
        ));
    }

    #[test]
    fn test_decode_rejects_chunks_that_miss_the_size() {
        let mut manifest = sample();
        manifest.size = 21;
        let bytes = manifest.encode(&key());

        assert!(matches!(
            Manifest::decode(&key(), manifest_id(&bytes), &bytes),
            Err(EngineError::Corrupt(_))
        ));
    }
}
