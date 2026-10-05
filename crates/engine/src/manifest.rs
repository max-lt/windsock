//! Manifest format: an object as a list of chunks in packs.
//!
//! Layout: `VERSION | postcard(Manifest)`. The ObjectId is the blake3 hash of these bytes.
//! The nonce makes it unique per write: the GC deletes `manifests/<id>`, so the same key
//! must never be written again.

use std::collections::BTreeMap;

use model::{ObjectId, PackId};
use pack::PackEntry;
use serde::{Deserialize, Serialize};

use crate::EngineError;

const VERSION: u8 = 2;

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
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![VERSION];
        bytes.extend(postcard::to_allocvec(self).expect("a manifest always serializes"));
        bytes
    }

    /// Checks `bytes` against `id` and decodes them.
    pub fn decode(id: ObjectId, bytes: &[u8]) -> Result<Self, EngineError> {
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

        let manifest: Self = postcard::from_bytes(body)
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
        let bytes = sample().encode();

        assert_eq!(
            Manifest::decode(manifest_id(&bytes), &bytes).unwrap(),
            sample()
        );
    }

    #[test]
    fn test_manifest_format_is_stable() {
        assert_eq!(
            manifest_id(&sample().encode()).to_string(),
            "b3fb0b2eb7894104c5b11c1ba96fb7f90169a5674fb5a3e449c3b02e0caeca18"
        );
    }

    #[test]
    fn test_decode_rejects_hash_mismatch() {
        let bytes = sample().encode();
        let other = manifest_id(b"other");

        assert!(matches!(
            Manifest::decode(other, &bytes),
            Err(EngineError::Corrupt(_))
        ));
    }

    #[test]
    fn test_decode_rejects_unknown_version() {
        let mut bytes = sample().encode();
        bytes[0] = VERSION + 1;

        assert!(matches!(
            Manifest::decode(manifest_id(&bytes), &bytes),
            Err(EngineError::Corrupt(_))
        ));
    }

    #[test]
    fn test_decode_rejects_chunks_that_miss_the_size() {
        let mut manifest = sample();
        manifest.size = 21;
        let bytes = manifest.encode();

        assert!(matches!(
            Manifest::decode(manifest_id(&bytes), &bytes),
            Err(EngineError::Corrupt(_))
        ));
    }
}
