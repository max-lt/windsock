//! Content-defined chunking and per-chunk compression.
//!
//! The chunk size bounds and the chunk hash are part of the storage format.
//! Other values give other chunk IDs, and dedup against stored data stops.

use std::borrow::Cow;
use std::io::Read;

use model::ChunkId;
use ruzstd::decoding::StreamingDecoder;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};
use serde::{Deserialize, Serialize};

/// Minimum chunk size, except for the last chunk of an input.
pub const MIN_SIZE: usize = 16 * 1024;

/// Target average chunk size.
pub const AVG_SIZE: usize = 64 * 1024;

/// Maximum chunk size.
pub const MAX_SIZE: usize = 256 * 1024;

/// A content-defined chunk of an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk<'a> {
    pub id: ChunkId,
    pub offset: usize,
    pub data: &'a [u8],
}

/// How a chunk is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compression {
    None,
    Zstd,
}

/// A stored chunk is not valid.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid zstd frame: {0}")]
    Zstd(String),
    #[error("chunk is larger than {MAX_SIZE} bytes")]
    TooLarge,
    #[error("chunk hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: ChunkId, actual: ChunkId },
}

/// Splits `data` into content-defined chunks. Empty input gives no chunks.
pub fn chunks(data: &[u8]) -> impl Iterator<Item = Chunk<'_>> {
    fastcdc::v2020::FastCDC::new(data, MIN_SIZE, AVG_SIZE, MAX_SIZE).map(move |c| {
        let bytes = &data[c.offset..c.offset + c.length];
        Chunk {
            id: chunk_id(bytes),
            offset: c.offset,
            data: bytes,
        }
    })
}

/// Splits `data` into chunks of [`MAX_SIZE`] bytes, the last one shorter. Empty input gives no chunks.
pub fn fixed_chunks(data: &[u8]) -> impl Iterator<Item = Chunk<'_>> {
    data.chunks(MAX_SIZE).enumerate().map(|(i, bytes)| Chunk {
        id: chunk_id(bytes),
        offset: i * MAX_SIZE,
        data: bytes,
    })
}

/// Returns the ID of a raw chunk.
pub fn chunk_id(raw: &[u8]) -> ChunkId {
    ChunkId::from_bytes(*blake3::hash(raw).as_bytes())
}

/// Compresses a raw chunk. Keeps the raw bytes when zstd does not make them smaller.
pub fn compress(raw: &[u8]) -> (Compression, Cow<'_, [u8]>) {
    let compressed = compress_to_vec(raw, CompressionLevel::Fastest);

    if compressed.len() >= raw.len() {
        return (Compression::None, Cow::Borrowed(raw));
    }

    (Compression::Zstd, Cow::Owned(compressed))
}

/// Restores a raw chunk from its stored form and checks it against `id`.
pub fn decode(
    id: ChunkId,
    compression: Compression,
    stored: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let raw = match compression {
        Compression::None if stored.len() > MAX_SIZE => return Err(DecodeError::TooLarge),
        Compression::None => stored.to_vec(),
        Compression::Zstd => decompress(stored)?,
    };

    let actual = chunk_id(&raw);

    if actual != id {
        return Err(DecodeError::HashMismatch {
            expected: id,
            actual,
        });
    }

    Ok(raw)
}

fn decompress(stored: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let decoder = StreamingDecoder::new(stored).map_err(|e| DecodeError::Zstd(e.to_string()))?;
    let mut raw = Vec::new();

    // The remote is not trusted: stop a frame that expands past the maximum chunk size.
    decoder
        .take(MAX_SIZE as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| DecodeError::Zstd(e.to_string()))?;

    if raw.len() > MAX_SIZE {
        return Err(DecodeError::TooLarge);
    }

    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        blake3::Hasher::new()
            .update(&[seed])
            .finalize_xof()
            .fill(&mut out);
        out
    }

    #[test]
    fn test_empty_input_has_no_chunks() {
        assert_eq!(chunks(b"").count(), 0);
    }

    #[test]
    fn test_chunks_cover_input() {
        let data = random_bytes(1, 2 * 1024 * 1024);
        let mut rebuilt = Vec::new();

        for chunk in chunks(&data) {
            assert_eq!(chunk.offset, rebuilt.len());
            rebuilt.extend_from_slice(chunk.data);
        }

        assert_eq!(rebuilt, data);
    }

    #[test]
    fn test_fixed_chunks_cover_input() {
        let data = random_bytes(7, 2 * MAX_SIZE + 10);
        let all: Vec<_> = fixed_chunks(&data).collect();

        assert_eq!(
            all.iter().map(|c| c.data.len()).collect::<Vec<_>>(),
            [MAX_SIZE, MAX_SIZE, 10]
        );
        assert_eq!(all[2].offset, 2 * MAX_SIZE);
        assert_eq!(all[1].id, chunk_id(&data[MAX_SIZE..2 * MAX_SIZE]));
        assert_eq!(fixed_chunks(b"").count(), 0);
    }

    #[test]
    fn test_chunk_sizes_within_bounds() {
        let data = random_bytes(2, 4 * 1024 * 1024);
        let all: Vec<_> = chunks(&data).collect();
        let (last, rest) = all.split_last().unwrap();

        assert!(
            rest.iter()
                .all(|c| (MIN_SIZE..=MAX_SIZE).contains(&c.data.len()))
        );
        assert!(last.data.len() <= MAX_SIZE);
    }

    #[test]
    fn test_storage_format_is_stable() {
        let data = random_bytes(3, 1024 * 1024);
        let lengths: Vec<_> = chunks(&data).map(|c| c.data.len()).collect();
        let first = chunks(&data).next().unwrap().id.to_string();

        assert_eq!(
            lengths,
            [
                111011, 154477, 78132, 51425, 156309, 111339, 177290, 98426, 105418, 4749
            ]
        );
        assert_eq!(
            first,
            "35120ec9d1890e3daeeadbb2e90969698bc8a5df64cb82a4b481f8c4d1fa2857"
        );
    }

    #[test]
    fn test_insert_changes_only_nearby_chunks() {
        let data = random_bytes(4, 2 * 1024 * 1024);
        let mut edited = data.clone();
        edited.splice(1024 * 1024..1024 * 1024, random_bytes(5, 100));

        let before: Vec<_> = chunks(&data).map(|c| c.id).collect();
        let after: Vec<_> = chunks(&edited).map(|c| c.id).collect();
        let changed = after.iter().filter(|id| !before.contains(id)).count();

        assert!(changed <= 2, "{changed} of {} chunks changed", after.len());
    }

    #[test]
    fn test_compressible_chunk_roundtrip() {
        let raw = b"windsock ".repeat(4096);
        let (compression, stored) = compress(&raw);

        assert_eq!(compression, Compression::Zstd);
        assert!(stored.len() < raw.len());
        assert_eq!(decode(chunk_id(&raw), compression, &stored).unwrap(), raw);
    }

    #[test]
    fn test_incompressible_chunk_is_stored_raw() {
        let raw = random_bytes(6, 64 * 1024);
        let (compression, stored) = compress(&raw);

        assert_eq!(compression, Compression::None);
        assert_eq!(decode(chunk_id(&raw), compression, &stored).unwrap(), raw);
    }

    #[test]
    fn test_decode_rejects_hash_mismatch() {
        let raw = b"windsock ".repeat(4096);
        let (compression, stored) = compress(&raw);
        let other = chunk_id(b"other");

        assert!(matches!(
            decode(other, compression, &stored),
            Err(DecodeError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_decode_rejects_oversized_frame() {
        let raw = vec![0u8; 4 * MAX_SIZE];
        let (compression, stored) = compress(&raw);

        assert!(matches!(
            decode(chunk_id(&raw), compression, &stored),
            Err(DecodeError::TooLarge)
        ));
    }

    #[test]
    fn test_decode_rejects_invalid_frame() {
        let raw = b"not a zstd frame";

        assert!(matches!(
            decode(chunk_id(raw), Compression::Zstd, raw),
            Err(DecodeError::Zstd(_))
        ));
    }
}
