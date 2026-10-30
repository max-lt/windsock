//! Content-defined chunking and per-chunk compression.
//!
//! The chunk size bounds and the chunk hash are part of the storage format.
//! Other values give other chunk IDs, and dedup against stored data stops.

use std::borrow::Cow;
use std::io::Read;

use fastcdc::v2020::{FastCDC, Normalization};
use model::ChunkId;
use ruzstd::decoding::StreamingDecoder;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};
pub use seal::Keys;
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
/// The FastCDC seed comes from `keys`, so the chunk sizes do not show the structure of `data`.
pub fn chunks<'a>(keys: &'a Keys, data: &'a [u8]) -> impl Iterator<Item = Chunk<'a>> {
    let seed = keys.cdc_seed();
    FastCDC::with_level_and_seed(
        data,
        MIN_SIZE,
        AVG_SIZE,
        MAX_SIZE,
        Normalization::Level1,
        seed,
    )
    .map(move |c| {
        let bytes = &data[c.offset..c.offset + c.length];
        Chunk {
            id: keys.chunk_id(bytes),
            offset: c.offset,
            data: bytes,
        }
    })
}

/// Splits `data` into chunks of [`MAX_SIZE`] bytes, the last one shorter. Empty input gives no chunks.
pub fn fixed_chunks<'a>(keys: &'a Keys, data: &'a [u8]) -> impl Iterator<Item = Chunk<'a>> {
    data.chunks(MAX_SIZE).enumerate().map(|(i, bytes)| Chunk {
        id: keys.chunk_id(bytes),
        offset: i * MAX_SIZE,
        data: bytes,
    })
}

/// How an input is cut into chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cuts {
    /// [`chunks`].
    ContentDefined,
    /// [`fixed_chunks`].
    Fixed,
}

/// A chunk with its own copy of its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedChunk {
    pub id: ChunkId,
    pub offset: usize,
    pub data: Vec<u8>,
}

/// The chunks of an input that comes in pieces: the same chunks as [`chunks`] or
/// [`fixed_chunks`] over the whole input. A content-defined cut depends only on the
/// [`MAX_SIZE`] bytes after the start of its chunk, so a chunk goes out once that many bytes are
/// in. The chunker holds at most [`MAX_SIZE`] bytes and one piece.
pub struct StreamChunker {
    keys: Keys,
    cuts: Cuts,
    pending: Vec<u8>,
    /// Offset of `pending` in the input.
    offset: usize,
}

impl StreamChunker {
    pub fn new(keys: Keys, cuts: Cuts) -> Self {
        Self {
            keys,
            cuts,
            pending: Vec::new(),
            offset: 0,
        }
    }

    /// The chunks that `piece` completes.
    pub fn push(&mut self, piece: &[u8]) -> Vec<OwnedChunk> {
        self.pending.extend_from_slice(piece);
        self.take(End::More)
    }

    /// The last chunks, at the end of the input.
    pub fn finish(mut self) -> Vec<OwnedChunk> {
        self.take(End::Reached)
    }

    fn take(&mut self, end: End) -> Vec<OwnedChunk> {
        let len = self.pending.len();
        let spans: Vec<(usize, usize)> = match self.cuts {
            Cuts::ContentDefined => FastCDC::with_level_and_seed(
                &self.pending,
                MIN_SIZE,
                AVG_SIZE,
                MAX_SIZE,
                Normalization::Level1,
                self.keys.cdc_seed(),
            )
            .map(|c| (c.offset, c.length))
            .collect(),
            Cuts::Fixed => (0..len)
                .step_by(MAX_SIZE)
                .map(|offset| (offset, MAX_SIZE.min(len - offset)))
                .collect(),
        };
        let mut out = Vec::new();
        let mut used = 0;
        for (offset, length) in spans {
            // More input can still move the cut of this chunk.
            if end == End::More && offset + MAX_SIZE > len {
                break;
            }
            let data = self.pending[offset..offset + length].to_vec();
            out.push(OwnedChunk {
                id: self.keys.chunk_id(&data),
                offset: self.offset + offset,
                data,
            });
            used = offset + length;
        }
        self.pending.drain(..used);
        self.offset += used;
        out
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    More,
    Reached,
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
    keys: &Keys,
    id: ChunkId,
    compression: Compression,
    stored: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let raw = match compression {
        Compression::None if stored.len() > MAX_SIZE => return Err(DecodeError::TooLarge),
        Compression::None => stored.to_vec(),
        Compression::Zstd => decompress(stored)?,
    };

    let actual = keys.chunk_id(&raw);

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
    use std::sync::OnceLock;

    use super::*;

    /// A fixed test key: the golden values below depend on it.
    fn keys() -> &'static Keys {
        static KEYS: OnceLock<Keys> = OnceLock::new();
        KEYS.get_or_init(|| seal::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys())
    }

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
        assert_eq!(chunks(keys(), b"").count(), 0);
    }

    #[test]
    fn test_chunks_cover_input() {
        let data = random_bytes(1, 2 * 1024 * 1024);
        let mut rebuilt = Vec::new();

        for chunk in chunks(keys(), &data) {
            assert_eq!(chunk.offset, rebuilt.len());
            rebuilt.extend_from_slice(chunk.data);
        }

        assert_eq!(rebuilt, data);
    }

    #[test]
    fn test_fixed_chunks_cover_input() {
        let data = random_bytes(7, 2 * MAX_SIZE + 10);
        let all: Vec<_> = fixed_chunks(keys(), &data).collect();

        assert_eq!(
            all.iter().map(|c| c.data.len()).collect::<Vec<_>>(),
            [MAX_SIZE, MAX_SIZE, 10]
        );
        assert_eq!(all[2].offset, 2 * MAX_SIZE);
        assert_eq!(all[1].id, keys().chunk_id(&data[MAX_SIZE..2 * MAX_SIZE]));
        assert_eq!(fixed_chunks(keys(), b"").count(), 0);
    }

    #[test]
    fn test_chunk_sizes_within_bounds() {
        let data = random_bytes(2, 4 * 1024 * 1024);
        let all: Vec<_> = chunks(keys(), &data).collect();
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
        let lengths: Vec<_> = chunks(keys(), &data).map(|c| c.data.len()).collect();
        let first = chunks(keys(), &data).next().unwrap().id.to_string();

        assert_eq!(
            lengths,
            [
                113675, 27053, 41767, 66999, 49662, 37607, 94109, 37898, 112877, 30712, 35794,
                23595, 27534, 26724, 109505, 29886, 105707, 70310, 7162
            ]
        );
        assert_eq!(
            first,
            "8c6e63446f6c2ae4d8e49057478a44ca63afac59766d0ea40ba3e1cfb08f53a7"
        );
    }

    #[test]
    fn test_insert_changes_only_nearby_chunks() {
        let data = random_bytes(4, 2 * 1024 * 1024);
        let mut edited = data.clone();
        edited.splice(1024 * 1024..1024 * 1024, random_bytes(5, 100));

        let before: Vec<_> = chunks(keys(), &data).map(|c| c.id).collect();
        let after: Vec<_> = chunks(keys(), &edited).map(|c| c.id).collect();
        let changed = after.iter().filter(|id| !before.contains(id)).count();

        assert!(changed <= 2, "{changed} of {} chunks changed", after.len());
    }

    #[test]
    fn test_compressible_chunk_roundtrip() {
        let raw = b"windsock ".repeat(4096);
        let (compression, stored) = compress(&raw);

        assert_eq!(compression, Compression::Zstd);
        assert!(stored.len() < raw.len());
        assert_eq!(
            decode(keys(), keys().chunk_id(&raw), compression, &stored).unwrap(),
            raw
        );
    }

    #[test]
    fn test_incompressible_chunk_is_stored_raw() {
        let raw = random_bytes(6, 64 * 1024);
        let (compression, stored) = compress(&raw);

        assert_eq!(compression, Compression::None);
        assert_eq!(
            decode(keys(), keys().chunk_id(&raw), compression, &stored).unwrap(),
            raw
        );
    }

    #[test]
    fn test_decode_rejects_hash_mismatch() {
        let raw = b"windsock ".repeat(4096);
        let (compression, stored) = compress(&raw);
        let other = keys().chunk_id(b"other");

        assert!(matches!(
            decode(keys(), other, compression, &stored),
            Err(DecodeError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_decode_rejects_oversized_frame() {
        let raw = vec![0u8; 4 * MAX_SIZE];
        let (compression, stored) = compress(&raw);

        assert!(matches!(
            decode(keys(), keys().chunk_id(&raw), compression, &stored),
            Err(DecodeError::TooLarge)
        ));
    }

    #[test]
    fn test_decode_rejects_invalid_frame() {
        let raw = b"not a zstd frame";

        assert!(matches!(
            decode(keys(), keys().chunk_id(raw), Compression::Zstd, raw),
            Err(DecodeError::Zstd(_))
        ));
    }

    #[test]
    fn test_other_key_gives_other_ids_and_other_cut_points() {
        let other = seal::RepoKey::from_hex(&"08".repeat(32)).unwrap().keys();
        let data = random_bytes(5, 2 * 1024 * 1024);

        let ours: Vec<_> = chunks(keys(), &data).map(|c| (c.id, c.offset)).collect();
        let again: Vec<_> = chunks(keys(), &data).map(|c| (c.id, c.offset)).collect();
        let theirs: Vec<_> = chunks(&other, &data).map(|c| (c.id, c.offset)).collect();

        assert_eq!(ours, again);
        let our_ids: std::collections::HashSet<_> = ours.iter().map(|(id, _)| *id).collect();
        assert!(theirs.iter().all(|(id, _)| !our_ids.contains(id)));
        let our_cuts: Vec<_> = ours.iter().map(|(_, at)| *at).collect();
        let their_cuts: Vec<_> = theirs.iter().map(|(_, at)| *at).collect();
        assert_ne!(our_cuts, their_cuts);
        assert_ne!(
            fixed_chunks(keys(), &data).next().unwrap().id,
            fixed_chunks(&other, &data).next().unwrap().id
        );
    }
    /// The chunks of `data` fed to a [`StreamChunker`] in pieces of `piece` bytes.
    fn streamed(cuts: Cuts, data: &[u8], piece: usize) -> Vec<(ChunkId, usize, usize)> {
        let mut chunker = StreamChunker::new(keys().clone(), cuts);
        let mut out = Vec::new();
        for part in data.chunks(piece.max(1)) {
            out.extend(chunker.push(part));
        }
        out.extend(chunker.finish());
        out.into_iter()
            .map(|chunk| (chunk.id, chunk.offset, chunk.data.len()))
            .collect()
    }

    #[test]
    fn test_streamed_chunks_are_the_chunks_of_the_whole_input() {
        for len in [0, 1, MIN_SIZE - 1, 3 * AVG_SIZE + 5, 5 * MAX_SIZE + 123] {
            let data = random_bytes(len as u8, len);
            let whole: Vec<_> = chunks(keys(), &data)
                .map(|c| (c.id, c.offset, c.data.len()))
                .collect();
            let fixed: Vec<_> = fixed_chunks(keys(), &data)
                .map(|c| (c.id, c.offset, c.data.len()))
                .collect();

            for piece in [1, 7, 4096, 100_000, 1 << 20] {
                // Each push cuts all the bytes it holds again: tiny pieces stay on small inputs.
                if piece < 4096 && len > MIN_SIZE {
                    continue;
                }
                assert_eq!(
                    streamed(Cuts::ContentDefined, &data, piece),
                    whole,
                    "{len} {piece}"
                );
                assert_eq!(streamed(Cuts::Fixed, &data, piece), fixed, "{len} {piece}");
            }
        }
    }
}
