//! Pack files: many stored chunks in one remote object.
//!
//! Layout, all offsets relative to the start of the pack:
//!
//! ```text
//! header   MAGIC | VERSION | nonce (16 bytes)
//! body     sealed chunks, back to back
//! footer   sealed postcard(Vec<PackEntry>)
//! trailer  footer length (u32 LE) | MAGIC
//! ```
//!
//! Each chunk has its own seal, so a range read opens one chunk. The seal nonce
//! of chunk `i` is the pack nonce then `i`; the footer takes `u64::MAX`.
//!
//! The PackId is the blake3 hash of the whole pack. The nonce makes it unique per
//! upload: the GC deletes a pack key, so the same key must never be written again.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;

use chunking::{Chunk, Compression};
use keys::RepoKey;
use model::{ChunkId, PackId};
use serde::{Deserialize, Serialize};

const MAGIC: [u8; 4] = *b"WSPK";
/// Makes every pack key unique, also for the same chunks.
pub type Nonce = [u8; 16];

const VERSION: u8 = 3;
const HEADER_LEN: usize = MAGIC.len() + 1 + 16;
/// Seal position of the footer: no pack holds that many chunks.
const FOOTER_POSITION: u64 = u64::MAX;
const TRAILER_LEN: usize = 4 + MAGIC.len();

/// Location and encoding of one chunk inside a pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackEntry {
    pub chunk_id: ChunkId,
    pub offset: u64,
    pub stored_len: u32,
    pub raw_len: u32,
    pub compression: Compression,
}

impl PackEntry {
    /// Byte range of the stored chunk inside the pack.
    pub fn range(&self) -> Range<u64> {
        self.offset..self.offset + u64::from(self.stored_len)
    }
}

/// A finished pack, ready to upload as `packs/<id>`.
#[derive(Debug)]
pub struct Pack {
    pub id: PackId,
    pub bytes: Vec<u8>,
    pub entries: Vec<PackEntry>,
}

/// A pack or a stored chunk is not valid.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("pack hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: PackId, actual: PackId },
    #[error("unsupported pack version {0}")]
    UnsupportedVersion(u8),
    #[error("malformed pack: {0}")]
    Malformed(&'static str),
    #[error("invalid pack footer: {0}")]
    Footer(#[from] postcard::Error),
    #[error(transparent)]
    Seal(#[from] keys::SealError),
    #[error(transparent)]
    Chunk(#[from] chunking::DecodeError),
}

/// Builds a pack from chunks. A chunk added twice is stored once.
pub struct PackBuilder {
    nonce: Nonce,
    bytes: Vec<u8>,
    entries: Vec<PackEntry>,
    positions: HashMap<ChunkId, usize>,
}

impl PackBuilder {
    pub fn new(nonce: Nonce) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&nonce);

        Self {
            nonce,
            bytes,
            entries: Vec::new(),
            positions: HashMap::new(),
        }
    }

    /// Appends a chunk. Returns its entry.
    ///
    /// With `Compression::Zstd`, the chunk is stored compressed when zstd makes it smaller.
    pub fn add(&mut self, key: &RepoKey, chunk: Chunk<'_>, mode: Compression) -> PackEntry {
        if let Some(&position) = self.positions.get(&chunk.id) {
            return self.entries[position];
        }

        let (compression, plain) = match mode {
            Compression::Zstd => chunking::compress(chunk.data),
            Compression::None => (Compression::None, Cow::Borrowed(chunk.data)),
        };
        let position = self.entries.len() as u64;
        let stored = key.seal(&seal_nonce(&self.nonce, position), &plain);
        let entry = PackEntry {
            chunk_id: chunk.id,
            offset: self.bytes.len() as u64,
            stored_len: u32::try_from(stored.len()).expect("chunk is smaller than 4 GiB"),
            raw_len: u32::try_from(chunk.data.len()).expect("chunk is smaller than 4 GiB"),
            compression,
        };

        self.bytes.extend_from_slice(&stored);
        self.positions.insert(chunk.id, self.entries.len());
        self.entries.push(entry);
        entry
    }

    /// Size of the pack so far, in bytes, without the footer.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    /// Writes the footer and computes the PackId.
    pub fn finish(mut self, key: &RepoKey) -> Pack {
        let entries = postcard::to_allocvec(&self.entries).expect("entries always serialize");
        let footer = key.seal(&seal_nonce(&self.nonce, FOOTER_POSITION), &entries);
        let footer_len = u32::try_from(footer.len()).expect("footer is smaller than 4 GiB");

        self.bytes.extend_from_slice(&footer);
        self.bytes.extend_from_slice(&footer_len.to_le_bytes());
        self.bytes.extend_from_slice(&MAGIC);

        Pack {
            id: pack_id(&self.bytes),
            bytes: self.bytes,
            entries: self.entries,
        }
    }
}

/// The seal nonce of the chunk at `position`, or of the footer.
fn seal_nonce(nonce: &Nonce, position: u64) -> keys::Nonce {
    let mut seal = [0u8; 24];
    seal[..16].copy_from_slice(nonce);
    seal[16..].copy_from_slice(&position.to_le_bytes());
    seal
}

/// Returns the ID of a whole pack.
pub fn pack_id(bytes: &[u8]) -> PackId {
    PackId::from_bytes(*blake3::hash(bytes).as_bytes())
}

/// Checks a whole pack against `id` and returns its entries.
pub fn parse(key: &RepoKey, id: PackId, bytes: &[u8]) -> Result<Vec<PackEntry>, PackError> {
    let actual = pack_id(bytes);

    if actual != id {
        return Err(PackError::HashMismatch {
            expected: id,
            actual,
        });
    }

    if bytes.len() < HEADER_LEN + TRAILER_LEN {
        return Err(PackError::Malformed("pack is truncated"));
    }

    let (header, rest) = bytes.split_at(HEADER_LEN);

    if header[..MAGIC.len()] != MAGIC {
        return Err(PackError::Malformed("bad header magic"));
    }

    if header[MAGIC.len()] != VERSION {
        return Err(PackError::UnsupportedVersion(header[MAGIC.len()]));
    }

    let (rest, trailer) = rest.split_at(rest.len() - TRAILER_LEN);

    if trailer[4..] != MAGIC {
        return Err(PackError::Malformed("bad trailer magic"));
    }

    let footer_len = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]) as usize;

    if footer_len > rest.len() {
        return Err(PackError::Malformed("footer is larger than the pack"));
    }

    let (body, footer) = rest.split_at(rest.len() - footer_len);
    let entries: Vec<PackEntry> = postcard::from_bytes(&key.open(footer)?)?;
    let mut next = HEADER_LEN as u64;

    for entry in &entries {
        if entry.offset != next {
            return Err(PackError::Malformed("entries do not cover the body"));
        }
        next += u64::from(entry.stored_len);
    }

    if next != (HEADER_LEN + body.len()) as u64 {
        return Err(PackError::Malformed("entries do not cover the body"));
    }

    Ok(entries)
}

/// Restores a raw chunk from the bytes at `entry.range()` in its pack.
pub fn read_chunk(key: &RepoKey, entry: &PackEntry, stored: &[u8]) -> Result<Vec<u8>, PackError> {
    if stored.len() != entry.stored_len as usize {
        return Err(PackError::Malformed(
            "stored length does not match the entry",
        ));
    }

    let plain = key.open(stored)?;
    let raw = chunking::decode(key, entry.chunk_id, entry.compression, &plain)?;

    if raw.len() != entry.raw_len as usize {
        return Err(PackError::Malformed("raw length does not match the entry"));
    }

    Ok(raw)
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;

    fn key() -> &'static RepoKey {
        static KEY: OnceLock<RepoKey> = OnceLock::new();
        KEY.get_or_init(|| RepoKey::from_bytes([7u8; 32]))
    }

    fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        blake3::Hasher::new()
            .update(&[seed])
            .finalize_xof()
            .fill(&mut out);
        out
    }

    /// Random data with a compressible run in the middle.
    fn sample() -> Vec<u8> {
        let mut data = random_bytes(1, 512 * 1024);
        data.extend(b"windsock ".repeat(64 * 1024));
        data.extend(random_bytes(2, 512 * 1024));
        data
    }

    fn build(data: &[u8]) -> Pack {
        let mut builder = PackBuilder::new([0u8; 16]);
        for chunk in chunking::chunks(key(), data) {
            builder.add(key(), chunk, Compression::Zstd);
        }
        builder.finish(key())
    }

    fn slice(bytes: &[u8], range: Range<u64>) -> &[u8] {
        &bytes[range.start as usize..range.end as usize]
    }

    #[test]
    fn test_pack_roundtrip() {
        let data = sample();
        let pack = build(&data);
        let entries = parse(key(), pack.id, &pack.bytes).unwrap();

        assert_eq!(entries, pack.entries);
        assert!(entries.iter().any(|e| e.compression == Compression::Zstd));
        assert!(entries.iter().any(|e| e.compression == Compression::None));

        let mut rebuilt = Vec::new();
        for entry in &entries {
            let stored = slice(&pack.bytes, entry.range());
            rebuilt.extend(read_chunk(key(), entry, stored).unwrap());
        }
        assert_eq!(rebuilt, data);
    }

    #[test]
    fn test_duplicate_chunk_is_stored_once() {
        let data = random_bytes(3, 64 * 1024);
        let chunk = chunking::chunks(key(), &data).next().unwrap();
        let mut builder = PackBuilder::new([0u8; 16]);

        let first = builder.add(key(), chunk, Compression::Zstd);
        let size = builder.size();
        let second = builder.add(key(), chunk, Compression::Zstd);

        assert_eq!(first, second);
        assert_eq!(builder.size(), size);
        assert_eq!(builder.finish(key()).entries.len(), 1);
    }

    #[test]
    fn test_uncompressed_mode_stores_raw_chunks() {
        let data = b"windsock ".repeat(4096);
        let chunk = chunking::chunks(key(), &data).next().unwrap();
        let mut builder = PackBuilder::new([0u8; 16]);

        let entry = builder.add(key(), chunk, Compression::None);
        let pack = builder.finish(key());

        assert_eq!(entry.compression, Compression::None);
        assert_eq!(
            entry.stored_len as usize,
            entry.raw_len as usize + keys::SEAL_OVERHEAD
        );
        assert_eq!(
            read_chunk(key(), &entry, slice(&pack.bytes, entry.range())).unwrap(),
            chunk.data
        );
    }

    #[test]
    fn test_nonce_makes_the_pack_id_unique() {
        let data = random_bytes(8, 64 * 1024);
        let pack = |nonce: Nonce| {
            let mut builder = PackBuilder::new(nonce);
            for chunk in chunking::chunks(key(), &data) {
                builder.add(key(), chunk, Compression::None);
            }
            builder.finish(key())
        };

        let first = pack([1u8; 16]);
        let second = pack([2u8; 16]);

        assert_ne!(first.id, second.id);
        assert_eq!(first.entries, second.entries);
        assert_eq!(
            parse(key(), second.id, &second.bytes).unwrap(),
            second.entries
        );
    }

    #[test]
    fn test_empty_pack_is_valid() {
        let pack = PackBuilder::new([0u8; 16]).finish(key());

        assert!(parse(key(), pack.id, &pack.bytes).unwrap().is_empty());
    }

    #[test]
    fn test_pack_format_is_stable() {
        // Raw chunks only: the PackId must not depend on the zstd encoder output.
        let pack = build(&random_bytes(7, 512 * 1024));

        assert!(
            pack.entries
                .iter()
                .all(|e| e.compression == Compression::None)
        );
        assert_eq!(
            pack.id.to_string(),
            "b2c6605a08d0d350ccfeaff22998291ebdcc53171b15c7b966e5549cc94226c6"
        );
    }

    #[test]
    fn test_pack_hides_chunks_and_chunk_ids() {
        let data = b"windsock ".repeat(4096);
        let pack = build(&data);

        assert!(!pack.bytes.windows(9).any(|w| w == b"windsock "));
        for entry in &pack.entries {
            assert!(
                !pack
                    .bytes
                    .windows(32)
                    .any(|w| w == entry.chunk_id.as_bytes())
            );
        }
    }

    #[test]
    fn test_parse_rejects_another_key() {
        let pack = build(&sample());
        let other = RepoKey::from_bytes([8u8; 32]);

        assert!(matches!(
            super::parse(&other, pack.id, &pack.bytes),
            Err(PackError::Seal(_))
        ));
    }

    #[test]
    fn test_parse_rejects_corrupt_pack() {
        let pack = build(&sample());
        let mut bytes = pack.bytes.clone();
        bytes[HEADER_LEN + 10] ^= 1;

        assert!(matches!(
            parse(key(), pack.id, &bytes),
            Err(PackError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_parse_rejects_unknown_version() {
        let mut bytes = build(&sample()).bytes;
        bytes[MAGIC.len()] = VERSION + 1;

        assert!(matches!(
            parse(key(), pack_id(&bytes), &bytes),
            Err(PackError::UnsupportedVersion(v)) if v == VERSION + 1
        ));
    }

    #[test]
    fn test_parse_rejects_truncated_pack() {
        let bytes = &build(&sample()).bytes[..HEADER_LEN + 2];

        assert!(matches!(
            parse(key(), pack_id(bytes), bytes),
            Err(PackError::Malformed(_))
        ));
    }

    #[test]
    fn test_read_chunk_rejects_wrong_range() {
        let pack = build(&sample());
        let [first, second, ..] = pack.entries[..] else {
            panic!("sample gives at least two chunks");
        };
        let stored = slice(&pack.bytes, second.range());

        assert!(read_chunk(key(), &first, stored).is_err());
    }
}
