//! Pack and read planning. No I/O.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use chunking::Chunk;
use model::{ChunkId, PackId};
use pack::{Nonce, Pack, PackBuilder, PackEntry};

use crate::config::{Chunking, Policy};
use crate::manifest::{ChunkRef, Manifest};

/// Nonces for the packs and manifests of one flush.
pub(crate) struct Nonces {
    seed: [u8; 32],
    next: u64,
}

impl Nonces {
    /// `seed` must be different for every flush of every node.
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed, next: 0 }
    }

    fn next(&mut self) -> Nonce {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.seed).update(&self.next.to_le_bytes());
        self.next += 1;

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        nonce
    }
}

/// Where a chunk of a planned object goes.
#[derive(Clone, Copy)]
enum Slot {
    Stored(ChunkRef),
    /// In the pack with this number. Its PackId is known once the pack closes.
    Building {
        pack: usize,
        entry: PackEntry,
    },
}

struct OpenPack {
    number: usize,
    builder: PackBuilder,
}

struct PlannedObject {
    size: u64,
    content_hash: [u8; 32],
    metadata: BTreeMap<String, String>,
    slots: Vec<Slot>,
}

/// Puts the new chunks of a batch of objects into packs.
///
/// Small objects share packs that close at `pack_target`. An object of at least
/// `own_pack_threshold` bytes gets packs of its own, so it can be deleted as a whole.
pub(crate) struct Planner {
    pack_target: usize,
    own_pack_threshold: usize,
    nonces: Nonces,
    shared: Option<OpenPack>,
    /// PackId of every pack by number, once it is closed.
    pack_ids: Vec<Option<PackId>>,
    /// Chunks already placed in this batch.
    placed: HashMap<ChunkId, Slot>,
    objects: Vec<PlannedObject>,
}

impl Planner {
    pub fn new(pack_target: usize, own_pack_threshold: usize, nonces: Nonces) -> Self {
        Self {
            pack_target,
            own_pack_threshold,
            nonces,
            shared: None,
            pack_ids: Vec::new(),
            placed: HashMap::new(),
            objects: Vec::new(),
        }
    }

    /// Adds the next object of the batch. Returns the packs that closed: upload them now.
    ///
    /// `stored` gives the location of a chunk that is already in the remote.
    pub fn add<E>(
        &mut self,
        data: &[u8],
        content_hash: [u8; 32],
        metadata: BTreeMap<String, String>,
        policy: Policy,
        mut stored: impl FnMut(ChunkId) -> Result<Option<ChunkRef>, E>,
    ) -> Result<Vec<Pack>, E> {
        let chunks: Vec<Chunk<'_>> = match policy.chunking {
            Chunking::ContentDefined => chunking::chunks(data).collect(),
            Chunking::Fixed => chunking::fixed_chunks(data).collect(),
        };
        let own = data.len() >= self.own_pack_threshold;
        let mut own_pack = None;
        let mut closed = Vec::new();
        let mut slots = Vec::with_capacity(chunks.len());

        for chunk in chunks {
            if let Some(slot) = self.placed.get(&chunk.id) {
                slots.push(*slot);
                continue;
            }

            if let Some(location) = stored(chunk.id)? {
                slots.push(Slot::Stored(location));
                continue;
            }

            let target = if own { &mut own_pack } else { &mut self.shared };
            let open = target.get_or_insert_with(|| {
                self.pack_ids.push(None);
                OpenPack {
                    number: self.pack_ids.len() - 1,
                    builder: PackBuilder::new(self.nonces.next()),
                }
            });
            let slot = Slot::Building {
                pack: open.number,
                entry: open.builder.add(chunk, policy.compression),
            };
            self.placed.insert(chunk.id, slot);
            slots.push(slot);

            if open.builder.size() >= self.pack_target {
                let full = target.take().expect("the pack was just opened");
                closed.push(close(&mut self.pack_ids, full));
            }
        }

        closed.extend(own_pack.map(|open| close(&mut self.pack_ids, open)));
        self.objects.push(PlannedObject {
            size: data.len() as u64,
            content_hash,
            metadata,
            slots,
        });
        Ok(closed)
    }

    /// Closes the last shared pack. Returns it, and the manifests in the order of `add`.
    pub fn finish(mut self) -> (Option<Pack>, Vec<Manifest>) {
        let last = self
            .shared
            .take()
            .map(|open| close(&mut self.pack_ids, open));
        let manifests = self
            .objects
            .into_iter()
            .map(|object| Manifest {
                nonce: self.nonces.next(),
                size: object.size,
                content_hash: object.content_hash,
                metadata: object.metadata,
                chunks: object
                    .slots
                    .into_iter()
                    .map(|slot| resolve(&self.pack_ids, slot))
                    .collect(),
            })
            .collect();

        (last, manifests)
    }
}

fn close(pack_ids: &mut [Option<PackId>], open: OpenPack) -> Pack {
    let pack = open.builder.finish();
    pack_ids[open.number] = Some(pack.id);
    pack
}

fn resolve(pack_ids: &[Option<PackId>], slot: Slot) -> ChunkRef {
    match slot {
        Slot::Stored(location) => location,
        Slot::Building { pack, entry } => ChunkRef {
            pack: pack_ids[pack].expect("finish closes every pack"),
            entry,
        },
    }
}

/// One range read of a pack: chunks that lie back to back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fetch {
    pub pack: PackId,
    pub range: Range<u64>,
    pub entries: Vec<PackEntry>,
}

/// The fetches that cover `range` of an object, and the position of
/// `range.start` in the bytes they decode to.
pub(crate) fn plan_read(chunks: &[ChunkRef], range: Range<u64>) -> (Vec<Fetch>, u64) {
    let mut fetches: Vec<Fetch> = Vec::new();
    let mut skip = 0;
    let mut position = 0;

    for chunk in chunks {
        let start = position;
        position += u64::from(chunk.entry.raw_len);

        if range.is_empty() || position <= range.start || start >= range.end {
            continue;
        }

        if fetches.is_empty() {
            skip = range.start - start;
        }

        match fetches.last_mut() {
            Some(last) if last.pack == chunk.pack && last.range.end == chunk.entry.offset => {
                last.range.end = chunk.entry.range().end;
                last.entries.push(chunk.entry);
            }
            _ => fetches.push(Fetch {
                pack: chunk.pack,
                range: chunk.entry.range(),
                entries: vec![chunk.entry],
            }),
        }
    }

    (fetches, skip)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use chunking::Compression;

    use super::*;
    use crate::manifest;

    fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        blake3::Hasher::new()
            .update(&[seed])
            .finalize_xof()
            .fill(&mut out);
        out
    }

    fn fixed() -> Policy {
        Policy {
            chunking: Chunking::Fixed,
            compression: Compression::None,
            create_only: false,
        }
    }

    fn nothing_stored(_: ChunkId) -> Result<Option<ChunkRef>, Infallible> {
        Ok(None)
    }

    fn add(planner: &mut Planner, data: &[u8]) -> Vec<Pack> {
        planner
            .add(data, [0u8; 32], BTreeMap::new(), fixed(), nothing_stored)
            .unwrap()
    }

    fn packs_of(manifest: &Manifest) -> Vec<PackId> {
        let mut packs: Vec<_> = manifest.chunks.iter().map(|c| c.pack).collect();
        packs.dedup();
        packs
    }

    #[test]
    fn test_small_objects_share_one_pack() {
        let mut planner = Planner::new(1 << 30, 1 << 30, Nonces::new([0u8; 32]));

        assert!(add(&mut planner, &random_bytes(1, 1000)).is_empty());
        assert!(add(&mut planner, &random_bytes(2, 1000)).is_empty());
        let (last, manifests) = planner.finish();

        let pack = last.unwrap();
        assert_eq!(pack.entries.len(), 2);
        assert_eq!(packs_of(&manifests[0]), [pack.id]);
        assert_eq!(packs_of(&manifests[1]), [pack.id]);
    }

    #[test]
    fn test_shared_pack_closes_at_target_size() {
        let chunk = chunking::MAX_SIZE;
        let mut planner = Planner::new(2 * chunk, 1 << 30, Nonces::new([0u8; 32]));

        let closed = add(&mut planner, &random_bytes(1, 3 * chunk));
        let (last, manifests) = planner.finish();

        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].entries.len(), 2);
        assert_eq!(last.unwrap().entries.len(), 1);
        assert_eq!(packs_of(&manifests[0]).len(), 2);
    }

    #[test]
    fn test_large_object_gets_its_own_pack() {
        let mut planner = Planner::new(1 << 30, 2 * chunking::MAX_SIZE, Nonces::new([0u8; 32]));

        add(&mut planner, &random_bytes(1, 1000));
        let closed = add(&mut planner, &random_bytes(2, 2 * chunking::MAX_SIZE));
        add(&mut planner, &random_bytes(3, 1000));
        let (last, manifests) = planner.finish();

        assert_eq!(closed.len(), 1);
        assert_eq!(packs_of(&manifests[1]), [closed[0].id]);
        assert_eq!(closed[0].entries.len(), 2);
        assert_eq!(last.unwrap().entries.len(), 2, "small objects share");
    }

    #[test]
    fn test_chunk_seen_twice_in_a_batch_is_packed_once() {
        let mut planner = Planner::new(1 << 30, 1 << 30, Nonces::new([0u8; 32]));
        let data = random_bytes(1, 1000);

        add(&mut planner, &data);
        add(&mut planner, &data);
        let (last, manifests) = planner.finish();

        assert_eq!(last.unwrap().entries.len(), 1);
        assert_eq!(manifests[0].chunks, manifests[1].chunks);
    }

    #[test]
    fn test_stored_chunk_is_not_packed_again() {
        let data = random_bytes(1, 1000);
        let location = ChunkRef {
            pack: PackId::from_bytes([9u8; 32]),
            entry: PackEntry {
                chunk_id: chunking::chunk_id(&data),
                offset: 5,
                stored_len: 1000,
                raw_len: 1000,
                compression: Compression::None,
            },
        };
        let mut planner = Planner::new(1 << 30, 1 << 30, Nonces::new([0u8; 32]));

        planner
            .add(&data, [0u8; 32], BTreeMap::new(), fixed(), |_| {
                Ok::<_, Infallible>(Some(location))
            })
            .unwrap();
        let (last, manifests) = planner.finish();

        assert!(last.is_none());
        assert_eq!(manifests[0].chunks, [location]);
    }

    #[test]
    fn test_two_flushes_of_the_same_data_get_new_keys() {
        let data = random_bytes(1, 1000);
        let flush = |seed: u8| {
            let mut planner = Planner::new(1 << 30, 1 << 30, Nonces::new([seed; 32]));
            add(&mut planner, &data);
            let (last, manifests) = planner.finish();
            (
                last.unwrap().id,
                manifest::manifest_id(&manifests[0].encode()),
            )
        };

        let (first_pack, first_manifest) = flush(1);
        let (second_pack, second_manifest) = flush(2);

        assert_ne!(first_pack, second_pack);
        assert_ne!(first_manifest, second_manifest);
    }

    #[test]
    fn test_empty_object_has_no_chunks() {
        let mut planner = Planner::new(1 << 30, 1 << 30, Nonces::new([0u8; 32]));

        add(&mut planner, b"");
        let (last, manifests) = planner.finish();

        assert!(last.is_none());
        assert_eq!(manifests[0].size, 0);
        assert!(manifests[0].chunks.is_empty());
    }

    fn chunk(pack: u8, offset: u64, len: u32) -> ChunkRef {
        ChunkRef {
            pack: PackId::from_bytes([pack; 32]),
            entry: PackEntry {
                chunk_id: ChunkId::from_bytes([0u8; 32]),
                offset,
                stored_len: len,
                raw_len: len,
                compression: Compression::None,
            },
        }
    }

    #[test]
    fn test_read_merges_adjacent_chunks_of_one_pack() {
        let chunks = [chunk(1, 5, 10), chunk(1, 15, 10), chunk(2, 5, 10)];

        let (fetches, skip) = plan_read(&chunks, 3..25);

        assert_eq!(skip, 3);
        assert_eq!(fetches.len(), 2);
        assert_eq!(fetches[0].range, 5..25);
        assert_eq!(fetches[0].entries.len(), 2);
        assert_eq!(fetches[1].range, 5..15);
    }

    #[test]
    fn test_read_skips_chunks_outside_the_range() {
        let chunks = [chunk(1, 5, 10), chunk(1, 15, 10), chunk(1, 25, 10)];

        let (fetches, skip) = plan_read(&chunks, 12..18);

        assert_eq!(skip, 2);
        assert_eq!(fetches.len(), 1);
        assert_eq!(fetches[0].range, 15..25);
    }

    #[test]
    fn test_read_does_not_merge_chunks_with_a_gap() {
        let chunks = [chunk(1, 5, 10), chunk(1, 40, 10)];

        let (fetches, _) = plan_read(&chunks, 0..20);

        assert_eq!(fetches.len(), 2);
    }

    #[test]
    fn test_empty_range_needs_no_fetch() {
        let chunks = [chunk(1, 5, 10)];

        assert!(plan_read(&chunks, 4..4).0.is_empty());
    }
}
