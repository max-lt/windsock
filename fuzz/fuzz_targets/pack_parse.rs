#![no_main]

use chunking::{Chunk, Compression};
use libfuzzer_sys::fuzz_target;
use seal::RepoKey;

fuzz_target!(|data: &[u8]| {
    let keys = RepoKey::from_hex(&"07".repeat(32))
        .expect("a fixed key")
        .keys();
    // The ID is the hash of the input, or else the hash check stops every run.
    let _ = pack::parse(&keys, pack::pack_id(data), data);

    // A valid pack of the input chunks, with one byte changed: parse and read_chunk run with a
    // footer that opens.
    let Some((&flip, rest)) = data.split_first() else {
        return;
    };
    let mut builder = pack::PackBuilder::new([flip; 16], &keys);
    for (n, raw) in rest.chunks(64).enumerate() {
        let chunk = Chunk {
            id: keys.chunk_id(raw),
            offset: n * 64,
            data: raw,
        };
        let mode = if n % 2 == 0 {
            Compression::None
        } else {
            Compression::Zstd
        };
        builder.add(chunk, mode);
    }
    let mut bytes = builder.finish().bytes;
    let at = usize::from(flip) * bytes.len() / 256;
    bytes[at] ^= 1;
    let Ok(entries) = pack::parse(&keys, pack::pack_id(&bytes), &bytes) else {
        return;
    };
    for entry in &entries {
        let _ = pack::read_chunk(
            &keys,
            entry,
            &bytes[entry.range().start as usize..entry.range().end as usize],
        );
    }
});
