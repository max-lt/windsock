#![no_main]

use libfuzzer_sys::fuzz_target;
use seal::RepoKey;

fuzz_target!(|data: &[u8]| {
    let keys = RepoKey::from_hex(&"07".repeat(32))
        .expect("a fixed key")
        .keys();
    // The ID is the hash of the input, or else the hash check stops every run.
    let id = pack::pack_id(data);
    if let Ok(entries) = pack::parse(&keys, id, data) {
        for entry in &entries {
            let _ = pack::read_chunk(&keys, entry, data);
        }
    }
});
