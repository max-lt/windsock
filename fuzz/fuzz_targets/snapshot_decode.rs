#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let hash = *blake3::hash(data).as_bytes();
    let _ = index::Snapshot::decode(&hash, data);
});
