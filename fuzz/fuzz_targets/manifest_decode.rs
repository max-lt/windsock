#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let id = engine::manifest_id(data);
    let _ = engine::Manifest::decode(id, data);
});
