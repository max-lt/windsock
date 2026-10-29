#![no_main]

use libfuzzer_sys::fuzz_target;
use seal::RepoKey;

fuzz_target!(|data: &[u8]| {
    let keys = RepoKey::from_hex(&"07".repeat(32))
        .expect("a fixed key")
        .keys();
    if let Ok(entry) = journal::Entry::from_wire(data, keys.sealer()) {
        let _ = entry.signature_is_valid();
        let _ = entry.actions_are_intact();
        assert_eq!(entry.redacted().hash(), entry.hash());
    }
    let _ = journal::redact_wire(data);
});
