#![no_main]

use libfuzzer_sys::fuzz_target;
use seal::RepoKey;

fuzz_target!(|data: &[u8]| {
    let keys = RepoKey::from_hex(&"07".repeat(32))
        .expect("a fixed key")
        .keys();
    let _ = journal::redact_wire(data);
    let _ = journal::Entry::from_wire(data, keys.sealer());
    // With a valid MAC and seal, the input reaches the action decode and the checks after it.
    let Some(wire) = journal::Entry::fuzz_wire(data, keys.sealer()) else {
        return;
    };
    let Ok(entry) = journal::Entry::from_wire(&wire, keys.sealer()) else {
        return;
    };
    let _ = entry.signature_is_valid();
    let _ = entry.actions_are_intact();
    assert_eq!(entry.redacted().hash(), entry.hash());
    // A redaction drops the actions and nothing else: the entry still reads, with no actions.
    let redacted = journal::redact_wire(&wire).expect("a valid entry decodes");
    match redacted {
        Some(bytes) => {
            let read =
                journal::Entry::from_wire(&bytes, keys.sealer()).expect("a redacted entry reads");
            assert_eq!(read.hash(), entry.hash());
            assert!(read.actions.is_none());
        }
        None => assert!(entry.actions.is_none()),
    }
});
