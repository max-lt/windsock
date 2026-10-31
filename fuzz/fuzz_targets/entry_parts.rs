#![no_main]

use journal::{Entry, EntryHead, TAIL_LEN};
use libfuzzer_sys::fuzz_target;
use seal::RepoKey;

/// The parts of `wire` as a ranged reader cuts them, read with `from_parts`. `None` when the bytes
/// are shorter than their header says.
fn read_parts(wire: &[u8], sealer: &seal::Sealer) -> Option<Result<Entry, journal::WireError>> {
    let head = match EntryHead::parse(wire) {
        Ok(head) => head,
        Err(e) => return Some(Err(e)),
    };
    let end = usize::try_from(head.wire_len()?).ok()?;
    if end > wire.len() {
        return None;
    }
    let tail = &wire[end - TAIL_LEN as usize..end];
    if let Err(e) = head.check_tail(tail, sealer) {
        return Some(Err(e));
    }
    let start = head.header_len() as usize;
    let sealed = head
        .sealed_len()
        .map(|_| wire[start..end - TAIL_LEN as usize].to_vec());
    Some(Entry::from_parts(head, sealed, tail, sealer))
}

fuzz_target!(|data: &[u8]| {
    let keys = RepoKey::from_hex(&"07".repeat(32))
        .expect("a fixed key")
        .keys();
    // The ranged read and the whole read give the same entry or the same error.
    if let Some(parts) = read_parts(data, keys.sealer()) {
        assert_eq!(parts, Entry::from_wire(data, keys.sealer()));
    }
    // With a valid MAC and seal, the input reaches the checks after the MAC.
    let Some(wire) = Entry::fuzz_wire(data, keys.sealer()) else {
        return;
    };
    let parts = read_parts(&wire, keys.sealer()).expect("a whole wire entry has all its parts");
    assert_eq!(parts, Entry::from_wire(&wire, keys.sealer()));
});
