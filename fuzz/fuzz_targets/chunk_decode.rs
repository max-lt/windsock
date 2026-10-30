#![no_main]

use libfuzzer_sys::fuzz_target;
use s3proto::sigv4::{ChunkDecoder, ChunkError, ChunkSigner, signing_key};

fn signer() -> ChunkSigner {
    ChunkSigner {
        key: signing_key("secret", "20261030", "us-east-1"),
        timestamp: "20261030T000000Z".to_string(),
        scope: "20261030/us-east-1/s3/aws4_request".to_string(),
        previous: "00".repeat(32),
    }
}

/// Feeds `body` cut at `cuts`, and returns the data or the first error.
fn run(body: &[u8], cuts: &[usize], signed: bool) -> Result<Vec<u8>, ChunkError> {
    let mut decoder = ChunkDecoder::new(signed.then(signer));
    let mut out = Vec::new();
    let mut start = 0;
    for &end in cuts.iter().chain([&body.len()]) {
        let mut data = Vec::new();
        decoder.push(&body[start..end], &mut data)?;
        data.iter().for_each(|piece| out.extend_from_slice(piece));
        start = end;
    }
    let decoded = decoder.finish()?;
    assert_eq!(decoded, out.len() as u64);
    Ok(out)
}

// The first byte picks signed or unsigned and the cut points; the rest is the body. Any split
// must give the result of the whole body.
fuzz_target!(|input: &[u8]| {
    let Some((&control, body)) = input.split_first() else {
        return;
    };
    let signed = control & 1 == 1;
    let step = usize::from(control >> 1) + 1;
    let cuts: Vec<usize> = (step..body.len()).step_by(step).collect();

    let whole = run(body, &[], signed);

    assert_eq!(run(body, &cuts, signed), whole);
});
