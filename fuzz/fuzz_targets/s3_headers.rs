#![no_main]

use libfuzzer_sys::fuzz_target;
use s3proto::{sigv4, time};

fuzz_target!(|data: &[u8]| {
    let _ = sigv4::decode_chunked(data, None);
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = sigv4::Authorization::parse(text);
    let _ = time::parse_http_date(text);
    let _ = time::parse_amz_date(text);
});
