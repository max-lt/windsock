//! AWS Signature Version 4 for S3: header signatures, payload hashes, and
//! `aws-chunked` bodies. No I/O.
//!
//! The signing side serves tests and tools. Known-answer tests from the AWS
//! documentation pin both sides, so a shared bug cannot hide.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// The body is not part of the signature.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// `aws-chunked` body, each chunk signed.
pub const STREAMING_SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/// `aws-chunked` body, each chunk signed, then signed trailers.
pub const STREAMING_SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
/// `aws-chunked` body, no chunk signatures, then trailers.
pub const STREAMING_UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The parts of an `Authorization: AWS4-HMAC-SHA256 ...` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub access_key: String,
    /// `YYYYMMDD`
    pub date: String,
    pub region: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

impl Authorization {
    pub fn parse(header: &str) -> Option<Self> {
        let rest = header.trim().strip_prefix(ALGORITHM)?.trim();
        let (mut credential, mut signed, mut signature) = (None, None, None);

        for part in rest.split(',').map(str::trim) {
            if let Some(value) = part.strip_prefix("Credential=") {
                credential = Some(value);
            } else if let Some(value) = part.strip_prefix("SignedHeaders=") {
                signed = Some(value);
            } else if let Some(value) = part.strip_prefix("Signature=") {
                signature = Some(value);
            }
        }

        let scope: Vec<&str> = credential?.split('/').collect();
        let [access_key, date, region, "s3", "aws4_request"] = scope[..] else {
            return None;
        };

        Some(Self {
            access_key: access_key.to_string(),
            date: date.to_string(),
            region: region.to_string(),
            signed_headers: signed?.split(';').map(str::to_string).collect(),
            signature: signature?.to_string(),
        })
    }

    pub fn scope(&self) -> String {
        format!("{}/{}/s3/aws4_request", self.date, self.region)
    }
}

/// RFC 3986 encoding: everything but `A-Z a-z 0-9 - _ . ~` is `%XX`, and `/` when asked.
pub fn uri_encode(bytes: &[u8], encode_slash: bool) -> String {
    let mut out = String::with_capacity(bytes.len());

    for &b in bytes {
        let plain = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (b == b'/' && !encode_slash);

        if plain {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }

    out
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match (bytes[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }

    out
}

/// Every name and value encoded once, sorted by name then value. A client may
/// send a character raw or encoded: both give the same canonical form.
pub fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                uri_encode(&percent_decode(name), true),
                uri_encode(&percent_decode(value), true),
            )
        })
        .collect();
    pairs.sort();

    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// `headers` are (lowercase name, value) pairs; several values of one name are joined with commas.
pub fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    signed_headers: &[String],
    payload_hash: &str,
) -> String {
    let mut canonical_headers = String::new();

    for name in signed_headers {
        let values: Vec<String> = headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        canonical_headers.push_str(&format!("{name}:{}\n", values.join(",")));
    }

    let path = if path.is_empty() { "/" } else { path };

    format!(
        "{method}\n{path}\n{}\n{canonical_headers}\n{}\n{payload_hash}",
        canonical_query(query),
        signed_headers.join(";")
    )
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes a key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The signing key of one secret, day and region.
pub fn signing_key(secret: &str, date: &str, region: &str) -> [u8; 32] {
    let date_key = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let region_key = hmac(&date_key, region.as_bytes());
    let service_key = hmac(&region_key, b"s3");
    hmac(&service_key, b"aws4_request")
}

pub fn signature(key: &[u8; 32], timestamp: &str, scope: &str, canonical_request: &str) -> String {
    let to_sign = format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    hex::encode(hmac(key, to_sign.as_bytes()))
}

/// Compares two hex signatures in constant time.
pub fn same_signature(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// What signs the chunks of an `aws-chunked` body.
#[derive(Clone, Debug)]
pub struct ChunkSigner {
    pub key: [u8; 32],
    pub timestamp: String,
    pub scope: String,
    /// The signature of the previous chunk; the request signature for the first one.
    pub previous: String,
}

impl ChunkSigner {
    fn sign_chunk(&mut self, data: &[u8]) -> String {
        let to_sign = format!(
            "{ALGORITHM}-PAYLOAD\n{}\n{}\n{}\n{EMPTY_SHA256}\n{}",
            self.timestamp,
            self.scope,
            self.previous,
            sha256_hex(data)
        );
        self.previous = hex::encode(hmac(&self.key, to_sign.as_bytes()));
        self.previous.clone()
    }

    fn sign_trailer(&mut self, trailer: &str) -> String {
        let to_sign = format!(
            "{ALGORITHM}-TRAILER\n{}\n{}\n{}\n{}",
            self.timestamp,
            self.scope,
            self.previous,
            sha256_hex(trailer.as_bytes())
        );
        hex::encode(hmac(&self.key, to_sign.as_bytes()))
    }
}

/// An `aws-chunked` body that does not decode, or a chunk signature that does not match.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChunkError {
    #[error("malformed aws-chunked body")]
    Malformed,
    #[error("chunk signature does not match")]
    BadSignature,
}

fn line(body: &[u8]) -> Result<(&str, &[u8]), ChunkError> {
    let end = body
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(ChunkError::Malformed)?;
    let text = std::str::from_utf8(&body[..end]).map_err(|_| ChunkError::Malformed)?;
    Ok((text, &body[end + 2..]))
}

/// Decodes an `aws-chunked` body. With a signer, every chunk signature and the
/// trailer signature, when there is one, must match.
pub fn decode_chunked(
    mut body: &[u8],
    mut signer: Option<ChunkSigner>,
) -> Result<Vec<u8>, ChunkError> {
    let mut out = Vec::new();

    loop {
        let (header, rest) = line(body)?;
        let (size, extension) = header.split_once(';').unwrap_or((header, ""));
        let size = usize::from_str_radix(size.trim(), 16).map_err(|_| ChunkError::Malformed)?;

        if rest.len() < size {
            return Err(ChunkError::Malformed);
        }
        let (data, rest) = rest.split_at(size);

        if let Some(signer) = signer.as_mut() {
            let given = extension
                .strip_prefix("chunk-signature=")
                .ok_or(ChunkError::BadSignature)?;
            if !same_signature(&signer.sign_chunk(data), given) {
                return Err(ChunkError::BadSignature);
            }
        }

        if size == 0 {
            return decode_trailers(rest, signer).map(|()| out);
        }

        out.extend_from_slice(data);
        body = rest.strip_prefix(b"\r\n").ok_or(ChunkError::Malformed)?;
    }
}

/// After the last chunk: optional trailer lines, an optional trailer signature, an empty line.
fn decode_trailers(mut rest: &[u8], mut signer: Option<ChunkSigner>) -> Result<(), ChunkError> {
    let mut trailers = String::new();

    loop {
        if rest.is_empty() {
            // Some clients end the body right after the last chunk line.
            return if trailers.is_empty() {
                Ok(())
            } else {
                Err(ChunkError::Malformed)
            };
        }

        let (text, next) = line(rest)?;
        rest = next;

        if text.is_empty() {
            return Ok(());
        }

        if let Some(given) = text.strip_prefix("x-amz-trailer-signature:") {
            let signer = signer.as_mut().ok_or(ChunkError::BadSignature)?;
            if !same_signature(&signer.sign_trailer(&trailers), given.trim()) {
                return Err(ChunkError::BadSignature);
            }
            continue;
        }

        trailers.push_str(text);
        trailers.push('\n');
    }
}

/// Encodes `data` as `aws-chunked` with chunks of `chunk_size` bytes, signed when a signer is given.
pub fn encode_chunked(data: &[u8], chunk_size: usize, mut signer: Option<ChunkSigner>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
    chunks.push(&[]);

    for chunk in chunks {
        out.extend_from_slice(format!("{:x}", chunk.len()).as_bytes());
        if let Some(signer) = signer.as_mut() {
            out.extend_from_slice(
                format!(";chunk-signature={}", signer.sign_chunk(chunk)).as_bytes(),
            );
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }

    out
}

/// The `x-amz-date` value of a unix time.
pub fn timestamp(unix_secs: u64) -> String {
    crate::time::amz_date(unix_secs)
}

/// A request to sign: the client side, for tests and tools.
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    /// Every header to sign, `host` included, with lowercase names.
    pub headers: &'a [(String, String)],
    pub payload_hash: &'a str,
}

/// The `Authorization` header value for `request`, and the signature in it.
pub fn sign(
    request: &Request<'_>,
    access_key: &str,
    secret: &str,
    timestamp: &str,
    region: &str,
) -> (String, String) {
    let date = &timestamp[..8];
    let mut signed: Vec<String> = request.headers.iter().map(|(n, _)| n.clone()).collect();
    signed.sort();
    signed.dedup();

    let canonical = canonical_request(
        request.method,
        request.path,
        request.query,
        request.headers,
        &signed,
        request.payload_hash,
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let signature = signature(
        &signing_key(secret, date, region),
        timestamp,
        &scope,
        &canonical,
    );
    let header = format!(
        "{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={}, Signature={signature}",
        signed.join(";")
    );

    (header, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const TIMESTAMP: &str = "20130524T000000Z";

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    /// AWS documentation, "Example: GET Object".
    #[test]
    fn test_known_answer_get_object() {
        let headers = headers(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", EMPTY_SHA256),
            ("x-amz-date", TIMESTAMP),
        ]);
        let request = Request {
            method: "GET",
            path: "/test.txt",
            query: "",
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        };

        let (_, signature) = sign(&request, ACCESS_KEY, SECRET, TIMESTAMP, "us-east-1");

        assert_eq!(
            signature,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// AWS documentation, "Signature Calculations for the Authorization Header:
    /// Transferring Payload in Multiple Chunks": 66560 bytes of 'a' in chunks of 64 KiB.
    #[test]
    fn test_known_answer_chunked_upload() {
        let headers = headers(&[
            ("content-encoding", "aws-chunked"),
            ("content-length", "66824"),
            ("host", "s3.amazonaws.com"),
            ("x-amz-content-sha256", STREAMING_SIGNED),
            ("x-amz-date", TIMESTAMP),
            ("x-amz-decoded-content-length", "66560"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ]);
        let request = Request {
            method: "PUT",
            path: "/examplebucket/chunkObject.txt",
            query: "",
            headers: &headers,
            payload_hash: STREAMING_SIGNED,
        };
        let (_, seed) = sign(&request, ACCESS_KEY, SECRET, TIMESTAMP, "us-east-1");
        assert_eq!(
            seed,
            "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
        );

        let signer = ChunkSigner {
            key: signing_key(SECRET, "20130524", "us-east-1"),
            timestamp: TIMESTAMP.to_string(),
            scope: "20130524/us-east-1/s3/aws4_request".to_string(),
            previous: seed,
        };
        let data = vec![b'a'; 66560];
        let body = encode_chunked(&data, 65536, Some(signer.clone()));
        let text = String::from_utf8_lossy(&body);

        assert_eq!(body.len(), 66824);
        assert!(text.starts_with(
            "10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n"
        ));
        assert!(text.contains(
            "400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n"
        ));
        assert!(text.ends_with(
            "0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n\r\n"
        ));
        assert_eq!(decode_chunked(&body, Some(signer)).unwrap(), data);
    }

    fn signer() -> ChunkSigner {
        ChunkSigner {
            key: signing_key(SECRET, "20130524", "us-east-1"),
            timestamp: TIMESTAMP.to_string(),
            scope: "20130524/us-east-1/s3/aws4_request".to_string(),
            previous: "00".repeat(32),
        }
    }

    #[test]
    fn test_tampered_chunk_is_rejected() {
        let mut body = encode_chunked(b"hello world", 4, Some(signer()));
        let at = body.iter().position(|&b| b == b'h').unwrap();
        body[at] = b'j';

        assert_eq!(
            decode_chunked(&body, Some(signer())),
            Err(ChunkError::BadSignature)
        );
    }

    #[test]
    fn test_unsigned_chunks_with_trailer_decode() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n";

        assert_eq!(decode_chunked(body, None).unwrap(), b"hello world");
    }

    #[test]
    fn test_signed_trailer_is_checked() {
        let mut signer = signer();
        let mut body = encode_chunked(b"hello", 8, Some(signer.clone()));
        body.truncate(body.len() - 2);
        for chunk in [&b"hello"[..], &[]] {
            signer.sign_chunk(chunk);
        }
        let trailer = "x-amz-checksum-crc32:AAAAAA==\n";
        let good = signer.sign_trailer(trailer);
        let with = |signature: &str| {
            let mut out = body.clone();
            out.extend_from_slice(
                format!(
                    "x-amz-checksum-crc32:AAAAAA==\r\nx-amz-trailer-signature:{signature}\r\n\r\n"
                )
                .as_bytes(),
            );
            out
        };

        assert_eq!(
            decode_chunked(&with(&good), Some(self::signer())).unwrap(),
            b"hello"
        );
        assert_eq!(
            decode_chunked(&with(&"0".repeat(64)), Some(self::signer())),
            Err(ChunkError::BadSignature)
        );
    }

    #[test]
    fn test_truncated_chunk_is_malformed() {
        assert_eq!(
            decode_chunked(b"a\r\nhello", None),
            Err(ChunkError::Malformed)
        );
        assert_eq!(decode_chunked(b"zz\r\n", None), Err(ChunkError::Malformed));
    }

    #[test]
    fn test_canonical_query_encodes_once_and_sorts() {
        assert_eq!(
            canonical_query("prefix=a/b&list-type=2&uploads"),
            "list-type=2&prefix=a%2Fb&uploads="
        );
        assert_eq!(canonical_query("prefix=a%2Fb"), "prefix=a%2Fb");
        assert_eq!(canonical_query("k=a%20b"), "k=a%20b");
    }

    #[test]
    fn test_parse_authorization() {
        let header = format!(
            "{ALGORITHM} Credential=AK/20260101/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=ab"
        );
        let parsed = Authorization::parse(&header).unwrap();

        assert_eq!(parsed.access_key, "AK");
        assert_eq!(parsed.scope(), "20260101/eu-west-1/s3/aws4_request");
        assert_eq!(parsed.signed_headers, ["host", "x-amz-date"]);
        assert!(Authorization::parse("Bearer x").is_none());
        assert!(Authorization::parse(&header.replace("/s3/", "/ec2/")).is_none());
    }
}
