//! SigV4 in the query string: presigned URLs for GET, HEAD and PUT of one object.

use std::collections::HashMap;

use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use tracing::debug;

use crate::S3Error;
use crate::keys::{Grants, Key, KeyStore};
use s3proto::sigv4;
use s3proto::time::parse_amz_date;

const ALGORITHM: &str = "X-Amz-Algorithm";
const CREDENTIAL: &str = "X-Amz-Credential";
const DATE: &str = "X-Amz-Date";
const EXPIRES: &str = "X-Amz-Expires";
const SIGNED_HEADERS: &str = "X-Amz-SignedHeaders";
const SIGNATURE: &str = "X-Amz-Signature";
const SECURITY_TOKEN: &str = "X-Amz-Security-Token";

/// The six parameters of a presigned URL. Each one comes exactly once.
const REQUIRED: [&str; 6] = [
    ALGORITHM,
    CREDENTIAL,
    DATE,
    EXPIRES,
    SIGNED_HEADERS,
    SIGNATURE,
];

/// S3 caps the life of a presigned URL at 7 days.
pub(crate) const MAX_EXPIRES_SECS: u64 = 7 * 24 * 3600;

/// A presigned request whose signature matched.
pub(crate) struct Presigned {
    pub access_key: String,
    pub grants: Grants,
}

fn malformed(message: impl Into<String>) -> S3Error {
    S3Error::new(
        "AuthorizationQueryParametersError",
        StatusCode::BAD_REQUEST,
        message,
    )
}

/// True when the query carries one of the presigned parameters, in any case and any encoding:
/// then a missing one is an error, not a request with no authentication.
pub(crate) fn is_presigned(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        query.split('&').any(|pair| {
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            decode(name).is_some_and(|name| {
                REQUIRED
                    .iter()
                    .any(|known| name.eq_ignore_ascii_case(known.as_bytes()))
            })
        })
    })
}

/// Percent-decoding that refuses a `%` with no two hex digits after it.
fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let digits = bytes.get(i + 1..i + 3)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let digits = std::str::from_utf8(digits).ok()?;
        out.push(u8::from_str_radix(digits, 16).ok()?);
        i += 3;
    }
    Some(out)
}

/// The six parameters, decoded. A parameter of the presigned form in another case or encoding
/// counts as a second copy, so it cannot stay out of the signed query.
fn parameters(query: &str) -> Result<HashMap<&'static str, String>, S3Error> {
    let mut found: HashMap<&'static str, String> = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(name), Some(value)) = (decode(name), decode(value)) else {
            return Err(malformed(
                "a query parameter has an invalid percent-encoding",
            ));
        };
        if name.eq_ignore_ascii_case(SECURITY_TOKEN.as_bytes()) {
            return Err(malformed("X-Amz-Security-Token is not supported"));
        }
        let Some(&known) = REQUIRED
            .iter()
            .find(|known| name.eq_ignore_ascii_case(known.as_bytes()))
        else {
            continue;
        };
        if name != known.as_bytes() {
            return Err(malformed(format!("{known} must be written as {known}")));
        }
        let value = String::from_utf8(value)
            .map_err(|_| malformed(format!("{known} is not valid UTF-8")))?;
        if found.insert(known, value).is_some() {
            return Err(malformed(format!("{known} comes more than once")));
        }
    }
    for known in REQUIRED {
        if !found.contains_key(known) {
            return Err(malformed(format!("{known} is missing")));
        }
    }
    Ok(found)
}

/// The query with the signature taken out, for the canonical request.
fn signed_query(query: &str) -> String {
    query
        .split('&')
        .filter(|pair| {
            let name = pair.split_once('=').map_or(*pair, |(name, _)| name);
            decode(name).is_none_or(|name| name != SIGNATURE.as_bytes())
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Only GET, HEAD and a single PUT of an object take a presigned URL.
fn check_scope(parts: &Parts) -> Result<(), S3Error> {
    let refused = || S3Error::access_denied("presigned URLs cover GET, HEAD and PUT of an object");
    let segments = parts
        .uri
        .path()
        .trim_start_matches('/')
        .splitn(2, '/')
        .filter(|segment| !segment.is_empty())
        .count();
    if segments < 2 {
        return Err(refused());
    }
    match parts.method {
        Method::GET | Method::HEAD => Ok(()),
        Method::PUT => {
            let query = parts.uri.query().unwrap_or("");
            let multipart = query.split('&').any(|pair| {
                let name = pair.split_once('=').map_or(pair, |(name, _)| name);
                name == "uploadId" || name == "partNumber"
            });
            if multipart || parts.headers.contains_key("x-amz-copy-source") {
                return Err(refused());
            }
            Ok(())
        }
        _ => Err(refused()),
    }
}

fn expires(value: &str) -> Result<u64, S3Error> {
    // One spelling for one number: no sign, no leading zero, at most 6 digits.
    let digits = !value.is_empty()
        && value.len() <= 6
        && !value.starts_with('0')
        && value.bytes().all(|b| b.is_ascii_digit());
    let seconds = value.parse::<u64>().ok().filter(|_| digits);
    match seconds {
        Some(seconds) if (1..=MAX_EXPIRES_SECS).contains(&seconds) => Ok(seconds),
        _ => Err(malformed(format!(
            "X-Amz-Expires must be a number of seconds from 1 to {MAX_EXPIRES_SECS}"
        ))),
    }
}

/// Checks a presigned request at `now` (Unix seconds). The messages name a parameter, never
/// its value: the query holds the signature.
pub(crate) async fn verify(
    parts: &Parts,
    keys: &dyn KeyStore,
    now: u64,
    max_skew: u64,
) -> Result<Presigned, S3Error> {
    if parts.headers.contains_key("authorization") {
        return Err(malformed(
            "a request takes one authentication: a header or a query",
        ));
    }
    let query = parts.uri.query().unwrap_or("");
    let found = parameters(query)?;
    check_scope(parts)?;

    if found[ALGORITHM] != "AWS4-HMAC-SHA256" {
        return Err(malformed("X-Amz-Algorithm must be AWS4-HMAC-SHA256"));
    }
    let scope: Vec<&str> = found[CREDENTIAL].split('/').collect();
    let [access_key, date, region, "s3", "aws4_request"] = scope[..] else {
        return Err(malformed(
            "X-Amz-Credential is not access/date/region/s3/aws4_request",
        ));
    };
    let timestamp = found[DATE].as_str();
    let signed_at = parse_amz_date(timestamp)
        .filter(|_| timestamp.starts_with(date) && date.len() == 8)
        .ok_or_else(|| malformed("X-Amz-Date is not valid, or not the date of the credential"))?;
    let lifetime = expires(&found[EXPIRES])?;
    let signed_headers: Vec<String> = found[SIGNED_HEADERS]
        .split(';')
        .map(str::to_string)
        .collect();
    if !signed_headers.iter().any(|name| name == "host") {
        return Err(malformed("X-Amz-SignedHeaders must contain host"));
    }
    let signature = found[SIGNATURE].as_str();
    let hex = signature.len() == 64
        && signature
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !hex {
        return Err(malformed("X-Amz-Signature must be 64 lowercase hex digits"));
    }

    if signed_at > now.saturating_add(max_skew) {
        return Err(S3Error::access_denied("Request is not valid yet"));
    }
    if now >= signed_at.saturating_add(lifetime) {
        return Err(S3Error::access_denied("Request has expired"));
    }

    let Key { secret, grants } = crate::keys::key_of(keys, access_key).await?;
    let payload_hash = payload_hash(&parts.headers)?;
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(name, value)| {
            let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
            (name.as_str().to_string(), value)
        })
        .collect();
    let canonical = sigv4::canonical_request(
        parts.method.as_str(),
        parts.uri.path(),
        &signed_query(query),
        &headers,
        &signed_headers,
        payload_hash,
    );
    let key = sigv4::signing_key(secret.expose(), date, region);
    let scope = format!("{date}/{region}/s3/aws4_request");
    let expected = sigv4::signature(&key, timestamp, &scope, &canonical);
    if !sigv4::same_signature(&expected, signature) {
        debug!(access_key, "presigned signature mismatch");
        return Err(S3Error::new(
            "SignatureDoesNotMatch",
            StatusCode::FORBIDDEN,
            "the request signature does not match",
        ));
    }

    Ok(Presigned {
        access_key: access_key.to_string(),
        grants,
    })
}

/// A presigned body is unsigned, or signed by its hash. An `aws-chunked` body is refused.
fn payload_hash(headers: &HeaderMap) -> Result<&str, S3Error> {
    let Some(value) = headers.get("x-amz-content-sha256") else {
        return Ok(sigv4::UNSIGNED_PAYLOAD);
    };
    let value = value
        .to_str()
        .map_err(|_| malformed("x-amz-content-sha256 is not visible ASCII"))?;
    if value.starts_with("STREAMING-") {
        return Err(malformed("a presigned request takes no aws-chunked body"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_refuses_a_percent_with_no_two_hex_digits() {
        assert_eq!(decode("a%2Fb").unwrap(), b"a/b");
        assert!(decode("a%2").is_none());
        assert!(decode("a%zz").is_none());
        assert!(decode("a%+f").is_none());
    }

    #[tokio::test]
    async fn test_errors_never_hold_the_signature() {
        let signature = "5ec2e7".repeat(10) + "abcd";
        let keys =
            crate::StaticKeys::new(HashMap::from([("KEY".to_string(), "secret".to_string())]));
        let query = |expires: &str| {
            format!(
                "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=KEY%2F20261030%2Fus-east-1%2Fs3%2F\
                 aws4_request&X-Amz-Date=20261030T000000Z&X-Amz-Expires={expires}\
                 &X-Amz-SignedHeaders=host&X-Amz-Signature={signature}"
            )
        };
        let now = parse_amz_date("20261030T000000Z").unwrap();

        for query in [
            query("300"),
            query("0"),
            format!("{}&X-Amz-Date=x", query("300")),
        ] {
            let request = axum::http::Request::get(format!("/bkt/k?{query}"))
                .header("host", "localhost")
                .body(())
                .unwrap();
            let (parts, ()) = request.into_parts();
            let Err(error) = verify(&parts, &keys, now, 900).await else {
                panic!("{query} passed");
            };

            assert!(!format!("{error:?}").contains(&signature), "{error:?}");
            assert!(!error.to_string().contains(&signature));
        }
    }

    #[test]
    fn test_expires_takes_digits_only() {
        assert_eq!(expires("604800").unwrap(), MAX_EXPIRES_SECS);
        for refused in ["0", "604801", "+1", "0007", "1e3", "", "1234567", " 1"] {
            assert!(expires(refused).is_err(), "{refused}");
        }
    }
}
