//! Request authentication: SigV4 on the head, then the payload against its signed hash.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use bytes::Bytes;
use remote::Remote;
use tracing::debug;

use crate::{AppState, Caller, S3Error, presign};
use s3proto::sigv4::{self, Authorization, ChunkSigner};
use s3proto::time::parse_amz_date;

/// AWS rejects a request whose `x-amz-date` is further than this from its clock.
const MAX_SKEW_SECS: u64 = 15 * 60;

/// A request head whose signature matched.
struct Verified {
    access_key: String,
    signing_key: [u8; 32],
    timestamp: String,
    scope: String,
    signature: String,
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn signature_mismatch() -> S3Error {
    S3Error::new(
        "SignatureDoesNotMatch",
        StatusCode::FORBIDDEN,
        "the request signature does not match",
    )
}

fn verify_head(
    parts: &Parts,
    keys: &HashMap<String, String>,
    now: u64,
) -> Result<Verified, S3Error> {
    let authorization = header(&parts.headers, "authorization")
        .and_then(Authorization::parse)
        .ok_or_else(|| S3Error::access_denied("a SigV4 Authorization header is required"))?;

    let secret = keys.get(&authorization.access_key).ok_or_else(|| {
        S3Error::new(
            "InvalidAccessKeyId",
            StatusCode::FORBIDDEN,
            "the access key does not exist",
        )
    })?;

    let timestamp = header(&parts.headers, "x-amz-date")
        .ok_or_else(|| S3Error::access_denied("x-amz-date is required"))?;
    let signed_at = parse_amz_date(timestamp)
        .ok_or_else(|| S3Error::access_denied("x-amz-date is not valid"))?;

    if now.abs_diff(signed_at) > MAX_SKEW_SECS || !timestamp.starts_with(&authorization.date) {
        return Err(S3Error::new(
            "RequestTimeTooSkewed",
            StatusCode::FORBIDDEN,
            "the request time is too far from the server time",
        ));
    }

    if !authorization.signed_headers.iter().any(|h| h == "host") {
        return Err(signature_mismatch());
    }

    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(name, value)| {
            let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
            (name.as_str().to_string(), value)
        })
        .collect();
    let payload_hash =
        header(&parts.headers, "x-amz-content-sha256").unwrap_or(sigv4::UNSIGNED_PAYLOAD);
    let canonical = sigv4::canonical_request(
        parts.method.as_str(),
        parts.uri.path(),
        parts.uri.query().unwrap_or(""),
        &headers,
        &authorization.signed_headers,
        payload_hash,
    );

    let signing_key = sigv4::signing_key(secret, &authorization.date, &authorization.region);
    let scope = authorization.scope();
    let expected = sigv4::signature(&signing_key, timestamp, &scope, &canonical);

    if !sigv4::same_signature(&expected, &authorization.signature) {
        debug!(access_key = %authorization.access_key, "signature mismatch");
        return Err(signature_mismatch());
    }

    Ok(Verified {
        access_key: authorization.access_key,
        signing_key,
        timestamp: timestamp.to_string(),
        scope,
        signature: authorization.signature,
    })
}

/// The body as the client meant it: checked against the signed hash, or decoded from `aws-chunked`.
/// A presigned request has no signer: it takes no signed chunks.
fn payload(
    headers: &HeaderMap,
    signer: Option<ChunkSigner>,
    body: Bytes,
) -> Result<Bytes, S3Error> {
    let hash = header(headers, "x-amz-content-sha256").unwrap_or(sigv4::UNSIGNED_PAYLOAD);
    let incomplete = |e: sigv4::ChunkError| match e {
        sigv4::ChunkError::BadSignature => signature_mismatch(),
        sigv4::ChunkError::Malformed => {
            S3Error::new("IncompleteBody", StatusCode::BAD_REQUEST, e.to_string())
        }
    };
    let decoded = match hash {
        sigv4::UNSIGNED_PAYLOAD => return Ok(body),
        sigv4::STREAMING_SIGNED | sigv4::STREAMING_SIGNED_TRAILER => {
            let signer = signer.ok_or_else(signature_mismatch)?;
            sigv4::decode_chunked(&body, Some(signer)).map_err(incomplete)?
        }
        sigv4::STREAMING_UNSIGNED_TRAILER => {
            sigv4::decode_chunked(&body, None).map_err(incomplete)?
        }
        hex if sigv4::sha256_hex(&body) == hex.to_ascii_lowercase() => return Ok(body),
        _ => {
            return Err(S3Error::new(
                "XAmzContentSHA256Mismatch",
                StatusCode::BAD_REQUEST,
                "the body does not match x-amz-content-sha256",
            ));
        }
    };

    let declared =
        header(headers, "x-amz-decoded-content-length").and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|len| len != decoded.len()) {
        return Err(S3Error::new(
            "IncompleteBody",
            StatusCode::BAD_REQUEST,
            "the body is shorter or longer than x-amz-decoded-content-length",
        ));
    }

    Ok(Bytes::from(decoded))
}

/// `aws-chunked` is a transfer detail: it must not reach the stored Content-Encoding.
fn strip_aws_chunked(headers: &mut HeaderMap) {
    let Some(encoding) = header(headers, "content-encoding") else {
        return;
    };

    let rest: Vec<&str> = encoding
        .split(',')
        .map(str::trim)
        .filter(|e| !e.eq_ignore_ascii_case("aws-chunked") && !e.is_empty())
        .collect();

    if rest.is_empty() {
        headers.remove("content-encoding");
    } else if let Ok(value) = HeaderValue::from_str(&rest.join(", ")) {
        headers.insert("content-encoding", value);
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The longest XML request body: 10 000 parts or 1 000 keys fit in less.
const MAX_XML_BODY: usize = 4 * 1024 * 1024;

/// Middleware for every S3 route. The handlers get the checked, decoded body.
pub(crate) async fn authenticate<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    request: Request,
    next: Next,
) -> Result<Response, S3Error> {
    let (mut parts, body) = request.into_parts();
    let (access_key, signer) = match presign::is_presigned(parts.uri.query()) {
        true => {
            // The expiry needs a wall clock that the proxy trusts.
            state.engine.check_clock()?;
            let presigned = presign::verify(&parts, &state.keys, unix_now(), MAX_SKEW_SECS)?;
            (presigned.access_key, None)
        }
        false => {
            let verified = verify_head(&parts, &state.keys, unix_now())?;
            let signer = ChunkSigner {
                key: verified.signing_key,
                timestamp: verified.timestamp,
                scope: verified.scope,
                previous: verified.signature,
            };
            (verified.access_key, Some(signer))
        }
    };
    parts.extensions.insert(Caller(access_key));

    // A POST carries XML only. Its body must not take the memory of an object upload.
    let (limit, too_large) = match parts.method {
        Method::POST => (MAX_XML_BODY.min(state.max_body), "MaxMessageLengthExceeded"),
        _ => (state.max_body, "EntityTooLarge"),
    };
    let body = axum::body::to_bytes(body, limit).await.map_err(|e| {
        let over_limit = std::iter::successors(Some(&e as &dyn std::error::Error), |e| e.source())
            .any(|e| e.is::<http_body_util::LengthLimitError>());
        match over_limit {
            true => S3Error::new(
                too_large,
                StatusCode::BAD_REQUEST,
                format!("the body is larger than {limit} bytes"),
            ),
            false => S3Error::new(
                "IncompleteBody",
                StatusCode::BAD_REQUEST,
                "the body did not arrive whole",
            ),
        }
    })?;
    let body = payload(&parts.headers, signer, body)?;
    strip_aws_chunked(&mut parts.headers);

    Ok(next.run(Request::from_parts(parts, Body::from(body))).await)
}
