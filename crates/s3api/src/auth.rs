//! Request authentication: SigV4 on the head, then the payload against its signed hash.

use std::sync::Arc;
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

use crate::keys::{self, Grants, Key, KeyStore};
use crate::metrics::CallerSlot;
use crate::{AppState, Caller, S3Error, StreamedBody, grants, presign};
use s3proto::sigv4::{self, Authorization, ChunkDecoder, ChunkSigner};
use s3proto::time::parse_amz_date;

/// AWS rejects a request whose `x-amz-date` is further than this from its clock.
const MAX_SKEW_SECS: u64 = 15 * 60;

/// A request head whose signature matched.
struct Verified {
    access_key: String,
    grants: Grants,
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

async fn verify_head(parts: &Parts, keys: &dyn KeyStore, now: u64) -> Result<Verified, S3Error> {
    let authorization = header(&parts.headers, "authorization")
        .and_then(Authorization::parse)
        .ok_or_else(|| S3Error::access_denied("a SigV4 Authorization header is required"))?;

    let Key { secret, grants } = keys::key_of(keys, &authorization.access_key).await?;

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

    let signing_key =
        sigv4::signing_key(secret.expose(), &authorization.date, &authorization.region);
    let scope = authorization.scope();
    let expected = sigv4::signature(&signing_key, timestamp, &scope, &canonical);

    if !sigv4::same_signature(&expected, &authorization.signature) {
        debug!(access_key = %authorization.access_key, "signature mismatch");
        return Err(signature_mismatch());
    }

    Ok(Verified {
        access_key: authorization.access_key,
        grants,
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
    let decoded = match hash {
        sigv4::UNSIGNED_PAYLOAD => return Ok(body),
        sigv4::STREAMING_SIGNED | sigv4::STREAMING_SIGNED_TRAILER => {
            let signer = signer.ok_or_else(signature_mismatch)?;
            sigv4::decode_chunked(&body, Some(signer)).map_err(chunk_error)?
        }
        sigv4::STREAMING_UNSIGNED_TRAILER => {
            sigv4::decode_chunked(&body, None).map_err(chunk_error)?
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

/// A PUT body up to this size goes through the buffer in one record, with the group fsync.
const SMALL_PUT: u64 = 1024 * 1024;

/// The body check of a PUT that the handler streams: an upload part, or an object with a larger
/// or unknown length.
/// `None` for any other request. A signed aws-chunked body with no chunk signer is refused.
fn streamed(parts: &Parts, signer: Option<&ChunkSigner>) -> Result<Option<StreamedBody>, S3Error> {
    if parts.method != Method::PUT || parts.headers.contains_key("x-amz-copy-source") {
        return Ok(None);
    }
    let object = parts.uri.path().trim_start_matches('/').split_once('/');
    if object.is_none_or(|(_, key)| key.is_empty()) {
        return Ok(None);
    }
    let query = parts.uri.query().unwrap_or("");
    let part = query.split('&').any(|pair| {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        name == "uploadId" || name == "partNumber"
    });
    let length = header(&parts.headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    // An HTTP/2 body or a chunked body has no length: only a stream bounds its memory.
    let large = length.is_none_or(|length| length > SMALL_PUT);
    // Every upload part streams to its part file; a small PUT goes through the buffer.
    if !part && !large {
        return Ok(None);
    }
    let hash = header(&parts.headers, "x-amz-content-sha256").unwrap_or(sigv4::UNSIGNED_PAYLOAD);
    let decoded_length =
        header(&parts.headers, "x-amz-decoded-content-length").and_then(|v| v.parse().ok());
    let streamed = |sha256, chunked| {
        Some(StreamedBody {
            sha256,
            length,
            chunked,
            decoded_length,
        })
    };
    Ok(match hash {
        sigv4::UNSIGNED_PAYLOAD => streamed(None, None),
        sigv4::STREAMING_SIGNED | sigv4::STREAMING_SIGNED_TRAILER => {
            let signer = signer.cloned().ok_or_else(signature_mismatch)?;
            streamed(None, Some(ChunkDecoder::new(Some(signer))))
        }
        sigv4::STREAMING_UNSIGNED_TRAILER => streamed(None, Some(ChunkDecoder::new(None))),
        hash => streamed(Some(hash.to_ascii_lowercase()), None),
    })
}

/// Refuses, before any read, a body that no check can take: an unknown payload hash, or a
/// Content-Length next to a Transfer-Encoding, which two parsers can read in two ways.
fn check_framing(parts: &Parts) -> Result<(), S3Error> {
    let hash = header(&parts.headers, "x-amz-content-sha256").unwrap_or(sigv4::UNSIGNED_PAYLOAD);
    let known = matches!(
        hash,
        sigv4::UNSIGNED_PAYLOAD
            | sigv4::STREAMING_SIGNED
            | sigv4::STREAMING_SIGNED_TRAILER
            | sigv4::STREAMING_UNSIGNED_TRAILER
    ) || (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()));
    if !known {
        return Err(S3Error::invalid_argument(
            "x-amz-content-sha256 must be a SHA-256 hex digest, UNSIGNED-PAYLOAD or a known \
             STREAMING- value",
        ));
    }
    let framed = ["content-length", "transfer-encoding"];
    if framed.iter().all(|name| parts.headers.contains_key(*name)) {
        return Err(S3Error::invalid_argument(
            "a request with Transfer-Encoding must have no Content-Length",
        ));
    }
    Ok(())
}

/// The S3 error of an aws-chunked body that fails to decode.
pub(crate) fn chunk_error(e: sigv4::ChunkError) -> S3Error {
    match e {
        sigv4::ChunkError::BadSignature => signature_mismatch(),
        sigv4::ChunkError::Malformed | sigv4::ChunkError::Incomplete => {
            S3Error::new("IncompleteBody", StatusCode::BAD_REQUEST, e.to_string())
        }
    }
}

/// The longest XML request body: 10 000 parts or 1 000 keys fit in less.
const MAX_XML_BODY: usize = 4 * 1024 * 1024;

/// The longest body of a request that carries no data, as a copy: S3 gives it no body.
const MAX_EMPTY_BODY: usize = 64 * 1024;

/// The cap of a body that is read whole into memory, and the error code above it.
fn buffered_limit(parts: &Parts) -> (usize, &'static str) {
    let path = parts.uri.path().trim_start_matches('/');
    let object = path.split_once('/').is_some_and(|(_, key)| !key.is_empty());
    let copy = parts.headers.contains_key("x-amz-copy-source");
    match parts.method {
        Method::POST => (MAX_XML_BODY, "MaxMessageLengthExceeded"),
        Method::PUT if object && !copy => (SMALL_PUT as usize, "EntityTooLarge"),
        Method::PUT if !object => (MAX_XML_BODY, "EntityTooLarge"),
        _ => (MAX_EMPTY_BODY, "EntityTooLarge"),
    }
}

/// Middleware for every S3 route. The handlers get the checked, decoded body.
pub(crate) async fn authenticate<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    request: Request,
    next: Next,
) -> Result<Response, S3Error> {
    let (mut parts, body) = request.into_parts();
    let (access_key, grants, signer) = match presign::is_presigned(parts.uri.query()) {
        true => {
            // The expiry needs a wall clock that the proxy trusts.
            if let Err(engine::EngineError::ClockAhead { wait_secs }) = state.engine.check_clock() {
                return Err(S3Error::new(
                    "SlowDown",
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("the clock is ahead, presigned requests resume in {wait_secs} s"),
                ));
            }
            let presigned =
                presign::verify(&parts, state.keys.as_ref(), unix_now(), MAX_SKEW_SECS).await?;
            (presigned.access_key, presigned.grants, None)
        }
        false => {
            let verified = verify_head(&parts, state.keys.as_ref(), unix_now()).await?;
            let signer = ChunkSigner {
                key: verified.signing_key,
                timestamp: verified.timestamp,
                scope: verified.scope,
                previous: verified.signature,
            };
            (verified.access_key, verified.grants, Some(signer))
        }
    };
    if let Some(slot) = parts.extensions.get::<CallerSlot>() {
        slot.set(&access_key);
    }
    grants::check(&state.engine, &parts, &access_key, &grants).await?;
    parts
        .extensions
        .insert(Caller(access_key, Arc::new(grants)));
    check_framing(&parts)?;
    if let Some(stream) = streamed(&parts, signer.as_ref())? {
        if stream
            .length
            .is_some_and(|length| length > state.max_body as u64)
        {
            return Err(S3Error::entity_too_large(state.max_body));
        }
        strip_aws_chunked(&mut parts.headers);
        parts.extensions.insert(stream);
        return Ok(next.run(Request::from_parts(parts, body)).await);
    }

    let (limit, too_large) = buffered_limit(&parts);
    let limit = limit.min(state.max_body);
    let length = header(&parts.headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    if length.is_some_and(|length| length > limit as u64) {
        return Err(S3Error::new(
            too_large,
            StatusCode::BAD_REQUEST,
            format!("the body is larger than {limit} bytes"),
        ));
    }
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
