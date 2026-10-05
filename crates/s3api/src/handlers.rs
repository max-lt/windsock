//! S3 operations. A query parameter picks the operation when a path and method have several.

use std::collections::BTreeMap;
use std::ops::Range;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use bytes::Bytes;
use engine::{ObjectInfo, WriteMode};
use remote::Remote;
use tracing::info;

use crate::list::{After, Item, page};
use crate::xml::{self, ListPage, ListedObject};
use crate::{AppState, Caller, S3Error};
use s3proto::time::{http_date, parse_http_date};

type Reply = Result<axum::response::Response, S3Error>;
type Params = Query<BTreeMap<String, String>>;

/// Headers stored with an object and returned as they were sent.
const STORED_HEADERS: &[&str] = &[
    "content-type",
    "cache-control",
    "content-encoding",
    "content-disposition",
    "content-language",
    "expires",
];

/// Bucket sub-resources that Windsock does not implement.
const BUCKET_UNSUPPORTED: &[&str] = &[
    "accelerate",
    "acl",
    "analytics",
    "cors",
    "encryption",
    "intelligent-tiering",
    "inventory",
    "lifecycle",
    "logging",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "policy",
    "publicAccessBlock",
    "replication",
    "requestPayment",
    "tagging",
    "versions",
    "website",
];

/// Object sub-resources that Windsock does not implement.
const OBJECT_UNSUPPORTED: &[&str] = &[
    "acl",
    "attributes",
    "legal-hold",
    "restore",
    "retention",
    "select",
    "tagging",
    "torrent",
];

const MAX_KEYS: usize = 1000;
const MAX_DELETE_KEYS: usize = 1000;

fn reply(status: StatusCode) -> axum::http::response::Builder {
    Response::builder().status(status)
}

fn empty(status: StatusCode) -> Reply {
    Ok(reply(status)
        .body(Body::empty())
        .expect("static headers are valid"))
}

fn xml_reply(body: String) -> Reply {
    Ok(reply(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(body))
        .expect("static headers are valid"))
}

fn reject_unsupported(
    params: &BTreeMap<String, String>,
    unsupported: &[&str],
) -> Result<(), S3Error> {
    match unsupported.iter().find(|op| params.contains_key(**op)) {
        Some(op) => Err(S3Error::not_implemented(format!("'{op}' is not supported"))),
        None => Ok(()),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn etag(info: &ObjectInfo) -> String {
    hex::encode(info.content_hash)
}

/// Stored headers, and `x-amz-meta-*` headers under their full names.
fn metadata(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| {
            STORED_HEADERS.contains(&name.as_str()) || name.as_str().starts_with("x-amz-meta-")
        })
        .filter_map(|(name, value)| {
            Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
        })
        .collect()
}

/// ETag, Last-Modified, Content-Type and the stored metadata of an object.
fn object_headers(
    mut builder: axum::http::response::Builder,
    info: &ObjectInfo,
) -> axum::http::response::Builder {
    builder = builder
        .header("etag", xml::quoted(&etag(info)))
        .header("last-modified", http_date(info.last_modified))
        .header("accept-ranges", "bytes");

    if !info.metadata.contains_key("content-type") {
        builder = builder.header("content-type", "binary/octet-stream");
    }

    // Metadata can come from another proxy: skip what is not a valid header.
    for (name, value) in &info.metadata {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(name, value);
        }
    }

    builder
}

// ----------------------------------------------------------------------
// Conditional requests (RFC 7232, section 6)
// ----------------------------------------------------------------------

/// What the precondition headers allow.
#[derive(Debug, PartialEq, Eq)]
enum Precondition {
    Proceed,
    NotModified,
    Failed,
}

/// `If-Match` and `If-None-Match` hold a list of ETags, or `*`.
fn etag_matches(list: &str, etag: &str) -> bool {
    list.split(',').map(str::trim).any(|candidate| {
        let candidate = candidate.strip_prefix("W/").unwrap_or(candidate);
        candidate == "*" || candidate.trim_matches('"') == etag
    })
}

fn precondition(headers: &HeaderMap, info: &ObjectInfo) -> Precondition {
    let etag = etag(info);
    let modified = info.last_modified / 1_000_000_000;
    let date = |name| header(headers, name).and_then(parse_http_date);

    match header(headers, "if-match") {
        Some(list) if !etag_matches(list, &etag) => return Precondition::Failed,
        Some(_) => {}
        None if date("if-unmodified-since").is_some_and(|since| modified > since) => {
            return Precondition::Failed;
        }
        None => {}
    }

    match header(headers, "if-none-match") {
        Some(list) if etag_matches(list, &etag) => Precondition::NotModified,
        Some(_) => Precondition::Proceed,
        None if date("if-modified-since").is_some_and(|since| modified <= since) => {
            Precondition::NotModified
        }
        None => Precondition::Proceed,
    }
}

fn not_modified(info: &ObjectInfo) -> Reply {
    Ok(reply(StatusCode::NOT_MODIFIED)
        .header("etag", xml::quoted(&etag(info)))
        .header("last-modified", http_date(info.last_modified))
        .body(Body::empty())
        .expect("formatted headers are valid"))
}

// ----------------------------------------------------------------------
// Ranges (RFC 7233)
// ----------------------------------------------------------------------

/// The byte range of a `Range` header. `None` serves the whole object: a header
/// that does not parse, or that asks for several ranges, is ignored, as RFC 7233 allows.
fn byte_range(headers: &HeaderMap, size: u64) -> Result<Option<Range<u64>>, S3Error> {
    let Some(spec) = header(headers, "range").and_then(|r| r.trim().strip_prefix("bytes=")) else {
        return Ok(None);
    };
    if spec.contains(',') {
        return Ok(None);
    }
    let Some((start, end)) = spec.split_once('-') else {
        return Ok(None);
    };
    let unsatisfiable = || S3Error::invalid_range(format!("bytes={spec} is outside {size} bytes"));

    let range = match (
        start.trim().parse::<u64>().ok(),
        end.trim().parse::<u64>().ok(),
    ) {
        (None, Some(_)) if !start.trim().is_empty() => return Ok(None),
        (None, Some(0)) => return Err(unsatisfiable()),
        (None, Some(suffix)) => size.saturating_sub(suffix)..size,
        (Some(first), None) if end.trim().is_empty() => first..size,
        (Some(first), Some(last)) if first <= last => first..size.min(last + 1),
        _ => return Ok(None),
    };

    if range.start >= size {
        return Err(unsatisfiable());
    }

    Ok(Some(range))
}

// ----------------------------------------------------------------------
// Service and buckets
// ----------------------------------------------------------------------

pub(crate) async fn list_buckets<R: Remote + 'static>(State(state): State<AppState<R>>) -> Reply {
    xml_reply(xml::list_buckets(&state.engine.list_buckets().await?))
}

pub(crate) async fn bucket_put<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Extension(caller): Extension<Caller>,
    Path(bucket): Path<String>,
    Query(params): Params,
) -> Reply {
    reject_unsupported(&params, BUCKET_UNSUPPORTED)?;
    if params.contains_key("versioning") {
        return Err(S3Error::not_implemented("versioning cannot be enabled"));
    }

    state.engine.create_bucket(&bucket, Some(caller.0)).await?;
    info!(bucket, "create bucket");
    Ok(reply(StatusCode::OK)
        .header("location", format!("/{bucket}"))
        .body(Body::empty())
        .expect("a bucket name is a valid header value"))
}

pub(crate) async fn bucket_delete<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path(bucket): Path<String>,
    Query(params): Params,
) -> Reply {
    reject_unsupported(&params, BUCKET_UNSUPPORTED)?;
    state.engine.delete_bucket(&bucket).await?;
    info!(bucket, "delete bucket");
    empty(StatusCode::NO_CONTENT)
}

pub(crate) async fn bucket_head<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path(bucket): Path<String>,
) -> Reply {
    state.engine.bucket(&bucket).await?;
    empty(StatusCode::OK)
}

pub(crate) async fn bucket_get<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path(bucket): Path<String>,
    Query(params): Params,
) -> Reply {
    reject_unsupported(&params, BUCKET_UNSUPPORTED)?;
    state.engine.bucket(&bucket).await?;

    if params.contains_key("versioning") {
        return xml_reply(xml::versioning());
    }
    if params.contains_key("location") {
        return xml_reply(xml::location());
    }
    if params.contains_key("uploads") {
        let uploads = state.uploads.list(&bucket).await?;
        return xml_reply(xml::list_uploads(&bucket, &uploads));
    }

    list_objects(&state, &bucket, &params).await
}

/// ListObjectsV2 with `list-type=2`, ListObjects (v1) without.
async fn list_objects<R: Remote + 'static>(
    state: &AppState<R>,
    bucket: &str,
    params: &BTreeMap<String, String>,
) -> Reply {
    let param = |name: &str| params.get(name).filter(|v| !v.is_empty()).cloned();
    let v2 = params.get("list-type").is_some_and(|t| t == "2");
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    let delimiter = param("delimiter");
    let max_keys = match params.get("max-keys") {
        Some(n) => n
            .parse::<usize>()
            .map_err(|_| S3Error::invalid_argument("max-keys must be a number"))?
            .min(MAX_KEYS),
        None => MAX_KEYS,
    };
    let encoding_type = param("encoding-type");
    if encoding_type.as_deref().is_some_and(|e| e != "url") {
        return Err(S3Error::invalid_argument("encoding-type must be 'url'"));
    }

    let continuation = param("continuation-token");
    let start_after = param("start-after");
    let marker = param("marker").unwrap_or_default();
    let after = match (v2, &continuation) {
        (true, Some(token)) => Some(After::from_token(token)?),
        (true, None) => start_after.clone().map(After::Key),
        (false, _) if marker.is_empty() => None,
        // A v1 NextMarker can be a common prefix: resume after its whole group.
        (false, _)
            if delimiter
                .as_ref()
                .is_some_and(|d| marker.ends_with(d.as_str())) =>
        {
            Some(After::Prefix(marker.clone()))
        }
        (false, _) => Some(After::Key(marker.clone())),
    };

    let objects = state.engine.list(bucket, &prefix).await?;
    let keys: Vec<String> = objects.iter().map(|o| o.key.clone()).collect();
    let page = page(
        &keys,
        &prefix,
        delimiter.as_deref(),
        max_keys,
        after.as_ref(),
    );
    let next = page.next(&keys);

    let encode = |text: &str| match encoding_type {
        Some(_) => form_urlencoded::byte_serialize(text.as_bytes()).collect(),
        None => text.to_string(),
    };
    let mut listed = ListPage {
        bucket: bucket.to_string(),
        prefix: encode(&prefix),
        delimiter: delimiter.as_deref().map(encode),
        max_keys,
        encoding_type: encoding_type.clone(),
        is_truncated: page.truncated,
        objects: Vec::new(),
        common_prefixes: Vec::new(),
    };
    for item in &page.items {
        match item {
            Item::Object(i) => listed.objects.push(ListedObject {
                key: encode(&objects[*i].key),
                size: objects[*i].size,
                etag: etag(&objects[*i]),
                last_modified: objects[*i].last_modified,
            }),
            Item::CommonPrefix(common) => listed.common_prefixes.push(encode(common)),
        }
    }

    if v2 {
        let next_token = next.map(|n| n.token());
        return xml_reply(xml::list_v2(
            &listed,
            continuation,
            next_token,
            start_after.as_deref().map(encode),
        ));
    }

    // S3 gives NextMarker only with a delimiter; without one, clients resume after the last key.
    let next_marker = next.filter(|_| delimiter.is_some()).map(|n| match n {
        After::Key(key) | After::Prefix(key) => encode(&key),
    });
    xml_reply(xml::list_v1(&listed, encode(&marker), next_marker))
}

pub(crate) async fn bucket_post<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path(bucket): Path<String>,
    Query(params): Params,
    body: Bytes,
) -> Reply {
    if !params.contains_key("delete") {
        return Err(S3Error::not_implemented(
            "this POST on a bucket is not supported",
        ));
    }

    state.engine.bucket(&bucket).await?;
    let (keys, quiet) = xml::parse_delete(&body)?;
    if keys.len() > MAX_DELETE_KEYS {
        return Err(S3Error::malformed_xml());
    }

    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for key in keys {
        match state.engine.delete(&bucket, &key).await {
            Ok(()) => deleted.push(key),
            Err(e) => errors.push((key, S3Error::from(e))),
        }
    }

    info!(
        bucket,
        deleted = deleted.len(),
        errors = errors.len(),
        "delete objects"
    );
    xml_reply(xml::delete_result(&deleted, &errors, quiet))
}

// ----------------------------------------------------------------------
// Objects
// ----------------------------------------------------------------------

pub(crate) async fn object_put<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    reject_unsupported(&params, OBJECT_UNSUPPORTED)?;

    if let (Some(upload_id), Some(number)) = (params.get("uploadId"), params.get("partNumber")) {
        if headers.contains_key("x-amz-copy-source") {
            return Err(S3Error::not_implemented("UploadPartCopy is not supported"));
        }
        let part_etag = state
            .uploads
            .put_part(upload_id, &bucket, &key, number, &body)
            .await?;
        return Ok(reply(StatusCode::OK)
            .header("etag", xml::quoted(&part_etag))
            .body(Body::empty())
            .expect("a hex ETag is a valid header value"));
    }

    if let Some(source) = header(&headers, "x-amz-copy-source") {
        return copy_object(&state, source, &bucket, &key, &headers).await;
    }

    if headers.contains_key("if-match") {
        return Err(S3Error::not_implemented(
            "If-Match on PutObject is not supported",
        ));
    }
    let mode = match header(&headers, "if-none-match") {
        Some("*") => WriteMode::CreateOnly,
        Some(_) => {
            return Err(S3Error::not_implemented(
                "If-None-Match on PutObject takes only '*'",
            ));
        }
        None => WriteMode::Overwrite,
    };

    let info = state
        .engine
        .put(&bucket, &key, body, metadata(&headers), mode)
        .await?;
    Ok(reply(StatusCode::OK)
        .header("etag", xml::quoted(&etag(&info)))
        .body(Body::empty())
        .expect("a hex ETag is a valid header value"))
}

/// CopyObject reads the source and writes it again: the engine has no reference copy.
async fn copy_object<R: Remote + 'static>(
    state: &AppState<R>,
    source: &str,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Reply {
    if headers
        .keys()
        .any(|name| name.as_str().starts_with("x-amz-copy-source-if-"))
    {
        return Err(S3Error::not_implemented(
            "conditional copy is not supported",
        ));
    }

    let source = form_urlencoded::parse(format!("s={}", source.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    let source = source.strip_prefix('/').unwrap_or(&source);
    if source.contains("?versionId=") {
        return Err(S3Error::not_implemented(
            "versioned copy sources are not supported",
        ));
    }
    let (source_bucket, source_key) = source
        .split_once('/')
        .ok_or_else(|| S3Error::invalid_argument("x-amz-copy-source must be bucket/key"))?;

    let replace = match header(headers, "x-amz-metadata-directive") {
        None | Some("COPY") => false,
        Some("REPLACE") => true,
        Some(_) => {
            return Err(S3Error::invalid_argument(
                "x-amz-metadata-directive must be COPY or REPLACE",
            ));
        }
    };
    if !replace && source_bucket == bucket && source_key == key {
        return Err(S3Error::new(
            "InvalidRequest",
            StatusCode::BAD_REQUEST,
            "a copy onto itself must replace the metadata",
        ));
    }

    let object = state.engine.get(source_bucket, source_key, None).await?;
    let metadata = if replace {
        metadata(headers)
    } else {
        object.info.metadata
    };
    let info = state
        .engine
        .put(bucket, key, object.data, metadata, WriteMode::Overwrite)
        .await?;

    xml_reply(xml::copy_result(&etag(&info), info.last_modified))
}

pub(crate) async fn object_get<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    headers: HeaderMap,
) -> Reply {
    reject_unsupported(&params, OBJECT_UNSUPPORTED)?;

    if let Some(upload_id) = params.get("uploadId") {
        let parts = state.uploads.parts(upload_id, &bucket, &key).await?;
        return xml_reply(xml::list_parts(&bucket, &key, upload_id, &parts));
    }

    // The head decides the preconditions and the range; the read must return the same object.
    loop {
        let info = state.engine.head(&bucket, &key).await?;
        match precondition(&headers, &info) {
            Precondition::Failed => return Err(S3Error::precondition_failed()),
            Precondition::NotModified => return not_modified(&info),
            Precondition::Proceed => {}
        }

        let range = byte_range(&headers, info.size)?;
        let object = state.engine.get(&bucket, &key, range.clone()).await?;
        if object.info.content_hash != info.content_hash {
            continue;
        }

        let mut builder = object_headers(reply(StatusCode::OK), &object.info)
            .header("content-length", object.data.len().to_string());
        if let Some(range) = range {
            builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
                "content-range",
                format!("bytes {}-{}/{}", range.start, range.end - 1, info.size),
            );
        }

        return Ok(builder
            .body(Body::from(object.data))
            .expect("object headers are valid"));
    }
}

pub(crate) async fn object_head<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Reply {
    let info = state.engine.head(&bucket, &key).await?;
    match precondition(&headers, &info) {
        Precondition::Failed => return Err(S3Error::precondition_failed()),
        Precondition::NotModified => return not_modified(&info),
        Precondition::Proceed => {}
    }

    Ok(object_headers(reply(StatusCode::OK), &info)
        .header("content-length", info.size.to_string())
        .body(Body::empty())
        .expect("object headers are valid"))
}

pub(crate) async fn object_delete<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
) -> Reply {
    reject_unsupported(&params, OBJECT_UNSUPPORTED)?;

    if let Some(upload_id) = params.get("uploadId") {
        state.uploads.abort(upload_id, &bucket, &key).await?;
        return empty(StatusCode::NO_CONTENT);
    }

    state.engine.delete(&bucket, &key).await?;
    empty(StatusCode::NO_CONTENT)
}

pub(crate) async fn object_post<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    if params.contains_key("uploads") {
        state.engine.bucket(&bucket).await?;
        let upload_id = state
            .uploads
            .initiate(&bucket, &key, metadata(&headers))
            .await?;
        info!(bucket, key, upload_id, "initiate multipart upload");
        return xml_reply(xml::initiate(&bucket, &key, &upload_id));
    }

    let Some(upload_id) = params.get("uploadId") else {
        return Err(S3Error::not_implemented(
            "this POST on an object is not supported",
        ));
    };

    let requested = xml::parse_complete(&body)?;
    let assembled = state
        .uploads
        .assemble(upload_id, &bucket, &key, &requested)
        .await?;
    let info = state
        .engine
        .put(
            &bucket,
            &key,
            Bytes::from(assembled.data),
            assembled.metadata,
            WriteMode::Overwrite,
        )
        .await?;
    state.uploads.finish(upload_id).await?;

    info!(
        bucket,
        key,
        upload_id,
        parts = requested.len(),
        "complete multipart upload"
    );
    xml_reply(xml::complete(&bucket, &key, &etag(&info)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().unwrap());
        }
        map
    }

    fn info() -> ObjectInfo {
        ObjectInfo {
            key: "k".into(),
            size: 100,
            content_hash: [0xab; 32],
            metadata: BTreeMap::new(),
            // Mon, 05 Oct 2026 12:00:00 GMT
            last_modified: 1_791_201_600_000_000_000,
            conflicted: false,
        }
    }

    #[test]
    fn test_ranges() {
        let range = |spec: &str| byte_range(&headers(&[("range", spec)]), 100);

        assert_eq!(range("bytes=0-9").unwrap(), Some(0..10));
        assert_eq!(range("bytes=90-").unwrap(), Some(90..100));
        assert_eq!(range("bytes=-10").unwrap(), Some(90..100));
        assert_eq!(range("bytes=95-200").unwrap(), Some(95..100));
        assert_eq!(range("bytes=-500").unwrap(), Some(0..100));
        assert!(range("bytes=100-").is_err());
        assert!(range("bytes=-0").is_err());
        assert_eq!(range("bytes=0-1,5-6").unwrap(), None);
        assert_eq!(range("bytes=9-1").unwrap(), None);
        assert_eq!(range("items=0-1").unwrap(), None);
        assert_eq!(byte_range(&HeaderMap::new(), 100).unwrap(), None);
    }

    #[test]
    fn test_preconditions() {
        let tag = format!("\"{}\"", "ab".repeat(32));
        let check = |pairs: &[(&'static str, &str)]| precondition(&headers(pairs), &info());

        assert_eq!(check(&[]), Precondition::Proceed);
        assert_eq!(check(&[("if-match", &tag)]), Precondition::Proceed);
        assert_eq!(check(&[("if-match", "\"other\"")]), Precondition::Failed);
        assert_eq!(check(&[("if-none-match", &tag)]), Precondition::NotModified);
        assert_eq!(check(&[("if-none-match", "*")]), Precondition::NotModified);
        assert_eq!(
            check(&[("if-none-match", "\"other\", W/\"x\"")]),
            Precondition::Proceed
        );
        assert_eq!(
            check(&[("if-modified-since", "Mon, 05 Oct 2026 12:00:00 GMT")]),
            Precondition::NotModified
        );
        assert_eq!(
            check(&[("if-modified-since", "Sun, 04 Oct 2026 12:00:00 GMT")]),
            Precondition::Proceed
        );
        assert_eq!(
            check(&[("if-unmodified-since", "Sun, 04 Oct 2026 12:00:00 GMT")]),
            Precondition::Failed
        );
        assert_eq!(
            check(&[
                ("if-match", &tag),
                ("if-unmodified-since", "Sun, 04 Oct 2026 12:00:00 GMT")
            ]),
            Precondition::Proceed,
            "If-Match takes over If-Unmodified-Since"
        );
        assert_eq!(
            check(&[
                ("if-none-match", "\"other\""),
                ("if-modified-since", "Mon, 05 Oct 2026 12:00:00 GMT")
            ]),
            Precondition::Proceed,
            "If-None-Match takes over If-Modified-Since"
        );
    }

    #[test]
    fn test_metadata_keeps_stored_and_user_headers() {
        let stored = metadata(&headers(&[
            ("content-type", "text/plain"),
            ("x-amz-meta-color", "blue"),
            ("authorization", "secret"),
            ("x-amz-date", "20260101T000000Z"),
        ]));

        assert_eq!(
            stored,
            BTreeMap::from([
                ("content-type".to_string(), "text/plain".to_string()),
                ("x-amz-meta-color".to_string(), "blue".to_string()),
            ])
        );
    }
}
