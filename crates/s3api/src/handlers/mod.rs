//! S3 operations. A query parameter picks the operation when a path and method have several.

mod bucket;
mod conditions;
mod object;

pub(crate) use bucket::{
    bucket_delete, bucket_get, bucket_head, bucket_post, bucket_put, list_buckets,
};
pub(crate) use object::{
    copy_source_path, object_delete, object_get, object_head, object_post, object_put,
};

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use bytes::Bytes;
use engine::sim::Point;
use engine::{Engine, ObjectInfo, ObjectReader, PutSpool, ReadRoom, WriteMode};
use remote::Remote;
use tracing::{info, warn};

use crate::multipart::{Claim, PartWriter};
use crate::xml::{self, ListPage, ListedObject};
use crate::{AppState, Caller, S3Error, StreamedBody, presign};
use s3proto::time::http_date;

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

/// The query keys of ListObjects and ListObjectsV2.
const LIST_KEYS: &[&str] = &[
    "list-type",
    "prefix",
    "delimiter",
    "max-keys",
    "encoding-type",
    "continuation-token",
    "start-after",
    "marker",
];

/// The query keys of UploadPart and UploadPartCopy.
const PART_KEYS: &[&str] = &["uploadId", "partNumber"];

/// How long the first piece of a GET waits for room in the read budget before a 503.
const FIRST_PIECE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
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

/// 501 for a query key that the operation does not read: a 2xx would hide what S3 does with it.
fn only(params: &BTreeMap<String, String>, read: &[&str]) -> Result<(), S3Error> {
    // The authentication checked the presigned parameters; AWS SDKs add x-id.
    let unread = params.keys().find(|key| {
        !read.contains(&key.as_str()) && key.as_str() != "x-id" && !presign::is_parameter(key)
    });
    match unread {
        Some(key) => Err(S3Error::not_implemented(format!(
            "'{key}' is not supported"
        ))),
        None => Ok(()),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn etag(info: &ObjectInfo) -> String {
    hex::encode(info.content_hash)
}

/// The S3 limit on user metadata: names and values of the `x-amz-meta-*` headers together.
const MAX_USER_METADATA: usize = 2048;

/// The limit on all stored headers, names and values together.
const MAX_STORED_HEADERS: usize = 8192;

/// Stored headers, and `x-amz-meta-*` headers under their full names.
fn metadata(headers: &HeaderMap) -> Result<BTreeMap<String, String>, S3Error> {
    let stored: BTreeMap<String, String> = headers
        .iter()
        .filter(|(name, _)| {
            STORED_HEADERS.contains(&name.as_str()) || name.as_str().starts_with("x-amz-meta-")
        })
        .filter_map(|(name, value)| {
            Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
        })
        .collect();

    let user: usize = stored
        .iter()
        .filter_map(|(name, value)| Some(name.strip_prefix("x-amz-meta-")?.len() + value.len()))
        .sum();
    if user > MAX_USER_METADATA {
        return Err(S3Error::new(
            "MetadataTooLarge",
            StatusCode::BAD_REQUEST,
            format!("user metadata is {user} bytes, more than {MAX_USER_METADATA}"),
        ));
    }
    let all: usize = stored
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum();
    if all > MAX_STORED_HEADERS {
        return Err(S3Error::new(
            "MetadataTooLarge",
            StatusCode::BAD_REQUEST,
            format!("stored headers are {all} bytes, more than {MAX_STORED_HEADERS}"),
        ));
    }
    Ok(stored)
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

    #[test]
    fn test_metadata_keeps_stored_and_user_headers() {
        let stored = metadata(&headers(&[
            ("content-type", "text/plain"),
            ("x-amz-meta-color", "blue"),
            ("authorization", "secret"),
            ("x-amz-date", "20260101T000000Z"),
        ]))
        .unwrap();

        assert_eq!(
            stored,
            BTreeMap::from([
                ("content-type".to_string(), "text/plain".to_string()),
                ("x-amz-meta-color".to_string(), "blue".to_string()),
            ])
        );
    }
}
