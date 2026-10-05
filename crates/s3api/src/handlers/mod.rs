//! S3 operations. A query parameter picks the operation when a path and method have several.

mod bucket;
mod conditions;
mod object;

pub(crate) use bucket::{
    bucket_delete, bucket_get, bucket_head, bucket_post, bucket_put, list_buckets,
};
pub(crate) use object::{object_delete, object_get, object_head, object_post, object_put};

use std::collections::BTreeMap;
use std::ops::Range;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use bytes::Bytes;
use engine::{ObjectInfo, WriteMode};
use remote::Remote;
use tracing::info;

use crate::xml::{self, ListPage, ListedObject};
use crate::{AppState, Caller, S3Error};
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
