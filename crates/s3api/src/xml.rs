//! XML bodies of the S3 API, with `quick-xml` and `serde`.

use serde::{Deserialize, Serialize};

use crate::S3Error;
use s3proto::time::iso8601;

const XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

fn to_xml<T: Serialize>(value: &T) -> String {
    let body = quick_xml::se::to_string(value).expect("response types always serialize");
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{body}")
}

/// XML 1.0 cannot carry most control characters: they are dropped.
fn xml_text(s: &str) -> String {
    s.chars()
        .filter(|&c| matches!(c, '\t' | '\n' | '\r' | '\u{20}'..))
        .collect()
}

pub fn quoted(etag: &str) -> String {
    format!("\"{etag}\"")
}

#[derive(Serialize)]
#[serde(rename = "Error")]
struct ErrorXml<'a> {
    #[serde(rename = "Code")]
    code: &'a str,
    #[serde(rename = "Message")]
    message: String,
}

pub fn error(code: &str, message: &str) -> String {
    to_xml(&ErrorXml {
        code,
        message: xml_text(message),
    })
}

// ----------------------------------------------------------------------
// Buckets
// ----------------------------------------------------------------------

#[derive(Serialize)]
struct Owner {
    #[serde(rename = "ID")]
    id: &'static str,
    #[serde(rename = "DisplayName")]
    display_name: &'static str,
}

const OWNER: Owner = Owner {
    id: "windsock",
    display_name: "windsock",
};

#[derive(Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
struct ListAllMyBuckets {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "Owner")]
    owner: Owner,
    #[serde(rename = "Buckets")]
    buckets: BucketList,
}

#[derive(Serialize)]
struct BucketList {
    #[serde(rename = "Bucket", default)]
    bucket: Vec<BucketXml>,
}

#[derive(Serialize)]
struct BucketXml {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "CreationDate")]
    creation_date: String,
}

pub fn list_buckets(buckets: &[engine::BucketInfo]) -> String {
    to_xml(&ListAllMyBuckets {
        xmlns: XMLNS,
        owner: OWNER,
        buckets: BucketList {
            bucket: buckets
                .iter()
                .map(|b| BucketXml {
                    name: b.name.clone(),
                    creation_date: iso8601(b.created),
                })
                .collect(),
        },
    })
}

#[derive(Serialize)]
#[serde(rename = "VersioningConfiguration")]
struct Versioning {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
}

/// Versioning is never enabled: an empty configuration says so.
pub fn versioning() -> String {
    to_xml(&Versioning { xmlns: XMLNS })
}

#[derive(Serialize)]
#[serde(rename = "LocationConstraint")]
struct Location {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
}

/// An empty location: the default region.
pub fn location() -> String {
    to_xml(&Location { xmlns: XMLNS })
}

// ----------------------------------------------------------------------
// Listing
// ----------------------------------------------------------------------

/// One entry of a listing page.
pub struct ListedObject {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub last_modified: u64,
}

/// A listing page, already cut to `max_keys`. Keys and prefixes are already encoded.
pub struct ListPage {
    pub bucket: String,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub max_keys: usize,
    pub encoding_type: Option<String>,
    pub is_truncated: bool,
    pub objects: Vec<ListedObject>,
    pub common_prefixes: Vec<String>,
}

#[derive(Serialize)]
struct Contents {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "StorageClass")]
    storage_class: &'static str,
}

#[derive(Serialize)]
struct CommonPrefix {
    #[serde(rename = "Prefix")]
    prefix: String,
}

fn contents(page: &ListPage) -> Vec<Contents> {
    page.objects
        .iter()
        .map(|o| Contents {
            key: xml_text(&o.key),
            last_modified: iso8601(o.last_modified),
            etag: quoted(&o.etag),
            size: o.size,
            storage_class: "STANDARD",
        })
        .collect()
}

fn common_prefixes(page: &ListPage) -> Vec<CommonPrefix> {
    page.common_prefixes
        .iter()
        .map(|p| CommonPrefix {
            prefix: xml_text(p),
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
struct ListV2 {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Prefix")]
    prefix: String,
    #[serde(rename = "Delimiter", skip_serializing_if = "Option::is_none")]
    delimiter: Option<String>,
    #[serde(rename = "MaxKeys")]
    max_keys: usize,
    #[serde(rename = "KeyCount")]
    key_count: usize,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "EncodingType", skip_serializing_if = "Option::is_none")]
    encoding_type: Option<String>,
    #[serde(rename = "ContinuationToken", skip_serializing_if = "Option::is_none")]
    continuation_token: Option<String>,
    #[serde(
        rename = "NextContinuationToken",
        skip_serializing_if = "Option::is_none"
    )]
    next_continuation_token: Option<String>,
    #[serde(rename = "StartAfter", skip_serializing_if = "Option::is_none")]
    start_after: Option<String>,
    #[serde(rename = "Contents", default)]
    contents: Vec<Contents>,
    #[serde(rename = "CommonPrefixes", default)]
    common_prefixes: Vec<CommonPrefix>,
}

pub fn list_v2(
    page: &ListPage,
    continuation_token: Option<String>,
    next_continuation_token: Option<String>,
    start_after: Option<String>,
) -> String {
    to_xml(&ListV2 {
        xmlns: XMLNS,
        name: page.bucket.clone(),
        prefix: xml_text(&page.prefix),
        delimiter: page.delimiter.clone(),
        max_keys: page.max_keys,
        key_count: page.objects.len() + page.common_prefixes.len(),
        is_truncated: page.is_truncated,
        encoding_type: page.encoding_type.clone(),
        continuation_token,
        next_continuation_token,
        start_after: start_after.map(|s| xml_text(&s)),
        contents: contents(page),
        common_prefixes: common_prefixes(page),
    })
}

#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
struct ListV1 {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Prefix")]
    prefix: String,
    #[serde(rename = "Marker")]
    marker: String,
    #[serde(rename = "NextMarker", skip_serializing_if = "Option::is_none")]
    next_marker: Option<String>,
    #[serde(rename = "Delimiter", skip_serializing_if = "Option::is_none")]
    delimiter: Option<String>,
    #[serde(rename = "MaxKeys")]
    max_keys: usize,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "EncodingType", skip_serializing_if = "Option::is_none")]
    encoding_type: Option<String>,
    #[serde(rename = "Contents", default)]
    contents: Vec<Contents>,
    #[serde(rename = "CommonPrefixes", default)]
    common_prefixes: Vec<CommonPrefix>,
}

pub fn list_v1(page: &ListPage, marker: String, next_marker: Option<String>) -> String {
    to_xml(&ListV1 {
        xmlns: XMLNS,
        name: page.bucket.clone(),
        prefix: xml_text(&page.prefix),
        marker: xml_text(&marker),
        next_marker: next_marker.map(|m| xml_text(&m)),
        delimiter: page.delimiter.clone(),
        max_keys: page.max_keys,
        is_truncated: page.is_truncated,
        encoding_type: page.encoding_type.clone(),
        contents: contents(page),
        common_prefixes: common_prefixes(page),
    })
}

// ----------------------------------------------------------------------
// Objects
// ----------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename = "CopyObjectResult")]
struct CopyResult {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag: String,
}

pub fn copy_result(etag: &str, last_modified: u64) -> String {
    to_xml(&CopyResult {
        xmlns: XMLNS,
        last_modified: iso8601(last_modified),
        etag: quoted(etag),
    })
}

#[derive(Serialize)]
#[serde(rename = "DeleteResult")]
struct DeleteResult {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "Deleted", default)]
    deleted: Vec<Deleted>,
    #[serde(rename = "Error", default)]
    error: Vec<DeleteError>,
}

#[derive(Serialize)]
struct Deleted {
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Serialize)]
struct DeleteError {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

/// In quiet mode, only the errors are listed.
pub fn delete_result(deleted: &[String], errors: &[(String, S3Error)], quiet: bool) -> String {
    let deleted = if quiet { &[][..] } else { deleted };

    to_xml(&DeleteResult {
        xmlns: XMLNS,
        deleted: deleted
            .iter()
            .map(|key| Deleted { key: xml_text(key) })
            .collect(),
        error: errors
            .iter()
            .map(|(key, e)| DeleteError {
                key: xml_text(key),
                code: e.code.to_string(),
                message: xml_text(&e.message),
            })
            .collect(),
    })
}

#[derive(Deserialize)]
struct DeleteRequest {
    #[serde(rename = "Quiet", default)]
    quiet: bool,
    #[serde(rename = "Object", default)]
    object: Vec<DeleteRequestObject>,
}

#[derive(Deserialize)]
struct DeleteRequestObject {
    #[serde(rename = "Key")]
    key: String,
}

/// The keys of a DeleteObjects request, and its quiet flag.
pub fn parse_delete(body: &[u8]) -> Result<(Vec<String>, bool), S3Error> {
    let text = std::str::from_utf8(body).map_err(|_| S3Error::malformed_xml())?;
    let request: DeleteRequest =
        quick_xml::de::from_str(text).map_err(|_| S3Error::malformed_xml())?;
    let keys = request.object.into_iter().map(|o| o.key).collect();
    Ok((keys, request.quiet))
}

// ----------------------------------------------------------------------
// Multipart uploads
// ----------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
struct Initiate {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "UploadId")]
    upload_id: String,
}

pub fn initiate(bucket: &str, key: &str, upload_id: &str) -> String {
    to_xml(&Initiate {
        xmlns: XMLNS,
        bucket: bucket.to_string(),
        key: xml_text(key),
        upload_id: upload_id.to_string(),
    })
}

#[derive(Serialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
struct Complete {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "ETag")]
    etag: String,
}

pub fn complete(bucket: &str, key: &str, etag: &str) -> String {
    to_xml(&Complete {
        xmlns: XMLNS,
        bucket: bucket.to_string(),
        key: xml_text(key),
        etag: quoted(etag),
    })
}

#[derive(Deserialize)]
struct CompleteRequest {
    #[serde(rename = "Part", default)]
    part: Vec<CompletePart>,
}

#[derive(Deserialize)]
struct CompletePart {
    #[serde(rename = "PartNumber")]
    part_number: u16,
    #[serde(rename = "ETag")]
    etag: String,
}

/// The parts of a CompleteMultipartUpload request: number and ETag, unquoted.
pub fn parse_complete(body: &[u8]) -> Result<Vec<(u16, String)>, S3Error> {
    let text = std::str::from_utf8(body).map_err(|_| S3Error::malformed_xml())?;
    let request: CompleteRequest =
        quick_xml::de::from_str(text).map_err(|_| S3Error::malformed_xml())?;
    Ok(request
        .part
        .into_iter()
        .map(|p| (p.part_number, p.etag.trim_matches('"').to_string()))
        .collect())
}

/// One stored part: number, size, ETag, upload time in unix nanoseconds.
pub type PartInfo = (u16, u64, String, u64);

#[derive(Serialize)]
#[serde(rename = "ListPartsResult")]
struct ListParts {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "UploadId")]
    upload_id: String,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "Part", default)]
    part: Vec<PartXml>,
}

#[derive(Serialize)]
struct PartXml {
    #[serde(rename = "PartNumber")]
    part_number: u16,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "Size")]
    size: u64,
}

pub fn list_parts(bucket: &str, key: &str, upload_id: &str, parts: &[PartInfo]) -> String {
    to_xml(&ListParts {
        xmlns: XMLNS,
        bucket: bucket.to_string(),
        key: xml_text(key),
        upload_id: upload_id.to_string(),
        is_truncated: false,
        part: parts
            .iter()
            .map(|(number, size, etag, time)| PartXml {
                part_number: *number,
                last_modified: iso8601(*time),
                etag: quoted(etag),
                size: *size,
            })
            .collect(),
    })
}

#[derive(Serialize)]
#[serde(rename = "ListMultipartUploadsResult")]
struct ListUploads {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "Upload", default)]
    upload: Vec<UploadXml>,
}

#[derive(Serialize)]
struct UploadXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "UploadId")]
    upload_id: String,
    #[serde(rename = "Initiated")]
    initiated: String,
}

/// Uploads as (key, upload id, initiation time in unix nanoseconds).
pub fn list_uploads(bucket: &str, uploads: &[(String, String, u64)]) -> String {
    to_xml(&ListUploads {
        xmlns: XMLNS,
        bucket: bucket.to_string(),
        is_truncated: false,
        upload: uploads
            .iter()
            .map(|(key, upload_id, time)| UploadXml {
                key: xml_text(key),
                upload_id: upload_id.clone(),
                initiated: iso8601(*time),
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_complete_strips_quotes() {
        let body = br#"<CompleteMultipartUpload>
            <Part><PartNumber>1</PartNumber><ETag>"aa"</ETag></Part>
            <Part><PartNumber>2</PartNumber><ETag>bb</ETag></Part>
        </CompleteMultipartUpload>"#;

        assert_eq!(
            parse_complete(body).unwrap(),
            [(1, "aa".to_string()), (2, "bb".to_string())]
        );
    }

    #[test]
    fn test_parse_delete_reads_keys_and_quiet() {
        let body = br#"<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Quiet>true</Quiet>
            <Object><Key>a</Key></Object><Object><Key>b/c</Key></Object></Delete>"#;

        assert_eq!(
            parse_delete(body).unwrap(),
            (vec!["a".to_string(), "b/c".to_string()], true)
        );
    }

    #[test]
    fn test_malformed_body_is_an_error() {
        assert!(parse_delete(b"<Delete><Object>").is_err());
        assert_eq!(parse_complete(b"not xml").unwrap_err().code, "MalformedXML");
    }

    #[test]
    fn test_error_drops_control_characters() {
        let body = error("NoSuchKey", "no such key: a\u{1}b");

        assert!(body.contains("<Code>NoSuchKey</Code>"));
        assert!(body.contains("no such key: ab"));
    }
}
