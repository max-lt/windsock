//! Every S3 operation through the router, with signed requests, on an engine over a DirRemote.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use ed25519_dalek::SigningKey;
use engine::{Config, Engine};
use http_body_util::BodyExt;
use remote::DirRemote;
use s3api::{S3Config, sigv4};
use tempfile::TempDir;
use tower::ServiceExt;

const ACCESS: &str = "WINDSOCKTEST";
const SECRET: &str = "secret-key";
const REGION: &str = "us-east-1";

struct Server {
    _dir: TempDir,
    engine: Arc<Engine<DirRemote>>,
    app: Router,
}

async fn server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(DirRemote::open(dir.path().join("remote")).unwrap());
    let engine = Engine::open(
        dir.path().join("engine"),
        remote,
        SigningKey::from_bytes(&[1u8; 32]),
        Config::default(),
    )
    .await
    .unwrap();
    let engine = Arc::new(engine);
    let config = S3Config::new(
        HashMap::from([(ACCESS.to_string(), SECRET.to_string())]),
        dir.path().join("uploads"),
    );
    let app = s3api::router(engine.clone(), config);

    Server {
        _dir: dir,
        engine,
        app,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// What a test request differs in.
struct Call<'a> {
    method: &'a str,
    /// Path and query, already encoded.
    uri: &'a str,
    headers: Vec<(&'a str, String)>,
    body: Vec<u8>,
    payload_hash: Option<String>,
    secret: &'a str,
    time: u64,
}

fn call<'a>(method: &'a str, uri: &'a str) -> Call<'a> {
    Call {
        method,
        uri,
        headers: Vec::new(),
        body: Vec::new(),
        payload_hash: None,
        secret: SECRET,
        time: now(),
    }
}

impl<'a> Call<'a> {
    fn header(mut self, name: &'a str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    fn request(self) -> Request<Body> {
        let (path, query) = self.uri.split_once('?').unwrap_or((self.uri, ""));
        let timestamp = sigv4::timestamp(self.time);
        let payload_hash = self
            .payload_hash
            .unwrap_or_else(|| sigv4::sha256_hex(&self.body));
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), "localhost".into()),
            ("x-amz-date".into(), timestamp.clone()),
            ("x-amz-content-sha256".into(), payload_hash.clone()),
        ];
        headers.extend(self.headers.iter().map(|(n, v)| (n.to_string(), v.clone())));

        let (authorization, _) = sigv4::sign(
            &sigv4::Request {
                method: self.method,
                path,
                query,
                headers: &headers,
                payload_hash: &payload_hash,
            },
            ACCESS,
            self.secret,
            &timestamp,
            REGION,
        );

        let mut request = Request::builder().method(self.method).uri(self.uri);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request
            .header("authorization", authorization)
            .body(Body::from(self.body))
            .unwrap()
    }
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The text of the first `<tag>` in an XML body.
    fn xml(&self, tag: &str) -> Option<String> {
        let text = self.text();
        let start = text.find(&format!("<{tag}>"))? + tag.len() + 2;
        let end = start + text[start..].find(&format!("</{tag}>"))?;
        Some(text[start..end].to_string())
    }

    /// The prefix of every `<CommonPrefixes>` in a listing.
    fn common_prefixes(&self) -> Vec<String> {
        self.xml_all("CommonPrefixes")
            .iter()
            .filter_map(|inner| {
                let inner = inner.strip_prefix("<Prefix>")?;
                Some(inner.strip_suffix("</Prefix>")?.to_string())
            })
            .collect()
    }

    /// The text of every `<tag>` in an XML body.
    fn xml_all(&self, tag: &str) -> Vec<String> {
        self.text()
            .split(&format!("<{tag}>"))
            .skip(1)
            .filter_map(|part| part.split(&format!("</{tag}>")).next())
            .map(str::to_string)
            .collect()
    }
}

async fn send(server: &Server, request: Request<Body>) -> Reply {
    let response: Response<Body> = server.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

async fn run(server: &Server, call: Call<'_>) -> Reply {
    send(server, call.request()).await
}

async fn with_bucket() -> Server {
    let server = server().await;
    let reply = run(&server, call("PUT", "/bkt")).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    server
}

async fn put(server: &Server, key: &str, body: &str) -> Reply {
    let uri = format!("/bkt/{key}");
    run(server, call("PUT", &uri).body(body)).await
}

// ----------------------------------------------------------------------
// Authentication
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_request_without_signature_is_denied() {
    let server = server().await;
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();

    let reply = send(&server, request).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.xml("Code").unwrap(), "AccessDenied");
}

#[tokio::test]
async fn test_wrong_secret_is_denied() {
    let server = server().await;
    let mut wrong = call("GET", "/");
    wrong.secret = "other";

    let reply = run(&server, wrong).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.xml("Code").unwrap(), "SignatureDoesNotMatch");
}

#[tokio::test]
async fn test_old_signature_is_denied() {
    let server = server().await;
    let mut old = call("GET", "/");
    old.time = now() - 3600;

    let reply = run(&server, old).await;

    assert_eq!(reply.xml("Code").unwrap(), "RequestTimeTooSkewed");
}

#[tokio::test]
async fn test_body_must_match_its_signed_hash() {
    let server = with_bucket().await;
    let mut lying = call("PUT", "/bkt/k").body("actual");
    lying.payload_hash = Some(sigv4::sha256_hex(b"signed"));

    let reply = run(&server, lying).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.xml("Code").unwrap(), "XAmzContentSHA256Mismatch");
}

#[tokio::test]
async fn test_presigned_url_is_not_supported() {
    let server = server().await;

    let reply = run(&server, call("GET", "/bkt/k?X-Amz-Signature=ab")).await;

    assert_eq!(reply.status, StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn test_aws_chunked_bodies_are_decoded() {
    let server = with_bucket().await;
    let unsigned =
        b"5\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n".to_vec();
    let mut trailer = call("PUT", "/bkt/unsigned")
        .header("content-encoding", "aws-chunked")
        .header("x-amz-decoded-content-length", "11")
        .body(unsigned);
    trailer.payload_hash = Some(sigv4::STREAMING_UNSIGNED_TRAILER.to_string());

    assert_eq!(run(&server, trailer).await.status, StatusCode::OK);
    let reply = run(&server, call("GET", "/bkt/unsigned")).await;

    assert_eq!(reply.text(), "hello world");
    assert_eq!(
        reply.header("content-encoding"),
        None,
        "aws-chunked is not stored"
    );
}

#[tokio::test]
async fn test_signed_chunks_are_checked() {
    let server = with_bucket().await;
    let time = now();
    let timestamp = sigv4::timestamp(time);
    let headers: Vec<(String, String)> = vec![
        ("host".into(), "localhost".into()),
        ("x-amz-date".into(), timestamp.clone()),
        (
            "x-amz-content-sha256".into(),
            sigv4::STREAMING_SIGNED.into(),
        ),
        ("x-amz-decoded-content-length".into(), "11".into()),
    ];
    let (authorization, seed) = sigv4::sign(
        &sigv4::Request {
            method: "PUT",
            path: "/bkt/signed",
            query: "",
            headers: &headers,
            payload_hash: sigv4::STREAMING_SIGNED,
        },
        ACCESS,
        SECRET,
        &timestamp,
        REGION,
    );
    let signer = sigv4::ChunkSigner {
        key: sigv4::signing_key(SECRET, &timestamp[..8], REGION),
        timestamp: timestamp.clone(),
        scope: format!("{}/{REGION}/s3/aws4_request", &timestamp[..8]),
        previous: seed,
    };
    let request = |body: Vec<u8>| {
        let mut request = Request::builder().method("PUT").uri("/bkt/signed");
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request
            .header("authorization", authorization.as_str())
            .body(Body::from(body))
            .unwrap()
    };
    let good = sigv4::encode_chunked(b"hello world", 4, Some(signer));
    let mut forged = good.clone();
    let at = forged.iter().position(|&b| b == b'h').unwrap();
    forged[at] = b'j';

    assert_eq!(
        send(&server, request(forged)).await.xml("Code").unwrap(),
        "SignatureDoesNotMatch"
    );
    assert_eq!(send(&server, request(good)).await.status, StatusCode::OK);
    assert_eq!(
        run(&server, call("GET", "/bkt/signed")).await.text(),
        "hello world"
    );
}

// ----------------------------------------------------------------------
// Buckets
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_bucket_lifecycle() {
    let server = with_bucket().await;

    assert_eq!(
        run(&server, call("PUT", "/bkt")).await.xml("Code").unwrap(),
        "BucketAlreadyOwnedByYou"
    );
    assert_eq!(
        run(&server, call("HEAD", "/bkt")).await.status,
        StatusCode::OK
    );
    assert_eq!(
        run(&server, call("HEAD", "/nope")).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        run(&server, call("GET", "/")).await.xml_all("Name"),
        ["bkt"]
    );

    put(&server, "k", "data").await;
    assert_eq!(
        run(&server, call("DELETE", "/bkt"))
            .await
            .xml("Code")
            .unwrap(),
        "BucketNotEmpty"
    );
    run(&server, call("DELETE", "/bkt/k")).await;
    assert_eq!(
        run(&server, call("DELETE", "/bkt")).await.status,
        StatusCode::NO_CONTENT
    );
    assert!(
        run(&server, call("GET", "/"))
            .await
            .xml_all("Name")
            .is_empty()
    );
}

#[tokio::test]
async fn test_invalid_bucket_name_is_rejected() {
    let server = server().await;

    assert_eq!(
        run(&server, call("PUT", "/Bad_Name"))
            .await
            .xml("Code")
            .unwrap(),
        "InvalidBucketName"
    );
}

#[tokio::test]
async fn test_bucket_versioning_and_location() {
    let server = with_bucket().await;

    let versioning = run(&server, call("GET", "/bkt?versioning")).await;
    let location = run(&server, call("GET", "/bkt?location")).await;

    assert!(versioning.text().contains("<VersioningConfiguration"));
    assert!(!versioning.text().contains("<Status>"));
    assert!(location.text().contains("<LocationConstraint"));
    assert_eq!(
        run(&server, call("PUT", "/bkt?versioning")).await.status,
        StatusCode::NOT_IMPLEMENTED
    );
}

// ----------------------------------------------------------------------
// Objects
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_etag_is_the_same_everywhere() {
    let server = with_bucket().await;

    let stored = put(&server, "k", "hello").await;
    let read = run(&server, call("GET", "/bkt/k")).await;
    let head = run(&server, call("HEAD", "/bkt/k")).await;
    server.engine.flush().await.unwrap();
    let flushed = run(&server, call("GET", "/bkt/k")).await;
    let listed = run(&server, call("GET", "/bkt?list-type=2")).await;

    let etag = stored.header("etag").unwrap().to_string();
    assert_eq!(etag, format!("\"{}\"", blake3::hash(b"hello")));
    assert_eq!(read.header("etag").unwrap(), etag);
    assert_eq!(head.header("etag").unwrap(), etag);
    assert_eq!(flushed.header("etag").unwrap(), etag);
    assert_eq!(listed.xml("ETag").unwrap(), etag);
    assert_eq!(flushed.text(), "hello");
    assert_eq!(head.header("content-length"), Some("5"));
}

#[tokio::test]
async fn test_metadata_comes_back() {
    let server = with_bucket().await;
    let put = call("PUT", "/bkt/k")
        .header("content-type", "text/plain")
        .header("cache-control", "no-cache")
        .header("x-amz-meta-color", "blue")
        .body("x");
    run(&server, put).await;

    let head = run(&server, call("HEAD", "/bkt/k")).await;
    put_plain(&server).await;
    let plain = run(&server, call("HEAD", "/bkt/plain")).await;

    assert_eq!(head.header("content-type"), Some("text/plain"));
    assert_eq!(head.header("cache-control"), Some("no-cache"));
    assert_eq!(head.header("x-amz-meta-color"), Some("blue"));
    assert!(head.header("last-modified").unwrap().ends_with(" GMT"));
    assert_eq!(plain.header("content-type"), Some("binary/octet-stream"));
}

async fn put_plain(server: &Server) {
    put(server, "plain", "x").await;
}

/// Axum limits extracted bodies to 2 MB unless told otherwise.
#[tokio::test]
async fn test_body_larger_than_two_megabytes_is_stored() {
    let server = with_bucket().await;
    let data = vec![7u8; 3 * 1024 * 1024];

    let reply = run(&server, call("PUT", "/bkt/big").body(data.clone())).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(run(&server, call("GET", "/bkt/big")).await.body, data);
}

#[tokio::test]
async fn test_range_reads() {
    let server = with_bucket().await;
    put(&server, "k", "0123456789").await;

    let middle = run(&server, call("GET", "/bkt/k").header("range", "bytes=2-4")).await;
    let suffix = run(&server, call("GET", "/bkt/k").header("range", "bytes=-3")).await;
    let outside = run(&server, call("GET", "/bkt/k").header("range", "bytes=20-")).await;

    assert_eq!(middle.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(middle.text(), "234");
    assert_eq!(middle.header("content-range"), Some("bytes 2-4/10"));
    assert_eq!(suffix.text(), "789");
    assert_eq!(outside.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(outside.xml("Code").unwrap(), "InvalidRange");
}

#[tokio::test]
async fn test_conditional_requests() {
    let server = with_bucket().await;
    let etag = put(&server, "k", "v1")
        .await
        .header("etag")
        .unwrap()
        .to_string();

    let not_modified = run(
        &server,
        call("GET", "/bkt/k").header("if-none-match", etag.as_str()),
    )
    .await;
    let wrong_tag = run(
        &server,
        call("GET", "/bkt/k").header("if-match", "\"other\""),
    )
    .await;
    let head_since = run(
        &server,
        call("HEAD", "/bkt/k").header("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT"),
    )
    .await;
    let create_only = run(
        &server,
        call("PUT", "/bkt/k")
            .header("if-none-match", "*")
            .body("v2"),
    )
    .await;
    let fresh_key = run(
        &server,
        call("PUT", "/bkt/new")
            .header("if-none-match", "*")
            .body("v"),
    )
    .await;
    let if_match_put = run(
        &server,
        call("PUT", "/bkt/k")
            .header("if-match", etag.as_str())
            .body("v3"),
    )
    .await;

    assert_eq!(not_modified.status, StatusCode::NOT_MODIFIED);
    assert!(not_modified.body.is_empty());
    assert_eq!(wrong_tag.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(head_since.status, StatusCode::NOT_MODIFIED);
    assert_eq!(create_only.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(fresh_key.status, StatusCode::OK);
    assert_eq!(if_match_put.status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(run(&server, call("GET", "/bkt/k")).await.text(), "v1");
}

#[tokio::test]
async fn test_delete_object() {
    let server = with_bucket().await;
    put(&server, "k", "v").await;

    assert_eq!(
        run(&server, call("DELETE", "/bkt/k")).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        run(&server, call("DELETE", "/bkt/k")).await.status,
        StatusCode::NO_CONTENT
    );
    let missing = run(&server, call("GET", "/bkt/k")).await;

    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.xml("Code").unwrap(), "NoSuchKey");
}

#[tokio::test]
async fn test_key_with_special_characters() {
    let server = with_bucket().await;

    put(&server, "dir/a%20b%2Bc%C3%A9", "v").await;
    let read = run(&server, call("GET", "/bkt/dir/a%20b%2Bc%C3%A9")).await;
    let listed = run(&server, call("GET", "/bkt?list-type=2&encoding-type=url")).await;

    assert_eq!(read.text(), "v");
    assert_eq!(listed.xml("Key").unwrap(), "dir%2Fa+b%2Bc%C3%A9");
    assert_eq!(listed.xml("EncodingType").unwrap(), "url");
}

#[tokio::test]
async fn test_delete_objects_in_one_request() {
    let server = with_bucket().await;
    for key in ["a", "b", "c"] {
        put(&server, key, "v").await;
    }
    let body = "<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object>\
                <Object><Key>missing</Key></Object></Delete>";

    let reply = run(&server, call("POST", "/bkt?delete").body(body)).await;
    let listed = run(&server, call("GET", "/bkt?list-type=2")).await;

    assert_eq!(reply.xml_all("Key"), ["a", "b", "missing"]);
    assert_eq!(listed.xml_all("Key"), ["c"]);
}

#[tokio::test]
async fn test_copy_object() {
    let server = with_bucket().await;
    run(
        &server,
        call("PUT", "/bkt/src")
            .header("x-amz-meta-color", "blue")
            .body("data"),
    )
    .await;

    let copied = run(
        &server,
        call("PUT", "/bkt/dst").header("x-amz-copy-source", "/bkt/src"),
    )
    .await;
    let replaced = run(
        &server,
        call("PUT", "/bkt/dst2")
            .header("x-amz-copy-source", "bkt/src")
            .header("x-amz-metadata-directive", "REPLACE")
            .header("x-amz-meta-color", "red"),
    )
    .await;
    let onto_itself = run(
        &server,
        call("PUT", "/bkt/src").header("x-amz-copy-source", "bkt/src"),
    )
    .await;
    let missing = run(
        &server,
        call("PUT", "/bkt/x").header("x-amz-copy-source", "bkt/nope"),
    )
    .await;

    assert!(copied.text().contains("<CopyObjectResult"));
    assert_eq!(run(&server, call("GET", "/bkt/dst")).await.text(), "data");
    assert_eq!(
        run(&server, call("HEAD", "/bkt/dst"))
            .await
            .header("x-amz-meta-color"),
        Some("blue")
    );
    assert_eq!(replaced.status, StatusCode::OK);
    assert_eq!(
        run(&server, call("HEAD", "/bkt/dst2"))
            .await
            .header("x-amz-meta-color"),
        Some("red")
    );
    assert_eq!(onto_itself.status, StatusCode::BAD_REQUEST);
    assert_eq!(missing.xml("Code").unwrap(), "NoSuchKey");
}

#[tokio::test]
async fn test_unsupported_sub_resource_is_not_implemented() {
    let server = with_bucket().await;
    put(&server, "k", "v").await;

    assert_eq!(
        run(&server, call("GET", "/bkt/k?tagging")).await.status,
        StatusCode::NOT_IMPLEMENTED
    );
    assert_eq!(
        run(&server, call("GET", "/bkt?policy")).await.status,
        StatusCode::NOT_IMPLEMENTED
    );
}

// ----------------------------------------------------------------------
// Listing
// ----------------------------------------------------------------------

async fn listing_fixture() -> Server {
    let server = with_bucket().await;
    for key in ["a/1", "a/2", "b", "c/1", "c/2", "d"] {
        put(&server, key, "v").await;
    }
    server
}

#[tokio::test]
async fn test_list_v2_with_delimiter() {
    let server = listing_fixture().await;

    let reply = run(&server, call("GET", "/bkt?list-type=2&delimiter=%2F")).await;
    let under = run(&server, call("GET", "/bkt?list-type=2&prefix=c%2F")).await;

    assert_eq!(reply.xml_all("Key"), ["b", "d"]);
    assert_eq!(reply.common_prefixes(), ["a/", "c/"]);
    assert_eq!(reply.xml("KeyCount").unwrap(), "4");
    assert_eq!(under.xml_all("Key"), ["c/1", "c/2"]);
}

#[tokio::test]
async fn test_list_v2_pages_with_continuation_tokens() {
    let server = listing_fixture().await;
    let mut seen = Vec::new();
    let mut token: Option<String> = None;

    for _ in 0..10 {
        let uri = match &token {
            Some(t) => format!("/bkt?list-type=2&delimiter=%2F&max-keys=1&continuation-token={t}"),
            None => "/bkt?list-type=2&delimiter=%2F&max-keys=1".to_string(),
        };
        let reply = run(&server, call("GET", &uri)).await;
        seen.extend(reply.xml_all("Key"));
        seen.extend(reply.common_prefixes());
        token = reply.xml("NextContinuationToken");

        if reply.xml("IsTruncated").unwrap() == "false" {
            break;
        }
    }

    assert_eq!(seen, ["a/", "b", "c/", "d"]);
    assert_eq!(token, None);
}

#[tokio::test]
async fn test_list_v2_start_after() {
    let server = listing_fixture().await;

    let reply = run(&server, call("GET", "/bkt?list-type=2&start-after=c%2F1")).await;

    assert_eq!(reply.xml_all("Key"), ["c/2", "d"]);
}

#[tokio::test]
async fn test_list_v1_with_markers() {
    let server = listing_fixture().await;

    let first = run(&server, call("GET", "/bkt?delimiter=%2F&max-keys=2")).await;
    let marker = first.xml("NextMarker").unwrap();
    let uri = format!(
        "/bkt?delimiter=%2F&max-keys=2&marker={}",
        marker.replace('/', "%2F")
    );
    let second = run(&server, call("GET", &uri)).await;

    assert_eq!(first.xml("IsTruncated").unwrap(), "true");
    assert_eq!(marker, "b");
    assert_eq!(second.common_prefixes(), ["c/"]);
    assert_eq!(second.xml_all("Key"), ["d"]);
}

#[tokio::test]
async fn test_listing_reads_flushed_objects() {
    let server = listing_fixture().await;
    server.engine.flush().await.unwrap();

    let reply = run(&server, call("GET", "/bkt?list-type=2")).await;

    assert_eq!(reply.xml_all("Key").len(), 6);
}

// ----------------------------------------------------------------------
// Multipart uploads
// ----------------------------------------------------------------------

async fn upload_part(server: &Server, id: &str, number: u32, data: &str) -> Reply {
    let uri = format!("/bkt/big?partNumber={number}&uploadId={id}");
    run(server, call("PUT", &uri).body(data)).await
}

#[tokio::test]
async fn test_multipart_upload() {
    let server = with_bucket().await;
    let initiated = run(
        &server,
        call("POST", "/bkt/big?uploads").header("content-type", "text/plain"),
    )
    .await;
    let id = initiated.xml("UploadId").unwrap();

    let second = upload_part(&server, &id, 2, "world")
        .await
        .header("etag")
        .unwrap()
        .to_string();
    let first = upload_part(&server, &id, 1, "hello ")
        .await
        .header("etag")
        .unwrap()
        .to_string();
    let parts = run(&server, call("GET", &format!("/bkt/big?uploadId={id}"))).await;
    let uploads = run(&server, call("GET", "/bkt?uploads")).await;
    let body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{first}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{second}</ETag></Part></CompleteMultipartUpload>"
    );
    let completed = run(
        &server,
        call("POST", &format!("/bkt/big?uploadId={id}")).body(body),
    )
    .await;
    let read = run(&server, call("GET", "/bkt/big")).await;

    assert_eq!(parts.xml_all("PartNumber"), ["1", "2"]);
    assert_eq!(uploads.xml("UploadId").unwrap(), id);
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text());
    assert_eq!(read.text(), "hello world");
    assert_eq!(read.header("content-type"), Some("text/plain"));
    assert_eq!(completed.xml("ETag").unwrap(), read.header("etag").unwrap());
    assert!(
        run(&server, call("GET", "/bkt?uploads"))
            .await
            .xml("UploadId")
            .is_none()
    );
}

#[tokio::test]
async fn test_aborted_upload_is_gone() {
    let server = with_bucket().await;
    let id = run(&server, call("POST", "/bkt/k?uploads"))
        .await
        .xml("UploadId")
        .unwrap();
    run(
        &server,
        call("PUT", &format!("/bkt/k?partNumber=1&uploadId={id}")).body("x"),
    )
    .await;

    let aborted = run(&server, call("DELETE", &format!("/bkt/k?uploadId={id}"))).await;
    let parts = run(&server, call("GET", &format!("/bkt/k?uploadId={id}"))).await;

    assert_eq!(aborted.status, StatusCode::NO_CONTENT);
    assert_eq!(parts.xml("Code").unwrap(), "NoSuchUpload");
}

#[tokio::test]
async fn test_complete_with_a_wrong_part_etag_fails() {
    let server = with_bucket().await;
    let id = run(&server, call("POST", "/bkt/k?uploads"))
        .await
        .xml("UploadId")
        .unwrap();
    run(
        &server,
        call("PUT", &format!("/bkt/k?partNumber=1&uploadId={id}")).body("x"),
    )
    .await;
    let body = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"bad\"</ETag></Part>\
                </CompleteMultipartUpload>";

    let reply = run(
        &server,
        call("POST", &format!("/bkt/k?uploadId={id}")).body(body),
    )
    .await;

    assert_eq!(reply.xml("Code").unwrap(), "InvalidPart");
}
