//! Every S3 operation through the router, with signed requests, on an engine over a DirRemote.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, Response, StatusCode};
use ed25519_dalek::SigningKey;
use engine::sim::Point;
use engine::{Config, Engine};
use http_body_util::BodyExt;
use remote::DirRemote;
use s3api::{KeyStore, KeyStoreError, S3Config, Secret, sigv4};
use tempfile::TempDir;
use tower::ServiceExt;

const ACCESS: &str = "WINDSOCKTEST";
const SECRET: &str = "secret-key";
const REGION: &str = "us-east-1";

struct Server {
    _dir: TempDir,
    engine: Arc<Engine<DirRemote>>,
    uploads: Arc<s3api::Uploads>,
    app: Router,
}

async fn server() -> Server {
    server_with(Config::default()).await
}

async fn server_with(config: Config) -> Server {
    server_in(
        tempfile::tempdir().unwrap(),
        config,
        s3api::DEFAULT_PARTS_LIMIT,
    )
    .await
}

async fn server_in(dir: TempDir, config: Config, parts_limit: u64) -> Server {
    let remote = Arc::new(DirRemote::open(dir.path().join("remote")).unwrap());
    let engine = Engine::open(
        dir.path().join("engine"),
        remote,
        SigningKey::from_bytes(&[1u8; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config,
    )
    .await
    .unwrap();
    let engine = Arc::new(engine);
    let mut config = S3Config::new(
        HashMap::from([(ACCESS.to_string(), SECRET.to_string())]),
        dir.path().join("uploads"),
    );
    config.uploads = Arc::new(s3api::Uploads::new(dir.path().join("uploads"), parts_limit));
    config.uploads.start().await.unwrap();
    config.uploads.settle(&engine).await.unwrap();
    let uploads = config.uploads.clone();
    let app = s3api::router(engine.clone(), config);

    Server {
        _dir: dir,
        engine,
        uploads,
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
    bucket_on(server().await).await
}

async fn bucket_on(server: Server) -> Server {
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

/// Metadata can come from the manifest of another proxy: a key that is not a
/// header name must not break the response.
#[tokio::test]
async fn test_metadata_that_is_not_a_header_name_is_skipped() {
    let server = with_bucket().await;
    let metadata = std::collections::BTreeMap::from([
        ("bad name\n".to_string(), "x".to_string()),
        ("x-amz-meta-good".to_string(), "y".to_string()),
    ]);
    server
        .engine
        .put(
            "bkt",
            "k",
            bytes::Bytes::from("data"),
            metadata,
            engine::WriteMode::Overwrite,
        )
        .await
        .unwrap();

    let read = run(&server, call("GET", "/bkt/k")).await;
    let head = run(&server, call("HEAD", "/bkt/k")).await;

    assert_eq!(
        (read.status, read.text().as_str()),
        (StatusCode::OK, "data")
    );
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.header("x-amz-meta-good"), Some("y"));
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
    assert_eq!(if_match_put.status, StatusCode::OK);
    assert_eq!(run(&server, call("GET", "/bkt/k")).await.text(), "v3");
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

/// A copy of `bkt/src` onto `bkt/{key}` with one more header.
async fn copy_with(server: &Server, key: &str, name: &'static str, value: &str) -> Reply {
    let uri = format!("/bkt/{key}");
    let call = call("PUT", &uri)
        .header("x-amz-copy-source", "/bkt/src")
        .header(name, value);
    run(server, call).await
}

#[tokio::test]
async fn test_copy_with_if_none_match_keeps_an_existing_destination() {
    let server = with_bucket().await;
    put(&server, "src", "new").await;
    put(&server, "dst", "old").await;

    let onto_existing = copy_with(&server, "dst", "if-none-match", "*").await;
    let onto_missing = copy_with(&server, "fresh", "if-none-match", "*").await;

    assert_eq!(onto_existing.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(run(&server, call("GET", "/bkt/dst")).await.text(), "old");
    assert_eq!(
        onto_missing.status,
        StatusCode::OK,
        "{}",
        onto_missing.text()
    );
}

#[tokio::test]
async fn test_copy_with_if_match_needs_the_etag_of_the_destination() {
    let server = with_bucket().await;
    put(&server, "src", "new").await;
    let etag = put(&server, "dst", "old").await;
    let etag = etag.header("etag").unwrap().to_string();

    let wrong = copy_with(
        &server,
        "dst",
        "if-match",
        &format!("\"{}\"", "0".repeat(64)),
    )
    .await;
    let kept = run(&server, call("GET", "/bkt/dst")).await.text();
    let right = copy_with(&server, "dst", "if-match", &etag).await;

    assert_eq!(wrong.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(kept, "old");
    assert_eq!(right.status, StatusCode::OK, "{}", right.text());
    assert_eq!(run(&server, call("GET", "/bkt/dst")).await.text(), "new");
}

#[tokio::test]
async fn test_copy_onto_a_create_only_prefix_keeps_an_existing_destination() {
    let config = engine::Config {
        policies: vec![engine::PrefixPolicy {
            bucket: "bkt".into(),
            prefix: "wal/".into(),
            policy: engine::Policy {
                create_only: true,
                ..engine::Policy::default()
            },
        }],
        ..engine::Config::default()
    };
    let server = bucket_on(server_with(config).await).await;
    put(&server, "src", "new").await;
    put(&server, "wal/dst", "old").await;

    let reply = run(
        &server,
        call("PUT", "/bkt/wal/dst").header("x-amz-copy-source", "/bkt/src"),
    )
    .await;

    assert_eq!(reply.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        run(&server, call("GET", "/bkt/wal/dst")).await.text(),
        "old"
    );
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
async fn test_list_with_max_keys_0_is_an_empty_page_that_is_not_truncated() {
    let server = with_bucket().await;
    put(&server, "a", "1").await;

    for uri in ["/bkt?list-type=2&max-keys=0", "/bkt?max-keys=0"] {
        let reply = run(&server, call("GET", uri)).await;

        assert_eq!(reply.status, StatusCode::OK, "{uri}");
        assert_eq!(reply.xml("IsTruncated").as_deref(), Some("false"), "{uri}");
        assert!(reply.xml("Contents").is_none(), "{uri}");
        assert!(reply.xml("NextContinuationToken").is_none(), "{uri}");
    }
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

async fn start_upload(server: &Server) -> String {
    run(server, call("POST", "/bkt/big?uploads"))
        .await
        .xml("UploadId")
        .unwrap()
}

fn complete_body(parts: &[(u32, &str)]) -> String {
    let parts: String = parts
        .iter()
        .map(|(n, etag)| format!("<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"))
        .collect();
    format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>")
}

async fn complete(server: &Server, id: &str, parts: &[(u32, &str)]) -> Reply {
    let uri = format!("/bkt/big?uploadId={id}");
    run(server, call("POST", &uri).body(complete_body(parts))).await
}

#[tokio::test]
async fn test_complete_with_parts_out_of_order_is_refused() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let one = upload_part(&server, &id, 1, "a")
        .await
        .header("etag")
        .unwrap()
        .to_string();
    let two = upload_part(&server, &id, 2, "b")
        .await
        .header("etag")
        .unwrap()
        .to_string();

    let reply = complete(&server, &id, &[(2, &two), (1, &one)]).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.xml("Code").unwrap(), "InvalidPartOrder");
}

#[tokio::test]
async fn test_complete_with_a_part_that_was_never_uploaded_is_refused() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let one = upload_part(&server, &id, 1, "a")
        .await
        .header("etag")
        .unwrap()
        .to_string();

    let reply = complete(&server, &id, &[(1, &one), (2, "\"missing\"")]).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.xml("Code").unwrap(), "InvalidPart");
}

#[tokio::test]
async fn test_complete_after_abort_and_second_complete_find_no_upload() {
    let server = with_bucket().await;
    let aborted = start_upload(&server).await;
    let etag = upload_part(&server, &aborted, 1, "a")
        .await
        .header("etag")
        .unwrap()
        .to_string();
    run(
        &server,
        call("DELETE", &format!("/bkt/big?uploadId={aborted}")),
    )
    .await;
    let done = start_upload(&server).await;
    let part = upload_part(&server, &done, 1, "b")
        .await
        .header("etag")
        .unwrap()
        .to_string();
    assert_eq!(
        complete(&server, &done, &[(1, &part)]).await.status,
        StatusCode::OK
    );

    let after_abort = complete(&server, &aborted, &[(1, &etag)]).await;
    let twice = complete(&server, &done, &[(1, &part)]).await;

    assert_eq!(after_abort.status, StatusCode::NOT_FOUND);
    assert_eq!(after_abort.xml("Code").unwrap(), "NoSuchUpload");
    assert_eq!(twice.status, StatusCode::NOT_FOUND);
    assert_eq!(twice.xml("Code").unwrap(), "NoSuchUpload");
    assert_eq!(run(&server, call("GET", "/bkt/big")).await.text(), "b");
}

#[tokio::test]
async fn test_conditional_get_on_dates_and_tags() {
    let server = with_bucket().await;
    let etag = put(&server, "k", "v")
        .await
        .header("etag")
        .unwrap()
        .to_string();
    let past = "Mon, 01 Jan 2001 00:00:00 GMT";
    let future = "Fri, 01 Jan 2100 00:00:00 GMT";
    let get = |name: &'static str, value: &str| {
        let value = value.to_string();
        let server = &server;
        async move {
            run(server, call("GET", "/bkt/k").header(name, value))
                .await
                .status
        }
    };

    assert_eq!(get("if-match", &etag).await, StatusCode::OK);
    assert_eq!(get("if-none-match", "\"other\"").await, StatusCode::OK);
    assert_eq!(get("if-modified-since", past).await, StatusCode::OK);
    assert_eq!(
        get("if-modified-since", future).await,
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(get("if-unmodified-since", future).await, StatusCode::OK);
    assert_eq!(
        get("if-unmodified-since", past).await,
        StatusCode::PRECONDITION_FAILED
    );
}

#[tokio::test]
async fn test_range_edges() {
    let server = with_bucket().await;
    put(&server, "k", "0123456789").await;
    put(&server, "empty", "").await;
    let get = |key: &'static str, range: &'static str| {
        let server = &server;
        async move { run(server, call("GET", key).header("range", range)).await }
    };

    let past_end = get("/bkt/k", "bytes=5-100").await;
    let long_suffix = get("/bkt/k", "bytes=-100").await;
    let multi = get("/bkt/k", "bytes=0-1,3-4").await;
    let on_empty = get("/bkt/empty", "bytes=0-0").await;

    assert_eq!(past_end.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(past_end.text(), "56789");
    assert_eq!(past_end.header("content-range"), Some("bytes 5-9/10"));
    assert_eq!(long_suffix.text(), "0123456789");
    assert_eq!(
        multi.status,
        StatusCode::OK,
        "S3 serves the whole object for several ranges"
    );
    assert_eq!(multi.text(), "0123456789");
    assert_eq!(on_empty.status, StatusCode::RANGE_NOT_SATISFIABLE);
}

#[tokio::test]
async fn test_head_of_an_empty_object_and_of_a_missing_key() {
    let server = with_bucket().await;
    put(&server, "empty", "").await;

    let empty = run(&server, call("HEAD", "/bkt/empty")).await;
    let missing = run(&server, call("HEAD", "/bkt/missing")).await;

    assert_eq!(empty.status, StatusCode::OK);
    assert_eq!(empty.header("content-length"), Some("0"));
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(missing.body.is_empty());
}

#[tokio::test]
async fn test_key_longer_than_1024_bytes_is_refused() {
    let server = with_bucket().await;
    let uri = format!("/bkt/{}", "k".repeat(1025));

    let reply = run(&server, call("PUT", &uri).body("v")).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.xml("Code").unwrap(), "KeyTooLongError");
}

#[tokio::test]
async fn test_stored_headers_over_8_kib_are_refused() {
    let server = with_bucket().await;

    let reply = run(
        &server,
        call("PUT", "/bkt/a")
            .header("content-disposition", "x".repeat(100 * 1024))
            .body("v"),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.xml("Code").unwrap(), "MetadataTooLarge");
    assert_eq!(
        run(&server, call("GET", "/bkt/a")).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_user_metadata_over_2_kib_is_refused() {
    let server = with_bucket().await;
    // The name after x-amz-meta- counts: "a" + value.
    let fits = "v".repeat(2047);
    let over = "v".repeat(2048);

    let at_limit = run(
        &server,
        call("PUT", "/bkt/a").header("x-amz-meta-a", fits).body("v"),
    )
    .await;
    let above = run(
        &server,
        call("PUT", "/bkt/b").header("x-amz-meta-a", over).body("v"),
    )
    .await;

    assert_eq!(at_limit.status, StatusCode::OK);
    assert_eq!(above.status, StatusCode::BAD_REQUEST);
    assert_eq!(above.xml("Code").unwrap(), "MetadataTooLarge");
    assert_eq!(
        run(&server, call("GET", "/bkt/b")).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_part_number_outside_1_to_10000_is_refused() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;

    for number in [0, 10_001] {
        let reply = upload_part(&server, &id, number, "a").await;

        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "part {number}");
        assert_eq!(reply.xml("Code").unwrap(), "InvalidArgument");
    }
}

#[tokio::test]
async fn test_xml_body_over_4_mib_is_refused() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let body = format!(
        "<CompleteMultipartUpload>{}</CompleteMultipartUpload>",
        " ".repeat(5 << 20)
    );

    let reply = run(
        &server,
        call("POST", &format!("/bkt/big?uploadId={id}")).body(body),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.xml("Code").unwrap(), "MaxMessageLengthExceeded");
}

#[tokio::test]
async fn test_malformed_xml_body_gives_malformed_xml() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;

    let complete = run(
        &server,
        call("POST", &format!("/bkt/big?uploadId={id}")).body("<Complete"),
    )
    .await;
    let delete = run(&server, call("POST", "/bkt?delete").body("not xml")).await;

    for reply in [complete, delete] {
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.xml("Code").unwrap(), "MalformedXML");
    }
}

/// A request body that gives five bytes, then fails as a cut connection does.
struct StopsEarly(bool);

impl http_body::Body for StopsEarly {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if std::mem::replace(&mut self.0, true) {
            return std::task::Poll::Ready(Some(Err(std::io::Error::other("the client stopped"))));
        }
        std::task::Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from_static(
            b"01234",
        )))))
    }
}

#[tokio::test]
async fn test_body_that_stops_early_is_refused_and_stores_nothing() {
    let server = with_bucket().await;
    let request = call("PUT", "/bkt/half").body("0123456789").request();
    let (parts, _) = request.into_parts();
    let body = Body::new(StopsEarly(false));

    let reply = send(&server, Request::from_parts(parts, body)).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.xml("Code").unwrap(), "IncompleteBody");
    assert_eq!(
        run(&server, call("GET", "/bkt/half")).await.status,
        StatusCode::NOT_FOUND
    );
}

/// Two clients put one key at the same time, many times: a GET returns one whole version.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_puts_on_one_key_leave_one_whole_version() {
    let server = Arc::new(with_bucket().await);
    let a = "a".repeat(300 * 1024);
    let b = "b".repeat(300 * 1024);

    for round in 0..20 {
        let tasks = [a.clone(), b.clone()].map(|body| {
            let server = server.clone();
            tokio::spawn(async move { put(&server, "k", &body).await.status })
        });
        for task in tasks {
            assert_eq!(task.await.unwrap(), StatusCode::OK);
        }
        if round % 5 == 0 {
            server.engine.flush().await.unwrap();
        }

        let read = run(&server, call("GET", "/bkt/k")).await.text();
        assert!(read == a || read == b, "round {round}: a mixed object");
    }
}

/// A delete during a GET of a large object: the GET gives the whole object, or 404.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_delete_during_a_get_gives_whole_object_or_not_found() {
    let server = Arc::new(with_bucket().await);
    let data = "d".repeat(9 << 20);

    for flushed in [false, true] {
        put(&server, "big", &data).await;
        if flushed {
            server.engine.flush().await.unwrap();
        }
        let reader = server.clone();
        let read = tokio::spawn(async move { run(&reader, call("GET", "/bkt/big")).await });
        let deleted = run(&server, call("DELETE", "/bkt/big")).await;
        let read = read.await.unwrap();

        assert_eq!(deleted.status, StatusCode::NO_CONTENT);
        match read.status {
            StatusCode::OK => assert_eq!(read.body.len(), data.len(), "a partial body"),
            status => assert_eq!(status, StatusCode::NOT_FOUND),
        }
    }
}

/// Keys that exist for the whole listing appear once, while other keys come and go.
#[tokio::test]
async fn test_listing_pages_while_keys_change_skip_and_repeat_nothing() {
    let server = with_bucket().await;
    let stable: Vec<String> = (0..40).map(|i| format!("k{i:03}")).collect();
    for key in &stable {
        put(&server, key, "v").await;
    }
    for i in 0..40 {
        put(&server, &format!("k{i:03}-gone"), "v").await;
    }

    let mut seen = Vec::new();
    let mut token: Option<String> = None;
    let mut page = 0;
    loop {
        let uri = match &token {
            Some(token) => format!("/bkt?list-type=2&max-keys=7&continuation-token={token}"),
            None => "/bkt?list-type=2&max-keys=7".to_string(),
        };
        let reply = run(&server, call("GET", &uri)).await;
        seen.extend(reply.xml_all("Key"));
        // Between pages: delete a key behind and ahead of the cursor, add new ones on both sides.
        put(&server, &format!("a-new-{page}"), "v").await;
        put(&server, &format!("k{:03}-new", page * 5), "v").await;
        run(
            &server,
            call("DELETE", &format!("/bkt/k{:03}-gone", page * 3)),
        )
        .await;
        page += 1;
        token = reply.xml("NextContinuationToken");
        if token.is_none() {
            break;
        }
    }

    let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "a key came twice");
    for key in &stable {
        assert!(seen.contains(key), "{key} was skipped");
    }
}

async fn upload_whole(server: &Server, id: &str, data: &str) -> String {
    let etag = upload_part(server, id, 1, data)
        .await
        .header("etag")
        .unwrap()
        .to_string();
    complete(server, id, &[(1, etag.as_str())])
        .await
        .status
        .to_string()
}

#[tokio::test]
async fn test_two_uploads_on_one_key_each_complete_and_the_last_wins() {
    let server = with_bucket().await;
    let first = start_upload(&server).await;
    let second = start_upload(&server).await;
    let a = "a".repeat(100);
    let b = "b".repeat(100);

    assert_eq!(upload_whole(&server, &second, &b).await, "200 OK");
    assert_eq!(upload_whole(&server, &first, &a).await, "200 OK");

    assert_eq!(run(&server, call("GET", "/bkt/big")).await.text(), a);
}

#[tokio::test]
async fn test_complete_after_a_plain_put_on_the_same_key_wins() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let etag = upload_part(&server, &id, 1, "from the upload")
        .await
        .header("etag")
        .unwrap()
        .to_string();
    put(&server, "big", "from a plain put").await;

    let completed = complete(&server, &id, &[(1, etag.as_str())]).await;

    assert_eq!(completed.status, StatusCode::OK);
    assert_eq!(
        run(&server, call("GET", "/bkt/big")).await.text(),
        "from the upload"
    );
}

/// 10 000 copies of one attribute name: a quadratic duplicate check would take far longer.
#[tokio::test]
async fn test_xml_with_many_duplicate_attributes_answers_quickly() {
    let server = with_bucket().await;
    let attributes = " a=\"1\"".repeat(10_000);
    let padding = " ".repeat((4 << 20) - attributes.len() - 64);
    let body = format!("<Delete{attributes}{padding}></Delete>");
    assert!(body.len() <= 4 << 20);

    let started = std::time::Instant::now();
    let reply = run(&server, call("POST", "/bkt?delete").body(body)).await;

    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

/// A server whose multipart parts hold at most 1000 bytes together.
async fn small_parts() -> Server {
    let dir = tempfile::tempdir().unwrap();
    bucket_on(server_in(dir, Config::default(), 1000).await).await
}

async fn initiate(server: &Server) -> String {
    run(server, call("POST", "/bkt/big?uploads"))
        .await
        .xml("UploadId")
        .unwrap()
}

#[tokio::test]
async fn test_parts_have_their_own_limit_and_plain_puts_keep_room() {
    let server = small_parts().await;
    let id = initiate(&server).await;

    let other = initiate(&server).await;
    let first = upload_part(&server, &id, 1, &"x".repeat(600)).await;
    let second = upload_part(&server, &other, 1, &"x".repeat(600)).await;
    let plain = put(&server, "other", &"x".repeat(600)).await;

    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(second.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(second.xml("Code").unwrap(), "SlowDown");
    assert!(
        second.text().contains("parts_limit_bytes"),
        "{}",
        second.text()
    );
    assert_eq!(plain.status, StatusCode::OK);
}

#[tokio::test]
async fn test_replaced_and_aborted_parts_free_their_room() {
    let server = small_parts().await;
    let id = initiate(&server).await;
    upload_part(&server, &id, 1, &"x".repeat(600)).await;

    let replaced = upload_part(&server, &id, 1, &"x".repeat(400)).await;
    let beside = upload_part(&server, &id, 2, &"x".repeat(400)).await;
    run(&server, call("DELETE", &format!("/bkt/big?uploadId={id}"))).await;
    let other = initiate(&server).await;
    let after_abort = upload_part(&server, &other, 1, &"x".repeat(900)).await;

    assert_eq!(replaced.status, StatusCode::OK);
    assert_eq!(beside.status, StatusCode::OK);
    assert_eq!(after_abort.status, StatusCode::OK);
    assert_eq!(server.uploads.held(), 900);
}

#[tokio::test]
async fn test_complete_frees_the_room_of_its_parts() {
    let server = small_parts().await;
    let id = initiate(&server).await;
    let etag = upload_part(&server, &id, 1, &"x".repeat(600))
        .await
        .header("etag")
        .unwrap()
        .to_string();
    let body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );

    let completed = run(
        &server,
        call("POST", &format!("/bkt/big?uploadId={id}")).body(body),
    )
    .await;

    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text());
    assert_eq!(server.uploads.held(), 0);
    assert_eq!(
        run(&server, call("GET", "/bkt/big")).await.text().len(),
        600
    );
}

#[tokio::test]
async fn test_parts_of_an_earlier_process_count_against_the_parts_limit() {
    let server = small_parts().await;
    let id = initiate(&server).await;
    upload_part(&server, &id, 1, &"x".repeat(600)).await;
    let Server {
        _dir: dir,
        engine,
        app,
        ..
    } = server;
    drop(app);
    drop(engine);

    let server = server_in(dir, Config::default(), 1000).await;
    let other = initiate(&server).await;
    let part = upload_part(&server, &other, 1, &"x".repeat(600)).await;

    assert_eq!(part.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_expired_uploads_free_their_room() {
    let server = small_parts().await;
    let id = initiate(&server).await;
    upload_part(&server, &id, 1, &"x".repeat(600)).await;

    let young = server
        .uploads
        .expire(Duration::from_secs(3600))
        .await
        .unwrap();
    let old = server.uploads.expire(Duration::ZERO).await.unwrap();
    let other = initiate(&server).await;
    let part = upload_part(&server, &other, 1, &"x".repeat(600)).await;

    assert_eq!(young, (0, 0));
    assert_eq!(old, (1, 600));
    assert_eq!(part.status, StatusCode::OK);
}

#[tokio::test]
async fn test_if_match_put_follows_s3() {
    let server = with_bucket().await;
    let etag = put(&server, "k", "v1")
        .await
        .header("etag")
        .unwrap()
        .to_string();
    let put_if = async |key: &str, value: String| {
        let uri = format!("/bkt/{key}");
        run(
            &server,
            call("PUT", &uri).header("if-match", value).body("new"),
        )
        .await
    };

    let missing = put_if("absent", "*".into()).await;
    let wrong = put_if("k", "\"0000\"".into()).await;
    let listed = put_if("k", format!("\"x\", {etag}")).await;
    let any = put_if("k", "*".into()).await;
    let both = run(
        &server,
        call("PUT", "/bkt/k")
            .header("if-match", "*")
            .header("if-none-match", "*")
            .body("x"),
    )
    .await;

    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.xml("Code").unwrap(), "NoSuchKey");
    assert_eq!(wrong.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(any.status, StatusCode::OK);
    assert_eq!(both.status, StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn test_complete_takes_the_conditional_write_headers() {
    let server = with_bucket().await;
    put(&server, "big", "old").await;
    let complete = async |name: &str, value: &str| {
        let id = run(&server, call("POST", "/bkt/big?uploads"))
            .await
            .xml("UploadId")
            .unwrap();
        let etag = upload_part(&server, &id, 1, "part")
            .await
            .header("etag")
            .unwrap()
            .to_string();
        let body = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag>\
             </Part></CompleteMultipartUpload>"
        );
        run(
            &server,
            call("POST", &format!("/bkt/big?uploadId={id}"))
                .header(name, value)
                .body(body),
        )
        .await
    };

    let exists = complete("if-none-match", "*").await;
    let wrong = complete("if-match", "\"0000\"").await;
    let any = complete("if-match", "*").await;

    assert_eq!(exists.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(wrong.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(any.status, StatusCode::OK);
    assert_eq!(run(&server, call("GET", "/bkt/big")).await.text(), "part");
}

fn large_object() -> Vec<u8> {
    let mut data = vec![0; 3 * engine::READ_STEP + 17];
    blake3::Hasher::new().finalize_xof().fill(&mut data);
    data
}

/// A server with no chunk cache, so each GET of a flushed object reads the remote.
async fn uncached() -> Server {
    let config = Config {
        cache_bytes: 0,
        ..Config::default()
    };
    bucket_on(server_with(config).await).await
}

/// The response of a GET, with its body not read yet.
async fn get_response(server: &Server, uri: &str) -> Response<Body> {
    server
        .app
        .clone()
        .oneshot(call("GET", uri).request())
        .await
        .unwrap()
}

#[tokio::test]
async fn test_get_streams_a_large_object_in_pieces() {
    let server = uncached().await;
    let data = large_object();
    run(&server, call("PUT", "/bkt/big").body(data.clone())).await;
    server.engine.flush().await.unwrap();

    let response = get_response(&server, "/bkt/big").await;
    let length = response.headers()["content-length"]
        .to_str()
        .unwrap()
        .to_string();
    let mut body = response.into_body();
    let mut frames = Vec::new();
    while let Some(frame) = body.frame().await {
        let piece = frame.unwrap().into_data().unwrap();
        // A slow client: the next piece waits for the client.
        tokio::time::sleep(Duration::from_millis(10)).await;
        frames.push(piece);
    }
    let ranged = run(
        &server,
        call("GET", "/bkt/big").header("range", "bytes=10-5000000"),
    )
    .await;

    assert_eq!(length, data.len().to_string());
    assert!(frames.len() >= 4, "{} frames", frames.len());
    assert!(frames.iter().all(|piece| piece.len() <= engine::READ_STEP));
    assert!(frames.concat() == data);
    assert_eq!(ranged.status, StatusCode::PARTIAL_CONTENT);
    assert!(ranged.body == data[10..=5_000_000]);
}

#[tokio::test]
async fn test_get_that_the_client_cuts_leaves_the_server_working() {
    let server = uncached().await;
    let data = large_object();
    run(&server, call("PUT", "/bkt/big").body(data.clone())).await;
    server.engine.flush().await.unwrap();

    let mut body = get_response(&server, "/bkt/big").await.into_body();
    body.frame().await.unwrap().unwrap();
    drop(body);

    assert!(run(&server, call("GET", "/bkt/big")).await.body == data);
}

#[tokio::test]
async fn test_get_with_a_bad_chunk_ends_with_an_error_not_a_short_body() {
    let server = uncached().await;
    let data = large_object();
    run(&server, call("PUT", "/bkt/big").body(data.clone())).await;
    server.engine.flush().await.unwrap();
    let remote = server._dir.path().join("remote");
    let pack = walk(&remote)
        .into_iter()
        .find(|path| path.to_string_lossy().contains("packs"))
        .unwrap();
    let mut bytes = std::fs::read(&pack).unwrap();
    let late = bytes.len() * 3 / 4;
    bytes[late] ^= 1;
    std::fs::write(&pack, bytes).unwrap();

    let response = get_response(&server, "/bkt/big").await;
    let status = response.status();
    let body = response.into_body().collect().await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.is_err(), "the body ends with an error");
}

/// Every file under `dir`.
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[tokio::test]
async fn test_conditional_header_that_is_not_ascii_is_refused() {
    let server = with_bucket().await;
    put(&server, "k", "v1").await;

    for (name, value) in [("if-match", "\"é\""), ("if-none-match", "*é")] {
        let reply = run(
            &server,
            call("PUT", "/bkt/k").header(name, value).body("v2"),
        )
        .await;
        let read = run(&server, call("GET", "/bkt/k").header(name, value)).await;
        assert_eq!(read.status, StatusCode::BAD_REQUEST, "GET {name}");

        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{name}: {}",
            reply.text()
        );
    }
    assert_eq!(run(&server, call("GET", "/bkt/k")).await.text(), "v1");
}

#[tokio::test]
async fn test_two_completes_of_one_upload_free_its_room_once() {
    let server = small_parts().await;
    let id = initiate(&server).await;
    let etag = upload_part(&server, &id, 1, &"x".repeat(600))
        .await
        .header("etag")
        .unwrap()
        .to_string();
    let body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let other = initiate(&server).await;
    upload_part(&server, &other, 1, &"y".repeat(300)).await;
    let uri = format!("/bkt/big?uploadId={id}");

    let (a, b) = tokio::join!(
        run(&server, call("POST", &uri).body(body.clone())),
        run(&server, call("POST", &uri).body(body)),
    );

    let mut statuses = [a.status, b.status];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::NOT_FOUND]);
    assert_eq!(server.uploads.held(), 300, "the other upload still counts");
}

/// A server with the smallest read budget: 16 pieces of a GET in flight.
async fn small_budget() -> Server {
    let config = Config {
        read_budget: engine::MIN_READ_BUDGET,
        ..Config::default()
    };
    bucket_on(server_with(config).await).await
}

#[tokio::test]
async fn test_get_with_no_room_in_the_read_budget_gets_503() {
    let server = small_budget().await;
    let data = vec![3u8; 2 * engine::READ_STEP];
    run(&server, call("PUT", "/bkt/k").body(data)).await;
    // Each response holds the room of its first piece while its body is not read.
    let mut held = Vec::new();
    for _ in 0..engine::MIN_READ_BUDGET as usize / engine::READ_STEP {
        let response = get_response(&server, "/bkt/k").await;
        assert_eq!(response.status(), StatusCode::OK);
        held.push(response);
    }

    let started = std::time::Instant::now();
    let full = run(&server, call("GET", "/bkt/k")).await;
    let ranged = run(&server, call("GET", "/bkt/k").header("range", "bytes=0-9")).await;
    let head = run(&server, call("HEAD", "/bkt/k")).await;
    drop(held);
    let after = run(&server, call("GET", "/bkt/k")).await;

    assert_eq!(full.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(full.xml("Code").unwrap(), "SlowDown");
    assert!(full.header("retry-after").is_some());
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "the first piece waits 5 s"
    );
    assert_eq!(
        ranged.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a range takes room too"
    );
    assert_eq!(head.status, StatusCode::OK, "a HEAD takes no room");
    assert_eq!(after.status, StatusCode::OK);
    assert_eq!(after.body.len(), 2 * engine::READ_STEP);
}

/// What a presigned URL signs. The test changes one field to break it.
#[derive(Clone)]
struct Presign {
    method: &'static str,
    path: String,
    at: u64,
    expires: String,
    access: String,
    secret: String,
    host: &'static str,
}

impl Presign {
    fn new(method: &'static str, path: &str) -> Self {
        Self {
            method,
            path: path.to_string(),
            at: now(),
            expires: "300".into(),
            access: ACCESS.into(),
            secret: SECRET.into(),
            host: "localhost",
        }
    }

    /// The query of the URL: the five signed parameters, then the signature.
    fn query(&self) -> String {
        let timestamp = sigv4::timestamp(self.at);
        let date = &timestamp[..8];
        let encode = |value: &str| sigv4::uri_encode(value.as_bytes(), sigv4::Slash::Encode);
        let credential = format!("{}/{date}/{REGION}/s3/aws4_request", self.access);
        let query = format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Date={timestamp}\
             &X-Amz-Expires={}&X-Amz-SignedHeaders=host",
            encode(&credential),
            encode(&self.expires),
        );
        let headers = [("host".to_string(), self.host.to_string())];
        let canonical = sigv4::canonical_request(
            self.method,
            &self.path,
            &query,
            &headers,
            &["host".to_string()],
            sigv4::UNSIGNED_PAYLOAD,
        );
        let key = sigv4::signing_key(&self.secret, date, REGION);
        let scope = format!("{date}/{REGION}/s3/aws4_request");
        let signature = sigv4::signature(&key, &timestamp, &scope, &canonical);
        format!("{query}&X-Amz-Signature={signature}")
    }
}

/// A request to `path?query` with only a host header: no Authorization.
async fn send_raw(server: &Server, method: &str, uri: &str, host: &str, body: &str) -> Reply {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host)
        .body(Body::from(body.to_string()))
        .unwrap();
    send(server, request).await
}

async fn presigned(server: &Server, sign: &Presign, method: &str, path: &str) -> Reply {
    let uri = format!("{path}?{}", sign.query());
    send_raw(server, method, &uri, "localhost", "").await
}

#[tokio::test]
async fn test_presigned_get_head_and_put_work() {
    let server = with_bucket().await;
    put(&server, "k", "data").await;

    let get = presigned(&server, &Presign::new("GET", "/bkt/k"), "GET", "/bkt/k").await;
    let head = presigned(&server, &Presign::new("HEAD", "/bkt/k"), "HEAD", "/bkt/k").await;
    let put_uri = format!("/bkt/new?{}", Presign::new("PUT", "/bkt/new").query());
    let put_reply = send_raw(&server, "PUT", &put_uri, "localhost", "uploaded").await;

    assert_eq!(get.status, StatusCode::OK, "{}", get.text());
    assert_eq!(get.text(), "data");
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(put_reply.status, StatusCode::OK, "{}", put_reply.text());
    assert_eq!(
        run(&server, call("GET", "/bkt/new")).await.text(),
        "uploaded"
    );
}

#[tokio::test]
async fn test_presigned_url_that_changed_is_refused() {
    let server = with_bucket().await;
    put(&server, "k", "data").await;
    put(&server, "other", "data").await;
    let sign = Presign::new("GET", "/bkt/k");
    let code = |reply: &Reply| (reply.status, reply.xml("Code").unwrap_or_default());
    let mismatch = (StatusCode::FORBIDDEN, "SignatureDoesNotMatch".to_string());

    let path = presigned(&server, &sign, "GET", "/bkt/other").await;
    let method = presigned(&server, &sign, "HEAD", "/bkt/k").await;
    let added = send_raw(
        &server,
        "GET",
        &format!("/bkt/k?{}&a=b", sign.query()),
        "localhost",
        "",
    )
    .await;
    let expires = sign
        .query()
        .replace("X-Amz-Expires=300", "X-Amz-Expires=600");
    let longer = send_raw(
        &server,
        "GET",
        &format!("/bkt/k?{expires}"),
        "localhost",
        "",
    )
    .await;
    let host = send_raw(
        &server,
        "GET",
        &format!("/bkt/k?{}", sign.query()),
        "other",
        "",
    )
    .await;
    let secret = Presign {
        secret: "wrong".into(),
        ..sign.clone()
    };
    let wrong = presigned(&server, &secret, "GET", "/bkt/k").await;
    let removed = Presign {
        access: "NOSUCHKEY".into(),
        ..sign.clone()
    };
    let unknown = presigned(&server, &removed, "GET", "/bkt/k").await;

    for reply in [&path, &added, &longer, &host, &wrong] {
        assert_eq!(code(reply), mismatch, "{}", reply.text());
    }
    // A HEAD has no body, so its error code is in the status only.
    assert_eq!(method.status, StatusCode::FORBIDDEN);
    assert_eq!(
        code(&unknown),
        (StatusCode::FORBIDDEN, "InvalidAccessKeyId".to_string())
    );
}

#[tokio::test]
async fn test_presigned_url_outside_its_time_is_refused() {
    let server = with_bucket().await;
    put(&server, "k", "data").await;
    let expired = Presign {
        at: now() - 3600,
        expires: "60".into(),
        ..Presign::new("GET", "/bkt/k")
    };
    let early = Presign {
        at: now() + 3600,
        ..Presign::new("GET", "/bkt/k")
    };

    let late = presigned(&server, &expired, "GET", "/bkt/k").await;
    let future = presigned(&server, &early, "GET", "/bkt/k").await;

    assert_eq!(late.status, StatusCode::FORBIDDEN);
    assert!(
        late.text().contains("Request has expired"),
        "{}",
        late.text()
    );
    assert_eq!(future.status, StatusCode::FORBIDDEN);
    assert!(future.text().contains("not valid yet"), "{}", future.text());
}

#[tokio::test]
async fn test_presigned_parameters_must_come_once_and_be_valid() {
    let server = with_bucket().await;
    put(&server, "k", "data").await;
    let query = Presign::new("GET", "/bkt/k").query();
    let names = [
        "X-Amz-Algorithm",
        "X-Amz-Credential",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-SignedHeaders",
        "X-Amz-Signature",
    ];
    let mut queries = Vec::new();
    for name in names {
        let pair = query
            .split('&')
            .find(|pair| pair.starts_with(&format!("{name}=")))
            .unwrap();
        let missing: Vec<&str> = query.split('&').filter(|p| *p != pair).collect();
        queries.push(missing.join("&"));
        queries.push(format!("{query}&{pair}"));
    }
    // A second copy in another case, or encoded, cannot stay out of the signed query.
    let signature = query.rsplit_once("X-Amz-Signature=").unwrap().1;
    queries.push(format!("{query}&x-amz-signature={signature}"));
    queries.push(format!("{query}&X-Amz-%53ignature={signature}"));
    queries.push(query.replace(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "X-Amz-Algorithm=AWS4-HMAC-SHA1",
    ));
    for expires in ["0", "604801", "%2B1", "0007", "1e3"] {
        queries.push(query.replace("X-Amz-Expires=300", &format!("X-Amz-Expires={expires}")));
    }
    queries.push(format!("{query}&bad=%zz"));
    queries.push(format!("{query}&X-Amz-Security-Token=t"));

    for query in &queries {
        let reply = send_raw(&server, "GET", &format!("/bkt/k?{query}"), "localhost", "").await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{query}: {}",
            reply.text()
        );
        assert_eq!(
            reply.xml("Code").unwrap(),
            "AuthorizationQueryParametersError"
        );
        assert!(!reply.text().contains(signature), "the signature is echoed");
    }
}

#[tokio::test]
async fn test_presigned_url_covers_get_head_and_put_of_an_object_only() {
    let server = with_bucket().await;
    put(&server, "k", "data").await;

    let post = presigned(&server, &Presign::new("POST", "/bkt/k"), "POST", "/bkt/k").await;
    let delete = presigned(
        &server,
        &Presign::new("DELETE", "/bkt/k"),
        "DELETE",
        "/bkt/k",
    )
    .await;
    let bucket = presigned(&server, &Presign::new("GET", "/bkt"), "GET", "/bkt").await;
    let both = Request::builder()
        .method("GET")
        .uri(format!("/bkt/k?{}", Presign::new("GET", "/bkt/k").query()))
        .header("host", "localhost")
        .header("authorization", "AWS4-HMAC-SHA256 Credential=x")
        .body(Body::empty())
        .unwrap();
    let both = send(&server, both).await;

    for reply in [&post, &delete, &bucket] {
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());
        assert_eq!(reply.xml("Code").unwrap(), "AccessDenied");
    }
    assert_eq!(both.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_presigned_request_gets_503_while_the_clock_is_ahead() {
    let server = with_bucket().await;
    let real = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // Acks two days ahead, then the wall clock comes back: the expiry has no trusted clock.
    journal::set_manual_wall(Some(real + 2 * 24 * 3600 * 1_000_000_000));
    put(&server, "k", "data").await;
    journal::set_manual_wall(Some(real));

    let reply = presigned(&server, &Presign::new("GET", "/bkt/k"), "GET", "/bkt/k").await;
    journal::set_manual_wall(None);

    assert_eq!(
        reply.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        reply.text()
    );
    assert!(
        reply.text().contains("presigned requests resume in"),
        "{}",
        reply.text()
    );
}

/// A PUT of `body` with its Content-Length, signed with `hash` or the hash of the body.
async fn sized_put(
    server: &Server,
    key: &str,
    body: Vec<u8>,
    length: usize,
    hash: Option<String>,
) -> Reply {
    let uri = format!("/bkt/{key}");
    let mut put = call("PUT", &uri)
        .header("content-length", length.to_string())
        .body(body);
    put.payload_hash = hash;
    run(server, put).await
}

fn spool_files(server: &Server) -> usize {
    std::fs::read_dir(server._dir.path().join("engine/buffer/spool"))
        .map_or(0, |entries| entries.count())
}

/// Puts that start together take the room of their declared bodies at once: the one that the
/// buffer cannot hold gets 503 before its body, not in the middle of it.
#[tokio::test]
async fn test_declared_puts_over_the_buffer_room_are_refused_at_the_start() {
    let server = bucket_on(
        server_with(Config {
            buffer_limit: 8 * 1024 * 1024,
            ..Config::default()
        })
        .await,
    )
    .await;
    let declared = (6u64 * 1024 * 1024).to_string();
    let mut first = call("PUT", "/bkt/first").header("content-length", declared.clone());
    first.payload_hash = Some(sigv4::UNSIGNED_PAYLOAD.to_string());
    let (parts, _) = first.request().into_parts();
    let stalled =
        Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
    let app = server.app.clone();
    let held = tokio::spawn(app.oneshot(Request::from_parts(parts, stalled)));
    while spool_files(&server) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let second = call("PUT", "/bkt/second").header("content-length", declared);
    let (reply, taken) = send_counted(&server, second, 6 * 1024 * 1024).await;

    assert_eq!(
        reply.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        reply.text()
    );
    assert_eq!(taken, 0);
    held.abort();
}

#[tokio::test]
async fn test_large_put_streams_through_a_spool_file() {
    let server = with_bucket().await;
    let body = large_object();

    let put = sized_put(&server, "big", body.clone(), body.len(), None).await;
    let read = run(&server, call("GET", "/bkt/big")).await;

    assert_eq!(put.status, StatusCode::OK, "{}", put.text());
    assert_eq!(
        put.header("etag").unwrap(),
        format!("\"{}\"", blake3::hash(&body))
    );
    assert!(read.body == body);
    assert_eq!(spool_files(&server), 0);
}

#[tokio::test]
async fn test_large_put_with_a_bad_body_writes_nothing() {
    let server = with_bucket().await;
    let body = large_object();
    let wrong_hash = sigv4::sha256_hex(b"other");

    let mismatch = sized_put(&server, "a", body.clone(), body.len(), Some(wrong_hash)).await;
    let short = sized_put(
        &server,
        "b",
        body[..body.len() / 2].to_vec(),
        body.len(),
        None,
    )
    .await;
    let huge = sized_put(&server, "c", b"x".to_vec(), 6 << 30, None).await;

    assert_eq!(mismatch.status, StatusCode::BAD_REQUEST);
    assert_eq!(mismatch.xml("Code").unwrap(), "XAmzContentSHA256Mismatch");
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    assert_eq!(short.xml("Code").unwrap(), "IncompleteBody");
    assert_eq!(huge.status, StatusCode::BAD_REQUEST);
    assert_eq!(huge.xml("Code").unwrap(), "EntityTooLarge");
    for key in ["a", "b", "c"] {
        let read = run(&server, call("GET", &format!("/bkt/{key}"))).await;
        assert_eq!(read.status, StatusCode::NOT_FOUND, "{key}");
    }
    assert_eq!(spool_files(&server), 0);
}

/// A bucket on a server with a body limit of 2 MiB.
async fn with_max_body() -> Server {
    let mut server = with_bucket().await;
    let mut config = S3Config::new(
        HashMap::from([(ACCESS.to_string(), SECRET.to_string())]),
        server._dir.path().join("uploads"),
    );
    config.uploads = server.uploads.clone();
    config.max_body = 2 * 1024 * 1024;
    server.app = s3api::router(server.engine.clone(), config);
    server
}

/// A body with no Content-Length: the limit applies to the bytes that arrive.
fn chunked<'a>(call: Call<'a>, body: &[u8]) -> Call<'a> {
    call.header("transfer-encoding", "chunked").body(body)
}

#[tokio::test]
async fn test_chunked_put_with_no_length_stops_at_the_body_limit() {
    let server = with_max_body().await;
    let body = vec![7; 3 * 1024 * 1024];

    let over = run(&server, chunked(call("PUT", "/bkt/a"), &body)).await;
    let under = run(
        &server,
        chunked(call("PUT", "/bkt/b"), &body[..1024 * 1024 + 1]),
    )
    .await;
    let read = run(&server, call("GET", "/bkt/a")).await;

    assert_eq!(over.status, StatusCode::BAD_REQUEST, "{}", over.text());
    assert_eq!(over.xml("Code").unwrap(), "EntityTooLarge");
    assert_eq!(under.status, StatusCode::OK, "{}", under.text());
    assert_eq!(read.status, StatusCode::NOT_FOUND);
    assert_eq!(spool_files(&server), 0);
}

#[tokio::test]
async fn test_buffered_bodies_with_no_length_stop_at_the_body_limit() {
    let server = with_max_body().await;
    let id = start_upload(&server).await;
    let part = format!("/bkt/big?partNumber=1&uploadId={id}");
    let body = vec![7; 3 * 1024 * 1024];

    let replies = [
        run(&server, chunked(call("PUT", &part), &body)).await,
        run(
            &server,
            chunked(call("PUT", "/bkt/copy"), &body).header("x-amz-copy-source", "/bkt/source"),
        )
        .await,
        run(&server, chunked(call("PUT", "/other"), &body)).await,
    ];

    for reply in replies {
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
        assert_eq!(reply.xml("Code").unwrap(), "EntityTooLarge");
    }
}

/// A body of `len` bytes made on demand, and the count of bytes that the server took from it.
fn counted_body(len: u64) -> (Body, Arc<std::sync::atomic::AtomicU64>) {
    const PIECE: u64 = 1024 * 1024;
    let taken = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let count = taken.clone();
    let stream = futures_util::stream::unfold(0u64, move |sent| {
        let count = count.clone();
        async move {
            if sent >= len {
                return None;
            }
            let size = PIECE.min(len - sent);
            count.fetch_add(size, std::sync::atomic::Ordering::SeqCst);
            let piece = Bytes::from(vec![7u8; size as usize]);
            Some((Ok::<_, std::io::Error>(piece), sent + size))
        }
    });
    (Body::from_stream(stream), taken)
}

/// Sends `call` with a counted body of `len` bytes in place of its own body.
async fn send_counted(server: &Server, call: Call<'_>, len: u64) -> (Reply, u64) {
    let mut call = call;
    call.payload_hash = Some(sigv4::UNSIGNED_PAYLOAD.to_string());
    let (parts, _) = call.request().into_parts();
    let (body, taken) = counted_body(len);
    let reply = send(server, Request::from_parts(parts, body)).await;
    (reply, taken.load(std::sync::atomic::Ordering::SeqCst))
}

#[tokio::test]
async fn test_request_with_no_streamed_body_is_refused_before_its_body_is_read() {
    let server = with_bucket().await;
    put(&server, "source", "data").await;
    let huge = 5u64 * 1024 * 1024 * 1024;
    let length = huge.to_string();
    let calls = [
        call("PUT", "/bkt/copy").header("x-amz-copy-source", "/bkt/source"),
        call("PUT", "/other"),
        call("DELETE", "/bkt"),
        call("DELETE", "/bkt/source"),
        call("GET", "/bkt/source"),
        call("POST", "/bkt?delete"),
    ];

    for call in calls {
        let what = format!("{} {}", call.method, call.uri);
        let call = call.header("content-length", length.clone());
        let (reply, taken) = send_counted(&server, call, huge).await;

        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{what}: {}",
            reply.text()
        );
        assert_eq!(taken, 0, "{what}");
    }
}

#[tokio::test]
async fn test_unknown_payload_hash_is_refused_before_its_body_is_read() {
    let server = with_bucket().await;
    let body = 4u64 * 1024 * 1024;
    for value in ["STREAMING-SOMETHING-NEW", "not-a-hash"] {
        for (method, uri) in [("PUT", "/bkt/k"), ("POST", "/bkt?delete")] {
            let mut call = call(method, uri).header("content-length", body.to_string());
            call.payload_hash = Some(value.to_string());
            let (parts, _) = call.request().into_parts();
            let (counted, taken) = counted_body(body);

            let reply = send(&server, Request::from_parts(parts, counted)).await;

            let taken = taken.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{value} {method}");
            assert_eq!(taken, 0, "{value} {method}");
        }
    }
}

#[tokio::test]
async fn test_content_length_with_a_chunked_body_is_refused() {
    let server = with_bucket().await;
    let call = call("PUT", "/bkt/k")
        .header("content-length", "10")
        .header("transfer-encoding", "chunked");

    let (reply, taken) = send_counted(&server, call, 4 * 1024 * 1024).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
    assert_eq!(taken, 0);
}

#[tokio::test]
async fn test_chunked_put_in_another_case_streams() {
    let server = with_bucket().await;
    let data = vec![7u8; 3 * 1024 * 1024];

    let reply = run(
        &server,
        call("PUT", "/bkt/k")
            .header("transfer-encoding", "Chunked")
            .body(data.clone()),
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(run(&server, call("GET", "/bkt/k")).await.body, data);
}

/// The signature check uses the headers only: a client with no valid key makes no read.
#[tokio::test]
async fn test_request_with_a_wrong_signature_reads_no_body() {
    let server = with_bucket().await;
    let body = 4u64 * 1024 * 1024;
    for (method, uri) in [("POST", "/bkt?delete"), ("PUT", "/bkt/k")] {
        let mut call = call(method, uri).header("content-length", body.to_string());
        call.secret = "wrong";

        let (reply, taken) = send_counted(&server, call, body).await;

        assert_eq!(
            reply.status,
            StatusCode::FORBIDDEN,
            "{method}: {}",
            reply.text()
        );
        assert_eq!(taken, 0, "{method}");
    }
}

#[tokio::test]
async fn test_copy_body_with_no_length_stops_at_a_small_cap() {
    let server = with_bucket().await;
    put(&server, "source", "data").await;
    let call = call("PUT", "/bkt/copy")
        .header("x-amz-copy-source", "/bkt/source")
        .header("transfer-encoding", "chunked");

    let (reply, taken) = send_counted(&server, call, 64 * 1024 * 1024).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
    assert!(taken <= 2 * 1024 * 1024, "{taken} bytes read");
}

/// Keys that change while the server runs, as in a console. `down` makes every lookup fail.
#[derive(Default)]
struct LiveKeys {
    keys: std::sync::Mutex<HashMap<String, String>>,
    down: std::sync::atomic::AtomicBool,
    /// Every lookup waits for ever.
    hang: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl KeyStore for LiveKeys {
    async fn secret(&self, access_key: &str) -> Result<Option<Secret>, KeyStoreError> {
        if self.hang.load(std::sync::atomic::Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(KeyStoreError::new("the key database is locked"));
        }
        let keys = self.keys.lock().unwrap();
        Ok(keys
            .get(access_key)
            .map(|secret| Secret::new(secret.clone())))
    }
}

/// A bucket on a server whose keys come from `store`.
async fn with_key_store(store: Arc<LiveKeys>) -> Server {
    let mut server = with_bucket().await;
    store
        .keys
        .lock()
        .unwrap()
        .insert(ACCESS.to_string(), SECRET.to_string());
    let mut config = S3Config::new(HashMap::new(), server._dir.path().join("uploads"));
    config.uploads = server.uploads.clone();
    config.keys = store;
    server.app = s3api::router(server.engine.clone(), config);
    server
}

#[tokio::test]
async fn test_revoked_key_fails_at_the_next_request() {
    let store = Arc::new(LiveKeys::default());
    let server = with_key_store(store.clone()).await;
    put(&server, "k", "data").await;
    let sign = Presign::new("GET", "/bkt/k");

    let before = run(&server, call("GET", "/bkt/k")).await;
    let presigned_before = presigned(&server, &sign, "GET", "/bkt/k").await;
    store.keys.lock().unwrap().remove(ACCESS);
    let after = run(&server, call("GET", "/bkt/k")).await;
    let presigned_after = presigned(&server, &sign, "GET", "/bkt/k").await;

    assert_eq!(before.status, StatusCode::OK);
    assert_eq!(presigned_before.status, StatusCode::OK);
    for reply in [after, presigned_after] {
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(reply.xml("Code").unwrap(), "InvalidAccessKeyId");
    }
}

#[tokio::test]
async fn test_empty_secret_from_the_store_denies_the_request() {
    let store = Arc::new(LiveKeys::default());
    let server = with_key_store(store.clone()).await;
    put(&server, "k", "data").await;
    store
        .keys
        .lock()
        .unwrap()
        .insert(ACCESS.to_string(), String::new());

    let mut get = call("GET", "/bkt/k");
    get.secret = "";
    let reply = run(&server, get).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());
    assert_eq!(reply.xml("Code").unwrap(), "InvalidAccessKeyId");
}

#[tokio::test]
async fn test_key_store_failure_denies_the_request_with_503() {
    let store = Arc::new(LiveKeys::default());
    let server = with_key_store(store.clone()).await;
    put(&server, "k", "data").await;
    let sign = Presign::new("GET", "/bkt/k");

    store.down.store(true, std::sync::atomic::Ordering::SeqCst);
    let get = run(&server, call("GET", "/bkt/k")).await;
    let write = put(&server, "new", "data").await;
    let presigned_get = presigned(&server, &sign, "GET", "/bkt/k").await;
    store.down.store(false, std::sync::atomic::Ordering::SeqCst);
    let read = run(&server, call("GET", "/bkt/new")).await;

    for reply in [get, write, presigned_get] {
        assert_eq!(
            reply.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{}",
            reply.text()
        );
        assert_eq!(reply.xml("Code").unwrap(), "ServiceUnavailable");
        assert!(!reply.text().contains("locked"), "{}", reply.text());
    }
    assert_eq!(read.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_key_store_that_never_answers_gets_503_at_the_deadline() {
    let store = Arc::new(LiveKeys::default());
    let server = with_key_store(store.clone()).await;

    store.hang.store(true, std::sync::atomic::Ordering::SeqCst);
    let start = std::time::Instant::now();
    let reply = tokio::time::timeout(
        s3api::KEY_STORE_DEADLINE * 3,
        run(&server, call("GET", "/bkt/k")),
    )
    .await
    .expect("the deadline ends the lookup");

    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.xml("Code").unwrap(), "ServiceUnavailable");
    assert!(start.elapsed() >= s3api::KEY_STORE_DEADLINE);
}

/// A signed aws-chunked PUT of `key`: the encoded body for `data`, and the request with `body`.
struct ChunkedPut {
    encoded: Vec<u8>,
    headers: Vec<(String, String)>,
    authorization: String,
    uri: String,
}

impl ChunkedPut {
    fn new(key: &str, data: &[u8], decoded_length: usize) -> Self {
        Self::with_payload(key, data, decoded_length, sigv4::STREAMING_SIGNED)
    }

    /// `payload` is `STREAMING_SIGNED` or `STREAMING_UNSIGNED_TRAILER`.
    fn with_payload(key: &str, data: &[u8], decoded_length: usize, payload: &str) -> Self {
        let timestamp = sigv4::timestamp(now());
        // `key` can carry a query, as an upload part does.
        let uri = format!("/bkt/{key}");
        let (path, query) = uri.split_once('?').unwrap_or((&uri, ""));
        let headers: Vec<(String, String)> = vec![
            ("host".into(), "localhost".into()),
            ("x-amz-date".into(), timestamp.clone()),
            ("x-amz-content-sha256".into(), payload.into()),
            (
                "x-amz-decoded-content-length".into(),
                decoded_length.to_string(),
            ),
            ("content-encoding".into(), "aws-chunked".into()),
        ];
        let (authorization, seed) = sigv4::sign(
            &sigv4::Request {
                method: "PUT",
                path,
                query,
                headers: &headers,
                payload_hash: payload,
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
        Self {
            encoded: sigv4::encode_chunked(
                data,
                64 * 1024,
                (payload == sigv4::STREAMING_SIGNED).then_some(signer),
            ),
            headers,
            authorization,
            uri,
        }
    }

    /// The request, with a Content-Length of the whole encoded body.
    fn request(&self, body: Body) -> Request<Body> {
        let mut request = Request::builder().method("PUT").uri(&self.uri);
        for (name, value) in &self.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request
            .header("content-length", self.encoded.len().to_string())
            .header("authorization", self.authorization.as_str())
            .body(body)
            .unwrap()
    }
}

#[tokio::test]
async fn test_large_aws_chunked_put_streams_through_a_spool_file() {
    let server = with_bucket().await;
    let data = large_object();
    let put = ChunkedPut::new("big", &data, data.len());
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|piece| (Ok::<_, std::io::Error>(piece), rx))
    });
    let reply = tokio::spawn({
        let app = server.app.clone();
        let request = put.request(Body::from_stream(stream));
        async move { app.oneshot(request).await.unwrap().status() }
    });
    let half = put.encoded.len() / 2;

    tx.send(Bytes::copy_from_slice(&put.encoded[..half]))
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while spool_files(&server) == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let spooled_while_sending = spool_files(&server);
    tx.send(Bytes::copy_from_slice(&put.encoded[half..]))
        .await
        .unwrap();
    drop(tx);
    let status = reply.await.unwrap();
    let read = run(&server, call("GET", "/bkt/big")).await;

    assert_eq!(spooled_while_sending, 1);
    assert_eq!(status, StatusCode::OK);
    assert!(read.body == data);
    assert_eq!(read.header("content-encoding"), None);
    assert_eq!(spool_files(&server), 0);
}

#[tokio::test]
async fn test_large_aws_chunked_put_with_a_bad_body_writes_nothing() {
    let server = with_bucket().await;
    let data = large_object();
    let forged = {
        let put = ChunkedPut::new("forged", &data, data.len());
        let mut body = put.encoded.clone();
        let at = body.len() / 2;
        body[at] ^= 1;
        send(&server, put.request(Body::from(body))).await
    };
    let cut = {
        let put = ChunkedPut::new("cut", &data, data.len());
        let mut body = put.encoded.clone();
        body.truncate(body.len() - 100);
        let mut request = put.request(Body::from(body.clone()));
        request
            .headers_mut()
            .insert("content-length", body.len().to_string().parse().unwrap());
        send(&server, request).await
    };
    let wrong_length = {
        let put = ChunkedPut::new("wrong", &data, data.len() + 1);
        send(&server, put.request(Body::from(put.encoded.clone()))).await
    };

    assert_eq!(forged.status, StatusCode::FORBIDDEN, "{}", forged.text());
    assert_eq!(forged.xml("Code").unwrap(), "SignatureDoesNotMatch");
    for reply in [&cut, &wrong_length] {
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
        assert_eq!(reply.xml("Code").unwrap(), "IncompleteBody");
    }
    for key in ["forged", "cut", "wrong"] {
        let read = run(&server, call("GET", &format!("/bkt/{key}"))).await;
        assert_eq!(read.status, StatusCode::NOT_FOUND, "{key}");
    }
    assert_eq!(spool_files(&server), 0);
}

#[tokio::test]
async fn test_large_unsigned_trailer_put_streams_and_reads_back() {
    let server = with_bucket().await;
    let data = large_object();
    let put = ChunkedPut::with_payload(
        "unsigned",
        &data,
        data.len(),
        sigv4::STREAMING_UNSIGNED_TRAILER,
    );

    let reply = send(&server, put.request(Body::from(put.encoded.clone()))).await;
    let read = run(&server, call("GET", "/bkt/unsigned")).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert!(read.body == data);
    assert_eq!(spool_files(&server), 0);
}

/// The server again on its directory, as after a crash: the engine and the uploads open anew.
async fn restarted(server: Server) -> Server {
    let Server {
        _dir: dir,
        engine,
        app,
        ..
    } = server;
    drop(app);
    drop(engine);
    server_in(dir, Config::default(), s3api::DEFAULT_PARTS_LIMIT).await
}

/// Leaves `id` as a complete that a crash stopped after its mark of `hash`.
fn mark_by_hand(server: &Server, id: &str, hash: &str) -> std::path::PathBuf {
    let uploads = server._dir.path().join("uploads");
    let claimed = uploads.join(format!("{id}.completing"));
    std::fs::rename(uploads.join(id), &claimed).unwrap();
    std::fs::write(claimed.join("committing"), hash).unwrap();
    uploads.join(id)
}

#[tokio::test]
async fn test_start_gives_back_an_uncommitted_complete_without_its_mark() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let (etags, _) = two_big_parts(&server, &id).await;
    let back = mark_by_hand(&server, &id, &"ab".repeat(32));

    let server = restarted(server).await;

    assert!(back.join("meta").exists());
    assert!(!back.join("committing").exists(), "a stale mark stays");
    let done = complete_all(&server, &id, &etags).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
}

#[tokio::test]
async fn test_start_removes_a_committed_complete() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let (_, object) = two_big_parts(&server, &id).await;
    let put = run(&server, call("PUT", "/bkt/big").body(object.clone())).await;
    let hash = put.header("etag").unwrap().trim_matches('"').to_string();
    let back = mark_by_hand(&server, &id, &hash);

    let server = restarted(server).await;

    let uploads = server._dir.path().join("uploads");
    assert!(!back.exists());
    assert!(!uploads.join(format!("{id}.completing")).exists());
    assert_eq!(list_parts(&server, &id).await.status, StatusCode::NOT_FOUND);
}

/// Two parts of 2 MiB each: the etags and the object they make.
async fn two_big_parts(server: &Server, id: &str) -> (Vec<String>, Vec<u8>) {
    let parts = ["a".repeat(2 << 20), "b".repeat(2 << 20)];
    let mut etags = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let reply = upload_part(server, id, i as u32 + 1, part).await;
        etags.push(reply.header("etag").unwrap().to_string());
    }
    (etags, parts.concat().into_bytes())
}

async fn complete_all(server: &Server, id: &str, etags: &[String]) -> Reply {
    let parts: Vec<(u32, &str)> = etags
        .iter()
        .enumerate()
        .map(|(i, etag)| (i as u32 + 1, etag.as_str()))
        .collect();
    complete(server, id, &parts).await
}

async fn list_parts(server: &Server, id: &str) -> Reply {
    run(server, call("GET", &format!("/bkt/big?uploadId={id}"))).await
}

#[tokio::test]
async fn test_complete_streams_its_parts_through_a_spool() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let (etags, object) = two_big_parts(&server, &id).await;

    let done = complete_all(&server, &id, &etags).await;
    let read = run(&server, call("GET", "/bkt/big")).await;

    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert!(
        done.text()
            .contains(&blake3::hash(&object).to_hex().to_string())
    );
    assert!(read.body == object);
    assert_eq!(spool_files(&server), 0);
    assert_eq!(
        list_parts(&server, &id).await.xml("Code").unwrap(),
        "NoSuchUpload"
    );
}

#[tokio::test]
async fn test_complete_with_no_buffer_room_gets_503_and_keeps_its_parts() {
    let config = Config {
        buffer_limit: 6 << 20,
        ..Config::default()
    };
    let server = bucket_on(server_with(config).await).await;
    let id = start_upload(&server).await;
    let (etags, object) = two_big_parts(&server, &id).await;
    // 3 MiB in the buffer: the 4 MiB of the object do not fit next to them.
    put(&server, "filler", &"f".repeat(3 << 20)).await;

    let full = complete_all(&server, &id, &etags).await;
    let parts = list_parts(&server, &id).await;
    server.engine.flush().await.unwrap();
    let done = complete_all(&server, &id, &etags).await;
    let read = run(&server, call("GET", "/bkt/big")).await;

    assert_eq!(
        full.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        full.text()
    );
    assert_eq!(full.xml("Code").unwrap(), "SlowDown");
    assert!(full.header("retry-after").is_some());
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(parts.text().matches("<Part>").count(), 2);
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert!(read.body == object);
    assert_eq!(spool_files(&server), 0);
}

#[tokio::test]
async fn test_crash_before_the_commit_gives_the_upload_back_for_a_new_complete() {
    for point in [Point::CompleteAssembly, Point::CompleteMarked] {
        let server = with_bucket().await;
        let id = start_upload(&server).await;
        let (etags, object) = two_big_parts(&server, &id).await;

        engine::sim::arm_crash(Some(point));
        let crashed = complete_all(&server, &id, &etags).await;
        engine::sim::arm_crash(None);
        let server = restarted(server).await;
        let parts = list_parts(&server, &id).await;
        let spooled = spool_files(&server);
        let done = complete_all(&server, &id, &etags).await;
        let read = run(&server, call("GET", "/bkt/big")).await;

        assert_eq!(
            crashed.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{point:?}"
        );
        assert_eq!(parts.text().matches("<Part>").count(), 2, "{point:?}");
        assert_eq!(spooled, 0, "{point:?}");
        assert_eq!(done.status, StatusCode::OK, "{point:?}: {}", done.text());
        assert!(read.body == object, "{point:?}");
    }
}

#[tokio::test]
async fn test_crash_after_the_commit_keeps_the_object_and_the_start_removes_the_parts() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let (etags, object) = two_big_parts(&server, &id).await;

    engine::sim::arm_crash(Some(Point::CompleteCommitted));
    let crashed = complete_all(&server, &id, &etags).await;
    engine::sim::arm_crash(None);
    let server = restarted(server).await;
    let read = run(&server, call("GET", "/bkt/big")).await;
    let parts = list_parts(&server, &id).await;
    let again = complete_all(&server, &id, &etags).await;

    assert_eq!(crashed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(read.body == object);
    assert_eq!(parts.xml("Code").unwrap(), "NoSuchUpload");
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(again.xml("Code").unwrap(), "NoSuchUpload");
    assert_eq!(server.uploads.held(), 0);
}

/// Files of an upload directory that never got their name.
fn part_temps(server: &Server, id: &str) -> usize {
    std::fs::read_dir(server._dir.path().join("uploads").join(id))
        .map(|entries| {
            entries
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".tmp.")
                })
                .count()
        })
        .unwrap_or(0)
}

/// A signed upload part whose body comes through a channel, with a Content-Length of `length`.
fn part_through_channel(
    server: &Server,
    id: &str,
    number: u32,
    length: usize,
) -> (
    tokio::sync::mpsc::Sender<Bytes>,
    tokio::task::JoinHandle<StatusCode>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|piece| (Ok::<_, std::io::Error>(piece), rx))
    });
    let uri = format!("/bkt/big?partNumber={number}&uploadId={id}");
    let mut call = call("PUT", &uri).header("content-length", length.to_string());
    call.payload_hash = Some(sigv4::UNSIGNED_PAYLOAD.to_string());
    let mut request = call.request();
    *request.body_mut() = Body::from_stream(stream);
    let app = server.app.clone();
    (
        tx,
        tokio::spawn(async move { app.oneshot(request).await.unwrap().status() }),
    )
}

#[tokio::test]
async fn test_cut_part_body_or_bad_chunk_signature_leaves_no_part() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let data = vec![7u8; 3 << 20];

    let (tx, cut) = part_through_channel(&server, &id, 1, data.len());
    tx.send(Bytes::copy_from_slice(&data[..1 << 20]))
        .await
        .unwrap();
    drop(tx);
    let cut = cut.await.unwrap();
    let forged = {
        let target = format!("big?partNumber=2&uploadId={id}");
        let put = ChunkedPut::new(&target, &data, data.len());
        let mut body = put.encoded.clone();
        let at = body.len() / 2;
        body[at] ^= 1;
        send(&server, put.request(Body::from(body))).await
    };

    assert_eq!(cut, StatusCode::BAD_REQUEST);
    assert_eq!(forged.status, StatusCode::FORBIDDEN, "{}", forged.text());
    assert_eq!(
        list_parts(&server, &id)
            .await
            .text()
            .matches("<Part>")
            .count(),
        0
    );
    assert_eq!(part_temps(&server, &id), 0);
    assert_eq!(server.uploads.held(), 0);
}

#[tokio::test]
async fn test_two_writers_of_one_part_number_leave_the_last_one_and_count_it_once() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let first = vec![1u8; 2 << 20];
    let second = "2".repeat(3 << 20);

    let (tx, slow) = part_through_channel(&server, &id, 1, first.len());
    tx.send(Bytes::copy_from_slice(&first[..1 << 20]))
        .await
        .unwrap();
    let fast = upload_part(&server, &id, 1, &second).await;
    tx.send(Bytes::copy_from_slice(&first[1 << 20..]))
        .await
        .unwrap();
    drop(tx);
    let slow = slow.await.unwrap();
    let parts = list_parts(&server, &id).await.text();

    assert_eq!(fast.status, StatusCode::OK);
    assert_eq!(slow, StatusCode::OK);
    assert_eq!(parts.matches("<Part>").count(), 1);
    assert!(
        parts.contains(&blake3::hash(&first).to_hex().to_string()),
        "{parts}"
    );
    assert_eq!(server.uploads.held(), first.len() as u64);
    assert_eq!(part_temps(&server, &id), 0);
}

#[tokio::test]
async fn test_part_room_taken_by_another_upload_gets_503() {
    let server =
        bucket_on(server_in(tempfile::tempdir().unwrap(), Config::default(), 3 << 20).await).await;
    let one = start_upload(&server).await;
    let two = start_upload(&server).await;
    let data = vec![3u8; 2 << 20];

    let (tx, first) = part_through_channel(&server, &one, 1, data.len());
    tx.send(Bytes::copy_from_slice(&data[..1 << 20]))
        .await
        .unwrap();
    let full = upload_part(&server, &two, 1, &"x".repeat(2 << 20)).await;
    tx.send(Bytes::copy_from_slice(&data[1 << 20..]))
        .await
        .unwrap();
    drop(tx);
    let first = first.await.unwrap();

    assert_eq!(full.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(full.xml("Code").unwrap(), "SlowDown");
    assert_eq!(first, StatusCode::OK);
    assert_eq!(server.uploads.held(), data.len() as u64);
}

#[tokio::test]
async fn test_crash_while_a_part_is_written_or_named_keeps_the_old_part() {
    for point in [Point::PartWrite, Point::PartRename] {
        let server = with_bucket().await;
        let id = start_upload(&server).await;
        let old = upload_part(&server, &id, 1, "old part").await;
        let old_etag = old.header("etag").unwrap().to_string();

        engine::sim::arm_crash(Some(point));
        let crashed = upload_part(&server, &id, 1, &"n".repeat(2 << 20)).await;
        engine::sim::arm_crash(None);
        // A kill leaves the temporary file that the drop of the writer removed here.
        let dir = server._dir.path().join("uploads").join(&id);
        std::fs::write(dir.join(".tmp.1.1"), b"half a part").unwrap();
        let server = restarted(server).await;
        let parts = list_parts(&server, &id).await.text();

        assert_eq!(
            crashed.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{point:?}"
        );
        assert_eq!(parts.matches("<Part>").count(), 1, "{point:?}");
        assert!(
            parts.contains(old_etag.trim_matches('"')),
            "{point:?}: {parts}"
        );
        assert_eq!(part_temps(&server, &id), 0, "{point:?}");
        assert_eq!(server.uploads.held(), "old part".len() as u64, "{point:?}");
    }
}

#[tokio::test]
async fn test_crash_after_a_part_renamed_and_before_the_old_one_went_keeps_the_newest() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    upload_part(&server, &id, 1, "old part").await;
    let new = "n".repeat(2 << 20);

    engine::sim::arm_crash(Some(Point::PartReplace));
    let crashed = upload_part(&server, &id, 1, &new).await;
    engine::sim::arm_crash(None);
    let server = restarted(server).await;
    let parts = list_parts(&server, &id).await.text();
    let new_etag = blake3::hash(new.as_bytes()).to_hex().to_string();
    let done = complete(&server, &id, &[(1, new_etag.as_str())]).await;
    let read = run(&server, call("GET", "/bkt/big")).await;

    assert_eq!(crashed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(parts.matches("<Part>").count(), 1, "{parts}");
    assert!(parts.contains(&new_etag), "{parts}");
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert!(read.body == new.as_bytes());
}

#[tokio::test]
async fn test_part_body_reaches_its_temporary_file_before_the_body_ends() {
    let server = with_bucket().await;
    let id = start_upload(&server).await;
    let data = vec![5u8; 2 << 20];

    let (tx, part) = part_through_channel(&server, &id, 1, data.len());
    tx.send(Bytes::copy_from_slice(&data[..1 << 20]))
        .await
        .unwrap();
    let dir = server._dir.path().join("uploads").join(&id);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let written = loop {
        let size: u64 = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp."))
            .map(|e| e.metadata().unwrap().len())
            .sum();
        if size >= 1 << 20 || std::time::Instant::now() > deadline {
            break size;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    tx.send(Bytes::copy_from_slice(&data[1 << 20..]))
        .await
        .unwrap();
    drop(tx);
    let part = part.await.unwrap();

    assert_eq!(written, 1 << 20);
    assert_eq!(part, StatusCode::OK);
}

fn copy_call(destination: &'static str, source: &'static str) -> Call<'static> {
    call("PUT", destination).header("x-amz-copy-source", source)
}

#[tokio::test]
async fn test_large_copy_streams_from_a_buffered_and_a_flushed_source() {
    let server = with_bucket().await;
    let data = large_object();
    sized_put(&server, "src", data.clone(), data.len(), None).await;

    let buffered = run(&server, copy_call("/bkt/from-buffer", "/bkt/src")).await;
    server.engine.flush().await.unwrap();
    let flushed = run(&server, copy_call("/bkt/from-remote", "/bkt/src")).await;
    let reads = [
        run(&server, call("GET", "/bkt/from-buffer")).await,
        run(&server, call("GET", "/bkt/from-remote")).await,
    ];

    for copy in [&buffered, &flushed] {
        assert_eq!(copy.status, StatusCode::OK, "{}", copy.text());
        assert!(
            copy.text()
                .contains(&blake3::hash(&data).to_hex().to_string())
        );
    }
    for read in reads {
        assert!(read.body == data);
    }
    assert_eq!(spool_files(&server), 0);
}

/// A copy by reference and a spool copy give the ETag of the source.
#[tokio::test]
async fn test_copy_by_reference_and_through_the_spool_give_one_etag() {
    let server = bucket_on(
        server_with(Config {
            copy_ref_min: 1,
            ..Config::default()
        })
        .await,
    )
    .await;
    let data = large_object();
    sized_put(&server, "src", data.clone(), data.len(), None).await;

    let spooled = run(&server, copy_call("/bkt/spooled", "/bkt/src")).await;
    server.engine.flush().await.unwrap();
    let referenced = run(&server, copy_call("/bkt/referenced", "/bkt/src")).await;
    let buffered = server.engine.buffered_bytes().await;
    let reads = [
        run(&server, call("GET", "/bkt/spooled")).await,
        run(&server, call("GET", "/bkt/referenced")).await,
    ];

    assert_eq!(buffered, 0, "the copy by reference went to the buffer");
    let etag = blake3::hash(&data).to_hex().to_string();
    for copy in [&spooled, &referenced] {
        assert_eq!(copy.status, StatusCode::OK, "{}", copy.text());
        assert!(copy.text().contains(&etag), "{}", copy.text());
    }
    for read in reads {
        assert!(read.body == data);
        assert_eq!(read.header("etag"), Some(format!("\"{etag}\"").as_str()));
    }
}

#[tokio::test]
async fn test_large_copy_onto_itself_replaces_the_metadata() {
    let server = with_bucket().await;
    let data = large_object();
    sized_put(&server, "self", data.clone(), data.len(), None).await;

    let copy = run(
        &server,
        copy_call("/bkt/self", "/bkt/self")
            .header("x-amz-metadata-directive", "REPLACE")
            .header("x-amz-meta-color", "blue"),
    )
    .await;
    let read = run(&server, call("GET", "/bkt/self")).await;

    assert_eq!(copy.status, StatusCode::OK, "{}", copy.text());
    assert!(read.body == data);
    assert_eq!(read.header("x-amz-meta-color"), Some("blue"));
}

#[tokio::test]
async fn test_copy_with_no_buffer_room_gets_503_and_writes_nothing() {
    let config = Config {
        buffer_limit: 6 << 20,
        ..Config::default()
    };
    let server = bucket_on(server_with(config).await).await;
    let data = vec![4u8; 4 << 20];
    sized_put(&server, "src", data.clone(), data.len(), None).await;

    let full = run(&server, copy_call("/bkt/dst", "/bkt/src")).await;
    let read = run(&server, call("GET", "/bkt/dst")).await;

    assert_eq!(
        full.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        full.text()
    );
    assert_eq!(full.xml("Code").unwrap(), "SlowDown");
    assert_eq!(read.status, StatusCode::NOT_FOUND);
    assert_eq!(spool_files(&server), 0);
}

#[tokio::test]
async fn test_copy_with_no_read_room_gets_503_after_the_first_piece_wait() {
    let server = small_budget().await;
    let data = vec![3u8; 2 * engine::READ_STEP];
    run(&server, call("PUT", "/bkt/src").body(data)).await;
    let mut held = Vec::new();
    for _ in 0..engine::MIN_READ_BUDGET as usize / engine::READ_STEP {
        held.push(get_response(&server, "/bkt/src").await);
    }

    let started = std::time::Instant::now();
    let full = run(&server, copy_call("/bkt/dst", "/bkt/src")).await;
    drop(held);
    let after = run(&server, copy_call("/bkt/dst", "/bkt/src")).await;

    assert_eq!(
        full.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        full.text()
    );
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert_eq!(after.status, StatusCode::OK, "{}", after.text());
}

/// Each copy holds descriptors while it waits: past MAX_COPIES, a copy gets 503 at once.
#[tokio::test]
async fn test_copy_over_the_copy_cap_gets_503_at_once() {
    let server = small_budget().await;
    let data = vec![3u8; 2 * engine::READ_STEP];
    run(&server, call("PUT", "/bkt/src").body(data)).await;
    let mut held = Vec::new();
    for _ in 0..engine::MIN_READ_BUDGET as usize / engine::READ_STEP {
        held.push(get_response(&server, "/bkt/src").await);
    }
    let waiting: Vec<_> = (0..s3api::MAX_COPIES)
        .map(|i| {
            let uri = format!("/bkt/dst{i}");
            let request = call("PUT", &uri)
                .header("x-amz-copy-source", "/bkt/src")
                .request();
            tokio::spawn(server.app.clone().oneshot(request))
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let id = initiate(&server).await;

    let started = std::time::Instant::now();
    let over = run(&server, copy_call("/bkt/over", "/bkt/src")).await;
    let over_part = part_copy(&server, &id, 1, None).await;

    for over in [&over, &over_part] {
        assert_eq!(
            over.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{}",
            over.text()
        );
        assert!(
            over.text().contains("copies run at once"),
            "{}",
            over.text()
        );
        assert!(over.header("retry-after").is_some());
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the copy waited"
    );
    drop(held);
    for copy in waiting {
        copy.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn test_crash_during_a_copy_leaves_no_spool_and_no_object() {
    let server = with_bucket().await;
    let data = large_object();
    sized_put(&server, "src", data.clone(), data.len(), None).await;

    engine::sim::arm_crash(Some(Point::CopyPiece));
    let crashed = run(&server, copy_call("/bkt/dst", "/bkt/src")).await;
    engine::sim::arm_crash(None);
    let read = run(&server, call("GET", "/bkt/dst")).await;

    assert_eq!(crashed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(read.status, StatusCode::NOT_FOUND);
    assert_eq!(spool_files(&server), 0);
}

/// A store over a synchronous database, as the KeyStore docs show it: the blocking lookup runs on
/// a blocking thread, so the deadline can still end the request.
struct BlockingKeys {
    delay: Duration,
}

#[async_trait::async_trait]
impl KeyStore for BlockingKeys {
    async fn secret(&self, access_key: &str) -> Result<Option<Secret>, KeyStoreError> {
        let (delay, access_key) = (self.delay, access_key.to_string());
        tokio::task::spawn_blocking(move || {
            std::thread::sleep(delay);
            (access_key == ACCESS).then(|| Secret::new(SECRET.to_string()))
        })
        .await
        .map_err(|e| KeyStoreError::new(e.to_string()))
    }
}

#[tokio::test]
async fn test_blocking_store_on_a_blocking_thread_gets_503_at_the_deadline() {
    let mut server = with_bucket().await;
    let mut config = S3Config::new(HashMap::new(), server._dir.path().join("uploads"));
    config.uploads = server.uploads.clone();
    config.keys = Arc::new(BlockingKeys {
        delay: s3api::KEY_STORE_DEADLINE + Duration::from_secs(1),
    });
    server.app = s3api::router(server.engine.clone(), config);

    let start = std::time::Instant::now();
    let reply = run(&server, call("GET", "/bkt?list-type=2")).await;

    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    let waited = start.elapsed();
    assert!(waited >= s3api::KEY_STORE_DEADLINE, "{waited:?}");
    assert!(
        waited < s3api::KEY_STORE_DEADLINE + Duration::from_secs(1),
        "{waited:?}"
    );
}

/// An UploadPartCopy of `src` into part `number` of upload `id` on `big`, of `range` or all of it.
async fn part_copy(server: &Server, id: &str, number: u32, range: Option<&str>) -> Reply {
    let uri = format!("/bkt/big?partNumber={number}&uploadId={id}");
    let mut copy = call("PUT", &uri).header("x-amz-copy-source", "/bkt/src");
    if let Some(range) = range {
        copy = copy.header("x-amz-copy-source-range", range);
    }
    run(server, copy).await
}

/// The bytes in the files of upload `id` that never got their name.
fn temp_part_bytes(server: &Server, id: &str) -> u64 {
    std::fs::read_dir(server._dir.path().join("uploads").join(id)).map_or(0, |entries| {
        entries
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".tmp."))
            .map(|entry| entry.metadata().map_or(0, |m| m.len()))
            .sum()
    })
}

/// A server with a flushed `src` of 3 read pieces and 17 bytes, and an upload on `big`.
async fn with_part_source() -> (Server, Vec<u8>, String) {
    let server = with_bucket().await;
    let data = large_object();
    sized_put(&server, "src", data.clone(), data.len(), None).await;
    server.engine.flush().await.unwrap();
    let id = initiate(&server).await;
    (server, data, id)
}

#[tokio::test]
async fn test_upload_part_copy_gives_the_etag_of_upload_part() {
    let (server, data, id) = with_part_source().await;
    let cut = 5 * 1024 * 1024;
    let first = format!("bytes=0-{}", cut - 1);
    let rest = format!("bytes={cut}-{}", data.len() - 1);

    let copied = [
        part_copy(&server, &id, 1, Some(&first)).await,
        part_copy(&server, &id, 2, Some(&rest)).await,
    ];
    let other = initiate(&server).await;
    let uploaded = run(
        &server,
        call("PUT", &format!("/bkt/big?partNumber=1&uploadId={other}")).body(&data[..cut]),
    )
    .await;
    let etags: Vec<String> = copied.iter().map(|c| c.xml("ETag").unwrap()).collect();
    let body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etags[0], etags[1]
    );
    let completed = run(
        &server,
        call("POST", &format!("/bkt/big?uploadId={id}")).body(body),
    )
    .await;
    let read = run(&server, call("GET", "/bkt/big")).await;

    for copy in &copied {
        assert_eq!(copy.status, StatusCode::OK, "{}", copy.text());
        assert!(copy.text().contains("<CopyPartResult"), "{}", copy.text());
    }
    assert_eq!(Some(etags[0].as_str()), uploaded.header("etag"));
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text());
    assert!(read.body == data);
}

#[tokio::test]
async fn test_upload_part_copy_with_no_range_copies_the_whole_source() {
    let (server, data, id) = with_part_source().await;

    let copied = part_copy(&server, &id, 1, None).await;

    assert_eq!(copied.status, StatusCode::OK, "{}", copied.text());
    let etag = format!("\"{}\"", blake3::hash(&data).to_hex());
    assert_eq!(copied.xml("ETag").unwrap(), etag);
}

/// The range must name bytes of the source: `bytes=first-last`, first <= last < size.
#[tokio::test]
async fn test_upload_part_copy_refuses_a_range_outside_the_source() {
    let (server, data, id) = with_part_source().await;
    let size = data.len();
    let ranges = [
        format!("bytes=0-{size}"),
        format!("bytes={size}-{size}"),
        "bytes=9-3".to_string(),
        "bytes=5-".to_string(),
        "bytes=-5".to_string(),
        "5-6".to_string(),
        "bytes=0-1,4-5".to_string(),
    ];

    for range in &ranges {
        let refused = part_copy(&server, &id, 1, Some(range)).await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{range}: {}",
            refused.text()
        );
        assert_eq!(refused.xml("Code").unwrap(), "InvalidArgument", "{range}");
    }
    let parts = run(&server, call("GET", &format!("/bkt/big?uploadId={id}"))).await;
    assert!(parts.xml("PartNumber").is_none(), "{}", parts.text());
    assert_eq!(part_temps(&server, &id), 0);
}

/// As for a CopyObject: no condition on the source is checked, so none is taken.
#[tokio::test]
async fn test_upload_part_copy_refuses_source_conditions() {
    let (server, _, id) = with_part_source().await;
    let uri = format!("/bkt/big?partNumber=1&uploadId={id}");

    let refused = run(
        &server,
        call("PUT", &uri)
            .header("x-amz-copy-source", "/bkt/src")
            .header("x-amz-copy-source-if-match", "\"x\""),
    )
    .await;

    assert_eq!(
        refused.status,
        StatusCode::NOT_IMPLEMENTED,
        "{}",
        refused.text()
    );
}

#[tokio::test]
async fn test_upload_part_copy_of_a_missing_source_or_upload_fails() {
    let (server, _, id) = with_part_source().await;
    let uri = format!("/bkt/big?partNumber=1&uploadId={id}");

    let no_source = run(
        &server,
        call("PUT", &uri).header("x-amz-copy-source", "/bkt/missing"),
    )
    .await;
    let no_upload = part_copy(&server, "0123456789abcdef0123456789abcdef", 1, None).await;

    assert_eq!(no_source.xml("Code").unwrap(), "NoSuchKey");
    assert_eq!(no_upload.xml("Code").unwrap(), "NoSuchUpload");
}

#[tokio::test]
async fn test_upload_part_copy_of_a_buffered_source_works() {
    let server = with_bucket().await;
    let data = large_object();
    sized_put(&server, "src", data.clone(), data.len(), None).await;
    let id = initiate(&server).await;

    let copied = part_copy(&server, &id, 1, Some("bytes=10-20")).await;

    assert_eq!(copied.status, StatusCode::OK, "{}", copied.text());
    let etag = format!("\"{}\"", blake3::hash(&data[10..21]).to_hex());
    assert_eq!(copied.xml("ETag").unwrap(), etag);
}

/// The copy reads the version of the source that it opened: an overwrite during the copy does
/// not change the part.
#[tokio::test]
async fn test_upload_part_copy_keeps_the_source_version_of_its_start() {
    let (server, data, id) = with_part_source().await;

    let (copied, _) = tokio::join!(part_copy(&server, &id, 1, None), async {
        while temp_part_bytes(&server, &id) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let newer = put(&server, "src", "newer").await;
        assert_eq!(newer.status, StatusCode::OK);
        server.engine.flush().await.unwrap();
    });

    assert_eq!(copied.status, StatusCode::OK, "{}", copied.text());
    let etag = format!("\"{}\"", blake3::hash(&data).to_hex());
    assert_eq!(copied.xml("ETag").unwrap(), etag);
}

/// A client that goes away drops the request: no part file, no part, and no room held.
#[tokio::test]
async fn test_upload_part_copy_that_the_client_drops_leaves_no_part() {
    let (server, _, id) = with_part_source().await;
    let held = server.uploads.held();
    let budget = server.engine.read_state().budget_free;

    tokio::select! {
        _ = part_copy(&server, &id, 1, None) => panic!("the copy ended before the drop"),
        _ = async {
            while temp_part_bytes(&server, &id) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        } => {}
    }
    let parts = run(&server, call("GET", &format!("/bkt/big?uploadId={id}"))).await;

    assert_eq!(part_temps(&server, &id), 0);
    assert!(parts.xml("PartNumber").is_none(), "{}", parts.text());
    assert_eq!(server.uploads.held(), held);
    assert_eq!(server.engine.read_state().budget_free, budget);
}

#[tokio::test]
async fn test_copy_header_that_is_not_ascii_is_refused() {
    let (server, _, id) = with_part_source().await;

    let copy = run(
        &server,
        call("PUT", "/bkt/dst").header("x-amz-copy-source", "/bkt/sré"),
    )
    .await;
    let directive = run(
        &server,
        call("PUT", "/bkt/dst")
            .header("x-amz-copy-source", "/bkt/src")
            .header("x-amz-metadata-directive", "REPLACEé"),
    )
    .await;
    let part = part_copy(&server, &id, 1, Some("bytes=0-é")).await;

    for (reply, what) in [(copy, "copy"), (directive, "directive"), (part, "part")] {
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{what}: {}",
            reply.text()
        );
    }
    assert_eq!(
        run(&server, call("HEAD", "/bkt/dst")).await.status,
        StatusCode::NOT_FOUND
    );
    let parts = run(&server, call("GET", &format!("/bkt/big?uploadId={id}"))).await;
    assert!(parts.xml("PartNumber").is_none(), "{}", parts.text());
}

#[tokio::test]
async fn test_upload_part_copy_with_no_room_in_the_read_budget_gets_503() {
    let server = small_budget().await;
    let data = vec![3u8; 2 * engine::READ_STEP];
    run(&server, call("PUT", "/bkt/src").body(data.clone())).await;
    server.engine.flush().await.unwrap();
    let id = initiate(&server).await;
    let parts_held = server.uploads.held();
    let mut held = Vec::new();
    for _ in 0..engine::MIN_READ_BUDGET as usize / engine::READ_STEP {
        let response = get_response(&server, "/bkt/src").await;
        assert_eq!(response.status(), StatusCode::OK);
        held.push(response);
    }

    let refused = part_copy(&server, &id, 1, None).await;
    drop(held);
    let parts = run(&server, call("GET", &format!("/bkt/big?uploadId={id}"))).await;

    assert_eq!(
        refused.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        refused.text()
    );
    assert_eq!(refused.xml("Code").unwrap(), "SlowDown");
    assert!(parts.xml("PartNumber").is_none(), "{}", parts.text());
    assert_eq!(part_temps(&server, &id), 0);
    assert_eq!(server.uploads.held(), parts_held);
}
