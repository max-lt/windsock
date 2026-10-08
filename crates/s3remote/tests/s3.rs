//! The S3 remote against a local Windsock S3 server, and against scripted servers for retries.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Response, StatusCode};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, WriteMode};
use remote::{DirRemote, Remote, RemoteError};
use s3remote::{Retry, S3Config, S3Remote};
use tempfile::TempDir;

const ACCESS: &str = "TESTKEY";
const SECRET: &str = "testsecret";

/// A Windsock S3 server on a free local port, with the bucket `bkt`.
struct Server {
    _dir: TempDir,
    endpoint: String,
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
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
    engine.create_bucket("bkt", None).await.unwrap();
    let keys = HashMap::from([(ACCESS.to_string(), SECRET.to_string())]);
    let app = s3api::router(
        Arc::new(engine),
        s3api::S3Config::new(keys, dir.path().join("uploads")),
    );

    Server {
        endpoint: serve(app).await,
        _dir: dir,
    }
}

fn quick_retry() -> Retry {
    Retry {
        attempts: 3,
        first_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
        attempt_timeout: Duration::from_secs(5),
        total: Duration::from_secs(10),
    }
}

fn config(endpoint: &str, prefix: &str) -> S3Config {
    S3Config {
        endpoint: endpoint.to_string(),
        bucket: "bkt".into(),
        prefix: prefix.into(),
        region: "us-east-1".into(),
        access_key: ACCESS.into(),
        secret_key: SECRET.into(),
        retry: quick_retry(),
        ca_pem: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_s3_remote_meets_the_contract() {
    let server = server().await;
    let next = AtomicU32::new(0);

    remote::contract::check(|| {
        let prefix = format!("check-{}/", next.fetch_add(1, Ordering::SeqCst));
        let remote = S3Remote::new(config(&server.endpoint, &prefix)).unwrap();
        async move { remote }
    })
    .await;
}

/// The contract against another S3 implementation. Set S3REMOTE_TEST_ENDPOINT, _BUCKET,
/// _ACCESS_KEY and _SECRET_KEY, then run with `--ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_s3_remote_meets_the_contract_on_an_external_store() {
    let var = |name: &str| std::env::var(format!("S3REMOTE_TEST_{name}")).unwrap();
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let next = AtomicU32::new(0);

    remote::contract::check(|| {
        let config = S3Config {
            endpoint: var("ENDPOINT"),
            bucket: var("BUCKET"),
            prefix: format!("contract-{run}-{}/", next.fetch_add(1, Ordering::SeqCst)),
            region: std::env::var("S3REMOTE_TEST_REGION").unwrap_or("us-east-1".into()),
            access_key: var("ACCESS_KEY"),
            secret_key: var("SECRET_KEY"),
            retry: Retry::default(),
            ca_pem: None,
        };
        let remote = S3Remote::new(config).unwrap();
        async move { remote }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_probe_accepts_a_store_that_refuses_a_second_create() {
    let server = server().await;
    let remote = S3Remote::new(config(&server.endpoint, "probe-ok/")).unwrap();

    assert_eq!(
        remote::probe(&remote).await.unwrap(),
        remote::Verdict::Conformant
    );
}

/// A store that answers 200 to every PUT, so a second create overwrites the first.
#[tokio::test]
async fn test_probe_refuses_a_store_that_overwrites_on_create() {
    let (endpoint, _) = scripted(|_, _| respond(StatusCode::OK, "")).await;
    let remote = S3Remote::new(config(&endpoint, "")).unwrap();

    let verdict = remote::probe(&remote).await.unwrap();

    assert!(
        matches!(verdict, remote::Verdict::Violation(reason) if reason.contains("If-None-Match"))
    );
}

/// An engine whose remote is an S3 bucket served by another engine.
#[tokio::test(flavor = "multi_thread")]
async fn test_engine_runs_on_an_s3_remote() {
    let server = server().await;
    let remote = Arc::new(S3Remote::new(config(&server.endpoint, "windsock/")).unwrap());
    let open = |seed: u8, dir: &TempDir| {
        Engine::open(
            dir.path().to_path_buf(),
            remote.clone(),
            SigningKey::from_bytes(&[seed; 32]),
            Config::default(),
        )
    };
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let data: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();

    let a = open(2, &a_dir).await.unwrap();
    a.create_bucket("inner", None).await.unwrap();
    a.put(
        "inner",
        "k",
        Bytes::from(data.clone()),
        BTreeMap::new(),
        WriteMode::Overwrite,
    )
    .await
    .unwrap();
    a.flush().await.unwrap();
    let b = open(3, &b_dir).await.unwrap();

    assert_eq!(b.get("inner", "k", None).await.unwrap().data, data);
    assert_eq!(
        b.get("inner", "k", Some(1000..1010)).await.unwrap().data,
        data[1000..1010]
    );
    assert!(!remote.list("log/").await.unwrap().is_empty());
}

#[tokio::test]
async fn test_wrong_secret_is_a_service_error() {
    let server = server().await;
    let mut wrong = config(&server.endpoint, "");
    wrong.secret_key = "other".into();
    let remote = S3Remote::new(wrong).unwrap();

    let result = remote.get("packs/a").await;

    assert!(matches!(
        result,
        Err(RemoteError::Service { status: 403, ref code, .. }) if code == "SignatureDoesNotMatch"
    ));
}

#[tokio::test]
async fn test_missing_bucket_is_a_service_error() {
    let server = server().await;
    let mut missing = config(&server.endpoint, "");
    missing.bucket = "nope".into();
    let remote = S3Remote::new(missing).unwrap();

    let result = remote.list("").await;

    assert!(matches!(
        result,
        Err(RemoteError::Service { status: 404, ref code, .. }) if code == "NoSuchBucket"
    ));
}

// ----------------------------------------------------------------------
// Scripted servers
// ----------------------------------------------------------------------

/// Answers request `n` (from 0) with `script(n)`.
async fn scripted(script: fn(u32, &str) -> Response<Body>) -> (String, Arc<AtomicU32>) {
    let count = Arc::new(AtomicU32::new(0));
    let app = Router::new()
        .fallback(
            move |State(count): State<Arc<AtomicU32>>, request: Request| async move {
                let n = count.fetch_add(1, Ordering::SeqCst);
                script(n, request.uri().query().unwrap_or(""))
            },
        )
        .with_state(count.clone());
    (serve(app).await, count)
}

fn respond(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn slow_down() -> Response<Body> {
    respond(
        StatusCode::SERVICE_UNAVAILABLE,
        "<Error><Code>SlowDown</Code><Message>wait</Message></Error>",
    )
}

#[tokio::test]
async fn test_transient_errors_are_retried() {
    let (endpoint, count) = scripted(|n, _| match n {
        0 | 1 => slow_down(),
        _ => respond(StatusCode::OK, "data"),
    })
    .await;
    let remote = S3Remote::new(config(&endpoint, "")).unwrap();

    assert_eq!(remote.get("packs/a").await.unwrap().unwrap(), "data");
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn test_retries_stop_after_the_last_attempt() {
    let (endpoint, count) = scripted(|_, _| slow_down()).await;
    let remote = S3Remote::new(config(&endpoint, "")).unwrap();

    let result = remote.put("packs/a", Bytes::from("x")).await;

    assert!(matches!(
        result,
        Err(RemoteError::Service { status: 503, ref code, .. }) if code == "SlowDown"
    ));
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn test_client_errors_are_not_retried() {
    let (endpoint, count) = scripted(|_, _| {
        respond(
            StatusCode::FORBIDDEN,
            "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
        )
    })
    .await;
    let remote = S3Remote::new(config(&endpoint, "")).unwrap();

    assert!(remote.get("packs/a").await.is_err());
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_a_silent_server_hits_the_time_limit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    // Accepts connections and never answers.
    tokio::spawn(async move {
        let mut open = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            open.push(socket);
        }
    });
    let mut slow = config(&endpoint, "");
    slow.retry = Retry {
        attempts: 10,
        attempt_timeout: Duration::from_millis(100),
        total: Duration::from_millis(400),
        ..quick_retry()
    };
    let remote = S3Remote::new(slow).unwrap();
    let start = Instant::now();

    let result = remote.get("packs/a").await;

    assert!(
        matches!(result, Err(RemoteError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut)
    );
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn test_list_follows_continuation_tokens() {
    let (endpoint, count) = scripted(|_, query| {
        let page = |keys: &[&str], next: Option<&str>| {
            let contents: String = keys.iter().map(|k| format!("<Contents><Key>{k}</Key></Contents>")).collect();
            let next = next.map(|t| format!("<NextContinuationToken>{t}</NextContinuationToken>")).unwrap_or_default();
            let truncated = !next.is_empty();
            respond(
                StatusCode::OK,
                &format!("<ListBucketResult><IsTruncated>{truncated}</IsTruncated>{next}{contents}</ListBucketResult>"),
            )
        };
        if query.contains("continuation-token=second") {
            page(&["p/log/c"], None)
        } else {
            page(&["p/log/a", "p/log/b"], Some("second"))
        }
    })
    .await;
    let remote = S3Remote::new(config(&endpoint, "p/")).unwrap();

    assert_eq!(
        remote.list("log/").await.unwrap(),
        ["log/a", "log/b", "log/c"]
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
}
