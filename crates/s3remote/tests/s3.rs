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
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
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
            engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
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

/// A ranged read that gets far more bytes than it asked fails, and reads at most a bounded body.
#[tokio::test]
async fn test_ranged_read_with_a_huge_answer_fails() {
    let (endpoint, _) = scripted(|_, _| {
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .body(Body::from(vec![0u8; 4 << 20]))
            .unwrap()
    })
    .await;
    let remote = S3Remote::new(config(&endpoint, "")).unwrap();

    let error = remote.get_range("packs/p", 0..10).await.unwrap_err();

    let message = error.to_string();
    assert!(message.contains("packs/p"), "{message}");
    assert!(
        message.contains("larger than the limit of 65546 bytes"),
        "{message}"
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

/// A raw server: for each connection, reads a little of the request, writes `reply`, closes.
async fn raw_server(reply: &'static [u8]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 256];
            let _ = stream.read(&mut head).await;
            let _ = stream.write_all(reply).await;
        }
    });
    format!("http://{address}")
}

#[tokio::test]
async fn test_reply_shorter_than_its_content_length_fails() {
    let endpoint = raw_server(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort").await;
    let remote = S3Remote::new(config(&endpoint, "")).unwrap();

    assert!(remote.get("log/x").await.is_err());
}

#[tokio::test]
async fn test_connection_closed_during_the_request_body_fails() {
    let endpoint = raw_server(b"").await;
    let remote = S3Remote::new(config(&endpoint, "")).unwrap();

    let body = Bytes::from(vec![7u8; 4 << 20]);
    assert!(remote.put("packs/p", body).await.is_err());
}

/// R2 answers 411 to a PUT with no Content-Length, and the node marker is an empty object.
#[tokio::test]
async fn test_empty_put_sends_a_content_length() {
    let app = Router::new().fallback(|request: Request| async move {
        match request.headers().get("content-length") {
            Some(_) => respond(StatusCode::OK, ""),
            None => respond(
                StatusCode::LENGTH_REQUIRED,
                "<Error><Code>MissingContentLength</Code><Message>no length</Message></Error>",
            ),
        }
    });
    let remote = S3Remote::new(config(&serve(app).await, "")).unwrap();

    remote.put("nodes/a", Bytes::new()).await.unwrap();
}

/// A server that answers every request with `status` and an S3 error `code`.
async fn always(status: StatusCode, code: &'static str) -> (String, Arc<AtomicU32>) {
    let count = Arc::new(AtomicU32::new(0));
    let app = Router::new()
        .fallback(move |State(count): State<Arc<AtomicU32>>| async move {
            count.fetch_add(1, Ordering::SeqCst);
            respond(
                status,
                &format!("<Error><Code>{code}</Code><Message>m</Message></Error>"),
            )
        })
        .with_state(count.clone());
    (serve(app).await, count)
}

#[tokio::test]
async fn test_server_errors_retry_to_the_limit_and_client_errors_do_not() {
    let cases = [
        (StatusCode::INTERNAL_SERVER_ERROR, "InternalError", 3),
        (StatusCode::BAD_GATEWAY, "BadGateway", 3),
        (StatusCode::SERVICE_UNAVAILABLE, "SlowDown", 3),
        (StatusCode::TOO_MANY_REQUESTS, "TooManyRequests", 3),
        (StatusCode::BAD_REQUEST, "InvalidRequest", 1),
        (StatusCode::FORBIDDEN, "AccessDenied", 1),
        (StatusCode::NOT_FOUND, "NoSuchBucket", 1),
    ];

    for (status, code, attempts) in cases {
        let (endpoint, count) = always(status, code).await;
        let remote = S3Remote::new(config(&endpoint, "")).unwrap();

        let result = remote.put("packs/a", Bytes::from("x")).await;

        assert!(
            matches!(result, Err(RemoteError::Service { status: s, code: ref c, .. })
                if s == status.as_u16() && c == code),
            "{status}: {result:?}"
        );
        assert_eq!(count.load(Ordering::SeqCst), attempts, "{status}");
    }
}

/// A connection the server closes at once is retried, then fails as I/O.
#[tokio::test]
async fn test_dropped_connections_retry_to_the_limit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let count = Arc::new(AtomicU32::new(0));
    let accepted = count.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            drop(socket);
        }
    });
    let remote = S3Remote::new(config(&endpoint, "")).unwrap();

    let result = remote.get("packs/a").await;

    assert!(matches!(result, Err(RemoteError::Io(_))), "{result:?}");
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

/// The operator must see a clock problem by its S3 code.
#[tokio::test]
async fn test_clock_skew_error_names_its_code_and_is_not_retried() {
    let (endpoint, count) = always(StatusCode::FORBIDDEN, "RequestTimeTooSkewed").await;
    let remote = S3Remote::new(config(&endpoint, "")).unwrap();

    let error = remote.get("packs/a").await.unwrap_err();

    assert!(
        error.to_string().contains("RequestTimeTooSkewed"),
        "{error}"
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

/// A redirect would send the signed request to another host: the client does not follow it.
#[tokio::test]
async fn test_redirect_is_an_error_and_is_not_followed() {
    let (elsewhere, reached) = always(StatusCode::OK, "").await;
    let location = format!("{elsewhere}/bkt/packs/a");
    for status in [
        StatusCode::MOVED_PERMANENTLY,
        StatusCode::TEMPORARY_REDIRECT,
    ] {
        let target = location.clone();
        let app = Router::new().fallback(move || {
            let target = target.clone();
            async move {
                Response::builder()
                    .status(status)
                    .header("location", target)
                    .body(Body::empty())
                    .unwrap()
            }
        });
        let remote = S3Remote::new(config(&serve(app).await, "")).unwrap();

        let get = remote.get("packs/a").await;
        let put = remote.put("packs/a", Bytes::from("x")).await;

        assert!(
            matches!(get, Err(RemoteError::Service { status: s, .. }) if s == status.as_u16()),
            "{get:?}"
        );
        assert!(put.is_err(), "{put:?}");
    }
    assert_eq!(
        reached.load(Ordering::SeqCst),
        0,
        "no request reaches the other host"
    );
}

/// Keys that need URI encoding: the signature matches, and the key comes back the same.
/// A key with an empty segment, as one that ends with `/`, never leaves the client.
#[tokio::test]
async fn test_keys_that_need_encoding_round_trip() {
    let server = server().await;
    let remote = S3Remote::new(config(&server.endpoint, "p re+fix/")).unwrap();
    let keys = [
        "packs/with space",
        "packs/plus+sign",
        "packs/per%cent",
        "packs/%2F not a slash",
        "packs/\u{e9}t\u{e9}/\u{1f600}",
        "packs/a~b*c'd(e)!",
    ];

    for key in keys {
        remote.put(key, Bytes::from(key.to_string())).await.unwrap();
    }

    for key in keys {
        assert_eq!(
            remote.get(key).await.unwrap().unwrap(),
            key.as_bytes(),
            "{key}"
        );
    }
    let mut listed = remote.list("packs/").await.unwrap();
    listed.sort();
    let mut expected: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    expected.sort();
    assert_eq!(listed, expected);
    assert!(matches!(
        remote.put("packs/ends/", Bytes::new()).await,
        Err(RemoteError::InvalidKey(_))
    ));
}

/// The client reads no ETag and no request ID on a put: odd values change nothing.
#[tokio::test]
async fn test_odd_etag_and_request_id_on_a_put_change_nothing() {
    let app = Router::new().fallback(|| async {
        Response::builder()
            .status(StatusCode::OK)
            .header("etag", "\"not-the-md5\"")
            .header("x-amz-request-id", "not <an> id")
            .body(Body::empty())
            .unwrap()
    });
    let remote = S3Remote::new(config(&serve(app).await, "")).unwrap();

    remote.put("packs/a", Bytes::from("x")).await.unwrap();
}

/// A server that sends a full head, then the body one byte per second, or a chunked body with no end.
async fn dribbling(chunked: bool) -> String {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut request).await;
                let head = match chunked {
                    true => "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n1\r\nx\r\n",
                    false => "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n",
                };
                if socket.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let more: &[u8] = if chunked { b"1\r\nx\r\n" } else { b"x" };
                    if socket.write_all(more).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    endpoint
}

#[tokio::test]
async fn test_slow_and_endless_bodies_hit_the_attempt_timeout() {
    for chunked in [false, true] {
        let mut config = config(&dribbling(chunked).await, "");
        config.retry.attempt_timeout = Duration::from_millis(500);
        config.retry.total = Duration::from_secs(3);
        let remote = S3Remote::new(config).unwrap();
        let start = Instant::now();

        let result = remote.get("packs/a").await;

        assert!(matches!(result, Err(RemoteError::Io(_))), "{result:?}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }
}

/// A burst of reads shares a capped number of connections.
#[tokio::test(flavor = "multi_thread")]
async fn test_a_burst_of_reads_opens_a_capped_number_of_connections() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicU32::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|_| async {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    Ok::<_, std::convert::Infallible>(Response::new(Body::from("data")))
                });
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .await
                    .ok();
            });
        }
    });
    let remote = Arc::new(S3Remote::new(config(&endpoint, "")).unwrap());

    let reads: Vec<_> = (0..1000)
        .map(|_| {
            let remote = remote.clone();
            tokio::spawn(async move { remote.get("packs/a").await })
        })
        .collect();
    for read in reads {
        assert_eq!(read.await.unwrap().unwrap().unwrap(), "data");
    }

    let opened = accepted.load(Ordering::SeqCst) as usize;
    assert!(opened <= s3remote::MAX_IN_FLIGHT, "{opened} connections");
}

#[tokio::test]
async fn test_empty_credentials_are_refused_at_start() {
    for (access, secret) in [("", "secret"), ("key", ""), (" ", "secret")] {
        let mut config = config("http://127.0.0.1:1", "");
        config.access_key = access.into();
        config.secret_key = secret.into();

        let error = S3Remote::new(config).err().expect("refused");

        assert!(error.to_string().contains("must not be empty"), "{error}");
    }
}

/// A Windsock S3 server that waits `delay` before each answer, and counts the calls it serves at once.
async fn slow_server(delay: Duration) -> (Server, Arc<AtomicU32>) {
    let base = server().await;
    let busy = Arc::new(AtomicU32::new(0));
    let peak = Arc::new(AtomicU32::new(0));
    let (now, most) = (busy.clone(), peak.clone());
    let proxy = Router::new().fallback(move |request: Request| {
        let (now, most) = (now.clone(), most.clone());
        let target = base.endpoint.clone();
        async move {
            let n = now.fetch_add(1, Ordering::SeqCst) + 1;
            most.fetch_max(n, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            let reply = forward(&target, request).await;
            now.fetch_sub(1, Ordering::SeqCst);
            reply
        }
    });
    let endpoint = serve(proxy).await;
    (
        Server {
            _dir: base._dir,
            endpoint,
        },
        peak,
    )
}

/// Sends `request` on to `target` and returns its answer.
async fn forward(target: &str, request: Request) -> Response<Body> {
    use http_body_util::BodyExt;

    let (mut parts, body) = request.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let path = parts.uri.path_and_query().unwrap().as_str().to_string();
    parts.uri = format!("{target}{path}").parse().unwrap();
    let request = hyper::Request::from_parts(parts, http_body_util::Full::new(body));
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();
    let reply = client.request(request).await.unwrap();
    let (parts, body) = reply.into_parts();
    Response::from_parts(parts, Body::new(body))
}

/// With 65 slow reads in flight, a put is acknowledged from the buffer, and the 65th read waits.
#[tokio::test(flavor = "multi_thread")]
async fn test_slow_remote_with_a_full_cap_still_acknowledges_puts() {
    let (slow, peak) = slow_server(Duration::from_millis(200)).await;
    let remote = Arc::new(S3Remote::new(config(&slow.endpoint, "")).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[2u8; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        Config::default(),
    )
    .await
    .unwrap();
    engine.create_bucket("bkt2", None).await.unwrap();
    peak.store(0, Ordering::SeqCst);

    let start = Instant::now();
    let reads: Vec<_> = (0..s3remote::MAX_IN_FLIGHT + 1)
        .map(|_| {
            let remote = remote.clone();
            tokio::spawn(async move { remote.get("packs/none").await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let put_start = Instant::now();
    engine
        .put(
            "bkt2",
            "k",
            Bytes::from("v"),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
    let put = put_start.elapsed();
    for read in reads {
        assert_eq!(read.await.unwrap().unwrap(), None);
    }

    assert!(put < Duration::from_millis(150), "put took {put:?}");
    assert!(
        start.elapsed() >= Duration::from_millis(400),
        "the 65th read waits for a slot"
    );
    assert_eq!(
        peak.load(Ordering::SeqCst) as usize,
        s3remote::MAX_IN_FLIGHT
    );
}

/// A range past the end reports the object size: the snapshot load uses it as a size probe.
#[tokio::test]
async fn test_range_past_any_object_reports_its_size() {
    let server = server().await;
    let remote = S3Remote::new(config(&server.endpoint, "")).unwrap();
    remote
        .put("snapshots/a", Bytes::from(vec![7; 1234]))
        .await
        .unwrap();

    let result = remote
        .get_range("snapshots/a", u64::MAX - 1..u64::MAX)
        .await;

    assert!(
        matches!(result, Err(RemoteError::InvalidRange { len: 1234, .. })),
        "{result:?}"
    );
    assert!(
        remote
            .get_range("snapshots/none", u64::MAX - 1..u64::MAX)
            .await
            .unwrap()
            .is_none()
    );
}
