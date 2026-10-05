//! The daemon as a process: init, run, S3 calls, stop, restart.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use s3proto::sigv4;
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_windsockd");

/// `windsockd init`, then a free port instead of 9000.
fn init() -> (TempDir, PathBuf, (String, String)) {
    let dir = tempfile::tempdir().unwrap();
    let status = Command::new(BIN)
        .arg("init")
        .arg(dir.path())
        .status()
        .unwrap();
    assert!(status.success());

    let path = dir.path().join("windsock.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("127.0.0.1:9000", "127.0.0.1:0");
    std::fs::write(&path, &text).unwrap();
    let value = |name: &str| {
        let line = text.lines().find(|l| l.starts_with(name)).unwrap();
        line.split('"').nth(1).unwrap().to_string()
    };

    (dir, path, (value("access_key"), value("secret_key")))
}

struct Daemon {
    child: Child,
    address: String,
}

/// Starts `windsockd run` and waits for its listening address in the log.
fn start(config: &Path) -> Daemon {
    let mut child = Command::new(BIN)
        .arg("run")
        .arg(config)
        .env("RUST_LOG", "info")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let stderr = child.stderr.take().unwrap();
    let (found, address) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if let Some(at) = line.find("address=") {
                let text: String = line[at + 8..]
                    .chars()
                    .take_while(|c| !c.is_whitespace())
                    .collect();
                found.send(text).ok();
            }
        }
    });

    let address = address
        .recv_timeout(Duration::from_secs(30))
        .expect("the daemon logs its address");
    Daemon { child, address }
}

impl Daemon {
    /// SIGTERM, then the exit status.
    fn stop(mut self) -> bool {
        let pid = self.child.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-TERM", &pid])
                .status()
                .unwrap()
                .success()
        );

        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.success();
            }
            assert!(Instant::now() < deadline, "the daemon did not stop");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// SIGKILL: no flush, as a crash.
    fn crash(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

/// A signed request to the daemon.
async fn call(
    daemon: &Daemon,
    keys: &(String, String),
    method: &str,
    path: &str,
    body: &str,
) -> (StatusCode, String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp = sigv4::timestamp(now);
    let payload_hash = sigv4::sha256_hex(body.as_bytes());
    let headers = vec![
        ("host".to_string(), daemon.address.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), timestamp.clone()),
    ];
    let (authorization, _) = sigv4::sign(
        &sigv4::Request {
            method,
            path,
            query: "",
            headers: &headers,
            payload_hash: &payload_hash,
        },
        &keys.0,
        &keys.1,
        &timestamp,
        "us-east-1",
    );

    let mut request = Request::builder()
        .method(method)
        .uri(format!("http://{}{path}", daemon.address));
    for (name, value) in &headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let request = request
        .header("authorization", authorization)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let response = client.request(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn remote_entries(dir: &TempDir) -> usize {
    let log = dir.path().join("remote").join("log");
    let Ok(nodes) = std::fs::read_dir(log) else {
        return 0;
    };
    nodes
        .map(|node| std::fs::read_dir(node.unwrap().path()).unwrap().count())
        .sum()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_object_survives_a_stop_and_a_restart() {
    let (dir, config, keys) = init();
    let daemon = start(&config);

    assert_eq!(
        call(&daemon, &keys, "PUT", "/demo", "").await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(&daemon, &keys, "PUT", "/demo/hello.txt", "hello")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&daemon, &keys, "GET", "/demo/hello.txt", "").await.1,
        "hello"
    );
    assert!(daemon.stop(), "a clean stop exits with success");
    assert!(
        remote_entries(&dir) > 0,
        "the stop flushed the buffer to the remote"
    );

    let daemon = start(&config);
    let (status, body) = call(&daemon, &keys, "GET", "/demo/hello.txt", "").await;

    assert_eq!((status, body.as_str()), (StatusCode::OK, "hello"));
    assert!(daemon.stop());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_acknowledged_write_survives_a_crash() {
    let (_dir, config, keys) = init();
    let daemon = start(&config);
    call(&daemon, &keys, "PUT", "/demo", "").await;

    assert_eq!(
        call(&daemon, &keys, "PUT", "/demo/k", "acked").await.0,
        StatusCode::OK
    );
    daemon.crash();
    let daemon = start(&config);

    assert_eq!(call(&daemon, &keys, "GET", "/demo/k", "").await.1, "acked");
    assert!(daemon.stop());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wrong_key_is_refused() {
    let (_dir, config, _) = init();
    let daemon = start(&config);

    let (status, body) = call(&daemon, &("WSNOBODY".into(), "x".into()), "GET", "/", "").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("InvalidAccessKeyId"));
    assert!(daemon.stop());
}

#[test]
fn test_init_does_not_overwrite_a_configuration() {
    let (dir, _, _) = init();

    let again = Command::new(BIN)
        .arg("init")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(!again.status.success());
}
