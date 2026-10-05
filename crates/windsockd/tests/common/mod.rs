//! Helpers to run `windsockd` as a process and talk S3 to it.

#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderMap;
use hyper::{Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use s3proto::sigv4;

pub const BIN: &str = env!("CARGO_BIN_EXE_windsockd");

/// The key pair of the configurations that [`cluster_config`] writes.
pub fn test_keys() -> (String, String) {
    ("WSTESTKEY".to_string(), "test-secret".to_string())
}

pub struct Daemon {
    child: Child,
    pub address: String,
    lines: Receiver<String>,
}

/// Starts `windsockd run` and waits for its listening address in the log.
pub fn start(config: &Path, log: &str) -> Daemon {
    let mut child = Command::new(BIN)
        .arg("run")
        .arg(config)
        .env("RUST_LOG", log)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let stderr = child.stderr.take().unwrap();
    let (send, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if send.send(line).is_err() {
                return;
            }
        }
    });

    let mut daemon = Daemon {
        child,
        address: String::new(),
        lines,
    };
    let line = daemon
        .wait_for("address=", Duration::from_secs(30))
        .expect("the daemon logs its address");
    let at = line.find("address=").unwrap() + "address=".len();
    daemon.address = line[at..].split_whitespace().next().unwrap().to_string();
    daemon
}

impl Daemon {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The next log line that contains `needle`, or `None` after `limit`.
    pub fn wait_for(&mut self, needle: &str, limit: Duration) -> Option<String> {
        let deadline = Instant::now() + limit;

        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return Some(line),
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// SIGTERM, then the exit status.
    pub fn stop(mut self) -> bool {
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
    pub fn crash(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.child.kill().ok();
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn etag(&self) -> Option<String> {
        self.headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }
}

/// A signed request to a daemon.
pub async fn call(
    daemon: &Daemon,
    keys: &(String, String),
    method: &str,
    path: &str,
    body: &[u8],
) -> Reply {
    let (path_only, query) = path.split_once('?').unwrap_or((path, ""));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp = sigv4::timestamp(now);
    let payload_hash = sigv4::sha256_hex(body);
    let headers = vec![
        ("host".to_string(), daemon.address.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), timestamp.clone()),
    ];
    let (authorization, _) = sigv4::sign(
        &sigv4::Request {
            method,
            path: path_only,
            query,
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
        .body(Full::new(Bytes::copy_from_slice(body)))
        .unwrap();

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let response = client.request(request).await.unwrap();
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

/// A configuration for one proxy of a cluster on the local directory `remote`.
/// `gc` is the `[gc]` table, as TOML lines.
pub fn cluster_config(dir: &Path, remote: &Path, flush_delay_ms: u64, gc: &str) -> PathBuf {
    let (access, secret) = test_keys();
    let text = format!(
        r#"data_dir = "{data}"
listen = "127.0.0.1:0"
sync_interval_secs = 1

[remote]
type = "dir"
path = "{remote}"

[[keys]]
access_key = "{access}"
secret_key = "{secret}"

[engine]
flush_delay_ms = {flush_delay_ms}

[gc]
{gc}
"#,
        data = dir.join("data").display(),
        remote = remote.display(),
    );
    let path = dir.join("windsock.toml");
    std::fs::write(&path, text).unwrap();
    path
}

/// The seqs of every chain in a local directory remote, in order.
pub fn chains(remote: &Path) -> Vec<Vec<u64>> {
    let Ok(nodes) = std::fs::read_dir(remote.join("log")) else {
        return Vec::new();
    };

    nodes
        .map(|node| {
            let mut seqs: Vec<u64> = std::fs::read_dir(node.unwrap().path())
                .unwrap()
                .filter_map(|e| e.unwrap().file_name().to_str()?.parse().ok())
                .collect();
            seqs.sort_unstable();
            seqs
        })
        .collect()
}

/// Files under `remote/<dir>`.
pub fn count(remote: &Path, dir: &str) -> usize {
    std::fs::read_dir(remote.join(dir)).map_or(0, |entries| entries.count())
}
