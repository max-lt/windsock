//! Bench support: a counting remote, a signed S3 client, an in-process server, statistics.

use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Engine, EngineError};
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use remote::{DirRemote, Remote, RemoteError, Sweep};
use s3proto::sigv4;

pub const ACCESS: &str = "BENCHKEY";
pub const SECRET: &str = "bench-secret";

/// Remote operations, by kind.
#[derive(Default)]
pub struct Counts {
    pub put: AtomicU64,
    pub create: AtomicU64,
    pub get: AtomicU64,
    pub get_range: AtomicU64,
    pub list: AtomicU64,
    pub delete: AtomicU64,
}

impl Counts {
    /// Writes to the remote: what an S3 provider bills as class A.
    pub fn writes(&self) -> u64 {
        self.put.load(Ordering::Relaxed) + self.create.load(Ordering::Relaxed)
    }

    pub fn reads(&self) -> u64 {
        self.get.load(Ordering::Relaxed) + self.get_range.load(Ordering::Relaxed)
    }
}

/// A DirRemote that counts every call.
pub struct CountingRemote {
    inner: DirRemote,
    pub counts: Counts,
}

impl CountingRemote {
    pub fn open(path: &Path) -> Result<Self, RemoteError> {
        Ok(Self {
            inner: DirRemote::open(path)?,
            counts: Counts::default(),
        })
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

#[async_trait::async_trait]
impl Remote for CountingRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        bump(&self.counts.put);
        self.inner.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        bump(&self.counts.create);
        self.inner.create(key, data).await
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        bump(&self.counts.get);
        self.inner.get(key).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        bump(&self.counts.get_range);
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        bump(&self.counts.list);
        self.inner.list(prefix).await
    }
}

#[async_trait::async_trait]
impl Sweep for CountingRemote {
    async fn delete(&self, key: &str) -> Result<(), RemoteError> {
        bump(&self.counts.delete);
        self.inner.delete(key).await
    }
}

/// An engine behind the S3 router on a free local port.
pub struct Server {
    pub engine: Arc<Engine<CountingRemote>>,
    pub address: String,
    flusher: tokio::task::JoinHandle<()>,
    serve: tokio::task::JoinHandle<()>,
}

impl Server {
    pub async fn start(
        engine_dir: &Path,
        remote: Arc<CountingRemote>,
        seed: u8,
        config: engine::Config,
    ) -> Result<Self, EngineError> {
        let engine = Engine::open(
            engine_dir,
            remote,
            SigningKey::from_bytes(&[seed; 32]),
            config,
        )
        .await?;
        let engine = Arc::new(engine);
        let flusher = engine.spawn_flusher();
        let keys = [(ACCESS.to_string(), SECRET.to_string())].into();
        let router = s3api::router(
            engine.clone(),
            s3api::S3Config::new(keys, engine_dir.join("uploads")),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let serve = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        Ok(Self {
            engine,
            address,
            flusher,
            serve,
        })
    }

    pub fn stop(self) -> Arc<Engine<CountingRemote>> {
        self.flusher.abort();
        self.serve.abort();
        self.engine
    }
}

/// An S3 client that signs the body hash, as boto3 does over plain HTTP.
#[derive(Clone)]
pub struct S3Client {
    client: Client<HttpConnector, Full<Bytes>>,
    address: String,
}

impl S3Client {
    pub fn new(address: &str) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            address: address.to_string(),
        }
    }

    pub async fn send(
        &self,
        method: &str,
        path: &str,
        body: Bytes,
    ) -> Result<(StatusCode, usize), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let timestamp = sigv4::timestamp(now);
        let payload_hash = sigv4::sha256_hex(&body);
        let headers = vec![
            ("host".to_string(), self.address.clone()),
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
            ACCESS,
            SECRET,
            &timestamp,
            "us-east-1",
        );

        let mut request = Request::builder()
            .method(method)
            .uri(format!("http://{}{path}", self.address));
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let request = request
            .header("authorization", authorization)
            .body(Full::new(body))
            .map_err(|e| e.to_string())?;

        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok((status, body.len()))
    }
}

/// Incompressible bytes, the same for the same seed.
pub fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The `p`-th percentile (0 to 100) of sorted samples.
pub fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

/// The median, the lowest and the highest of several runs.
pub fn spread(mut values: Vec<f64>) -> (f64, f64, f64) {
    values.sort_by(f64::total_cmp);
    let median = values[values.len() / 2];
    (median, values[0], values[values.len() - 1])
}

/// The 1, 5 and 15 minute load averages.
pub fn load_average() -> String {
    let output = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .trim()
            .trim_matches(|c| c == '{' || c == '}')
            .trim()
            .to_string(),
        _ => std::fs::read_to_string("/proc/loadavg")
            .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
            .unwrap_or_else(|_| "unknown".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percentile_and_spread() {
        let samples: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();

        assert_eq!(percentile(&samples, 50.0), Duration::from_millis(51));
        assert_eq!(percentile(&samples, 99.0), Duration::from_millis(99));
        assert_eq!(percentile(&[], 50.0), Duration::ZERO);
        assert_eq!(spread(vec![3.0, 1.0, 2.0]), (2.0, 1.0, 3.0));
    }

    #[test]
    fn test_random_bytes_differ_by_seed() {
        assert_eq!(random_bytes(1, 1000).len(), 1000);
        assert_ne!(random_bytes(1, 64), random_bytes(2, 64));
        assert_eq!(random_bytes(3, 64), random_bytes(3, 64));
    }
}
