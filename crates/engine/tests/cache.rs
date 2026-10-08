//! The chunk cache: per-prefix policy, bound, hash check, one fetch per missing chunk.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{CacheMode, Config, Engine, Policy, PrefixPolicy, WriteMode};
use keys::RepoKey;
use remote::{MemoryRemote, Remote, RemoteError};
use tempfile::TempDir;

/// Every proxy of one remote shares the repository key.
fn repo_key() -> RepoKey {
    RepoKey::from_bytes([42u8; 32])
}

const BUCKET: &str = "bkt";

/// Counts the range reads, which only object reads make.
#[derive(Default)]
struct CountingRemote {
    inner: MemoryRemote,
    range_reads: AtomicUsize,
}

impl CountingRemote {
    fn range_reads(&self) -> usize {
        self.range_reads.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Remote for CountingRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.create(key, data).await
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        self.inner.get(key).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        self.range_reads.fetch_add(1, Ordering::SeqCst);
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        self.inner.list(prefix).await
    }
}

struct Proxy {
    dir: TempDir,
    engine: Engine<CountingRemote>,
}

/// `cache` applies to the keys under `c/`.
fn config(cache: CacheMode, cache_bytes: u64) -> Config {
    Config {
        cache_bytes,
        policies: vec![PrefixPolicy {
            bucket: BUCKET.into(),
            prefix: "c/".into(),
            policy: Policy {
                cache,
                ..Policy::default()
            },
        }],
        ..Config::default()
    }
}

async fn proxy(remote: &Arc<CountingRemote>, seed: u8, config: Config) -> Proxy {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[seed; 32]);
    let engine = Engine::open(dir.path(), remote.clone(), key, repo_key(), config)
        .await
        .unwrap();
    Proxy { dir, engine }
}

fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut out);
    out
}

/// Writes `data` at `key` and flushes it.
async fn write(proxy: &Proxy, key: &str, data: &[u8]) {
    proxy.engine.create_bucket(BUCKET, None).await.ok();
    proxy
        .engine
        .put(
            BUCKET,
            key,
            Bytes::copy_from_slice(data),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
    proxy.engine.flush().await.unwrap();
}

async fn read(proxy: &Proxy, key: &str) -> Vec<u8> {
    proxy
        .engine
        .get(BUCKET, key, None)
        .await
        .unwrap()
        .data
        .to_vec()
}

/// Range reads that one read of `key` makes.
async fn reads_for(remote: &CountingRemote, proxy: &Proxy, key: &str) -> usize {
    let before = remote.range_reads();
    read(proxy, key).await;
    remote.range_reads() - before
}

fn cache_files(dir: &Path) -> Vec<std::fs::Metadata> {
    let mut files = Vec::new();
    for sub in std::fs::read_dir(dir.join("cache")).unwrap() {
        for file in std::fs::read_dir(sub.unwrap().path()).unwrap() {
            files.push(file.unwrap().metadata().unwrap());
        }
    }
    files
}

#[tokio::test]
async fn test_read_write_policy_serves_recent_writes_locally() {
    let remote = Arc::new(CountingRemote::default());
    let a = proxy(&remote, 1, config(CacheMode::ReadWrite, 1 << 30)).await;
    write(&a, "c/k", &random_bytes(1, 300_000)).await;

    assert_eq!(reads_for(&remote, &a, "c/k").await, 0);
    assert_eq!(read(&a, "c/k").await, random_bytes(1, 300_000));
}

#[tokio::test]
async fn test_read_policy_caches_reads_and_not_writes() {
    let remote = Arc::new(CountingRemote::default());
    let a = proxy(&remote, 1, config(CacheMode::Read, 1 << 30)).await;
    write(&a, "c/k", &random_bytes(1, 300_000)).await;

    assert!(
        reads_for(&remote, &a, "c/k").await > 0,
        "the write went around the cache"
    );
    assert_eq!(
        reads_for(&remote, &a, "c/k").await,
        0,
        "the read filled the cache"
    );
}

#[tokio::test]
async fn test_off_policy_never_caches() {
    let remote = Arc::new(CountingRemote::default());
    let a = proxy(&remote, 1, config(CacheMode::Off, 1 << 30)).await;
    write(&a, "c/k", &random_bytes(1, 300_000)).await;

    assert!(reads_for(&remote, &a, "c/k").await > 0);
    assert!(reads_for(&remote, &a, "c/k").await > 0);
}

#[tokio::test]
async fn test_corrupt_cache_file_is_read_again_from_the_remote() {
    let remote = Arc::new(CountingRemote::default());
    let a = proxy(&remote, 1, config(CacheMode::ReadWrite, 1 << 30)).await;
    let data = random_bytes(1, 300_000);
    write(&a, "c/k", &data).await;
    for sub in std::fs::read_dir(a.dir.path().join("cache")).unwrap() {
        for file in std::fs::read_dir(sub.unwrap().path()).unwrap() {
            std::fs::write(file.unwrap().path(), b"corrupt").unwrap();
        }
    }

    assert!(reads_for(&remote, &a, "c/k").await > 0);
    assert_eq!(read(&a, "c/k").await, data);
    assert_eq!(
        reads_for(&remote, &a, "c/k").await,
        0,
        "the good chunks are cached again"
    );
}

#[tokio::test]
async fn test_cache_stays_within_its_bound() {
    let remote = Arc::new(CountingRemote::default());
    let bound = 400 * 1024;
    let a = proxy(&remote, 1, config(CacheMode::ReadWrite, bound)).await;

    for i in 0..4 {
        write(&a, &format!("c/{i}"), &random_bytes(i, 300_000)).await;
    }

    let total: u64 = cache_files(a.dir.path()).iter().map(|m| m.len()).sum();
    assert!(total <= bound, "{total} bytes cached, bound {bound}");
    assert_eq!(
        reads_for(&remote, &a, "c/3").await,
        0,
        "the newest write stays"
    );
    assert!(
        reads_for(&remote, &a, "c/0").await > 0,
        "the oldest write left"
    );
}

#[tokio::test]
async fn test_zero_bound_turns_the_cache_off() {
    let remote = Arc::new(CountingRemote::default());
    let a = proxy(&remote, 1, config(CacheMode::ReadWrite, 0)).await;
    write(&a, "c/k", &random_bytes(1, 300_000)).await;

    assert!(reads_for(&remote, &a, "c/k").await > 0);
    assert!(!a.dir.path().join("cache").exists());
}

/// Concurrent reads of a cold object make the range reads of one read, not one per reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_misses_fetch_each_chunk_once() {
    let remote = Arc::new(CountingRemote::default());
    let writer = proxy(&remote, 1, config(CacheMode::Off, 0)).await;
    write(&writer, "c/k", &random_bytes(1, 2 * 1024 * 1024)).await;
    let alone = proxy(&remote, 2, config(CacheMode::ReadWrite, 1 << 30)).await;
    let one_read = reads_for(&remote, &alone, "c/k").await;

    let shared = Arc::new(proxy(&remote, 3, config(CacheMode::ReadWrite, 1 << 30)).await);
    shared.engine.sync().await.unwrap();
    let before = remote.range_reads();
    let mut readers = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let shared = shared.clone();
        readers.spawn(async move { read(&shared, "c/k").await });
    }
    while let Some(data) = readers.join_next().await {
        assert_eq!(data.unwrap(), random_bytes(1, 2 * 1024 * 1024));
    }

    assert!(one_read > 0);
    assert_eq!(remote.range_reads() - before, one_read);
}
