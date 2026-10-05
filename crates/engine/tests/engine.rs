use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use chunking::Compression;
use ed25519_dalek::SigningKey;
use engine::{Chunking, Config, Engine, EngineError, Policy, PrefixPolicy, WriteMode};
use remote::{MemoryRemote, Remote, RemoteError};
use tempfile::TempDir;

const BUCKET: &str = "bkt";

/// A remote whose next create stores the object and then reports a failure,
/// as a timeout after a successful write does.
#[derive(Default)]
struct AmbiguousRemote {
    inner: MemoryRemote,
    fail_next_create: AtomicBool,
}

#[async_trait::async_trait]
impl Remote for AmbiguousRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.create(key, data).await?;

        if self.fail_next_create.swap(false, Ordering::SeqCst) {
            return Err(RemoteError::Io(std::io::Error::other("timeout")));
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        self.inner.get(key).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        self.inner.list(prefix).await
    }
}

struct Proxy<R> {
    dir: TempDir,
    engine: Engine<R>,
}

async fn open<R: Remote + 'static>(
    remote: &Arc<R>,
    seed: u8,
    dir: TempDir,
    config: Config,
) -> Proxy<R> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let engine = Engine::open(dir.path(), remote.clone(), key, config)
        .await
        .unwrap();
    Proxy { dir, engine }
}

async fn proxy<R: Remote + 'static>(remote: &Arc<R>, seed: u8) -> Proxy<R> {
    proxy_with(remote, seed, Config::default()).await
}

async fn proxy_with<R: Remote + 'static>(remote: &Arc<R>, seed: u8, config: Config) -> Proxy<R> {
    open(remote, seed, tempfile::tempdir().unwrap(), config).await
}

/// Closes the engine as a crash does, and opens a new one on the same disk.
async fn restart<R: Remote + 'static>(
    remote: &Arc<R>,
    seed: u8,
    proxy: Proxy<R>,
    config: Config,
) -> Proxy<R> {
    let Proxy { dir, engine } = proxy;
    drop(engine);
    open(remote, seed, dir, config).await
}

fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut out);
    out
}

async fn put<R: Remote + 'static>(engine: &Engine<R>, key: &str, data: &[u8]) {
    engine
        .put(
            BUCKET,
            key,
            Bytes::copy_from_slice(data),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
}

async fn get<R: Remote + 'static>(engine: &Engine<R>, key: &str) -> Result<Vec<u8>, EngineError> {
    Ok(engine.get(BUCKET, key, None).await?.data.to_vec())
}

async fn keys<R: Remote + 'static>(engine: &Engine<R>) -> Vec<String> {
    engine
        .list(BUCKET, "")
        .await
        .unwrap()
        .into_iter()
        .map(|info| info.key)
        .collect()
}

async fn count<R: Remote>(remote: &R, prefix: &str) -> usize {
    remote.list(prefix).await.unwrap().len()
}

#[tokio::test]
async fn test_buffered_writes_are_readable_before_the_flush() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "k", b"hello").await;

    assert_eq!(get(&a.engine, "k").await.unwrap(), b"hello");
    assert_eq!(keys(&a.engine).await, ["k"]);
    assert_eq!(count(&*remote, "log/").await, 0, "nothing is flushed yet");
}

#[tokio::test]
async fn test_flushed_object_is_read_from_the_remote() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    let data = random_bytes(1, 1024 * 1024);
    put(&a.engine, "k", &data).await;

    a.engine.flush().await.unwrap();
    let fresh = proxy(&remote, 2).await;

    assert_eq!(get(&fresh.engine, "k").await.unwrap(), data);
    assert_eq!(get(&a.engine, "k").await.unwrap(), data);
}

#[tokio::test]
async fn test_two_engines_converge() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", b"from a").await;
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();

    put(&b.engine, "y", b"from b").await;
    put(&a.engine, "z", b"from a again").await;
    a.engine.delete(BUCKET, "x").await.unwrap();
    a.engine.flush().await.unwrap();
    b.engine.flush().await.unwrap();
    a.engine.sync().await.unwrap();
    b.engine.sync().await.unwrap();

    assert_eq!(keys(&a.engine).await, ["y", "z"]);
    assert_eq!(keys(&b.engine).await, keys(&a.engine).await);
    assert_eq!(get(&a.engine, "y").await.unwrap(), b"from b");
    assert_eq!(get(&b.engine, "z").await.unwrap(), b"from a again");
}

#[tokio::test]
async fn test_chunk_written_by_two_engines_is_stored_once() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    let data = random_bytes(1, 1024 * 1024);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "first", &data).await;
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();

    put(&b.engine, "second", &data).await;
    b.engine.flush().await.unwrap();

    assert_eq!(count(&*remote, "packs/").await, 1);
    assert_eq!(get(&b.engine, "second").await.unwrap(), data);
}

#[tokio::test]
async fn test_delete_keeps_history() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "k", b"data").await;
    a.engine.flush().await.unwrap();

    a.engine.delete(BUCKET, "k").await.unwrap();
    a.engine.flush().await.unwrap();

    assert!(matches!(
        get(&a.engine, "k").await,
        Err(EngineError::NoSuchKey { .. })
    ));
    assert!(keys(&a.engine).await.is_empty());
    assert_eq!(
        a.engine
            .versions(BUCKET, "k")
            .unwrap()
            .unwrap()
            .versions
            .len(),
        2
    );
    assert_eq!(count(&*remote, "packs/").await, 1);
}

#[tokio::test]
async fn test_buffered_writes_survive_a_crash() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "k", b"acknowledged").await;

    let a = restart(&remote, 1, a, Config::default()).await;

    assert_eq!(get(&a.engine, "k").await.unwrap(), b"acknowledged");
    a.engine.flush().await.unwrap();
    let other = proxy(&remote, 2).await;
    assert_eq!(get(&other.engine, "k").await.unwrap(), b"acknowledged");
}

#[tokio::test]
async fn test_concurrent_creates_of_one_key_are_surfaced() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();

    for (proxy, data) in [(&a, "from a"), (&b, "from b")] {
        proxy
            .engine
            .put(
                BUCKET,
                "k",
                Bytes::from(data),
                BTreeMap::new(),
                WriteMode::CreateOnly,
            )
            .await
            .unwrap();
        proxy.engine.flush().await.unwrap();
    }
    a.engine.sync().await.unwrap();
    b.engine.sync().await.unwrap();

    let seen_by_a = a.engine.head(BUCKET, "k").await.unwrap();
    let seen_by_b = b.engine.head(BUCKET, "k").await.unwrap();
    assert!(seen_by_a.conflicted);
    assert_eq!(seen_by_a, seen_by_b, "both proxies pick the same winner");
}

#[tokio::test]
async fn test_create_only_rejects_an_existing_key() {
    let remote = Arc::new(MemoryRemote::default());
    let config = Config {
        policies: vec![PrefixPolicy {
            bucket: BUCKET.into(),
            prefix: "wal/".into(),
            policy: Policy {
                create_only: true,
                ..Policy::default()
            },
        }],
        ..Config::default()
    };
    let a = proxy_with(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    let create = |key: &'static str| {
        a.engine.put(
            BUCKET,
            key,
            Bytes::from("new"),
            BTreeMap::new(),
            WriteMode::CreateOnly,
        )
    };

    create("k").await.unwrap();
    let buffered = create("k").await;
    a.engine.flush().await.unwrap();
    let flushed = create("k").await;
    put(&a.engine, "wal/1", b"segment").await;
    let by_policy = a
        .engine
        .put(
            BUCKET,
            "wal/1",
            Bytes::from("again"),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await;

    assert!(matches!(
        buffered,
        Err(EngineError::PreconditionFailed { .. })
    ));
    assert!(matches!(
        flushed,
        Err(EngineError::PreconditionFailed { .. })
    ));
    assert!(matches!(
        by_policy,
        Err(EngineError::PreconditionFailed { .. })
    ));
    assert_eq!(get(&a.engine, "wal/1").await.unwrap(), b"segment");
}

#[tokio::test]
async fn test_many_small_puts_make_one_entry_and_one_pack() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    for i in 0..50u8 {
        put(&a.engine, &format!("k{i}"), &random_bytes(i, 10_000)).await;
    }

    a.engine.flush().await.unwrap();

    assert_eq!(count(&*remote, "log/").await, 1);
    assert_eq!(count(&*remote, "packs/").await, 1);
    assert_eq!(
        count(&*remote, "manifests/").await,
        0,
        "small manifests are inline"
    );
    let fresh = proxy(&remote, 2).await;
    assert_eq!(keys(&fresh.engine).await.len(), 50);
    assert_eq!(
        get(&fresh.engine, "k7").await.unwrap(),
        random_bytes(7, 10_000)
    );
}

#[tokio::test]
async fn test_large_manifest_goes_to_the_remote() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    let data = random_bytes(1, 8 * 1024 * 1024);
    put(&a.engine, "big", &data).await;

    a.engine.flush().await.unwrap();
    let fresh = proxy(&remote, 2).await;

    assert_eq!(count(&*remote, "manifests/").await, 1);
    assert_eq!(get(&fresh.engine, "big").await.unwrap(), data);
}

#[tokio::test]
async fn test_rewrite_of_the_same_data_gets_a_new_manifest_key() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    let data = random_bytes(1, 8 * 1024 * 1024);

    for _ in 0..2 {
        put(&a.engine, "big", &data).await;
        a.engine.flush().await.unwrap();
    }

    assert_eq!(count(&*remote, "manifests/").await, 2);
    assert_eq!(count(&*remote, "packs/").await, 1, "the chunks still dedup");
    assert_eq!(get(&a.engine, "big").await.unwrap(), data);
}

#[tokio::test]
async fn test_range_read_spans_chunks() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    let data = random_bytes(1, 2 * 1024 * 1024);
    put(&a.engine, "k", &data).await;
    let buffered = a
        .engine
        .get(BUCKET, "k", Some(100_000..900_000))
        .await
        .unwrap();
    a.engine.flush().await.unwrap();
    let fresh = proxy(&remote, 2).await;

    let stored = fresh
        .engine
        .get(BUCKET, "k", Some(100_000..900_000))
        .await
        .unwrap();
    let empty = fresh.engine.get(BUCKET, "k", Some(5..5)).await.unwrap();
    let outside = fresh.engine.get(BUCKET, "k", Some(0..3_000_000)).await;

    assert_eq!(buffered.data, data[100_000..900_000]);
    assert_eq!(stored.data, data[100_000..900_000]);
    assert!(empty.data.is_empty());
    assert!(matches!(outside, Err(EngineError::InvalidRange { .. })));
}

#[tokio::test]
async fn test_missing_key_triggers_a_sync() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "k", b"data").await;
    a.engine.flush().await.unwrap();

    assert_eq!(get(&b.engine, "k").await.unwrap(), b"data");
}

#[tokio::test]
async fn test_interrupted_commit_is_written_once() {
    let remote = Arc::new(AmbiguousRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "k", b"data").await;
    remote.fail_next_create.store(true, Ordering::SeqCst);

    assert!(a.engine.flush().await.is_err());
    let a = restart(&remote, 1, a, Config::default()).await;
    a.engine.flush().await.unwrap();
    a.engine.flush().await.unwrap();

    assert_eq!(count(&*remote, "log/").await, 1);
    assert_eq!(get(&a.engine, "k").await.unwrap(), b"data");
    let other = proxy(&remote, 2).await;
    assert_eq!(get(&other.engine, "k").await.unwrap(), b"data");
}

#[tokio::test]
async fn test_failed_flush_is_retried_in_the_same_process() {
    let remote = Arc::new(AmbiguousRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "k", b"data").await;
    remote.fail_next_create.store(true, Ordering::SeqCst);

    assert!(a.engine.flush().await.is_err());
    put(&a.engine, "k2", b"more").await;
    a.engine.flush().await.unwrap();

    assert_eq!(count(&*remote, "log/").await, 2);
    let other = proxy(&remote, 2).await;
    other.engine.sync().await.unwrap();
    assert_eq!(keys(&other.engine).await, ["k", "k2"]);
}

#[tokio::test]
async fn test_full_buffer_rejects_puts() {
    let remote = Arc::new(MemoryRemote::default());
    let config = Config {
        buffer_limit: 64 * 1024,
        ..Config::default()
    };
    let a = proxy_with(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();

    let result = a
        .engine
        .put(
            BUCKET,
            "k",
            Bytes::from(vec![0u8; 64 * 1024]),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await;

    assert!(matches!(result, Err(EngineError::BufferFull { .. })));
    a.engine.flush().await.unwrap();
    put(&a.engine, "k", b"fits once flushed").await;
}

#[tokio::test]
async fn test_bucket_rules() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    a.engine
        .create_bucket(BUCKET, Some("max".into()))
        .await
        .unwrap();
    put(&a.engine, "k", b"data").await;

    assert!(matches!(
        a.engine.create_bucket(BUCKET, None).await,
        Err(EngineError::BucketAlreadyExists(_))
    ));
    assert!(matches!(
        a.engine.delete_bucket(BUCKET).await,
        Err(EngineError::BucketNotEmpty(_))
    ));
    assert!(matches!(
        a.engine.create_bucket("Not_Valid", None).await,
        Err(EngineError::InvalidBucketName(_))
    ));
    assert!(matches!(
        a.engine
            .put(
                "nope",
                "k",
                Bytes::new(),
                BTreeMap::new(),
                WriteMode::Overwrite
            )
            .await,
        Err(EngineError::NoSuchBucket(_))
    ));

    a.engine.delete(BUCKET, "k").await.unwrap();
    a.engine.flush().await.unwrap();
    a.engine.delete_bucket(BUCKET).await.unwrap();

    assert!(a.engine.list_buckets().await.unwrap().is_empty());
    a.engine.flush().await.unwrap();
    assert!(a.engine.list_buckets().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_metadata_and_owner_are_kept() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    let metadata = BTreeMap::from([("content-type".to_string(), "text/plain".to_string())]);
    a.engine
        .create_bucket(BUCKET, Some("max".into()))
        .await
        .unwrap();
    a.engine
        .put(
            BUCKET,
            "k",
            Bytes::from("data"),
            metadata.clone(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
    let buffered = a.engine.head(BUCKET, "k").await.unwrap();
    a.engine.flush().await.unwrap();

    let fresh = proxy(&remote, 2).await;
    let stored = fresh.engine.head(BUCKET, "k").await.unwrap();

    assert_eq!(stored.metadata, metadata);
    assert_eq!(
        stored.content_hash, buffered.content_hash,
        "the ETag does not change at flush"
    );
    assert_eq!(stored.size, 4);
    assert_eq!(
        fresh.engine.bucket(BUCKET).await.unwrap().owner.as_deref(),
        Some("max")
    );
}

#[tokio::test]
async fn test_uncompressed_policy_stores_raw_chunks() {
    let remote = Arc::new(MemoryRemote::default());
    let config = Config {
        default_policy: Policy {
            chunking: Chunking::Fixed,
            compression: Compression::None,
            create_only: false,
        },
        ..Config::default()
    };
    let a = proxy_with(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    let data = b"windsock ".repeat(100_000);
    put(&a.engine, "k", &data).await;

    a.engine.flush().await.unwrap();

    let packs = remote.list("packs/").await.unwrap();
    let pack = remote.get(&packs[0]).await.unwrap().unwrap();
    assert!(pack.len() > data.len());
    assert_eq!(get(&a.engine, "k").await.unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_flusher_uploads_within_the_delay() {
    let remote = Arc::new(MemoryRemote::default());
    let config = Config {
        flush_delay: Duration::from_millis(20),
        ..Config::default()
    };
    let a = proxy_with(&remote, 1, config).await;
    let engine = Arc::new(a.engine);
    let flusher = engine.spawn_flusher();
    engine.create_bucket(BUCKET, None).await.unwrap();
    put(&engine, "k", b"data").await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while count(&*remote, "log/").await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no flush within 5 s"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    flusher.abort();
    drop(a.dir);
}
