//! Snapshots, bootstrap from a snapshot, and the journal prune.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, WriteMode};
use journal::Entry;
use keys::RepoKey;
use remote::{MemoryRemote, Remote, RemoteError, Sweep};
use tempfile::TempDir;

/// Every proxy of one remote shares the repository key.
fn repo_key() -> RepoKey {
    RepoKey::from_bytes([42u8; 32])
}

const BUCKET: &str = "bkt";

/// Counts the entry reads, and can make the next create store and then fail.
#[derive(Default)]
struct TestRemote {
    inner: MemoryRemote,
    log_gets: AtomicUsize,
    ambiguous_create: AtomicBool,
}

#[async_trait::async_trait]
impl Remote for TestRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.create(key, data).await?;

        if self.ambiguous_create.swap(false, Ordering::SeqCst) {
            return Err(RemoteError::Io(std::io::Error::other("timeout")));
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        if key.starts_with(journal::LOG_PREFIX) {
            self.log_gets.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(key).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        self.inner.list(prefix).await
    }
}

#[async_trait::async_trait]
impl Sweep for TestRemote {
    async fn delete(&self, key: &str) -> Result<(), RemoteError> {
        self.inner.delete(key).await
    }
}

struct Proxy {
    dir: TempDir,
    engine: Engine<TestRemote>,
}

async fn open(remote: &Arc<TestRemote>, seed: u8, dir: TempDir) -> Proxy {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        key,
        repo_key(),
        Config::default(),
    )
    .await
    .unwrap();
    Proxy { dir, engine }
}

async fn proxy(remote: &Arc<TestRemote>, seed: u8) -> Proxy {
    open(remote, seed, tempfile::tempdir().unwrap()).await
}

async fn put(engine: &Engine<TestRemote>, key: &str, data: &str) {
    engine
        .put(
            BUCKET,
            key,
            Bytes::copy_from_slice(data.as_bytes()),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
}

async fn get(engine: &Engine<TestRemote>, key: &str) -> String {
    let object = engine.get(BUCKET, key, None).await.unwrap();
    String::from_utf8(object.data.to_vec()).unwrap()
}

async fn keys(engine: &Engine<TestRemote>) -> Vec<String> {
    let listed = engine.list(BUCKET, "").await.unwrap();
    listed.into_iter().map(|info| info.key).collect()
}

/// Entries in the remote, read raw.
async fn entries(remote: &TestRemote) -> Vec<Entry> {
    let mut out = Vec::new();
    for key in remote.inner.list(journal::LOG_PREFIX).await.unwrap() {
        let bytes = remote.inner.get(&key).await.unwrap().unwrap();
        out.push(Entry::decode(&repo_key(), &bytes).unwrap());
    }
    out
}

/// Node 1 writes a bucket, three keys and a delete in four entries, then runs
/// the GC: one snapshot, and every entry so far redacted.
async fn history(remote: &Arc<TestRemote>) -> Proxy {
    let a = proxy(remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    for (key, data) in [("x", "one"), ("y", "two"), ("z", "three")] {
        put(&a.engine, key, data).await;
        a.engine.flush().await.unwrap();
    }
    a.engine.delete(BUCKET, "z").await.unwrap();
    a.engine.flush().await.unwrap();

    let report = a.engine.gc().await.unwrap();
    assert!(report.snapshot_written);
    assert_eq!(report.redacted_entries, 4);
    assert!(entries(remote).await.iter().all(|e| e.actions.is_none()));
    a
}

#[tokio::test]
async fn test_new_proxy_starts_from_the_snapshot() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    remote.log_gets.store(0, Ordering::SeqCst);

    let b = proxy(&remote, 2).await;

    assert_eq!(keys(&b.engine).await, ["x", "y"]);
    assert_eq!(get(&b.engine, "y").await, "two");
    assert_eq!(keys(&b.engine).await, keys(&a.engine).await);
    assert!(
        remote.log_gets.load(Ordering::SeqCst) <= 2,
        "b reads only the seq after each snapshot frontier"
    );
}

#[tokio::test]
async fn test_lagging_reader_loads_the_snapshot_at_a_redacted_entry() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "early", "seen by b").await;
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();

    put(&a.engine, "late", "after b").await;
    a.engine.flush().await.unwrap();
    a.engine.gc().await.unwrap();
    b.engine.sync().await.unwrap();

    assert_eq!(keys(&b.engine).await, ["early", "late"]);
    assert_eq!(get(&b.engine, "late").await, "after b");
}

#[tokio::test]
async fn test_writer_with_lost_state_continues_its_chain_after_the_prune() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    let before = entries(&remote).await.len();
    drop(a);

    let a = proxy(&remote, 1).await;
    put(&a.engine, "w", "after the loss").await;
    a.engine.flush().await.unwrap();

    let after = entries(&remote).await;
    assert_eq!(after.len(), before + 1, "one new entry, no fork");
    let reader = proxy(&remote, 3).await;
    reader.engine.sync().await.unwrap();
    assert_eq!(keys(&reader.engine).await, ["w", "x", "y"]);
}

#[tokio::test]
async fn test_interrupted_flush_finds_its_entry_after_the_prune() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy(&remote, 1).await;
    let gc = proxy(&remote, 2).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    put(&a.engine, "k", "data").await;
    remote.ambiguous_create.store(true, Ordering::SeqCst);
    assert!(a.engine.flush().await.is_err());

    gc.engine.gc().await.unwrap();
    let pruned = entries(&remote).await;
    assert!(pruned.iter().all(|e| e.actions.is_none()));
    a.engine.flush().await.unwrap();

    assert_eq!(
        entries(&remote).await.len(),
        pruned.len(),
        "no second entry"
    );
    assert_eq!(get(&a.engine, "k").await, "data");
}

#[tokio::test]
async fn test_snapshot_is_written_once_per_interval() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    put(&a.engine, "after", "the snapshot").await;
    a.engine.flush().await.unwrap();

    let report = a.engine.gc().await.unwrap();

    assert!(!report.snapshot_written);
    assert_eq!(
        report.redacted_entries, 0,
        "entries above the snapshot stay whole"
    );
    assert_eq!(
        remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap().len(),
        1
    );
    assert!(entries(&remote).await.iter().any(|e| e.actions.is_some()));
}

#[tokio::test]
async fn test_short_interval_writes_a_new_snapshot() {
    let remote = Arc::new(TestRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        snapshot_interval: Duration::ZERO,
        ..Config::default()
    };
    let key = SigningKey::from_bytes(&[1u8; 32]);
    let a = Engine::open(dir.path(), remote.clone(), key, repo_key(), config)
        .await
        .unwrap();
    a.create_bucket(BUCKET, None).await.unwrap();
    a.flush().await.unwrap();

    a.gc().await.unwrap();
    put(&a, "k", "v").await;
    a.flush().await.unwrap();
    let second = a.gc().await.unwrap();

    assert!(second.snapshot_written);
    assert!(second.redacted_entries >= 1);
    assert!(entries(&remote).await.iter().all(|e| e.actions.is_none()));
    assert_eq!(get(&a, "k").await, "v");
}

#[tokio::test]
async fn test_restart_keeps_reading_after_the_prune() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    let Proxy { dir, engine } = a;
    drop(engine);

    let a = open(&remote, 1, dir).await;

    assert_eq!(keys(&a.engine).await, ["x", "y"]);
    a.engine.sync().await.unwrap();
    drop(a.dir);
}
