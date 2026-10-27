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
use remote::{MemoryRemote, Remote, RemoteError, Sweep};
use tempfile::TempDir;

const BUCKET: &str = "bkt";

/// Counts the entry reads, and can make the next create store and then fail.
#[derive(Default)]
struct TestRemote {
    inner: MemoryRemote,
    log_gets: AtomicUsize,
    ambiguous_create: AtomicBool,
    /// Ranged reads of snapshots.
    snapshot_ranges: AtomicUsize,
    /// A whole get of a snapshot fails, as a reply over the S3 client cap does.
    refuse_snapshot_get: AtomicBool,
    /// The size a snapshot reports, when set.
    snapshot_len: std::sync::Mutex<Option<u64>>,
    /// A fault on the ranged reads of snapshot parts, when set.
    tamper: std::sync::Mutex<Option<Tamper>>,
}

/// What the remote does to a ranged read of a snapshot part.
#[derive(Clone, Copy)]
enum Tamper {
    /// Every part comes back one byte short.
    ShortRange,
    /// The last part comes back one byte short.
    TruncatedLast,
    /// The first part comes back with one bit flipped.
    FlippedBit,
    /// The object takes this size after the size probe.
    Resize(usize),
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
        if key.starts_with(engine::SNAPSHOTS_PREFIX)
            && !key.ends_with("/head")
            && self.refuse_snapshot_get.load(Ordering::SeqCst)
        {
            return Err(RemoteError::Io(std::io::Error::other(
                "the reply is larger than the limit",
            )));
        }
        if key.starts_with(journal::LOG_PREFIX) {
            self.log_gets.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(key).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        if key.starts_with(engine::SNAPSHOTS_PREFIX) {
            self.snapshot_ranges.fetch_add(1, Ordering::SeqCst);
            // Some stores parse the range as a signed 64-bit number.
            if range.start > i64::MAX as u64 {
                return Err(RemoteError::Service {
                    status: 400,
                    code: "InvalidArgument".into(),
                    message: "range start above i64::MAX".into(),
                });
            }
            if let Some(len) = *self.snapshot_len.lock().unwrap() {
                return Err(RemoteError::InvalidRange {
                    key: key.to_string(),
                    start: range.start,
                    end: range.end,
                    len,
                });
            }
            let tamper = *self.tamper.lock().unwrap();
            if range.start != engine::MAX_SNAPSHOT
                && let Some(tamper) = tamper
            {
                return self.tampered(key, range, tamper).await;
            }
        }
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        self.inner.list(prefix).await
    }
}

impl TestRemote {
    async fn tampered(
        &self,
        key: &str,
        range: Range<u64>,
        tamper: Tamper,
    ) -> Result<Option<Bytes>, RemoteError> {
        let whole = self.inner.get(key).await?.expect("the snapshot exists");
        if let Tamper::Resize(len) = tamper
            && range.start == 0
        {
            let mut resized = whole.to_vec();
            resized.resize(len, 0x5a);
            self.inner.put(key, Bytes::from(resized)).await?;
        }
        let Some(bytes) = self.inner.get_range(key, range.clone()).await? else {
            return Ok(None);
        };
        let mut part = bytes.to_vec();
        match tamper {
            Tamper::ShortRange => {
                part.pop();
            }
            Tamper::TruncatedLast if range.end == whole.len() as u64 => {
                part.pop();
            }
            Tamper::FlippedBit if range.start == 0 => part[0] ^= 1,
            _ => {}
        }
        Ok(Some(Bytes::from(part)))
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
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
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

/// Every object of the bucket: the tests keep fewer than 1000.
async fn objects<R: Remote + 'static>(engine: &Engine<R>) -> Vec<engine::ObjectInfo> {
    let all = engine::ListQuery {
        prefix: "",
        delimiter: None,
        after: None,
        max_keys: 1000,
    };
    let page = engine.list_page(BUCKET, &all).await.unwrap();
    assert!(!page.truncated);
    page.entries
        .into_iter()
        .filter_map(|entry| match entry {
            engine::ListEntry::Object(info) => Some(info),
            engine::ListEntry::CommonPrefix(_) => None,
        })
        .collect()
}

async fn keys(engine: &Engine<TestRemote>) -> Vec<String> {
    objects(engine)
        .await
        .into_iter()
        .map(|info| info.key)
        .collect()
}

/// Entries in the remote, read raw.
async fn entries(remote: &TestRemote) -> Vec<Entry> {
    let mut out = Vec::new();
    for key in remote.inner.list(journal::LOG_PREFIX).await.unwrap() {
        let bytes = remote.inner.get(&key).await.unwrap().unwrap();
        let keys = engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys();
        out.push(Entry::from_wire(&bytes, keys.sealer()).unwrap());
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

/// A proxy with another key would write a chain that the other proxies cannot read.
#[tokio::test]
async fn test_proxy_with_another_repository_key_is_refused_at_open() {
    let remote = Arc::new(TestRemote::default());
    history(&remote).await;
    let dir = tempfile::tempdir().unwrap();

    let result = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[2; 32]),
        engine::RepoKey::from_hex(&"08".repeat(32)).unwrap().keys(),
        Config::default(),
    )
    .await;

    assert!(matches!(result, Err(engine::EngineError::WrongRepoKey(_))));
    assert!(remote.list("log/").await.unwrap().iter().all(|k| {
        !k.contains(
            &model::NodeId::from_bytes(SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes())
                .to_string(),
        )
    }));
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
    assert_eq!(heads(&remote).await, 1);
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
    let a = Engine::open(
        dir.path(),
        remote.clone(),
        key,
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config,
    )
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

/// A snapshot larger than one remote reply loads in ranged reads, and gives the same index.
#[tokio::test]
async fn test_snapshot_loads_in_ranged_parts() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    let (_, len) = latest(&remote).await;
    remote.refuse_snapshot_get.store(true, Ordering::SeqCst);
    remote.snapshot_ranges.store(0, Ordering::SeqCst);
    let config = Config {
        snapshot_part: len.div_ceil(5),
        ..Config::default()
    };
    let key = SigningKey::from_bytes(&[2; 32]);
    let dir = tempfile::tempdir().unwrap();

    let b = Engine::open(
        dir.path(),
        remote.clone(),
        key,
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config,
    )
    .await
    .unwrap();

    assert_eq!(
        remote.snapshot_ranges.load(Ordering::SeqCst),
        1 + 5,
        "one size probe, five parts"
    );
    assert_eq!(keys(&b).await, keys(&a.engine).await);
    assert_eq!(get(&b, "y").await, "two");
}

/// The remote is not trusted with the size of the buffer a snapshot needs.
#[tokio::test]
async fn test_snapshot_over_the_cap_fails_with_its_key_and_the_cap() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    let _ = a;
    *remote.snapshot_len.lock().unwrap() = Some(engine::MAX_SNAPSHOT + 1);
    let b = proxy(&remote, 2).await;

    let error = b.engine.sync().await.unwrap_err().to_string();

    assert!(error.contains("snapshots/"), "{error}");
    assert!(error.contains(&engine::MAX_SNAPSHOT.to_string()), "{error}");
}

/// The first part of the newest snapshot, and its size.
async fn latest(remote: &TestRemote) -> (String, u64) {
    let key = remote
        .list(engine::SNAPSHOTS_PREFIX)
        .await
        .unwrap()
        .into_iter()
        .rfind(|key| key.ends_with("/000000"))
        .unwrap();
    let len = remote.inner.get(&key).await.unwrap().unwrap().len() as u64;
    (key, len)
}

async fn heads(remote: &TestRemote) -> usize {
    let keys = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    keys.iter().filter(|key| key.ends_with("/head")).count()
}

async fn open_with(remote: &Arc<TestRemote>, part: u64) -> Result<Proxy, engine::EngineError> {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[2; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        Config {
            snapshot_part: part,
            ..Config::default()
        },
    )
    .await?;
    Ok(Proxy { dir, engine })
}

/// Node 1 writes the same history as `history` and a snapshot, with no prune: a full replay works.
async fn history_with_entries(remote: &Arc<TestRemote>) -> Proxy {
    let a = proxy(remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    for (key, data) in [("x", "one"), ("y", "two"), ("z", "three")] {
        put(&a.engine, key, data).await;
        a.engine.flush().await.unwrap();
    }
    a.engine.delete(BUCKET, "z").await.unwrap();
    a.engine.flush().await.unwrap();
    a.engine.snapshot().await.unwrap();
    a
}

/// A load ends with the full index or with an error, never with a part of the index.
async fn assert_full_or_error(remote: &Arc<TestRemote>, part: u64) -> Option<String> {
    let b = match open_with(remote, part).await {
        Ok(b) => b,
        Err(e) => return Some(e.to_string()),
    };
    if let Err(e) = b.engine.sync().await {
        let error = e.to_string();
        assert!(b.engine.get(BUCKET, "y", None).await.is_err());
        return Some(error);
    }
    assert_eq!(keys(&b.engine).await, ["x", "y"]);
    assert_eq!(get(&b.engine, "y").await, "two");
    None
}

async fn ranges_to_load(remote: &Arc<TestRemote>, part: u64) -> usize {
    remote.refuse_snapshot_get.store(true, Ordering::SeqCst);
    remote.snapshot_ranges.store(0, Ordering::SeqCst);
    let b = open_with(remote, part).await.unwrap();
    assert_eq!(keys(&b.engine).await, ["x", "y"]);
    assert_eq!(get(&b.engine, "y").await, "two");
    remote.snapshot_ranges.load(Ordering::SeqCst)
}

#[tokio::test]
async fn test_snapshot_of_exactly_one_part_loads_in_one_read() {
    let remote = Arc::new(TestRemote::default());
    let _a = history(&remote).await;
    let (_, len) = latest(&remote).await;

    assert_eq!(ranges_to_load(&remote, len).await, 1 + 1);
}

#[tokio::test]
async fn test_snapshot_of_exactly_n_parts_loads_in_n_reads() {
    let remote = Arc::new(TestRemote::default());
    let _a = history(&remote).await;
    let (_, len) = latest(&remote).await;
    let n = (2..len)
        .find(|n| len % n == 0)
        .expect("the snapshot size is not a prime");

    assert_eq!(ranges_to_load(&remote, len / n).await, 1 + n as usize);
}

#[tokio::test]
async fn test_short_ranged_read_fails_the_load_with_the_key() {
    let remote = Arc::new(TestRemote::default());
    let _a = history(&remote).await;
    let (key, len) = latest(&remote).await;
    *remote.tamper.lock().unwrap() = Some(Tamper::ShortRange);

    let error = assert_full_or_error(&remote, len.div_ceil(3))
        .await
        .unwrap();

    assert!(error.contains(&key), "{error}");
    assert!(error.contains("ranged read"), "{error}");
}

#[tokio::test]
async fn test_truncated_last_part_fails_the_load_with_the_key() {
    let remote = Arc::new(TestRemote::default());
    let _a = history(&remote).await;
    let (key, len) = latest(&remote).await;
    *remote.tamper.lock().unwrap() = Some(Tamper::TruncatedLast);

    let error = assert_full_or_error(&remote, len.div_ceil(3))
        .await
        .unwrap();

    assert!(error.contains(&key), "{error}");
}

#[tokio::test]
async fn test_corrupted_part_skips_the_snapshot_and_replays_the_journal() {
    let remote = Arc::new(TestRemote::default());
    let _a = history_with_entries(&remote).await;
    let (_, len) = latest(&remote).await;
    *remote.tamper.lock().unwrap() = Some(Tamper::FlippedBit);

    assert_eq!(assert_full_or_error(&remote, len.div_ceil(3)).await, None);
}

#[tokio::test]
async fn test_corrupted_part_with_a_pruned_journal_fails_the_sync() {
    let remote = Arc::new(TestRemote::default());
    let _a = history(&remote).await;
    let (key, len) = latest(&remote).await;
    *remote.tamper.lock().unwrap() = Some(Tamper::FlippedBit);

    let error = assert_full_or_error(&remote, len.div_ceil(3))
        .await
        .unwrap();

    assert!(error.contains(&key), "{error}");
    assert!(error.contains("does not match its hash"), "{error}");
}

#[tokio::test]
async fn test_short_ranged_read_with_the_journal_falls_back_to_the_replay() {
    let remote = Arc::new(TestRemote::default());
    let _a = history_with_entries(&remote).await;
    let (_, len) = latest(&remote).await;
    *remote.tamper.lock().unwrap() = Some(Tamper::ShortRange);

    assert_eq!(assert_full_or_error(&remote, len.div_ceil(3)).await, None);
}

#[tokio::test]
async fn test_snapshot_that_shrinks_after_the_size_probe_fails_the_load() {
    let remote = Arc::new(TestRemote::default());
    let _a = history(&remote).await;
    let (key, len) = latest(&remote).await;
    *remote.tamper.lock().unwrap() = Some(Tamper::Resize(len as usize / 2));

    let error = assert_full_or_error(&remote, len.div_ceil(3))
        .await
        .unwrap();

    assert!(error.contains(&key), "{error}");
    assert!(error.contains("the head says"), "{error}");
}

#[tokio::test]
async fn test_snapshot_that_grows_after_the_size_probe_skips_to_the_replay() {
    let remote = Arc::new(TestRemote::default());
    let _a = history_with_entries(&remote).await;
    let (_, len) = latest(&remote).await;
    *remote.tamper.lock().unwrap() = Some(Tamper::Resize(len as usize * 2));

    assert_eq!(assert_full_or_error(&remote, len.div_ceil(3)).await, None);
}

#[tokio::test]
async fn test_empty_snapshot_is_skipped_for_the_older_one() {
    let remote = Arc::new(TestRemote::default());
    let _a = history(&remote).await;
    let keys = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    let key = keys.iter().find(|key| key.ends_with("/head")).unwrap();
    let (time, _) = key
        .strip_prefix(engine::SNAPSHOTS_PREFIX)
        .unwrap()
        .split_once('-')
        .unwrap();
    let newer = time.parse::<u64>().unwrap() + 1;
    let empty = format!(
        "{}{newer:020}-{}",
        engine::SNAPSHOTS_PREFIX,
        blake3::hash(&[])
    );
    remote.inner.put(&empty, Bytes::new()).await.unwrap();
    assert!(remote.list(&empty).await.unwrap().contains(&empty));

    assert_eq!(assert_full_or_error(&remote, 64).await, None);
}

async fn proxy_config(remote: &Arc<TestRemote>, seed: u8, config: Config) -> Proxy {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[seed; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config,
    )
    .await
    .unwrap();
    Proxy { dir, engine }
}

/// Like `history`, with a snapshot in parts of `object` bytes. Returns the snapshot base key
/// and the number of entries that the prune redacted.
async fn history_in_parts(remote: &Arc<TestRemote>, object: u64, keys: usize) -> (String, usize) {
    let config = Config {
        snapshot_object: object,
        ..Config::default()
    };
    let a = proxy_config(remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    for (key, data) in [("x", "one"), ("y", "two")] {
        put(&a.engine, key, data).await;
    }
    for n in 0..keys {
        put(&a.engine, &format!("more-{n:05}"), "v").await;
    }
    a.engine.flush().await.unwrap();
    let report = a.engine.gc().await.unwrap();
    assert!(report.snapshot_written);
    let head = remote
        .list(engine::SNAPSHOTS_PREFIX)
        .await
        .unwrap()
        .into_iter()
        .find(|key| key.ends_with("/head"))
        .unwrap();
    let base = head.strip_suffix("/head").unwrap().to_string();
    (base, report.redacted_entries)
}

/// A new proxy after a prune: the error, or `None` when it reads x and y.
async fn load_after_prune(remote: &Arc<TestRemote>) -> Option<String> {
    let b = proxy(remote, 2).await;
    if let Err(e) = b.engine.sync().await {
        assert!(b.engine.get(BUCKET, "y", None).await.is_err());
        return Some(e.to_string());
    }
    assert_eq!(get(&b.engine, "x").await, "one");
    assert_eq!(get(&b.engine, "y").await, "two");
    None
}

#[tokio::test]
async fn test_snapshot_in_parts_loads_and_checks_each_part() {
    let remote = Arc::new(TestRemote::default());
    let (base, redacted) = history_in_parts(&remote, 100, 0).await;
    assert!(redacted > 0);
    let parts = remote.list(&format!("{base}/")).await.unwrap().len() - 1;
    assert!(parts > 2, "{parts} parts");

    assert_eq!(load_after_prune(&remote).await, None);
}

#[tokio::test]
async fn test_snapshot_with_a_missing_part_fails_with_its_head_key() {
    let remote = Arc::new(TestRemote::default());
    let (base, redacted) = history_in_parts(&remote, 100, 0).await;
    assert!(redacted > 0);
    remote
        .inner
        .delete(&format!("{base}/000001"))
        .await
        .unwrap();

    let error = load_after_prune(&remote).await.unwrap();

    assert!(error.contains(&format!("{base}/head")), "{error}");
    assert!(error.contains("the remote has"), "{error}");
}

#[tokio::test]
async fn test_snapshot_with_a_corrupt_part_fails_with_the_part_key() {
    let remote = Arc::new(TestRemote::default());
    let (base, redacted) = history_in_parts(&remote, 100, 0).await;
    assert!(redacted > 0);
    let part = format!("{base}/000001");
    let mut bytes = remote.inner.get(&part).await.unwrap().unwrap().to_vec();
    bytes[10] ^= 1;
    remote.inner.put(&part, Bytes::from(bytes)).await.unwrap();

    let error = load_after_prune(&remote).await.unwrap();

    assert!(error.contains(&part), "{error}");
    assert!(error.contains("does not match its hash"), "{error}");
}

#[tokio::test]
async fn test_snapshot_with_a_short_part_fails_with_the_part_key() {
    let remote = Arc::new(TestRemote::default());
    let (base, redacted) = history_in_parts(&remote, 100, 0).await;
    assert!(redacted > 0);
    let part = format!("{base}/000001");
    let bytes = remote.inner.get(&part).await.unwrap().unwrap();
    remote.inner.put(&part, bytes.slice(..50)).await.unwrap();

    let error = load_after_prune(&remote).await.unwrap();

    assert!(error.contains(&part), "{error}");
    assert!(error.contains("the head says 100"), "{error}");
}

#[tokio::test]
async fn test_snapshot_head_with_a_wrong_part_count_is_skipped() {
    let remote = Arc::new(TestRemote::default());
    let (base, redacted) = history_in_parts(&remote, 100, 0).await;
    assert!(redacted > 0);
    let extra = format!("{base}/000999");
    remote
        .inner
        .put(&extra, Bytes::from_static(b"x"))
        .await
        .unwrap();

    let error = load_after_prune(&remote).await.unwrap();

    assert!(error.contains(&format!("{base}/head")), "{error}");
    assert!(error.contains("the remote has"), "{error}");
}

/// A head over the part cap does not load, so the GC does not prune under it.
#[tokio::test]
async fn test_snapshot_head_over_the_part_cap_is_skipped() {
    let remote = Arc::new(TestRemote::default());
    let (base, redacted) = history_in_parts(&remote, 1, 200).await;
    let parts = remote.list(&format!("{base}/")).await.unwrap().len() - 1;
    assert!(parts > engine::MAX_SNAPSHOT_PARTS, "{parts} parts");

    assert_eq!(redacted, 0, "no prune under a snapshot that does not load");
    assert_eq!(load_after_prune(&remote).await, None, "the journal replays");
}

#[tokio::test]
async fn test_snapshot_in_one_object_still_loads() {
    let remote = Arc::new(TestRemote::default());
    let (base, redacted) = history_in_parts(&remote, 1 << 30, 0).await;
    assert!(redacted > 0);
    let whole = remote
        .inner
        .get(&format!("{base}/000000"))
        .await
        .unwrap()
        .unwrap();
    for key in remote.list(&format!("{base}/")).await.unwrap() {
        remote.inner.delete(&key).await.unwrap();
    }
    remote.inner.put(&base, whole).await.unwrap();

    assert_eq!(load_after_prune(&remote).await, None);
}

#[tokio::test]
async fn test_gc_prune_reads_the_head_and_no_part() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    put(&a.engine, "after", "the snapshot").await;
    a.engine.flush().await.unwrap();
    remote.snapshot_ranges.store(0, Ordering::SeqCst);

    let report = a.engine.gc().await.unwrap();

    assert!(!report.snapshot_written);
    assert_eq!(remote.snapshot_ranges.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_gc_deletes_an_old_snapshot_with_all_its_parts() {
    let remote = Arc::new(TestRemote::default());
    let config = Config {
        snapshot_object: 100,
        snapshot_interval: Duration::ZERO,
        gc_horizon: Duration::from_millis(300),
        ..Config::default()
    };
    let a = proxy_config(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    a.engine.flush().await.unwrap();
    a.engine.gc().await.unwrap();
    let old = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    a.engine.gc().await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let report = a.engine.gc().await.unwrap();

    assert!(report.deleted_snapshots >= 1, "{report:?}");
    let left = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    assert!(old.iter().all(|key| !left.contains(key)), "{left:?}");
    assert_eq!(get(&proxy(&remote, 2).await.engine, "x").await, "one");
}
