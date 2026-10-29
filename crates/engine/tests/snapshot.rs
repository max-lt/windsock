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
    /// The put of a snapshot head first deletes part 0, as a GC on another proxy can.
    drop_part_at_head: AtomicBool,
    /// The next listing of the snapshots misses the newest one, as when a GC writes it just
    /// after the listing.
    hide_newest_snapshot: AtomicBool,
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
        if key.ends_with("/head") && self.drop_part_at_head.swap(false, Ordering::SeqCst) {
            let base = key.trim_end_matches("head");
            let parts = self.inner.list(base).await?;
            let first = parts.iter().find(|part| !part.ends_with("/head"));
            self.inner.delete(first.expect("a part exists")).await?;
        }
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
        let mut keys = self.inner.list(prefix).await?;
        if prefix.starts_with(engine::SNAPSHOTS_PREFIX)
            && self.hide_newest_snapshot.swap(false, Ordering::SeqCst)
        {
            let newest = keys.last().cloned().unwrap_or_default();
            let rest = &newest[engine::SNAPSHOTS_PREFIX.len()..];
            let base = rest.split('/').next().unwrap_or_default().to_string();
            keys.retain(|key| !key[engine::SNAPSHOTS_PREFIX.len()..].starts_with(&base));
        }
        Ok(keys)
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

thread_local! {
    /// H, R and M of the first proxy with its own configuration in this test: every proxy of a
    /// remote must use the same, so the default proxies of the test take them too.
    static RULES: std::cell::Cell<Option<(Duration, Duration, Duration)>> =
        const { std::cell::Cell::new(None) };
}

/// The default configuration, with the rules of the remote of this test.
fn default_config() -> Config {
    let mut config = Config::default();
    if let Some((horizon, retention, margin)) = RULES.with(std::cell::Cell::get) {
        config.gc_horizon = horizon;
        config.retention = retention;
        config.late_margin = margin;
    }
    config
}

async fn open(remote: &Arc<TestRemote>, seed: u8, dir: TempDir) -> Proxy {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        key,
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        default_config(),
    )
    .await
    .unwrap();
    Proxy { dir, engine }
}

async fn proxy(remote: &Arc<TestRemote>, seed: u8) -> Proxy {
    open(remote, seed, tempfile::tempdir().unwrap()).await
}

/// Opens a proxy, then syncs it. The open syncs too, so a load error shows at either step.
async fn open_and_sync(remote: &Arc<TestRemote>, seed: u8) -> Result<Proxy, String> {
    open_and_sync_with(remote, seed, Config::default()).await
}

async fn open_and_sync_with(
    remote: &Arc<TestRemote>,
    seed: u8,
    config: Config,
) -> Result<Proxy, String> {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[seed; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config,
    )
    .await
    .map_err(|e| e.to_string())?;
    engine.sync().await.map_err(|e| e.to_string())?;
    Ok(Proxy { dir, engine })
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
    // For the one chain: the seq after the frontier, the gap probe, and the audit read of
    // the last entry. For the own empty chain of b: seq 0 and the gap probe.
    assert!(
        remote.log_gets.load(Ordering::SeqCst) <= 5,
        "b reads only after each snapshot frontier: {}",
        remote.log_gets.load(Ordering::SeqCst)
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
    let Err(error) = open_and_sync(&remote, 2).await else {
        panic!("a snapshot over the cap loads");
    };

    assert!(error.contains("snapshots/"), "{error}");
    // A part is not read past the size that the head gives it.
    assert!(error.contains("larger than"), "{error}");
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
    RULES.with(|rules| {
        if rules.get().is_none() {
            rules.set(Some((
                config.gc_horizon,
                config.retention,
                config.late_margin,
            )));
        }
    });
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
    let b = match open_and_sync(remote, 2).await {
        Ok(b) => b,
        Err(e) => return Some(e),
    };
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

/// A snapshot over the part cap would load nowhere. The GC writes no part of it, logs an error,
/// and goes on: the journal stays whole and a new proxy replays it.
#[tokio::test]
async fn test_gc_writes_no_snapshot_over_the_part_cap() {
    let remote = Arc::new(TestRemote::default());
    let config = Config {
        snapshot_object: 1,
        ..Config::default()
    };
    let a = proxy_config(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    put(&a.engine, "y", "two").await;
    for n in 0..200 {
        put(&a.engine, &format!("more-{n:05}"), "v").await;
    }
    a.engine.flush().await.unwrap();

    let report = a.engine.gc().await.unwrap();

    assert!(!report.snapshot_written);
    assert_eq!(report.redacted_entries, 0);
    assert!(
        remote
            .list(engine::SNAPSHOTS_PREFIX)
            .await
            .unwrap()
            .is_empty()
    );
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
async fn test_gc_prune_loads_the_snapshot_in_full() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    put(&a.engine, "after", "the snapshot").await;
    a.engine.flush().await.unwrap();
    remote.snapshot_ranges.store(0, Ordering::SeqCst);

    let report = a.engine.gc().await.unwrap();

    assert!(!report.snapshot_written);
    assert_eq!(
        remote.snapshot_ranges.load(Ordering::SeqCst),
        2,
        "one size probe and one part"
    );
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

fn gc_config() -> Config {
    Config {
        snapshot_object: 100,
        snapshot_interval: Duration::from_secs(3600),
        gc_horizon: Duration::from_secs(3600),
        ..Config::default()
    }
}

/// Copies the parts of the newest snapshot to a new base with no head, as a crash before the
/// head leaves them. Returns the new part keys.
async fn parts_with_no_head(remote: &TestRemote, time: u64) -> Vec<String> {
    let keys = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    let head = keys.iter().rfind(|key| key.ends_with("/head")).unwrap();
    let base = head.strip_suffix("/head").unwrap();
    let orphan = format!("{}{time:020}-{}", engine::SNAPSHOTS_PREFIX, "ab".repeat(32));
    let mut out = Vec::new();
    for key in keys
        .iter()
        .filter(|key| key.starts_with(&format!("{base}/0")))
    {
        let part = key.rsplit_once('/').unwrap().1;
        let bytes = remote.inner.get(key).await.unwrap().unwrap();
        let copy = format!("{orphan}/{part}");
        remote.inner.put(&copy, bytes).await.unwrap();
        out.push(copy);
    }
    out
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// A crash before the head leaves parts with no head. A load ignores them, and the GC keeps
/// them for H: their writer can still be at work.
#[tokio::test]
async fn test_parts_with_no_head_are_ignored_and_kept_inside_the_horizon() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy_config(&remote, 1, gc_config()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    a.engine.flush().await.unwrap();
    a.engine.gc().await.unwrap();
    let orphans = parts_with_no_head(&remote, now_nanos()).await;
    assert!(!orphans.is_empty());

    let b = proxy(&remote, 2).await;
    a.engine.gc().await.unwrap();

    assert_eq!(get(&b.engine, "x").await, "one", "a load ignores the parts");
    let left = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    assert!(orphans.iter().all(|key| left.contains(key)), "{left:?}");
}

/// A GC that dies after it deleted a head, or a crash before the head, leaves parts. A GC run
/// deletes them once its own process has listed them for H.
#[tokio::test]
async fn test_parts_left_by_a_gc_that_died_are_deleted_h_after_the_first_listing() {
    let remote = Arc::new(TestRemote::default());
    let config = Config {
        gc_horizon: Duration::from_millis(300),
        ..gc_config()
    };
    let a = proxy_config(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    a.engine.flush().await.unwrap();
    a.engine.gc().await.unwrap();
    let old = parts_with_no_head(&remote, now_nanos() - 3_600_000_000_000).await;

    a.engine.gc().await.unwrap();
    let left = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    assert!(
        old.iter().all(|key| left.contains(key)),
        "kept at the first listing"
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    a.engine.gc().await.unwrap();

    let left = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    assert!(old.iter().all(|key| !left.contains(key)), "{left:?}");
}

/// A writer with a clock 25 h behind writes parts whose key time is old. A GC on another proxy
/// must not take them for orphans while the writer can still write its head.
#[tokio::test]
async fn test_fresh_parts_with_an_old_key_time_are_kept() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy_config(&remote, 1, gc_config()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    a.engine.flush().await.unwrap();
    a.engine.gc().await.unwrap();
    let behind = parts_with_no_head(&remote, now_nanos() - 25 * 3_600_000_000_000).await;

    a.engine.gc().await.unwrap();

    let left = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    assert!(behind.iter().all(|key| left.contains(key)), "{left:?}");
}

/// A snapshot key with a time 10 days ahead comes from a clock that is ahead. It must not stop
/// this GC from writing snapshots.
#[tokio::test]
async fn test_snapshot_key_time_in_the_future_does_not_block_new_snapshots() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy_config(&remote, 1, gc_config()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    let ahead = now_nanos() + 10 * 24 * 3_600_000_000_000;
    let future = format!(
        "{}{ahead:020}-{}/head",
        engine::SNAPSHOTS_PREFIX,
        "cd".repeat(32)
    );
    remote
        .inner
        .put(&future, Bytes::from_static(b"x"))
        .await
        .unwrap();

    let report = a.engine.gc().await.unwrap();

    assert!(report.snapshot_written);
}

#[tokio::test]
async fn test_newest_snapshot_in_parts_that_fails_falls_back_to_an_older_single_object() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy_config(&remote, 1, gc_config()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    a.engine.flush().await.unwrap();
    let older = a.engine.snapshot().await.unwrap();
    to_one_object(&remote, &older).await;
    put(&a.engine, "y", "two").await;
    a.engine.flush().await.unwrap();
    let newer = a.engine.snapshot().await.unwrap();
    let part = format!("{}/000000", newer.strip_suffix("/head").unwrap());
    remote
        .inner
        .put(&part, Bytes::from_static(b"bad"))
        .await
        .unwrap();
    remote.snapshot_ranges.store(0, Ordering::SeqCst);

    let b = proxy(&remote, 2).await;

    let older = older.strip_suffix("/head").unwrap().to_string();
    assert!(remote.inner.get(&older).await.unwrap().is_some());
    assert!(
        remote.snapshot_ranges.load(Ordering::SeqCst) >= 4,
        "the newest parts, then the older object"
    );
    assert_eq!(get(&b.engine, "x").await, "one");
    assert_eq!(get(&b.engine, "y").await, "two");
}

#[tokio::test]
async fn test_two_proxies_that_write_a_snapshot_at_once_get_two_keys_that_load() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy_config(&remote, 1, gc_config()).await;
    let b = proxy_config(&remote, 2, gc_config()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();

    let (first, second) = tokio::join!(a.engine.snapshot(), b.engine.snapshot());
    let (first, second) = (first.unwrap(), second.unwrap());

    assert_ne!(first, second);
    assert_eq!(heads(&remote).await, 2);
    for head in [&first, &second] {
        let fresh = proxy(&remote, 3).await;
        assert_eq!(get(&fresh.engine, "x").await, "one");
        drop(fresh);
        let base = head.strip_suffix("/head").unwrap();
        for key in remote.list(&format!("{base}/")).await.unwrap() {
            remote.inner.delete(&key).await.unwrap();
        }
    }
}

/// Flips one byte of a part and keeps its key.
async fn flip_part(remote: &TestRemote, head: &str, n: usize) {
    let part = format!("{}/{n:06}", head.strip_suffix("/head").unwrap());
    let mut bytes = remote.inner.get(&part).await.unwrap().unwrap().to_vec();
    bytes[0] ^= 1;
    remote.inner.put(&part, Bytes::from(bytes)).await.unwrap();
}

/// A part with flipped bytes keeps its key and the head stays whole. The prune must not redact
/// under that snapshot, or no snapshot loads and the redacted writes are lost.
#[tokio::test]
async fn test_prune_does_not_redact_under_a_snapshot_with_a_bad_part() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy_config(&remote, 1, gc_config()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    a.engine.flush().await.unwrap();
    let head = a.engine.snapshot().await.unwrap();
    flip_part(&remote, &head, 0).await;

    let report = a.engine.gc().await.unwrap();

    assert!(!report.snapshot_written);
    assert_eq!(report.redacted_entries, 0);
    let b = proxy(&remote, 2).await;
    assert_eq!(get(&b.engine, "x").await, "one");
}

/// A newer snapshot that does not load must not cause the delete of an older one that loads.
#[tokio::test]
async fn test_gc_keeps_the_older_snapshot_when_the_newer_does_not_load() {
    let remote = Arc::new(TestRemote::default());
    let config = Config {
        gc_horizon: Duration::from_millis(200),
        ..gc_config()
    };
    let a = proxy_config(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    a.engine.flush().await.unwrap();
    let older = a.engine.snapshot().await.unwrap();
    let newer = a.engine.snapshot().await.unwrap();
    flip_part(&remote, &newer, 0).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    a.engine.gc().await.unwrap();

    assert!(
        remote.inner.get(&older).await.unwrap().is_some(),
        "the older head stays"
    );
    let b = proxy(&remote, 2).await;
    assert_eq!(get(&b.engine, "x").await, "one");
}

/// Replaces a snapshot in parts with the same snapshot in one object.
async fn to_one_object(remote: &TestRemote, head: &str) {
    let base = head.strip_suffix("/head").unwrap();
    let mut whole = Vec::new();
    for key in remote.list(&format!("{base}/")).await.unwrap() {
        if !key.ends_with("/head") {
            whole.extend_from_slice(&remote.inner.get(&key).await.unwrap().unwrap());
        }
        remote.inner.delete(&key).await.unwrap();
    }
    remote.inner.put(base, Bytes::from(whole)).await.unwrap();
}

/// A snapshot over the cap is skipped like any snapshot that does not load: the GC run goes on.
#[tokio::test]
async fn test_snapshot_over_the_cap_is_skipped_and_the_gc_goes_on() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    *remote.snapshot_len.lock().unwrap() = Some(engine::MAX_SNAPSHOT + 1);

    let report = a.engine.gc().await.unwrap();

    assert_eq!(report.redacted_entries, 0);
}

/// A part that the remote replaces with a much larger object is not read: the head gives its
/// size, and the size probe stops at it.
#[tokio::test]
async fn test_part_larger_than_the_head_says_is_not_read() {
    let remote = Arc::new(TestRemote::default());
    let (base, _) = history_in_parts(&remote, 100, 0).await;
    let part = format!("{base}/000001");
    remote
        .inner
        .put(&part, Bytes::from(vec![0u8; 100_000]))
        .await
        .unwrap();
    remote.snapshot_ranges.store(0, Ordering::SeqCst);

    let error = assert_full_or_error(&remote, 100).await.unwrap();

    assert!(error.contains(&part), "{error}");
    assert!(error.contains("larger than 100 bytes"), "{error}");
    let reads = remote.snapshot_ranges.load(Ordering::SeqCst);
    assert!(reads < 50, "{reads} ranged reads");
}

/// The first listing of orphan parts survives a restart: a GC process that lives less than H
/// still deletes them.
#[tokio::test]
async fn test_orphan_count_survives_a_restart() {
    let remote = Arc::new(TestRemote::default());
    let config = Config {
        gc_horizon: Duration::from_millis(300),
        ..gc_config()
    };
    let a = proxy_config(&remote, 1, config.clone()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", "one").await;
    a.engine.flush().await.unwrap();
    a.engine.gc().await.unwrap();
    let orphans = parts_with_no_head(&remote, now_nanos()).await;
    a.engine.gc().await.unwrap();
    let Proxy { dir, engine } = a;
    drop(engine);
    tokio::time::sleep(Duration::from_millis(400)).await;

    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[1; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config,
    )
    .await
    .unwrap();
    engine.gc().await.unwrap();
    let kept = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    assert!(
        orphans.iter().all(|key| kept.contains(key)),
        "a restart starts the monotonic wait again"
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    engine.gc().await.unwrap();

    let left = remote.list(engine::SNAPSHOTS_PREFIX).await.unwrap();
    assert!(orphans.iter().all(|key| !left.contains(key)), "{left:?}");
}

/// A GC on another proxy can delete a part with no head yet. The writer lists the parts after
/// its head: a missing part fails the snapshot, so no proxy trusts a head with a part gone.
#[tokio::test]
async fn test_snapshot_fails_when_a_part_is_gone_after_its_head() {
    let remote = Arc::new(TestRemote::default());
    let a = history_with_entries(&remote).await;
    let b = open_with(&remote, 64).await.unwrap();
    put(&b.engine, "w", "four").await;
    b.engine.flush().await.unwrap();
    remote.drop_part_at_head.store(true, Ordering::SeqCst);

    let result = b.engine.snapshot().await;

    let error = result.unwrap_err().to_string();
    assert!(error.contains("listed after the head"), "{error}");
    drop(a);
}

/// A GC writes a newer snapshot and redacts up to it between the snapshot listing of a proxy and
/// its read of the chains. The proxy must load the newer snapshot, not mark the chains broken.
#[tokio::test]
async fn test_sync_that_races_a_new_snapshot_loads_it() {
    let remote = Arc::new(TestRemote::default());
    let a = history(&remote).await;
    let b = proxy(&remote, 2).await;
    put(&a.engine, "w", "four").await;
    a.engine.flush().await.unwrap();
    a.engine.snapshot().await.unwrap();
    let report = a.engine.gc().await.unwrap();
    assert!(report.redacted_entries > 0, "{report:?}");
    remote.hide_newest_snapshot.store(true, Ordering::SeqCst);

    let report = b.engine.sync().await.unwrap();

    assert!(report.broken.is_empty(), "{:?}", report.broken_causes);
    assert_eq!(keys(&b.engine).await, ["w", "x", "y"]);
}

/// Puts `count` forged snapshots, each one newer than `base`, of `len` bytes. Returns their keys.
async fn forge_snapshots(
    remote: &Arc<TestRemote>,
    base: &str,
    count: u64,
    len: usize,
) -> Vec<String> {
    let (time, _) = base
        .strip_prefix(engine::SNAPSHOTS_PREFIX)
        .unwrap()
        .split_once('-')
        .unwrap();
    let time = time.parse::<u64>().unwrap();
    let mut keys = Vec::new();
    for n in 1..=count {
        let bytes = vec![n as u8; len];
        let key = format!(
            "{}{:020}-{}",
            engine::SNAPSHOTS_PREFIX,
            time + n,
            blake3::hash(&bytes)
        );
        remote.inner.put(&key, Bytes::from(bytes)).await.unwrap();
        keys.push(key);
    }
    keys
}

#[tokio::test]
async fn test_load_tries_at_most_three_snapshots_and_names_each_one() {
    for (forged, loads) in [(2, true), (3, false)] {
        let remote = Arc::new(TestRemote::default());
        let (base, redacted) = history_in_parts(&remote, 1 << 30, 0).await;
        assert!(redacted > 0);
        let keys = forge_snapshots(&remote, &base, forged, 10).await;

        let error = load_after_prune(&remote).await;

        if loads {
            assert_eq!(error, None, "{forged} forged snapshots");
            continue;
        }
        let error = error.expect("three forged snapshots fail the load");
        for key in &keys {
            assert!(error.contains(key.as_str()), "{key} in {error}");
        }
        assert!(error.contains("1 older snapshot not tried"), "{error}");
    }
}

#[tokio::test]
async fn test_snapshot_in_one_object_over_one_part_is_not_read() {
    let remote = Arc::new(TestRemote::default());
    let (base, _) = history_in_parts(&remote, 1 << 30, 0).await;
    let config = Config {
        snapshot_object: 100,
        ..Config::default()
    };
    let keys = forge_snapshots(&remote, &base, 3, 101).await;

    let Err(error) = open_and_sync_with(&remote, 2, config).await else {
        panic!("the pruned journal needs a snapshot");
    };

    for key in &keys {
        let cause = format!("{key}: it is larger than 100 bytes");
        assert!(error.contains(&cause), "{error}");
    }
}
