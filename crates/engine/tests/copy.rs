//! Copies of an object: by reference to the stored chunks, or through a spool file.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::sim::Point;
use engine::{
    Chunking, Config, CopyPath, Engine, EngineError, Policy, PrefixPolicy, SpoolReason, WriteMode,
};
use remote::{MemoryRemote, Remote, RemoteError};
use tempfile::TempDir;

const BUCKET: &str = "bkt";
const WAIT: Duration = Duration::from_secs(5);
/// Large enough for a manifest over the inline limit.
const SIZE: usize = 8 * 1024 * 1024;

/// A memory remote that counts its calls, fails them all while `down`, and can make the next
/// log create ambiguous or hold the manifest or pack PUTs.
struct TestRemote {
    inner: MemoryRemote,
    calls: std::sync::Mutex<BTreeMap<(&'static str, String), u64>>,
    down: AtomicBool,
    ambiguous_log_create: AtomicBool,
    hold_manifests: AtomicBool,
    hold_packs: AtomicBool,
    /// Manifest and pack PUTs that wait for `release`.
    held: AtomicU64,
    release: tokio::sync::Semaphore,
}

impl Default for TestRemote {
    fn default() -> Self {
        Self {
            inner: MemoryRemote::default(),
            calls: Default::default(),
            down: AtomicBool::new(false),
            ambiguous_log_create: AtomicBool::new(false),
            hold_manifests: AtomicBool::new(false),
            hold_packs: AtomicBool::new(false),
            held: AtomicU64::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

impl TestRemote {
    fn count(&self, call: &'static str, key: &str) -> Result<(), RemoteError> {
        let prefix = key.split('/').next().unwrap_or_default().to_string();
        *self
            .calls
            .lock()
            .unwrap()
            .entry((call, prefix))
            .or_default() += 1;
        match self.down.load(Ordering::SeqCst) {
            true => Err(RemoteError::Io(std::io::Error::other("the remote is down"))),
            false => Ok(()),
        }
    }

    fn calls(&self, call: &'static str, prefix: &str) -> u64 {
        let calls = self.calls.lock().unwrap();
        calls.get(&(call, prefix.to_string())).copied().unwrap_or(0)
    }

    fn reset(&self) {
        self.calls.lock().unwrap().clear();
    }

    async fn held_manifests(&self, count: u64) {
        while self.held.load(Ordering::SeqCst) < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[async_trait::async_trait]
impl Remote for TestRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.count("put", key)?;
        let held = (key.starts_with(engine::MANIFESTS_PREFIX)
            && self.hold_manifests.load(Ordering::SeqCst))
            || (key.starts_with(engine::PACKS_PREFIX) && self.hold_packs.load(Ordering::SeqCst));
        if held {
            self.held.fetch_add(1, Ordering::SeqCst);
            self.release.acquire().await.unwrap().forget();
        }
        self.inner.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.count("create", key)?;
        self.inner.create(key, data).await?;
        if key.starts_with(journal::LOG_PREFIX)
            && self.ambiguous_log_create.swap(false, Ordering::SeqCst)
        {
            return Err(RemoteError::Io(std::io::Error::other("timeout")));
        }
        Ok(())
    }

    async fn get(&self, key: &str, max_len: u64) -> Result<Option<Bytes>, RemoteError> {
        self.count("get", key)?;
        self.inner.get(key, max_len).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        self.count("get_range", key)?;
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        self.count("list", prefix)?;
        self.inner.list(prefix).await
    }
}

struct Proxy {
    dir: TempDir,
    engine: Engine<TestRemote>,
}

/// Every copy of at least 1 byte goes by reference.
fn config() -> Config {
    Config {
        copy_ref_min: 1,
        ..Config::default()
    }
}

async fn open(remote: &Arc<TestRemote>, seed: u8, dir: TempDir, config: Config) -> Proxy {
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

async fn proxy(remote: &Arc<TestRemote>, seed: u8, config: Config) -> Proxy {
    open(remote, seed, tempfile::tempdir().unwrap(), config).await
}

fn data(seed: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut out);
    out
}

async fn put(engine: &Engine<TestRemote>, key: &str, body: &[u8]) {
    engine
        .put(
            BUCKET,
            key,
            Bytes::copy_from_slice(body),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
}

async fn get(engine: &Engine<TestRemote>, key: &str) -> Result<Vec<u8>, EngineError> {
    Ok(engine.get(BUCKET, key, None).await?.data.to_vec())
}

/// A proxy with `src` of SIZE bytes in the remote.
async fn with_source(remote: &Arc<TestRemote>, config: Config) -> (Proxy, Vec<u8>) {
    let proxy = proxy(remote, 1, config).await;
    proxy.engine.create_bucket(BUCKET, None).await.unwrap();
    let body = data(1, SIZE);
    put(&proxy.engine, "src", &body).await;
    proxy.engine.flush().await.unwrap();
    (proxy, body)
}

async fn copy(
    engine: &Engine<TestRemote>,
    target: &str,
    mode: WriteMode,
) -> Result<engine::Copied, EngineError> {
    engine
        .copy((BUCKET, "src"), (BUCKET, target), None, mode, WAIT)
        .await
}

/// Holds the wall clock of this thread at the system time, and returns it: the test moves it.
fn hold_clock() -> u64 {
    let now = journal::wall_clock_nanos();
    journal::set_manual_wall(Some(now));
    now
}

/// Nanoseconds past half of the default horizon.
fn past_half_horizon() -> u64 {
    (Config::default().gc_horizon / 2 + Duration::from_secs(1)).as_nanos() as u64
}

fn spool_files(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir.join("buffer/spool")).map_or(0, |entries| entries.count())
}

#[tokio::test]
async fn test_reference_copy_moves_no_data() {
    let remote = Arc::new(TestRemote::default());
    let (a, body) = with_source(&remote, config()).await;
    remote.reset();

    let copied = copy(&a.engine, "dst", WriteMode::Overwrite).await.unwrap();

    assert_eq!(copied.path, CopyPath::Reference);
    assert_eq!(remote.calls("put", "packs"), 0);
    assert_eq!(remote.calls("get", "packs"), 0);
    assert_eq!(remote.calls("get_range", "packs"), 0);
    assert_eq!(remote.calls("put", "manifests"), 1);
    assert_eq!(remote.calls("create", "log"), 1);
    assert_eq!(a.engine.buffered_bytes().await, 0);
    assert_eq!(copied.info.content_hash, *blake3::hash(&body).as_bytes());
    assert_eq!(copied.info.size, SIZE as u64);
    assert_eq!(get(&a.engine, "dst").await.unwrap(), body);
}

#[tokio::test]
async fn test_reference_copy_reads_on_another_proxy() {
    let remote = Arc::new(TestRemote::default());
    let (a, body) = with_source(&remote, config()).await;
    copy(&a.engine, "dst", WriteMode::Overwrite).await.unwrap();
    let b = proxy(&remote, 2, config()).await;

    b.engine.sync().await.unwrap();

    assert_eq!(get(&b.engine, "dst").await.unwrap(), body);
}

#[tokio::test]
async fn test_reference_copy_onto_itself_replaces_the_metadata() {
    let remote = Arc::new(TestRemote::default());
    let (a, body) = with_source(&remote, config()).await;
    let metadata = BTreeMap::from([("x-amz-meta-k".to_string(), "v".to_string())]);

    let copied = a
        .engine
        .copy(
            (BUCKET, "src"),
            (BUCKET, "src"),
            Some(metadata.clone()),
            WriteMode::Overwrite,
            WAIT,
        )
        .await
        .unwrap();

    assert_eq!(copied.path, CopyPath::Reference);
    let read = a.engine.get(BUCKET, "src", None).await.unwrap();
    assert_eq!(read.info.metadata, metadata);
    assert_eq!(read.info.content_hash, *blake3::hash(&body).as_bytes());
}

#[tokio::test]
async fn test_copy_takes_the_spool_when_off_or_small() {
    let remote = Arc::new(TestRemote::default());
    let (off, _) = with_source(&remote, Config::default()).await;
    let small = proxy(
        &remote,
        2,
        Config {
            copy_ref_min: SIZE as u64 + 1,
            ..Config::default()
        },
    )
    .await;
    small.engine.sync().await.unwrap();

    let first = copy(&off.engine, "a", WriteMode::Overwrite).await.unwrap();
    let second = copy(&small.engine, "b", WriteMode::Overwrite)
        .await
        .unwrap();

    assert_eq!(first.path, CopyPath::Spool(SpoolReason::Off));
    assert_eq!(second.path, CopyPath::Spool(SpoolReason::Small));
}

#[tokio::test]
async fn test_copy_of_a_buffered_source_takes_the_spool() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy(&remote, 1, config()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    let body = data(1, SIZE);
    put(&a.engine, "src", &body).await;

    let copied = copy(&a.engine, "dst", WriteMode::Overwrite).await.unwrap();

    assert_eq!(copied.path, CopyPath::Spool(SpoolReason::BufferedSource));
    assert_eq!(get(&a.engine, "dst").await.unwrap(), body);
}

/// A read gives the buffer before the index: an acked reference copy under an older buffered
/// put would not read until the flush.
#[tokio::test]
async fn test_copy_onto_a_buffered_target_takes_the_spool() {
    let remote = Arc::new(TestRemote::default());
    let (a, body) = with_source(&remote, config()).await;
    put(&a.engine, "dst", b"older").await;

    let copied = copy(&a.engine, "dst", WriteMode::Overwrite).await.unwrap();

    assert_eq!(copied.path, CopyPath::Spool(SpoolReason::BufferedTarget));
    assert_eq!(get(&a.engine, "dst").await.unwrap(), body);
}

#[tokio::test]
async fn test_copy_to_a_prefix_with_other_chunks_takes_the_spool() {
    let remote = Arc::new(TestRemote::default());
    let fixed = PrefixPolicy {
        bucket: BUCKET.to_string(),
        prefix: "fixed/".to_string(),
        policy: Policy {
            chunking: Chunking::Fixed,
            ..Policy::default()
        },
    };
    let (a, body) = with_source(
        &remote,
        Config {
            policies: vec![fixed],
            ..config()
        },
    )
    .await;

    let copied = copy(&a.engine, "fixed/dst", WriteMode::Overwrite)
        .await
        .unwrap();

    assert_eq!(copied.path, CopyPath::Spool(SpoolReason::Policy));
    assert_eq!(get(&a.engine, "fixed/dst").await.unwrap(), body);
}

/// GC rule 1: with a broken chain, a copy names no stored chunk.
#[tokio::test]
async fn test_copy_with_a_broken_chain_takes_the_spool() {
    let remote = Arc::new(TestRemote::default());
    let (a, body) = with_source(&remote, config()).await;
    let c = proxy(&remote, 3, config()).await;
    c.engine.sync().await.unwrap();
    put(&c.engine, "other", b"other").await;
    c.engine.flush().await.unwrap();
    let key = journal::entry_key(c.engine.node(), 0);
    let mut tampered = remote.get(&key, u64::MAX).await.unwrap().unwrap().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    remote.put(&key, Bytes::from(tampered)).await.unwrap();
    let b = proxy(&remote, 2, config()).await;
    assert!(!b.engine.sync().await.unwrap().broken.is_empty());

    let copied = copy(&b.engine, "dst", WriteMode::Overwrite).await.unwrap();

    assert_eq!(copied.path, CopyPath::Spool(SpoolReason::NoFreshSync));
    assert_eq!(get(&b.engine, "dst").await.unwrap(), body);
    drop(a);
}

/// The sync before the copy fails, and nothing went to the remote yet: the spool copy acks.
#[tokio::test]
async fn test_copy_with_the_remote_down_and_an_old_sync_takes_the_spool() {
    let remote = Arc::new(TestRemote::default());
    let start = hold_clock();
    let (a, body) = with_source(&remote, config()).await;
    journal::set_manual_wall(Some(start + past_half_horizon()));
    remote.down.store(true, Ordering::SeqCst);

    let copied = copy(&a.engine, "dst", WriteMode::Overwrite).await.unwrap();
    remote.down.store(false, Ordering::SeqCst);
    a.engine.flush().await.unwrap();
    let b = proxy(&remote, 2, config()).await;
    b.engine.sync().await.unwrap();

    assert_eq!(copied.path, CopyPath::Spool(SpoolReason::RemoteDown));
    assert_eq!(get(&b.engine, "dst").await.unwrap(), body);
}

/// With a fresh sync the first remote call is the manifest PUT: after it, no spool copy.
#[tokio::test]
async fn test_copy_with_the_remote_down_and_a_fresh_sync_fails_with_no_spool() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    remote.down.store(true, Ordering::SeqCst);

    let copied = copy(&a.engine, "dst", WriteMode::Overwrite).await;

    assert!(copied.is_err(), "{copied:?}");
    assert_eq!(a.engine.buffered_bytes().await, 0);
    assert_eq!(spool_files(a.dir.path()), 0);
}

/// The entry may be in the remote: a spool copy now would write the object a second time.
#[tokio::test]
async fn test_ambiguous_entry_create_fails_the_copy_with_no_spool() {
    let remote = Arc::new(TestRemote::default());
    let (a, body) = with_source(&remote, config()).await;
    remote.ambiguous_log_create.store(true, Ordering::SeqCst);

    let copied = copy(&a.engine, "dst", WriteMode::Overwrite).await;

    assert!(copied.is_err(), "{copied:?}");
    assert_eq!(a.engine.buffered_bytes().await, 0);
    assert_eq!(spool_files(a.dir.path()), 0);
    // The entry landed: the next flush finds it from the intent and applies it.
    a.engine.flush().await.unwrap();
    assert_eq!(get(&a.engine, "dst").await.unwrap(), body);
}

#[tokio::test]
async fn test_crash_after_the_entry_of_a_copy_recovers_at_the_next_flush() {
    let remote = Arc::new(TestRemote::default());
    let (a, body) = with_source(&remote, config()).await;

    engine::sim::arm_crash(Some(Point::CopyRefCommit));
    let crashed = copy(&a.engine, "dst", WriteMode::Overwrite).await;
    engine::sim::arm_crash(None);
    let Proxy { dir, engine } = a;
    drop(engine);
    let a = open(&remote, 1, dir, config()).await;
    a.engine.flush().await.unwrap();

    assert!(
        matches!(crashed, Err(EngineError::SimCrash(_))),
        "{crashed:?}"
    );
    assert_eq!(get(&a.engine, "dst").await.unwrap(), body);
}

#[tokio::test]
async fn test_crash_before_the_manifest_of_a_copy_writes_nothing() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    remote.reset();

    engine::sim::arm_crash(Some(Point::CopyRefPlan));
    let crashed = copy(&a.engine, "dst", WriteMode::Overwrite).await;
    engine::sim::arm_crash(None);

    assert!(
        matches!(crashed, Err(EngineError::SimCrash(_))),
        "{crashed:?}"
    );
    assert_eq!(remote.calls("put", "manifests"), 0);
    assert_eq!(remote.calls("create", "log"), 0);
    assert!(get(&a.engine, "dst").await.is_err());
}

/// GC rule 2: a plan older than H/2 can name a pack that the GC deleted.
#[tokio::test]
async fn test_copy_with_a_stale_plan_is_refused() {
    let remote = Arc::new(TestRemote::default());
    let start = hold_clock();
    let (a, _) = with_source(&remote, config()).await;

    engine::sim::arm_action(Point::CopyRefManifest, move || {
        journal::set_manual_wall(Some(start + past_half_horizon()))
    });
    let copied = copy(&a.engine, "dst", WriteMode::Overwrite).await;

    assert!(matches!(copied, Err(EngineError::StalePlan)), "{copied:?}");
    assert!(get(&a.engine, "dst").await.is_err());
}

#[tokio::test]
async fn test_create_only_copy_onto_an_object_fails() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    put(&a.engine, "dst", b"there").await;
    a.engine.flush().await.unwrap();

    let copied = copy(&a.engine, "dst", WriteMode::CreateOnly).await;

    assert!(
        matches!(copied, Err(EngineError::PreconditionFailed { .. })),
        "{copied:?}"
    );
    assert_eq!(get(&a.engine, "dst").await.unwrap(), b"there");
}

#[tokio::test]
async fn test_copy_onto_a_create_only_prefix_fails_on_an_object() {
    let remote = Arc::new(TestRemote::default());
    let locked = PrefixPolicy {
        bucket: BUCKET.to_string(),
        prefix: "locked/".to_string(),
        policy: Policy {
            create_only: true,
            ..Policy::default()
        },
    };
    let (a, _) = with_source(
        &remote,
        Config {
            policies: vec![locked],
            ..config()
        },
    )
    .await;
    put(&a.engine, "locked/dst", b"there").await;
    a.engine.flush().await.unwrap();

    let copied = copy(&a.engine, "locked/dst", WriteMode::Overwrite).await;

    assert!(
        matches!(copied, Err(EngineError::PreconditionFailed { .. })),
        "{copied:?}"
    );
}

#[tokio::test]
async fn test_if_match_copy_checks_the_target() {
    let remote = Arc::new(TestRemote::default());
    let (a, body) = with_source(&remote, config()).await;
    put(&a.engine, "dst", b"there").await;
    a.engine.flush().await.unwrap();
    let there = *blake3::hash(b"there").as_bytes();

    let wrong = copy(&a.engine, "dst", WriteMode::IfMatch(vec![[0; 32]])).await;
    let right = copy(&a.engine, "dst", WriteMode::IfMatch(vec![there]))
        .await
        .unwrap();

    assert!(
        matches!(wrong, Err(EngineError::PreconditionFailed { .. })),
        "{wrong:?}"
    );
    assert_eq!(right.path, CopyPath::Reference);
    assert_eq!(get(&a.engine, "dst").await.unwrap(), body);
}

/// The same size limit as a put: the buffer limit of this proxy, or 5 GiB.
#[tokio::test]
async fn test_copy_over_the_object_limit_fails() {
    let remote = Arc::new(TestRemote::default());
    let (_a, _) = with_source(&remote, config()).await;
    let b = proxy(
        &remote,
        2,
        Config {
            buffer_limit: SIZE as u64 / 2,
            ..config()
        },
    )
    .await;
    b.engine.sync().await.unwrap();

    let copied = copy(&b.engine, "dst", WriteMode::Overwrite).await;

    assert!(
        matches!(copied, Err(EngineError::ObjectTooLarge { .. })),
        "{copied:?}"
    );
}

#[tokio::test]
async fn test_copy_with_metadata_over_the_limit_fails() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    let metadata = BTreeMap::from([("x-amz-meta-k".to_string(), "v".repeat(70 * 1024))]);

    let copied = a
        .engine
        .copy(
            (BUCKET, "src"),
            (BUCKET, "dst"),
            Some(metadata),
            WriteMode::Overwrite,
            WAIT,
        )
        .await;

    assert!(
        matches!(copied, Err(EngineError::MetadataTooLarge { .. })),
        "{copied:?}"
    );
}

#[tokio::test]
async fn test_copy_while_the_clock_is_ahead_fails() {
    let remote = Arc::new(TestRemote::default());
    let start = journal::wall_clock_nanos();
    let (a, _) = with_source(&remote, config()).await;
    let back = start - 2 * Config::default().retention.as_nanos() as u64;

    journal::set_manual_wall(Some(back));
    let copied = copy(&a.engine, "dst", WriteMode::Overwrite).await;
    journal::set_manual_wall(None);

    assert!(
        matches!(copied, Err(EngineError::ClockAhead { .. })),
        "{copied:?}"
    );
}

/// Between its check and its apply, a reference copy is in no local state: a second
/// conditional write to its key must not pass its own check then.
#[tokio::test]
async fn test_conditional_write_during_a_reference_copy_gets_a_conflict() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    remote.hold_manifests.store(true, Ordering::SeqCst);

    let (copied, raced) = tokio::join!(copy(&a.engine, "dst", WriteMode::CreateOnly), async {
        remote.held_manifests(1).await;
        let raced = a
            .engine
            .put(
                BUCKET,
                "dst",
                Bytes::from_static(b"raced"),
                BTreeMap::new(),
                WriteMode::CreateOnly,
            )
            .await;
        remote.release.add_permits(1);
        raced
    });

    assert_eq!(copied.unwrap().path, CopyPath::Reference);
    assert!(
        matches!(raced, Err(EngineError::Conflict { .. })),
        "{raced:?}"
    );
}

#[tokio::test]
async fn test_at_most_four_reference_copies_run_at_once() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    remote.hold_manifests.store(true, Ordering::SeqCst);
    let targets: Vec<String> = (0..5).map(|n| format!("dst{n}")).collect();

    let copies = futures_util::future::join_all(
        targets
            .iter()
            .map(|target| copy(&a.engine, target, WriteMode::Overwrite)),
    );
    let check = async {
        remote.held_manifests(4).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let held = remote.held.load(Ordering::SeqCst);
        remote.release.add_permits(5);
        held
    };
    let (copied, held) = tokio::join!(copies, check);

    assert_eq!(held, 4);
    for copied in copied {
        assert_eq!(copied.unwrap().path, CopyPath::Reference);
    }
}

/// The source manifest and the new one are in memory until the PUT ends: they hold room in the
/// read budget as GET pieces do.
#[tokio::test]
async fn test_reference_copy_holds_read_budget_for_its_manifests() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    let budget = a.engine.read_state().budget_free;
    remote.hold_manifests.store(true, Ordering::SeqCst);

    let (copied, during) = tokio::join!(copy(&a.engine, "dst", WriteMode::Overwrite), async {
        remote.held_manifests(1).await;
        let during = a.engine.read_state().budget_free;
        remote.release.add_permits(1);
        during
    });

    assert_eq!(copied.unwrap().path, CopyPath::Reference);
    assert!(during < budget, "{during} of {budget}");
    assert_eq!(a.engine.read_state().budget_free, budget);
}

/// A reference copy into an empty bucket is in no local state until its apply: a delete of that
/// bucket must still see it, or the bucket comes back with the object in it.
#[tokio::test]
async fn test_delete_of_the_target_bucket_during_a_reference_copy_is_refused() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    a.engine.create_bucket("other", None).await.unwrap();
    remote.hold_manifests.store(true, Ordering::SeqCst);

    let copy = a.engine.copy(
        (BUCKET, "src"),
        ("other", "dst"),
        None,
        WriteMode::Overwrite,
        WAIT,
    );
    let (copied, deleted) = tokio::join!(copy, async {
        remote.held_manifests(1).await;
        let deleted = a.engine.delete_bucket("other").await;
        remote.release.add_permits(1);
        deleted
    });

    assert_eq!(copied.unwrap().path, CopyPath::Reference);
    assert!(
        matches!(deleted, Err(EngineError::BucketNotEmpty(_))),
        "{deleted:?}"
    );
}

/// A decoded source manifest is outside the read budget until the room is taken: a copy that waits
/// for its slot must not hold one, or 16 copies hold 16 of them.
#[tokio::test]
async fn test_copy_that_waits_for_its_slot_holds_no_source_manifest() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    remote.hold_manifests.store(true, Ordering::SeqCst);
    let before = engine::sim::copy_sources();
    let targets: Vec<String> = (0..6).map(|n| format!("dst{n}")).collect();

    let copies = futures_util::future::join_all(
        targets
            .iter()
            .map(|target| copy(&a.engine, target, WriteMode::Overwrite)),
    );
    let check = async {
        remote.held_manifests(4).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let decoded = engine::sim::copy_sources() - before;
        remote.release.add_permits(6);
        decoded
    };
    let (copied, decoded) = tokio::join!(copies, check);

    assert_eq!(decoded, 4);
    for copied in copied {
        assert_eq!(copied.unwrap().path, CopyPath::Reference);
    }
}

/// A flush holds its lock for its whole backlog. A copy that waits there must give back its read
/// room and its slot first, or every GET and copy waits for the flush too.
#[tokio::test]
async fn test_copy_that_waits_for_a_flush_holds_no_read_room() {
    let remote = Arc::new(TestRemote::default());
    let (a, _) = with_source(&remote, config()).await;
    let budget = a.engine.read_state().budget_free;
    put(&a.engine, "other", &data(2, 1024)).await;
    remote.hold_packs.store(true, Ordering::SeqCst);

    let (flushed, copied, during) = tokio::join!(
        a.engine.flush(),
        async {
            remote.held_manifests(1).await;
            copy(&a.engine, "dst", WriteMode::Overwrite).await
        },
        async {
            remote.held_manifests(1).await;
            while remote.calls("put", "manifests") == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            let during = a.engine.read_state().budget_free;
            remote.release.add_permits(1);
            during
        }
    );

    flushed.unwrap();
    assert_eq!(copied.unwrap().path, CopyPath::Reference);
    assert_eq!(during, budget);
}
