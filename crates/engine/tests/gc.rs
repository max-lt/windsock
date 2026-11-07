//! GC rules on a short horizon. The model in `protocol-check/src/gc.rs` is the reference.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, EngineError, GcReport, WriteMode};
use remote::{MemoryRemote, Remote, RemoteError, Sweep};
use tempfile::TempDir;

const BUCKET: &str = "bkt";
const HORIZON: Duration = Duration::from_millis(600);

/// How the next create of a [`TestRemote`] fails.
const CREATE_OK: u8 = 0;
/// The create stores nothing and fails.
const CREATE_LOST: u8 = 1;
/// The create stores the object and then fails, as a timeout after the write does.
const CREATE_AMBIGUOUS: u8 = 2;

#[derive(Default)]
struct TestRemote {
    inner: MemoryRemote,
    next_create: AtomicU8,
    /// Deletes that work before every next delete fails, as a GC that dies. Negative: no limit.
    deletes_left: AtomicI64,
}

impl TestRemote {
    fn new() -> Self {
        Self {
            deletes_left: AtomicI64::new(-1),
            ..Self::default()
        }
    }
}

#[async_trait::async_trait]
impl Remote for TestRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        let timeout = || RemoteError::Io(std::io::Error::other("timeout"));
        // The fault is for a journal entry, not for the node marker that comes before it.
        if !key.starts_with(journal::LOG_PREFIX) {
            return self.inner.create(key, data).await;
        }

        match self.next_create.swap(CREATE_OK, Ordering::SeqCst) {
            CREATE_LOST => Err(timeout()),
            CREATE_AMBIGUOUS => {
                self.inner.create(key, data).await?;
                Err(timeout())
            }
            _ => self.inner.create(key, data).await,
        }
    }

    async fn get(&self, key: &str, max_len: u64) -> Result<Option<Bytes>, RemoteError> {
        self.inner.get(key, max_len).await
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
        if self.deletes_left.fetch_sub(1, Ordering::SeqCst) == 0 {
            self.deletes_left.store(0, Ordering::SeqCst);
            return Err(RemoteError::Io(std::io::Error::other("the GC died")));
        }
        self.inner.delete(key).await
    }
}

struct Proxy {
    _dir: TempDir,
    engine: Engine<TestRemote>,
}

/// The shortest retention of the tests. A write must reach the journal within it.
const SHORT_RETENTION: Duration = Duration::from_secs(1);

fn config(retention: Duration) -> Config {
    Config {
        gc_horizon: HORIZON,
        retention: retention.max(SHORT_RETENTION),
        late_margin: Duration::ZERO,
        ..Config::default()
    }
}

async fn proxy_with(remote: &Arc<TestRemote>, seed: u8, config: Config) -> Proxy {
    hold_clock();
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[seed; 32]);
    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        key,
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config,
    )
    .await
    .unwrap();
    Proxy { _dir: dir, engine }
}

async fn proxy(remote: &Arc<TestRemote>, seed: u8) -> Proxy {
    proxy_with(remote, seed, config(Duration::ZERO)).await
}

fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut out);
    out
}

async fn put(engine: &Engine<TestRemote>, key: &str, data: &[u8]) {
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

async fn get(engine: &Engine<TestRemote>, key: &str) -> Result<Vec<u8>, EngineError> {
    Ok(engine.get(BUCKET, key, None).await?.data.to_vec())
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

async fn count(remote: &TestRemote, prefix: &str) -> usize {
    remote.list(prefix).await.unwrap().len()
}

/// A bucket with one flushed object, then deleted and flushed again.
async fn dead_object(engine: &Engine<TestRemote>, data: &[u8]) {
    engine.create_bucket(BUCKET, None).await.unwrap();
    put(engine, "dead", data).await;
    engine.flush().await.unwrap();
    engine.delete(BUCKET, "dead").await.unwrap();
    engine.flush().await.unwrap();
    past_retention().await;
}

thread_local! {
    /// The manual wall clock of the test on this thread: time moves only when the test says so,
    /// so a slow machine does not change what the GC rules see.
    static NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// A fixed start, far from the system clock of any machine.
const START: u64 = 1_900_000_000_000_000_000;

/// Sets the manual clock of this thread to its current value, from START at the first call.
fn hold_clock() {
    let now = NOW.with(|now| {
        if now.get() == 0 {
            now.set(START);
        }
        now.get()
    });
    journal::set_manual_wall(Some(now));
}

fn advance(by: Duration) {
    hold_clock();
    NOW.with(|now| now.set(now.get() + by.as_nanos() as u64));
    hold_clock();
}

/// Past the short retention: a GC can prune the versions written before.
async fn past_retention() {
    advance(SHORT_RETENTION + Duration::from_millis(20));
}

async fn past_horizon() {
    advance(HORIZON + Duration::from_millis(100));
}

async fn past_half_horizon() {
    advance(HORIZON / 2 + Duration::from_millis(100));
}

#[tokio::test]
async fn test_dead_pack_is_deleted_only_a_horizon_after_its_condemn() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    dead_object(&a.engine, &random_bytes(1, 100_000)).await;

    let first = a.engine.gc().await.unwrap();
    let again = a.engine.gc().await.unwrap();
    assert_eq!(first.condemned_packs, 1);
    assert_eq!(
        again,
        GcReport::default(),
        "a condemn waits for the horizon"
    );
    assert_eq!(count(&remote, "packs/").await, 1);

    past_horizon().await;
    let late = a.engine.gc().await.unwrap();

    assert_eq!(late.deleted_packs, 1);
    assert_eq!(count(&remote, "packs/").await, 0);
}

#[tokio::test]
async fn test_live_object_is_never_condemned() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "live", b"data").await;
    a.engine.flush().await.unwrap();

    a.engine.gc().await.unwrap();
    past_horizon().await;
    let report = a.engine.gc().await.unwrap();

    assert_eq!(report.condemned_packs, 0);
    assert_eq!(report.deleted_packs, 0);
    assert_eq!(get(&a.engine, "live").await.unwrap(), b"data");
}

#[tokio::test]
async fn test_retention_keeps_an_overwritten_version() {
    for (retention, condemned) in [(Duration::from_secs(600), 0), (Duration::ZERO, 1)] {
        let remote = Arc::new(TestRemote::new());
        let a = proxy_with(&remote, 1, config(retention)).await;
        a.engine.create_bucket(BUCKET, None).await.unwrap();
        put(&a.engine, "k", &random_bytes(1, 100_000)).await;
        a.engine.flush().await.unwrap();
        put(&a.engine, "k", &random_bytes(2, 100_000)).await;
        a.engine.flush().await.unwrap();
        past_retention().await;

        let report = a.engine.gc().await.unwrap();

        assert_eq!(report.condemned_packs, condemned, "retention {retention:?}");
    }
}

#[tokio::test]
async fn test_orphan_pack_is_deleted() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    let orphan = format!("packs/{}", "ab".repeat(32));
    remote
        .put(&orphan, Bytes::from("partial flush"))
        .await
        .unwrap();

    assert_eq!(a.engine.gc().await.unwrap().condemned_packs, 1);
    past_horizon().await;

    assert_eq!(a.engine.gc().await.unwrap().deleted_packs, 1);
    assert!(remote.get(&orphan, u64::MAX).await.unwrap().is_none());
}

/// Large metadata pushes the manifest past the inline limit, with a small object.
#[tokio::test]
async fn test_dead_external_manifest_is_deleted() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    let metadata = BTreeMap::from([("x-amz-meta-note".to_string(), "n".repeat(5000))]);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine
        .put(
            BUCKET,
            "dead",
            Bytes::from("data"),
            metadata,
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
    a.engine.flush().await.unwrap();
    a.engine.delete(BUCKET, "dead").await.unwrap();
    a.engine.flush().await.unwrap();
    assert_eq!(count(&remote, "manifests/").await, 1);
    past_retention().await;

    assert_eq!(a.engine.gc().await.unwrap().condemned_manifests, 1);
    past_horizon().await;

    assert_eq!(a.engine.gc().await.unwrap().deleted_manifests, 1);
    assert_eq!(count(&remote, "manifests/").await, 0);
}

/// Rule 1: a writer whose last sync is older than H/2 syncs before it dedups,
/// so it sees the condemn and uploads the chunks again.
#[tokio::test]
async fn test_writer_with_an_old_sync_does_not_dedup_against_a_condemned_pack() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    let data = random_bytes(1, 100_000);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", &data).await;
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();
    a.engine.delete(BUCKET, "x").await.unwrap();
    a.engine.flush().await.unwrap();
    past_retention().await;
    a.engine.gc().await.unwrap();

    past_half_horizon().await;
    put(&b.engine, "y", &data).await;
    b.engine.flush().await.unwrap();
    past_horizon().await;
    let report = a.engine.gc().await.unwrap();

    assert_eq!(report.deleted_packs, 1, "the condemned pack is gone");
    assert_eq!(count(&remote, "packs/").await, 1, "b uploaded its own pack");
    assert_eq!(get(&a.engine, "y").await.unwrap(), data);
}

/// Rule 3: a put from a writer that did not know the condemn names the pack;
/// the GC sync a horizon later finds the pack live and keeps it.
#[tokio::test]
async fn test_put_that_did_not_know_the_condemn_keeps_the_pack() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    let data = random_bytes(1, 100_000);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", &data).await;
    a.engine.flush().await.unwrap();
    a.engine.delete(BUCKET, "x").await.unwrap();
    a.engine.flush().await.unwrap();
    past_retention().await;
    // A sync before the condemn: b dedups with no new sync.
    b.engine.sync().await.unwrap();
    assert_eq!(a.engine.gc().await.unwrap().condemned_packs, 1);

    put(&b.engine, "y", &data).await;
    b.engine.flush().await.unwrap();
    assert_eq!(
        count(&remote, "packs/").await,
        1,
        "b deduped against the pack"
    );
    past_horizon().await;
    let report = a.engine.gc().await.unwrap();

    assert_eq!(report.deleted_packs, 0);
    assert_eq!(get(&a.engine, "y").await.unwrap(), data);
    assert_eq!(get(&b.engine, "y").await.unwrap(), data);
}

/// Rule 2: a plan older than H/2 that never reached the remote is planned again.
#[tokio::test]
async fn test_old_intent_that_was_never_written_is_planned_again() {
    let remote = Arc::new(TestRemote::new());
    // The write waits past H/2 in the buffer: a retention of 2 H keeps it young.
    let a = proxy_with(&remote, 1, config(2 * HORIZON)).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "k", b"data").await;
    remote.next_create.store(CREATE_LOST, Ordering::SeqCst);
    assert!(a.engine.flush().await.is_err());

    past_half_horizon().await;
    a.engine.flush().await.unwrap();

    assert_eq!(count(&remote, "log/").await, 1);
    assert_eq!(
        count(&remote, "packs/").await,
        2,
        "the new plan uploads new packs"
    );
    assert_eq!(get(&a.engine, "k").await.unwrap(), b"data");
}

/// Rule 2 with exactly-once: an old intent that did reach the remote is not written twice.
#[tokio::test]
async fn test_old_intent_that_was_written_is_not_written_again() {
    let remote = Arc::new(TestRemote::new());
    // The write waits past H/2 in the buffer: a retention of 2 H keeps it young.
    let a = proxy_with(&remote, 1, config(2 * HORIZON)).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "k", b"data").await;
    remote.next_create.store(CREATE_AMBIGUOUS, Ordering::SeqCst);
    assert!(a.engine.flush().await.is_err());

    past_half_horizon().await;
    a.engine.flush().await.unwrap();

    assert_eq!(count(&remote, "log/").await, 1);
    assert_eq!(count(&remote, "packs/").await, 1);
    assert_eq!(get(&a.engine, "k").await.unwrap(), b"data");
}

/// One broken chain among three: the two others sync, the GC refuses to run,
/// and a flush does not dedup. Once the chain reads back whole, all goes on.
#[tokio::test]
async fn test_broken_chain_fails_alone_and_recovers() {
    let remote = Arc::new(TestRemote::new());
    let writers = [
        proxy(&remote, 1).await,
        proxy(&remote, 2).await,
        proxy(&remote, 3).await,
    ];
    writers[0].engine.create_bucket(BUCKET, None).await.unwrap();
    writers[0].engine.flush().await.unwrap();
    for (i, writer) in writers.iter().enumerate() {
        put(
            &writer.engine,
            &format!("k{i}"),
            &random_bytes(i as u8, 1000),
        )
        .await;
        writer.engine.flush().await.unwrap();
    }
    let broken = writers[2].engine.node();
    let key = journal::entry_key(broken, 0);
    let good = remote.get(&key, u64::MAX).await.unwrap().unwrap();
    let mut tampered = good.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    remote.put(&key, Bytes::from(tampered)).await.unwrap();

    let reader = proxy(&remote, 4).await;
    let report = reader.engine.sync().await.unwrap();

    assert_eq!(report.broken, [broken]);
    assert_eq!(keys(&reader.engine).await, ["k0", "k1"]);
    assert!(matches!(
        reader.engine.gc().await,
        Err(EngineError::BrokenChains(nodes)) if nodes == [broken]
    ));
    let packs = count(&remote, "packs/").await;
    put(&reader.engine, "copy", &random_bytes(0, 1000)).await;
    reader.engine.flush().await.unwrap();
    assert_eq!(
        count(&remote, "packs/").await,
        packs + 1,
        "no dedup with a broken chain"
    );

    remote.put(&key, good).await.unwrap();
    // The first entry of the chain failed its MAC: a normal sync skips it, and the full audit
    // of the next GC run reads it again.
    let report = reader.engine.sync().await.unwrap();
    assert_eq!((report.broken.len(), report.skipped), (1, 1));

    reader.engine.gc().await.unwrap();
    assert_eq!(keys(&reader.engine).await, ["copy", "k0", "k1", "k2"]);
}

/// An entry far ahead of every clock would raise the stable HLC past real time, and a proxy with
/// a correct clock could then write under the prune bound. The chain is broken: the GC does not
/// run.
#[tokio::test]
async fn test_gc_refuses_to_run_with_an_entry_far_ahead_of_the_clocks() {
    let remote = Arc::new(TestRemote::new());
    // The first proxy writes the key check of the remote before any entry.
    drop(proxy(&remote, 1).await);
    let ahead = SigningKey::from_bytes(&[9u8; 32]);
    let node = model::NodeId::from_bytes(ahead.verifying_key().to_bytes());
    let far_future = u64::MAX / 2;
    let entry = journal::Entry::sign(
        &ahead,
        0,
        [0u8; 32],
        far_future,
        journal::Seen::new(),
        vec![],
        engine::RepoKey::from_hex(&"07".repeat(32))
            .unwrap()
            .keys()
            .sealer(),
    );
    remote
        .put(&entry.remote_key(), Bytes::from(entry.to_wire()))
        .await
        .unwrap();
    remote
        .put(&journal::node_key(node), Bytes::new())
        .await
        .unwrap();
    let a = proxy(&remote, 1).await;

    let result = a.engine.gc().await;

    assert!(
        matches!(result, Err(EngineError::BrokenChains(ref nodes)) if nodes == &[node]),
        "{result:?}"
    );
}

#[tokio::test]
async fn test_gc_prunes_an_old_delete_from_the_index() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    dead_object(&a.engine, b"data").await;
    assert_eq!(
        a.engine
            .versions(BUCKET, "dead")
            .unwrap()
            .unwrap()
            .versions
            .len(),
        2
    );

    let report = a.engine.gc().await.unwrap();

    assert_eq!(report.pruned_keys, 1);
    assert_eq!(a.engine.versions(BUCKET, "dead").unwrap(), None);
}

/// Two objects share their chunks. A delete of one keeps the chunks that the other uses.
#[tokio::test]
async fn test_chunks_shared_with_a_live_object_stay() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    let data = random_bytes(5, 300_000);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "kept", &data).await;
    a.engine.flush().await.unwrap();
    put(&a.engine, "copy", &data).await;
    a.engine.flush().await.unwrap();
    a.engine.delete(BUCKET, "copy").await.unwrap();
    a.engine.flush().await.unwrap();

    a.engine.gc().await.unwrap();
    past_horizon().await;
    let report = a.engine.gc().await.unwrap();

    assert_eq!(report.deleted_packs, 0);
    let fresh = proxy(&remote, 2).await;
    assert_eq!(get(&fresh.engine, "kept").await.unwrap(), data);
}

/// After the journal prune, live objects read back whole, and a deleted key does not come back.
#[tokio::test]
async fn test_redaction_keeps_live_versions_and_deleted_keys_stay_deleted() {
    let remote = Arc::new(TestRemote::new());
    let gc_config = Config {
        snapshot_interval: Duration::ZERO,
        ..config(Duration::ZERO)
    };
    let a = proxy_with(&remote, 1, gc_config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "a", b"first").await;
    put(&a.engine, "b", b"bee").await;
    put(&a.engine, "gone", b"old").await;
    a.engine.flush().await.unwrap();
    put(&a.engine, "a", b"second").await;
    a.engine.delete(BUCKET, "gone").await.unwrap();
    a.engine.flush().await.unwrap();

    let report = a.engine.gc().await.unwrap();
    assert!(report.redacted_entries > 0, "{report:?}");

    let fresh = proxy(&remote, 2).await;
    for engine in [&a.engine, &fresh.engine] {
        assert_eq!(get(engine, "a").await.unwrap(), b"second");
        assert_eq!(get(engine, "b").await.unwrap(), b"bee");
        assert!(matches!(
            get(engine, "gone").await,
            Err(EngineError::NoSuchKey { .. })
        ));
        assert_eq!(keys(engine).await, ["a", "b"]);
    }
}

/// A proxy that loads the snapshot and one that read the whole journal agree.
#[tokio::test]
async fn test_snapshot_bootstrap_and_full_replay_give_the_same_index() {
    let remote = Arc::new(TestRemote::new());
    let writer = proxy(&remote, 1).await;
    writer.engine.create_bucket(BUCKET, None).await.unwrap();
    for i in 0..5u8 {
        put(
            &writer.engine,
            &format!("k{i}"),
            &random_bytes(i, 1000 + usize::from(i)),
        )
        .await;
    }
    writer.engine.delete(BUCKET, "k3").await.unwrap();
    writer.engine.flush().await.unwrap();
    let replayed = proxy(&remote, 2).await;
    writer.engine.snapshot().await.unwrap();
    let bootstrapped = proxy(&remote, 3).await;
    put(&writer.engine, "k0", b"after the snapshot").await;
    writer.engine.flush().await.unwrap();

    let mut views = Vec::new();
    for engine in [&replayed.engine, &bootstrapped.engine] {
        engine.sync().await.unwrap();
        let view: Vec<_> = objects(engine)
            .await
            .into_iter()
            .map(|info| (info.key, info.size, info.content_hash))
            .collect();
        views.push(view);
    }

    assert_eq!(views[0], views[1]);
    assert_eq!(views[0].len(), 4);
}

/// A GC that dies in the middle of its deletes leaves a remote that the next run finishes.
#[tokio::test]
async fn test_gc_that_dies_mid_sweep_is_finished_by_the_next_run() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "live", b"kept").await;
    // Small objects: on a 600 ms horizon, a slow flush under load fails with StalePlan.
    for i in 0..3u8 {
        put(&a.engine, &format!("dead{i}"), &random_bytes(i, 20_000)).await;
        a.engine.flush().await.unwrap();
        a.engine.delete(BUCKET, &format!("dead{i}")).await.unwrap();
    }
    a.engine.flush().await.unwrap();
    past_retention().await;
    a.engine.gc().await.unwrap();
    past_horizon().await;
    let before = count(&remote, "packs/").await;

    remote.deletes_left.store(1, Ordering::SeqCst);
    assert!(a.engine.gc().await.is_err(), "the GC dies after one delete");
    remote.deletes_left.store(-1, Ordering::SeqCst);
    let report = a.engine.gc().await.unwrap();

    assert!(count(&remote, "packs/").await < before);
    assert_eq!(
        report.condemned_packs, 0,
        "the second run condemns nothing new"
    );
    assert!(report.deleted_packs > 0, "the second run deletes the rest");
    let after = a.engine.gc().await.unwrap();
    assert_eq!(
        (after.deleted_packs, after.deleted_manifests),
        (0, 0),
        "nothing was left for a third run"
    );
    let fresh = proxy(&remote, 2).await;
    assert_eq!(get(&fresh.engine, "live").await.unwrap(), b"kept");
    assert_eq!(keys(&fresh.engine).await, ["live"]);
}

/// Many dead objects make a condemn larger than one entry may be: it goes in several entries.
#[tokio::test]
async fn test_large_condemn_is_split_over_entries() {
    let remote = Arc::new(TestRemote::new());
    let config = Config {
        max_entry_actions: 100,
        ..config(Duration::ZERO)
    };
    let a = proxy_with(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    for i in 0..6u8 {
        put(&a.engine, &format!("dead{i}"), &random_bytes(i, 20_000)).await;
        a.engine.flush().await.unwrap();
        a.engine.delete(BUCKET, &format!("dead{i}")).await.unwrap();
    }
    a.engine.flush().await.unwrap();

    past_retention().await;
    let before = count(&remote, journal::LOG_PREFIX).await;

    let report = a.engine.gc().await.unwrap();

    // The prune redacts the condemn entries at once, so count them by their keys.
    assert_eq!(report.condemned_packs, 6);
    let condemns = count(&remote, journal::LOG_PREFIX).await - before;
    assert!(
        condemns >= 3,
        "{condemns} condemn entries for 6 packs, 2 IDs each"
    );
}

/// A second GC runner shows: the condemn of another node in the last H names that node. The
/// condemn comes after the snapshot of the day, so the prune keeps it whole.
#[tokio::test]
async fn test_condemn_of_another_node_names_a_second_gc_runner() {
    let remote = Arc::new(TestRemote::new());
    let config = Config {
        snapshot_interval: Duration::from_secs(3600),
        ..config(Duration::ZERO)
    };
    let a = proxy_with(&remote, 1, config).await;
    let b = proxy(&remote, 2).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    a.engine.snapshot().await.unwrap();
    put(&a.engine, "dead", &random_bytes(1, 20_000)).await;
    a.engine.flush().await.unwrap();
    a.engine.delete(BUCKET, "dead").await.unwrap();
    a.engine.flush().await.unwrap();
    past_retention().await;
    let report = a.engine.gc().await.unwrap();
    assert!(report.condemned_packs > 0 && !report.snapshot_written);
    assert_eq!(a.engine.other_gc_node(), None);

    b.engine.sync().await.unwrap();

    assert_eq!(b.engine.other_gc_node(), Some(a.engine.node()));
}

/// A forward step of the wall clock of the GC host: the monotonic clock does not move.
fn wall_step(by: Duration) {
    hold_clock();
    journal::suspend_manual(by.as_nanos() as u64);
    NOW.with(|now| now.set(now.get() + by.as_nanos() as u64));
}

/// A wall clock that steps H ahead on the GC host must not count as H: a writer can still commit
/// a plan that names the pack. The delete also waits H on the monotonic clock.
#[tokio::test]
async fn test_wall_step_on_the_gc_host_deletes_nothing() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    dead_object(&a.engine, &random_bytes(1, 100_000)).await;
    assert_eq!(a.engine.gc().await.unwrap().condemned_packs, 1);

    wall_step(HORIZON + Duration::from_millis(100));
    let stepped = a.engine.gc().await.unwrap();
    assert_eq!(stepped.deleted_packs, 0, "the wall step counted as H");
    assert_eq!(count(&remote, "packs/").await, 1);

    past_horizon().await;
    let late = a.engine.gc().await.unwrap();

    assert_eq!(late.deleted_packs, 1);
}

/// The monotonic wait lives in the process: after a restart it starts again, so a wall step
/// while the GC host was down cannot count either.
#[tokio::test]
async fn test_restart_of_the_gc_runner_starts_the_wait_again() {
    let remote = Arc::new(TestRemote::new());
    let dir = tempfile::tempdir().unwrap();
    let open = || async {
        hold_clock();
        Engine::open(
            dir.path(),
            remote.clone(),
            SigningKey::from_bytes(&[1; 32]),
            engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
            config(Duration::ZERO),
        )
        .await
        .unwrap()
    };
    let first = open().await;
    dead_object(&first, &random_bytes(1, 100_000)).await;
    assert_eq!(first.gc().await.unwrap().condemned_packs, 1);
    advance(HORIZON / 2);
    drop(first);

    let second = open().await;
    second.gc().await.unwrap();
    advance(HORIZON / 2 + Duration::from_millis(100));
    let early = second.gc().await.unwrap();
    assert_eq!(
        early.deleted_packs, 0,
        "the wait counted time from before the restart"
    );

    advance(HORIZON / 2 + Duration::from_millis(100));
    let late = second.gc().await.unwrap();

    assert_eq!(late.deleted_packs, 1);
}

#[tokio::test]
async fn test_reader_outlives_a_delete_until_the_gc_deletes_its_packs() {
    let remote = Arc::new(TestRemote::new());
    let no_cache = Config {
        cache_bytes: 0,
        ..config(Duration::ZERO)
    };
    let a = proxy_with(&remote, 1, no_cache).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    let data = random_bytes(5, 4 * engine::READ_STEP);
    put(&a.engine, "k", &data).await;
    a.engine.flush().await.unwrap();
    let mut reader = a.engine.get_reader(BUCKET, "k", None).await.unwrap();
    let first = a.engine.next_piece(&mut reader).await.unwrap().unwrap();

    a.engine.delete(BUCKET, "k").await.unwrap();
    a.engine.flush().await.unwrap();
    past_retention().await;
    let condemn = a.engine.gc().await.unwrap();
    let second = a.engine.next_piece(&mut reader).await.unwrap().unwrap();
    past_horizon().await;
    let sweep = a.engine.gc().await.unwrap();
    let after_sweep = a.engine.next_piece(&mut reader).await;

    assert!(condemn.condemned_packs > 0);
    let (one, two) = (first.len(), second.len());
    assert!(first[..] == data[..one]);
    assert!(second[..] == data[one..one + two]);
    assert!(sweep.deleted_packs > 0);
    assert!(
        matches!(after_sweep, Err(EngineError::Corrupt(_))),
        "a read past the sweep fails, it does not end early: {after_sweep:?}"
    );
}

/// Versions of `key` that the index of `engine` holds.
fn version_count(engine: &Engine<TestRemote>, key: &str) -> usize {
    engine
        .versions(BUCKET, key)
        .unwrap()
        .map_or(0, |state| state.versions.len())
}

/// The versions of k that stay after two GC runs with R = 1 s.
async fn prune_with(other: OtherProxy) -> usize {
    let remote = Arc::new(TestRemote::new());
    let config = Config {
        retire_chains: true,
        ..config(Duration::ZERO)
    };
    let a = proxy_with(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    if let OtherProxy::Stopped = other {
        let b = proxy(&remote, 2).await;
        put(&b.engine, "other", b"b").await;
        b.engine.flush().await.unwrap();
    }
    advance(Duration::from_secs(10));
    a.engine.sync().await.unwrap();
    put(&a.engine, "k", b"one").await;
    a.engine.flush().await.unwrap();
    advance(Duration::from_secs(10));
    put(&a.engine, "k", b"two").await;
    a.engine.flush().await.unwrap();
    advance(Duration::from_secs(10));
    a.engine.gc().await.unwrap();
    put(&a.engine, "z", b"later").await;
    a.engine.flush().await.unwrap();
    a.engine.gc().await.unwrap();
    version_count(&a.engine, "k")
}

#[tokio::test]
async fn test_version_prune_drops_an_old_version_with_live_chains_only() {
    assert_eq!(prune_with(OtherProxy::None).await, 1);
}

/// The stable HLC skips a chain that stopped for good once the GC retired it: the version prune
/// goes on.
#[tokio::test]
async fn test_stopped_chain_does_not_block_the_version_prune() {
    assert_eq!(prune_with(OtherProxy::Stopped).await, 1);
}

/// A second proxy for [`prune_with`]: none, or one that wrote once and stopped for good.
enum OtherProxy {
    None,
    Stopped,
}

/// The retire setting of [`retire_after`].
enum Retire {
    On,
    Off,
}

/// The seen of the last entry of `engine` in the remote.
async fn last_seen(remote: &TestRemote, engine: &Engine<TestRemote>) -> journal::Seen {
    let prefix = format!("{}{}/", journal::LOG_PREFIX, engine.node());
    let mut keys = remote.inner.list(&prefix).await.unwrap();
    keys.sort();
    let bytes = remote
        .inner
        .get(keys.last().unwrap(), u64::MAX)
        .await
        .unwrap()
        .unwrap();
    let keys = engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys();
    journal::Entry::from_wire(&bytes, keys.sealer())
        .unwrap()
        .seen
}

/// Proxy b writes once and stops; proxy a runs the GC after `quiet`, with the retire setting
/// `retire`, then writes once. The retired chain count and the seen of that write.
async fn retire_after(quiet: Duration, retire: Retire) -> (usize, bool) {
    let remote = Arc::new(TestRemote::new());
    let config = Config {
        retire_chains: matches!(retire, Retire::On),
        ..config(Duration::ZERO)
    };
    let a = proxy_with(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    let b = proxy(&remote, 2).await;
    put(&b.engine, "other", b"b").await;
    b.engine.flush().await.unwrap();
    let stopped = b.engine.node();
    drop(b);

    advance(quiet);
    let report = a.engine.gc().await.unwrap();
    put(&a.engine, "k", b"v").await;
    a.engine.flush().await.unwrap();
    let listed = last_seen(&remote, &a.engine).await.contains_key(&stopped);
    (report.retired_chains, listed)
}

#[tokio::test]
async fn test_gc_retires_a_chain_quiet_for_q_and_writers_leave_it_out() {
    // Q is max(R, H) + M: here max(1 s, 0.6 s) + 0.
    let past = SHORT_RETENTION + Duration::from_millis(500);
    assert_eq!(retire_after(past, Retire::On).await, (1, false));
}

#[tokio::test]
async fn test_gc_keeps_a_chain_that_is_not_quiet_for_q() {
    let early = SHORT_RETENTION - Duration::from_millis(300);
    assert_eq!(retire_after(early, Retire::On).await, (0, true));
}

#[tokio::test]
async fn test_gc_retires_nothing_with_the_setting_off() {
    let past = SHORT_RETENTION + Duration::from_millis(500);
    assert_eq!(retire_after(past, Retire::Off).await, (0, true));
}

/// With more chains than one header holds, a flush stops before its plan. The GC can still retire
/// them: each Retire entry lists only the chains that it retires, at most 500, so its header
/// stays small. After that, the flush writes.
#[tokio::test]
async fn test_gc_retires_chains_in_batches_when_the_header_guard_trips() {
    let remote = Arc::new(TestRemote::new());
    let config = Config {
        retire_chains: true,
        ..config(Duration::ZERO)
    };
    let a = proxy_with(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    quiet_chains(&remote, 1100).await;
    a.engine.sync().await.unwrap();

    advance(SHORT_RETENTION + Duration::from_millis(500));
    let report = a.engine.gc().await.unwrap();
    // Before the retire, this flush fails with HeaderTooLarge (flush_faults.rs).
    put(&a.engine, "k", b"v").await;
    let flushed = a.engine.flush().await;

    assert_eq!(report.retired_chains, 1100);
    assert!(flushed.is_ok(), "{flushed:?}");
    assert!(last_seen(&remote, &a.engine).await.len() < 10);
}

#[tokio::test]
async fn test_gc_retires_before_it_condemns_past_the_header_limit() {
    let remote = Arc::new(TestRemote::new());
    let config = Config {
        retire_chains: true,
        ..config(Duration::ZERO)
    };
    let a = proxy_with(&remote, 1, config).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    quiet_chains(&remote, 1100).await;
    let orphan = format!("packs/{}", "ab".repeat(32));
    remote
        .put(&orphan, Bytes::from("partial flush"))
        .await
        .unwrap();
    a.engine.sync().await.unwrap();

    advance(SHORT_RETENTION + Duration::from_millis(500));
    let report = a.engine.gc().await.unwrap();

    assert_eq!(report.retired_chains, 1100);
    assert_eq!(report.condemned_packs, 1);
}

/// `n` chains of one empty entry each, from writers that never write again.
async fn quiet_chains(remote: &Arc<TestRemote>, n: u32) {
    let keys = engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys();
    for n in 0..n {
        let key = SigningKey::from_bytes(blake3::hash(&n.to_le_bytes()).as_bytes());
        let mut chain = journal::Journal::new(
            remote.clone(),
            key,
            keys.sealer().clone(),
            Default::default(),
        );
        chain
            .append(Vec::new(), journal::Seen::new())
            .await
            .unwrap();
    }
}

/// Every copy of at least 1 byte goes by reference.
fn copy_config() -> Config {
    Config {
        copy_ref_min: 1,
        ..config(Duration::ZERO)
    }
}

async fn copy(
    engine: &Engine<TestRemote>,
    source: &str,
    target: &str,
    metadata: Option<BTreeMap<String, String>>,
) -> Result<engine::Copied, EngineError> {
    let wait = Duration::from_secs(5);
    engine
        .copy(
            (BUCKET, source),
            (BUCKET, target),
            metadata,
            WriteMode::Overwrite,
            wait,
        )
        .await
}

/// A copy by reference names the packs of its source: they stay live after the source goes.
#[tokio::test]
async fn test_reference_copy_keeps_its_packs_after_the_source_goes() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy_with(&remote, 1, copy_config()).await;
    let data = random_bytes(1, 1_000_000);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "src", &data).await;
    a.engine.flush().await.unwrap();

    let copied = copy(&a.engine, "src", "dst", None).await.unwrap();
    put(&a.engine, "src", b"newer").await;
    a.engine.flush().await.unwrap();
    a.engine.delete(BUCKET, "src").await.unwrap();
    a.engine.flush().await.unwrap();
    past_retention().await;
    a.engine.gc().await.unwrap();
    past_horizon().await;
    a.engine.gc().await.unwrap();
    let reader = proxy(&remote, 2).await;
    reader.engine.sync().await.unwrap();

    assert_eq!(copied.path, engine::CopyPath::Reference);
    assert_eq!(keys(&reader.engine).await, ["dst"]);
    assert_eq!(get(&reader.engine, "dst").await.unwrap(), data);
}

/// Rule 1: a chunk whose pack this proxy saw condemned has no location. A copy of an object
/// that names it reads the data again.
#[tokio::test]
async fn test_copy_of_an_object_with_condemned_chunks_takes_the_spool() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy(&remote, 1).await;
    let b = proxy_with(&remote, 2, copy_config()).await;
    let data = random_bytes(1, 100_000);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", &data).await;
    a.engine.flush().await.unwrap();
    a.engine.delete(BUCKET, "x").await.unwrap();
    a.engine.flush().await.unwrap();
    past_retention().await;
    b.engine.sync().await.unwrap();
    assert_eq!(a.engine.gc().await.unwrap().condemned_packs, 1);
    // A sync before the condemn: b dedups against the condemned pack, then learns the condemn.
    put(&b.engine, "y", &data).await;
    b.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();

    let copied = copy(&b.engine, "y", "z", None).await.unwrap();

    assert_eq!(
        copied.path,
        engine::CopyPath::Spool(engine::SpoolReason::MissingChunk)
    );
    assert_eq!(get(&b.engine, "z").await.unwrap(), data);
}

/// A copy that stops after its manifest PUT leaves a manifest that no entry names.
#[tokio::test]
async fn test_manifest_of_a_copy_that_stopped_is_deleted_after_h() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy_with(&remote, 1, copy_config()).await;
    let metadata = BTreeMap::from([("x-amz-meta-note".to_string(), "n".repeat(5000))]);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "src", &random_bytes(1, 100_000)).await;
    a.engine.flush().await.unwrap();

    engine::sim::arm_crash(Some(engine::sim::Point::CopyRefManifest));
    let crashed = copy(&a.engine, "src", "dst", Some(metadata)).await;
    engine::sim::arm_crash(None);
    assert!(
        matches!(crashed, Err(EngineError::SimCrash(_))),
        "{crashed:?}"
    );
    assert_eq!(count(&remote, "manifests/").await, 1);
    past_retention().await;

    assert_eq!(a.engine.gc().await.unwrap().condemned_manifests, 1);
    past_horizon().await;

    assert_eq!(a.engine.gc().await.unwrap().deleted_manifests, 1);
    assert_eq!(count(&remote, "manifests/").await, 0);
    assert_eq!(keys(&a.engine).await, ["src"]);
}

/// One intent file: a copy finishes the commit of an interrupted flush before its own.
#[tokio::test]
async fn test_reference_copy_finishes_an_interrupted_flush_first() {
    let remote = Arc::new(TestRemote::new());
    let a = proxy_with(&remote, 1, copy_config()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "src", &random_bytes(1, 100_000)).await;
    a.engine.flush().await.unwrap();
    put(&a.engine, "pending", b"pending").await;
    remote.next_create.store(CREATE_AMBIGUOUS, Ordering::SeqCst);
    assert!(a.engine.flush().await.is_err());

    let copied = copy(&a.engine, "src", "dst", None).await.unwrap();

    assert_eq!(copied.path, engine::CopyPath::Reference);
    assert_eq!(a.engine.buffered_bytes().await, 0);
    assert_eq!(keys(&a.engine).await, ["dst", "pending", "src"]);
}
