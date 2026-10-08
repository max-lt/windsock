//! GC rules on a short horizon. The model in `protocol-check/src/gc.rs` is the reference.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, EngineError, GcReport, WriteMode};
use keys::RepoKey;
use remote::{MemoryRemote, Remote, RemoteError, Sweep};
use tempfile::TempDir;

/// Every proxy of one remote shares the repository key.
fn repo_key() -> RepoKey {
    RepoKey::from_bytes([42u8; 32])
}

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
}

#[async_trait::async_trait]
impl Remote for TestRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        let timeout = || RemoteError::Io(std::io::Error::other("timeout"));

        match self.next_create.swap(CREATE_OK, Ordering::SeqCst) {
            CREATE_LOST => Err(timeout()),
            CREATE_AMBIGUOUS => {
                self.inner.create(key, data).await?;
                Err(timeout())
            }
            _ => self.inner.create(key, data).await,
        }
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

#[async_trait::async_trait]
impl Sweep for TestRemote {
    async fn delete(&self, key: &str) -> Result<(), RemoteError> {
        self.inner.delete(key).await
    }
}

struct Proxy {
    _dir: TempDir,
    engine: Engine<TestRemote>,
}

fn config(retention: Duration) -> Config {
    Config {
        gc_horizon: HORIZON,
        retention,
        ..Config::default()
    }
}

async fn proxy_with(remote: &Arc<TestRemote>, seed: u8, config: Config) -> Proxy {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[seed; 32]);
    let engine = Engine::open(dir.path(), remote.clone(), key, repo_key(), config)
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

async fn keys(engine: &Engine<TestRemote>) -> Vec<String> {
    let listed = engine.list(BUCKET, "").await.unwrap();
    listed.into_iter().map(|info| info.key).collect()
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
}

async fn past_horizon() {
    tokio::time::sleep(HORIZON + Duration::from_millis(100)).await;
}

async fn past_half_horizon() {
    tokio::time::sleep(HORIZON / 2 + Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_dead_pack_is_deleted_only_a_horizon_after_its_condemn() {
    let remote = Arc::new(TestRemote::default());
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
    let remote = Arc::new(TestRemote::default());
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
        let remote = Arc::new(TestRemote::default());
        let a = proxy_with(&remote, 1, config(retention)).await;
        a.engine.create_bucket(BUCKET, None).await.unwrap();
        put(&a.engine, "k", &random_bytes(1, 100_000)).await;
        a.engine.flush().await.unwrap();
        put(&a.engine, "k", &random_bytes(2, 100_000)).await;
        a.engine.flush().await.unwrap();

        let report = a.engine.gc().await.unwrap();

        assert_eq!(report.condemned_packs, condemned, "retention {retention:?}");
    }
}

#[tokio::test]
async fn test_orphan_pack_is_deleted() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy(&remote, 1).await;
    let orphan = format!("packs/{}", "ab".repeat(32));
    remote
        .put(&orphan, Bytes::from("partial flush"))
        .await
        .unwrap();

    assert_eq!(a.engine.gc().await.unwrap().condemned_packs, 1);
    past_horizon().await;

    assert_eq!(a.engine.gc().await.unwrap().deleted_packs, 1);
    assert!(remote.get(&orphan).await.unwrap().is_none());
}

/// Large metadata pushes the manifest past the inline limit, with a small object.
#[tokio::test]
async fn test_dead_external_manifest_is_deleted() {
    let remote = Arc::new(TestRemote::default());
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

    assert_eq!(a.engine.gc().await.unwrap().condemned_manifests, 1);
    past_horizon().await;

    assert_eq!(a.engine.gc().await.unwrap().deleted_manifests, 1);
    assert_eq!(count(&remote, "manifests/").await, 0);
}

/// Rule 1: a writer whose last sync is older than H/2 syncs before it dedups,
/// so it sees the condemn and uploads the chunks again.
#[tokio::test]
async fn test_writer_with_an_old_sync_does_not_dedup_against_a_condemned_pack() {
    let remote = Arc::new(TestRemote::default());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    let data = random_bytes(1, 100_000);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", &data).await;
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();
    a.engine.delete(BUCKET, "x").await.unwrap();
    a.engine.flush().await.unwrap();
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
    let remote = Arc::new(TestRemote::default());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    let data = random_bytes(1, 100_000);
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    put(&a.engine, "x", &data).await;
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();
    a.engine.delete(BUCKET, "x").await.unwrap();
    a.engine.flush().await.unwrap();
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
    let remote = Arc::new(TestRemote::default());
    let a = proxy(&remote, 1).await;
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
    let remote = Arc::new(TestRemote::default());
    let a = proxy(&remote, 1).await;
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
    let remote = Arc::new(TestRemote::default());
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
    let good = remote.get(&key).await.unwrap().unwrap();
    let mut tampered = journal::Entry::decode(&repo_key(), &good).unwrap();
    tampered.actions = Some(vec![]);
    remote
        .put(
            &key,
            Bytes::from(tampered.encode(&repo_key(), &keys::random())),
        )
        .await
        .unwrap();

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
    let report = reader.engine.sync().await.unwrap();

    assert!(report.broken.is_empty());
    assert_eq!(keys(&reader.engine).await, ["copy", "k0", "k1", "k2"]);
    reader.engine.gc().await.unwrap();
}

/// A chain whose HLC runs far ahead of the GC clock raises the stable HLC past real
/// time: a proxy with a correct clock could then write under the prune bound.
#[tokio::test]
async fn test_version_prune_refuses_to_run_when_clocks_run_far_ahead() {
    let remote = Arc::new(TestRemote::default());
    let ahead = SigningKey::from_bytes(&[9u8; 32]);
    let node = model::NodeId::from_bytes(ahead.verifying_key().to_bytes());
    let far_future = u64::MAX / 2;
    let entry = journal::Entry::sign(
        &ahead,
        &repo_key(),
        0,
        [0u8; 32],
        far_future,
        journal::Seen::new(),
        vec![],
    );
    remote
        .put(
            &entry.remote_key(),
            Bytes::from(entry.encode(&repo_key(), &keys::random())),
        )
        .await
        .unwrap();
    remote
        .put(&journal::node_key(node), Bytes::new())
        .await
        .unwrap();
    let a = proxy(&remote, 1).await;

    let report = a.engine.gc().await.unwrap();

    assert!(report.prune_refused);
}

#[tokio::test]
async fn test_gc_prunes_an_old_delete_from_the_index() {
    let remote = Arc::new(TestRemote::default());
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
