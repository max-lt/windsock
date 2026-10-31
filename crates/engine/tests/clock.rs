//! A wall clock that steps back across a restart, with acked writes in the buffer.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, EngineError, WriteMode};
use remote::MemoryRemote;

const BUCKET: &str = "bucket";
const RETENTION: Duration = Duration::from_secs(3600);
/// A fixed start, far from the system clock of any machine.
const START: u64 = 1_900_000_000_000_000_000;

fn config() -> Config {
    Config {
        retention: RETENTION,
        late_margin: Duration::ZERO,
        ..Config::default()
    }
}

async fn open(dir: &Path, remote: &Arc<MemoryRemote>) -> Result<Engine<MemoryRemote>, String> {
    Engine::open(
        dir,
        remote.clone(),
        SigningKey::from_bytes(&[1; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config(),
    )
    .await
    .map_err(|e| e.to_string())
}

fn set_wall(nanos: u64) {
    journal::set_manual_wall(Some(nanos));
}

#[tokio::test]
async fn test_acks_in_the_buffer_commit_after_the_wall_steps_back() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    set_wall(START);
    let a = open(dir.path(), &remote).await.unwrap();
    a.create_bucket(BUCKET, None).await.unwrap();
    a.put(
        BUCKET,
        "k",
        Bytes::from("acked"),
        BTreeMap::new(),
        WriteMode::Overwrite,
    )
    .await
    .unwrap();
    drop(a);

    let back = START - 2 * RETENTION.as_nanos() as u64;
    set_wall(back);
    let early = open(dir.path(), &remote).await.unwrap();
    let early_flush = early.flush().await;
    drop(early);
    set_wall(START + 10);
    let late = open(dir.path(), &remote).await.unwrap();
    late.flush().await.unwrap();

    assert!(
        matches!(early_flush, Err(EngineError::ClockAhead { .. })),
        "no commit while the wall is behind: {early_flush:?}"
    );
    let read = late.get(BUCKET, "k", None).await.unwrap();
    assert_eq!(read.data, "acked");
    assert_eq!(late.buffered_bytes().await, 0);
}

async fn put(engine: &Engine<MemoryRemote>, key: &str) -> Result<(), EngineError> {
    let data = Bytes::copy_from_slice(key.as_bytes());
    engine
        .put(BUCKET, key, data, BTreeMap::new(), WriteMode::Overwrite)
        .await
        .map(|_| ())
}

#[tokio::test]
async fn test_boot_in_1970_with_a_buffer_reads_and_refuses_writes() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    set_wall(START);
    let a = open(dir.path(), &remote).await.unwrap();
    a.create_bucket(BUCKET, None).await.unwrap();
    put(&a, "k").await.unwrap();
    drop(a);

    set_wall(1);
    let a = open(dir.path(), &remote).await.unwrap();
    let write = put(&a, "other").await;
    let read = a.get(BUCKET, "k", None).await.unwrap();

    let Err(EngineError::ClockAhead { wait_secs }) = write else {
        panic!("a write while the clock is ahead: {write:?}");
    };
    let expected = (START - RETENTION.as_nanos() as u64) / 1_000_000_000;
    assert!(
        wait_secs.abs_diff(expected) <= 1,
        "{wait_secs} s, not {expected} s"
    );
    assert_eq!(read.data, "k");
}

#[tokio::test]
async fn test_own_chain_a_year_ahead_waits_for_the_wall_then_writes() {
    let year = 365 * 24 * 3600 * 1_000_000_000u64;
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    set_wall(START + year);
    let a = open(dir.path(), &remote).await.unwrap();
    a.create_bucket(BUCKET, None).await.unwrap();
    put(&a, "k").await.unwrap();
    a.flush().await.unwrap();
    drop(a);

    set_wall(START);
    let fresh = tempfile::tempdir().unwrap();
    let b = open(fresh.path(), &remote).await.unwrap();
    let read = b.get(BUCKET, "k", None).await.unwrap();
    let early = put(&b, "early").await;
    let early_gc = b.gc().await;
    set_wall(START + year + 1);
    let late = put(&b, "late").await;

    assert_eq!(read.data, "k");
    assert!(matches!(early, Err(EngineError::ClockAhead { wait_secs }) if wait_secs > 0));
    assert!(matches!(early_gc, Err(EngineError::ClockAhead { .. })));
    late.unwrap();
    b.flush().await.unwrap();
}

#[tokio::test]
async fn test_own_acks_under_a_snapshot_stay_above_the_next_ack_after_an_index_loss() {
    let year = 365 * 24 * 3600 * 1_000_000_000u64;
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    set_wall(START + year);
    let a = open(dir.path(), &remote).await.unwrap();
    a.create_bucket(BUCKET, None).await.unwrap();
    put(&a, "k").await.unwrap();
    a.flush().await.unwrap();
    // The snapshot covers the own entries, and the prune redacts them.
    let report = a.gc().await.unwrap();
    assert!(report.snapshot_written && report.redacted_entries > 0);
    let high = a.last_hlc();
    drop(a);

    set_wall(START);
    let fresh = tempfile::tempdir().unwrap();
    let b = open(fresh.path(), &remote).await.unwrap();
    let write = put(&b, "later").await;

    assert!(b.last_hlc() >= high, "the clock went under an own ack");
    assert!(
        matches!(write, Err(EngineError::ClockAhead { .. })),
        "{write:?}"
    );
}

/// A memory remote that stores the next entry create and loses its answer.
#[derive(Default)]
struct LossyRemote {
    inner: MemoryRemote,
    lose_next_entry: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl remote::Remote for LossyRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), remote::RemoteError> {
        self.inner.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), remote::RemoteError> {
        self.inner.create(key, data).await?;
        let ordering = std::sync::atomic::Ordering::SeqCst;
        if key.starts_with(journal::LOG_PREFIX) && self.lose_next_entry.swap(false, ordering) {
            return Err(remote::RemoteError::Io(std::io::Error::other(
                "lost answer",
            )));
        }
        Ok(())
    }

    async fn get(&self, key: &str, max: u64) -> Result<Option<Bytes>, remote::RemoteError> {
        self.inner.get(key, max).await
    }

    async fn get_range(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<Option<Bytes>, remote::RemoteError> {
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, remote::RemoteError> {
        self.inner.list(prefix).await
    }
}

/// An entry that reached the remote with a lost answer stays in the intent file. After a step
/// back of the wall clock and a restart, the next own entry must still take a higher HLC, or
/// every later commit fails: the own chain must rise.
#[tokio::test]
async fn test_entry_with_a_lost_answer_keeps_the_chain_rising_after_a_step_back() {
    let remote = Arc::new(LossyRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let open = || async {
        Engine::open(
            dir.path(),
            remote.clone(),
            SigningKey::from_bytes(&[1; 32]),
            engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
            config(),
        )
        .await
        .unwrap()
    };
    set_wall(START);
    let a = open().await;
    a.create_bucket(BUCKET, None).await.unwrap();
    a.flush().await.unwrap();
    let data = || Bytes::from_static(b"v");
    a.put(BUCKET, "k1", data(), BTreeMap::new(), WriteMode::Overwrite)
        .await
        .unwrap();
    // The entry takes an HLC 10 s above the ack, and the wall then steps back 5 s: only the entry
    // in the intent and in the remote is above the next ack.
    set_wall(START + 10_000_000_000);
    remote
        .lose_next_entry
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(a.flush().await.is_err(), "the lost answer fails the flush");
    drop(a);

    set_wall(START + 5_000_000_000);
    let b = open().await;
    b.put(BUCKET, "k2", data(), BTreeMap::new(), WriteMode::Overwrite)
        .await
        .unwrap();
    let flushed = b.flush().await;

    assert!(flushed.is_ok(), "{flushed:?}");
    assert_eq!(b.buffered_bytes().await, 0);
    for key in ["k1", "k2"] {
        assert_eq!(b.get(BUCKET, key, None).await.unwrap().data, "v");
    }
    // Another proxy reads the chain: an entry under the one before it breaks the chain there.
    let other_dir = tempfile::tempdir().unwrap();
    let other = Engine::open(
        other_dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[2; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config(),
    )
    .await
    .unwrap();
    let report = other.sync().await.unwrap();
    assert!(report.broken.is_empty(), "{:?}", report.broken_causes);
    assert_eq!(other.get(BUCKET, "k2", None).await.unwrap().data, "v");
}
