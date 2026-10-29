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
