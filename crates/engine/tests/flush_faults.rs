//! A flush that meets buffered data that does not match its head, or a journal that cannot take
//! its entry.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::sim::Point;
use engine::{Config, Engine, EngineError, WriteMode};
use remote::{MemoryRemote, Remote};

const BUCKET: &str = "bucket";

async fn open(dir: &Path, remote: &Arc<MemoryRemote>) -> Result<Engine<MemoryRemote>, EngineError> {
    Engine::open(
        dir,
        remote.clone(),
        SigningKey::from_bytes(&[1; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        Config::default(),
    )
    .await
}

fn value(key: &str) -> Vec<u8> {
    format!("<{key}>").repeat(64).into_bytes()
}

async fn put(engine: &Engine<MemoryRemote>, key: &str) {
    engine
        .put(
            BUCKET,
            key,
            Bytes::from(value(key)),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
}

/// The buffer segment that holds the data of `key`, and where that data starts.
fn data_of(dir: &Path, key: &str) -> (PathBuf, usize) {
    let marker = value(key);
    std::fs::read_dir(dir.join("buffer"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "log"))
        .find_map(|path| {
            let content = std::fs::read(&path).unwrap();
            let at = content
                .windows(marker.len())
                .position(|window| window == marker)?;
            Some((path, at))
        })
        .expect("the data is in a segment")
}

fn flip(dir: &Path, key: &str) {
    let (path, at) = data_of(dir, key);
    let mut content = std::fs::read(&path).unwrap();
    content[at + 10] ^= 1;
    std::fs::write(&path, content).unwrap();
}

async fn log_entries(remote: &MemoryRemote) -> usize {
    remote.list("log/").await.unwrap().len()
}

async fn has(engine: &Engine<MemoryRemote>, key: &str) -> bool {
    match engine.get(BUCKET, key, None).await {
        Ok(object) => object.data == value(key),
        Err(EngineError::NoSuchKey { .. }) => false,
        Err(e) => panic!("{key}: {e}"),
    }
}

/// A restart moves the bad record to the quarantine; the operator empties it; the next start
/// flushes the rest.
async fn after_the_operator(dir: &Path, remote: &Arc<MemoryRemote>) -> Engine<MemoryRemote> {
    let refused = open(dir, remote).await.err().unwrap().to_string();
    assert!(refused.contains("bucket/b"), "{refused}");
    std::fs::remove_dir_all(dir.join("quarantine")).unwrap();
    let a = open(dir, remote).await.unwrap();
    a.flush().await.unwrap();
    a
}

#[tokio::test]
async fn test_bad_data_stops_the_flush_with_no_log_entry_and_writes_go_on() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let a = open(dir.path(), &remote).await.unwrap();
    a.create_bucket(BUCKET, None).await.unwrap();
    a.flush().await.unwrap();
    for key in ["a", "b", "c"] {
        put(&a, key).await;
    }
    flip(dir.path(), "b");
    let entries = log_entries(&remote).await;

    let flushed = a.flush().await;
    let after = log_entries(&remote).await;
    let quarantined = a.is_quarantined();
    put(&a, "d").await;
    drop(a);
    let a = after_the_operator(dir.path(), &remote).await;

    let error = flushed.err().unwrap().to_string();
    assert!(error.contains("bucket/b"), "{error}");
    assert!(error.contains("does not match its head"), "{error}");
    assert_eq!(after, entries);
    assert!(quarantined);
    for (key, kept) in [("a", true), ("b", false), ("c", true), ("d", true)] {
        assert_eq!(has(&a, key).await, kept, "{key}");
    }
}

#[tokio::test]
async fn test_data_that_changes_between_the_two_passes_gets_no_log_entry() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let a = open(dir.path(), &remote).await.unwrap();
    a.create_bucket(BUCKET, None).await.unwrap();
    a.flush().await.unwrap();
    put(&a, "b").await;
    let entries = log_entries(&remote).await;
    let path = dir.path().to_path_buf();

    engine::sim::arm_action(Point::FlushVerified, move || flip(&path, "b"));
    let flushed = a.flush().await;
    let after = log_entries(&remote).await;
    drop(a);
    let a = after_the_operator(dir.path(), &remote).await;

    let error = flushed.err().unwrap().to_string();
    assert!(error.contains("bucket/b"), "{error}");
    assert_eq!(after, entries);
    assert!(!has(&a, "b").await);
}

/// Chains of `count` other nodes, one entry each: the seen map of the next entry names them all.
async fn other_chains(remote: &Arc<MemoryRemote>, count: u32) {
    let keys = engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys();
    for n in 0..count {
        let key = SigningKey::from_bytes(blake3::hash(&n.to_le_bytes()).as_bytes());
        let mut chain = journal::Journal::new(
            remote.clone(),
            key,
            keys.sealer().clone(),
            journal::Frontiers::new(),
        );
        chain
            .append(Vec::new(), journal::Seen::new())
            .await
            .unwrap();
    }
}

/// With too many chains for one header, a flush stops before its plan: no pack, manifest or
/// entry goes up on any retry, and one ERROR names the cause.
#[tokio::test]
async fn test_flush_with_a_header_over_the_limit_uploads_nothing() {
    let logs = common::capture();
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(MemoryRemote::default());
    let engine = open(dir.path(), &remote).await.unwrap();
    engine.create_bucket(BUCKET, None).await.unwrap();
    engine.flush().await.unwrap();
    other_chains(&remote, 1100).await;
    engine.sync().await.unwrap();
    put(&engine, "k").await;
    let before = remote.list("").await.unwrap();

    for _ in 0..10 {
        let flushed = engine.flush().await;
        assert!(
            matches!(
                flushed,
                Err(EngineError::Journal(
                    journal::JournalError::HeaderTooLarge { .. }
                ))
            ),
            "{flushed:?}"
        );
    }

    let after = remote.list("").await.unwrap();
    let new: Vec<_> = after.iter().filter(|key| !before.contains(key)).collect();
    assert!(new.is_empty(), "{new:?}");
    assert_eq!(logs.lines("ERROR").len(), 1, "{:?}", logs.lines("ERROR"));
    assert!(has(&engine, "k").await);
}
