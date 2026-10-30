//! The replay of the buffer at open: a torn tail, a corrupt record, and the move of a record with a
//! valid head and bad data to the quarantine.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::sim::Point;
use engine::{Config, Engine, EngineError, WriteMode};
use remote::MemoryRemote;

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

/// The value of a key: a marker that a test can find in the segment file.
fn value(key: &str) -> Vec<u8> {
    format!("<{key}>").repeat(64).into_bytes()
}

/// A bucket that the remote holds, then puts of a, b and c in one buffer segment.
async fn three_puts(dir: &Path, remote: &Arc<MemoryRemote>) -> PathBuf {
    let a = open(dir, remote).await.unwrap();
    a.create_bucket(BUCKET, None).await.unwrap();
    a.flush().await.unwrap();
    for key in ["a", "b", "c"] {
        a.put(
            BUCKET,
            key,
            Bytes::from(value(key)),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
    }
    drop(a);
    segment_with(dir, &value("a")).expect("the puts are in one segment")
}

/// The buffer segment that holds `bytes`.
fn segment_with(dir: &Path, bytes: &[u8]) -> Option<PathBuf> {
    std::fs::read_dir(dir.join("buffer"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "log"))
        .find(|path| {
            let content = std::fs::read(path).unwrap();
            content.windows(bytes.len()).any(|window| window == bytes)
        })
}

/// Where the data of `key` starts in `segment`.
fn data_of(segment: &Path, key: &str) -> usize {
    let content = std::fs::read(segment).unwrap();
    let marker = value(key);
    content
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap()
}

fn flip(segment: &Path, at: usize) {
    let mut content = std::fs::read(segment).unwrap();
    content[at] ^= 1;
    std::fs::write(segment, content).unwrap();
}

/// The first byte of the head of `key`: right after its data, its head length and head hash.
fn head_of(segment: &Path, key: &str) -> usize {
    data_of(segment, key) + value(key).len() + 4 + 32
}

fn quarantine_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.join("quarantine"))
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

async fn quarantined(dir: &Path) -> Vec<String> {
    engine::quarantined_writes(dir)
        .await
        .unwrap()
        .into_iter()
        .map(|write| write.target)
        .collect()
}

/// The open after an operator emptied the quarantine.
async fn open_after_the_operator(dir: &Path, remote: &Arc<MemoryRemote>) -> Engine<MemoryRemote> {
    std::fs::remove_dir_all(dir.join("quarantine")).unwrap();
    open(dir, remote).await.unwrap()
}

async fn has(engine: &Engine<MemoryRemote>, key: &str) -> bool {
    match engine.get(BUCKET, key, None).await {
        Ok(object) => {
            assert!(object.data == value(key), "{key}");
            true
        }
        Err(EngineError::NoSuchKey { .. }) => false,
        Err(e) => panic!("{key}: {e}"),
    }
}

#[tokio::test]
async fn test_bad_data_under_a_valid_head_goes_to_quarantine_in_the_middle_and_at_the_end() {
    for key in ["b", "c"] {
        let remote = Arc::new(MemoryRemote::default());
        let dir = tempfile::tempdir().unwrap();
        let segment = three_puts(dir.path(), &remote).await;
        flip(&segment, data_of(&segment, key) + 10);

        let refused = open(dir.path(), &remote).await.err().unwrap().to_string();
        let held = quarantined(dir.path()).await;
        let again = open(dir.path(), &remote).await.err().unwrap().to_string();
        let a = open_after_the_operator(dir.path(), &remote).await;

        assert!(
            refused.contains(&format!("{BUCKET}/{key}")),
            "{key}: {refused}"
        );
        assert!(
            refused.contains("data does not match its head"),
            "{key}: {refused}"
        );
        assert!(!refused.contains("late limit"), "{key}: {refused}");
        assert_eq!(held, [format!("{BUCKET}/{key}")], "{key}");
        assert!(again.contains(&format!("{BUCKET}/{key}")), "{key}: {again}");
        assert_eq!(
            ["a", "b", "c"].map(|k| k != key),
            [has(&a, "a").await, has(&a, "b").await, has(&a, "c").await],
            "{key}"
        );
    }
}

#[tokio::test]
async fn test_crash_at_each_quarantine_step_moves_the_record_once() {
    for point in [Point::QuarantineCopy, Point::QuarantineRewrite] {
        let remote = Arc::new(MemoryRemote::default());
        let dir = tempfile::tempdir().unwrap();
        let segment = three_puts(dir.path(), &remote).await;
        flip(&segment, data_of(&segment, "b") + 10);

        engine::sim::arm_crash(Some(point));
        let crashed = open(dir.path(), &remote).await;
        engine::sim::arm_crash(None);
        let refused = open(dir.path(), &remote).await.err().unwrap().to_string();
        let files = quarantine_files(dir.path());
        let held = quarantined(dir.path()).await;
        let a = open_after_the_operator(dir.path(), &remote).await;

        assert!(
            matches!(crashed, Err(EngineError::SimCrash(p)) if p == point),
            "{point:?}: {:?}",
            crashed.err()
        );
        assert!(refused.contains("bucket/b"), "{point:?}: {refused}");
        assert_eq!(files.len(), 1, "{point:?}: {files:?}");
        assert_eq!(held, ["bucket/b"], "{point:?}");
        assert!(has(&a, "a").await && !has(&a, "b").await && has(&a, "c").await);
        assert!(
            quarantine_files(dir.path()).is_empty(),
            "{point:?}: moved twice"
        );
    }
}

#[tokio::test]
async fn test_bad_head_in_the_middle_stops_the_start_and_cuts_nothing() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let segment = three_puts(dir.path(), &remote).await;
    flip(&segment, head_of(&segment, "b"));
    let before = std::fs::read(&segment).unwrap();

    let refused = open(dir.path(), &remote).await.err().unwrap().to_string();

    assert!(refused.contains("key unknown"), "{refused}");
    assert!(refused.contains("docs/storage.md"), "{refused}");
    assert_eq!(std::fs::read(&segment).unwrap(), before);
    assert!(quarantine_files(dir.path()).is_empty());
}

#[tokio::test]
async fn test_bad_head_of_the_last_record_is_a_torn_tail() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let segment = three_puts(dir.path(), &remote).await;
    flip(&segment, head_of(&segment, "c"));

    let a = open(dir.path(), &remote).await.unwrap();

    assert!(has(&a, "a").await && has(&a, "b").await && !has(&a, "c").await);
}

#[tokio::test]
async fn test_cut_inside_the_data_inside_the_head_and_after_the_data_is_a_torn_tail() {
    for (name, cut) in [
        ("inside the data", 100),
        ("after the data", value("c").len()),
        ("inside the head", value("c").len() + 4 + 32 + 3),
    ] {
        let remote = Arc::new(MemoryRemote::default());
        let dir = tempfile::tempdir().unwrap();
        let segment = three_puts(dir.path(), &remote).await;
        let content = std::fs::read(&segment).unwrap();
        std::fs::write(&segment, &content[..data_of(&segment, "c") + cut]).unwrap();

        let a = open(dir.path(), &remote).await.unwrap();

        assert!(has(&a, "a").await && has(&a, "b").await, "{name}");
        assert!(!has(&a, "c").await, "{name}");
    }
}

/// Writes a huge data length (2^63) or head length (4 GiB) into the record of b.
fn huge_length(segment: &Path, field: &str) {
    let mut content = std::fs::read(segment).unwrap();
    let (at, huge) = match field {
        "data" => (
            data_of(segment, "b") - 8,
            (1u64 << 63).to_le_bytes().to_vec(),
        ),
        _ => (
            data_of(segment, "b") + value("b").len(),
            u32::MAX.to_le_bytes().to_vec(),
        ),
    };
    content[at..at + huge.len()].copy_from_slice(&huge);
    std::fs::write(segment, &content).unwrap();
}

#[tokio::test]
async fn test_huge_length_in_the_last_segment_is_a_torn_tail() {
    for field in ["data", "head"] {
        let remote = Arc::new(MemoryRemote::default());
        let dir = tempfile::tempdir().unwrap();
        let segment = three_puts(dir.path(), &remote).await;
        huge_length(&segment, field);

        let a = open(dir.path(), &remote).await.unwrap();

        assert!(has(&a, "a").await, "{field}");
        assert!(!has(&a, "b").await && !has(&a, "c").await, "{field}");
    }
}

#[tokio::test]
async fn test_huge_length_in_an_older_segment_stops_the_start_with_its_offset() {
    for field in ["data", "head"] {
        let remote = Arc::new(MemoryRemote::default());
        let dir = tempfile::tempdir().unwrap();
        let segment = three_puts(dir.path(), &remote).await;
        // A put in the next open goes to a later segment: the one of a, b and c is older.
        let a = open(dir.path(), &remote).await.unwrap();
        a.put(
            BUCKET,
            "d",
            Bytes::from(value("d")),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
        drop(a);
        huge_length(&segment, field);
        let before = std::fs::read(&segment).unwrap();

        let refused = open(dir.path(), &remote).await.err().unwrap().to_string();

        let offset = data_of(&segment, "b") - 8;
        assert!(
            refused.contains(&format!("offset {offset}")),
            "{field}: {refused}"
        );
        assert!(refused.contains("key unknown"), "{field}: {refused}");
        assert_eq!(std::fs::read(&segment).unwrap(), before, "{field}");
    }
}
