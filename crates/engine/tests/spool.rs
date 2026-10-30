//! Puts that stream their body through a spool file.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::sim::Point;
use engine::{Config, Engine, EngineError, WriteMode};
use remote::{MemoryRemote, Remote};

const BUCKET: &str = "bucket";
const PIECE: usize = 1 << 20;

async fn open(dir: &Path, remote: &Arc<MemoryRemote>, config: Config) -> Engine<MemoryRemote> {
    Engine::open(
        dir,
        remote.clone(),
        SigningKey::from_bytes(&[1; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        config,
    )
    .await
    .unwrap()
}

fn data(len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    blake3::Hasher::new()
        .update(&(len as u64).to_le_bytes())
        .finalize_xof()
        .fill(&mut out);
    out
}

/// Streams `body` in pieces of 1 MiB and commits it.
async fn spooled_put(
    engine: &Engine<MemoryRemote>,
    key: &str,
    body: &[u8],
    mode: WriteMode,
) -> Result<engine::ObjectInfo, EngineError> {
    let mut spool = engine.begin_put(BUCKET, key, BTreeMap::new(), mode).await?;
    for piece in body.chunks(PIECE) {
        engine.spool_write(&mut spool, piece).await?;
    }
    engine.finish_put(spool).await
}

fn spool_files(dir: &Path) -> usize {
    std::fs::read_dir(dir.join("buffer/spool")).map_or(0, |entries| entries.count())
}

#[tokio::test]
async fn test_spooled_put_reads_back_and_survives_a_restart() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let a = open(dir.path(), &remote, Config::default()).await;
    a.create_bucket(BUCKET, None).await.unwrap();
    let body = data(3 * PIECE + 17);

    let info = spooled_put(&a, "k", &body, WriteMode::Overwrite)
        .await
        .unwrap();
    let read = a.get(BUCKET, "k", None).await.unwrap();
    drop(a);
    let a = open(dir.path(), &remote, Config::default()).await;
    let replayed = a.get(BUCKET, "k", None).await.unwrap();
    a.flush().await.unwrap();
    let flushed = a.get(BUCKET, "k", None).await.unwrap();

    assert_eq!(info.size, body.len() as u64);
    assert_eq!(info.content_hash, *blake3::hash(&body).as_bytes());
    assert!(read.data == body);
    assert!(replayed.data == body);
    assert!(flushed.data == body);
    assert_eq!(spool_files(dir.path()), 0);
}

#[tokio::test]
async fn test_crash_at_each_spool_step_acks_nothing_and_keeps_only_durable_puts() {
    for (point, durable) in [
        (Point::SpoolData, false),
        (Point::SpoolHead, false),
        (Point::SpoolDirSync, true),
        (Point::SpoolRename, true),
        (Point::SpoolAck, true),
    ] {
        let remote = Arc::new(MemoryRemote::default());
        let dir = tempfile::tempdir().unwrap();
        let a = open(dir.path(), &remote, Config::default()).await;
        a.create_bucket(BUCKET, None).await.unwrap();
        let body = data(2 * PIECE);

        engine::sim::arm_crash(Some(point));
        let result = spooled_put(&a, "k", &body, WriteMode::Overwrite).await;
        engine::sim::arm_crash(None);
        drop(a);
        let a = open(dir.path(), &remote, Config::default()).await;
        let read = a.get(BUCKET, "k", None).await;

        assert!(
            matches!(result, Err(EngineError::SimCrash(p)) if p == point),
            "{point:?}: {result:?}"
        );
        match durable {
            true => assert!(read.unwrap().data == body, "{point:?}"),
            false => assert!(
                matches!(read, Err(EngineError::NoSuchKey { .. })),
                "{point:?}"
            ),
        }
        assert_eq!(
            spool_files(dir.path()),
            0,
            "{point:?}: the open clears the spool"
        );
    }
}

#[tokio::test]
async fn test_cut_body_removes_its_spool_file_and_gives_its_bytes_back() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        buffer_limit: 8 * PIECE as u64,
        ..Config::default()
    };
    let a = open(dir.path(), &remote, config).await;
    a.create_bucket(BUCKET, None).await.unwrap();
    a.flush().await.unwrap();

    let mut cut = a
        .begin_put(BUCKET, "k", BTreeMap::new(), WriteMode::Overwrite)
        .await
        .unwrap();
    a.spool_write(&mut cut, &data(3 * PIECE)).await.unwrap();
    let mut other = a
        .begin_put(BUCKET, "other", BTreeMap::new(), WriteMode::Overwrite)
        .await
        .unwrap();
    let over = a.spool_write(&mut other, &data(6 * PIECE)).await;
    let held = spool_files(dir.path());
    // The client of the first put cuts its body: the handler drops the spool.
    drop(cut);
    let after = a.spool_write(&mut other, &data(6 * PIECE)).await;
    let committed = a.finish_put(other).await;

    assert!(
        matches!(over, Err(EngineError::BufferFull { .. })),
        "{over:?}"
    );
    assert_eq!(held, 2);
    after.unwrap();
    assert_eq!(committed.unwrap().size, 6 * PIECE as u64);
    assert_eq!(spool_files(dir.path()), 0);
}

#[tokio::test]
async fn test_put_that_the_commit_would_refuse_writes_no_body() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let a = open(dir.path(), &remote, Config::default()).await;
    a.create_bucket(BUCKET, None).await.unwrap();
    a.put(
        BUCKET,
        "k",
        Bytes::from("old"),
        BTreeMap::new(),
        WriteMode::Overwrite,
    )
    .await
    .unwrap();

    let create = a
        .begin_put(BUCKET, "k", BTreeMap::new(), WriteMode::CreateOnly)
        .await;
    let wrong = a
        .begin_put(
            BUCKET,
            "k",
            BTreeMap::new(),
            WriteMode::IfMatch(vec![[9; 32]]),
        )
        .await;
    let missing = a
        .begin_put(BUCKET, "none", BTreeMap::new(), WriteMode::IfExists)
        .await;

    assert!(matches!(
        create,
        Err(EngineError::PreconditionFailed { .. })
    ));
    assert!(matches!(wrong, Err(EngineError::PreconditionFailed { .. })));
    assert!(matches!(missing, Err(EngineError::NoSuchKey { .. })));
    assert_eq!(spool_files(dir.path()), 0);
}

#[tokio::test]
async fn test_commit_checks_again_under_the_lock() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let a = open(dir.path(), &remote, Config::default()).await;
    a.create_bucket(BUCKET, None).await.unwrap();

    let mut spool = a
        .begin_put(BUCKET, "k", BTreeMap::new(), WriteMode::CreateOnly)
        .await
        .unwrap();
    a.spool_write(&mut spool, &data(PIECE)).await.unwrap();
    // Another put takes the key while the body streams.
    a.put(
        BUCKET,
        "k",
        Bytes::from("first"),
        BTreeMap::new(),
        WriteMode::CreateOnly,
    )
    .await
    .unwrap();
    let late = a.finish_put(spool).await;

    assert!(
        matches!(late, Err(EngineError::PreconditionFailed { .. })),
        "{late:?}"
    );
    assert_eq!(a.get(BUCKET, "k", None).await.unwrap().data, "first");
    assert_eq!(spool_files(dir.path()), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_spooled_put_over_the_pack_target_wakes_the_flusher() {
    let remote = Arc::new(MemoryRemote::default());
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        flush_delay: std::time::Duration::from_secs(60),
        pack_target: PIECE,
        ..Config::default()
    };
    let a = Arc::new(open(dir.path(), &remote, config).await);
    a.create_bucket(BUCKET, None).await.unwrap();
    let flusher = a.spawn_flusher();
    // The first pass of the flusher runs at once: wait until it sleeps for the delay.
    while remote.list("log/").await.unwrap().is_empty() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let before = remote.list("log/").await.unwrap().len();

    spooled_put(&a, "k", &data(2 * PIECE), WriteMode::Overwrite)
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while remote.list("log/").await.unwrap().len() == before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no flush within 5 s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    flusher.abort();
}

/// The last segment of the buffer: the active one, empty after a flush.
fn last_segment(dir: &Path) -> u64 {
    std::fs::read_dir(dir.join("buffer"))
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".log")?.parse().ok()
        })
        .max()
        .unwrap()
}

#[tokio::test]
async fn test_failure_after_the_rename_breaks_the_buffer_and_keeps_the_put() {
    for dir_sync_fails in [true, false] {
        let remote = Arc::new(MemoryRemote::default());
        let dir = tempfile::tempdir().unwrap();
        let a = open(dir.path(), &remote, Config::default()).await;
        a.create_bucket(BUCKET, None).await.unwrap();
        a.flush().await.unwrap();
        let body = data(2 * PIECE);
        // A directory with the name of the next segment makes its creation fail.
        let next = dir
            .path()
            .join(format!("buffer/{:020}.log", last_segment(dir.path()) + 1));
        match dir_sync_fails {
            true => engine::sim::arm_crash(Some(Point::SpoolDirSync)),
            false => std::fs::create_dir(&next).unwrap(),
        }

        let result = spooled_put(&a, "k", &body, WriteMode::Overwrite).await;
        engine::sim::arm_crash(None);
        let later = a
            .put(
                BUCKET,
                "j",
                Bytes::from("x"),
                BTreeMap::new(),
                WriteMode::Overwrite,
            )
            .await;
        drop(a);
        if next.is_dir() {
            std::fs::remove_dir(&next).unwrap();
        }
        let a = open(dir.path(), &remote, Config::default()).await;

        assert!(result.is_err(), "{dir_sync_fails}: {result:?}");
        assert!(
            matches!(later, Err(EngineError::BufferBroken)),
            "{dir_sync_fails}: {later:?}"
        );
        assert!(a.get(BUCKET, "k", None).await.unwrap().data == body);
    }
}
