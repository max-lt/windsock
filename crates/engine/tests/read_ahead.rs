//! Read-ahead of GETs from the remote: depth by the pace of the client, room, slots, tasks.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, ObjectReader, READ_AHEAD_IN_FLIGHT, WriteMode};
use remote::{MemoryRemote, Remote, RemoteError};
use tempfile::TempDir;

const BUCKET: &str = "bkt";
const MIB: usize = 1024 * 1024;

/// A remote whose range reads take `delay`, can fail at one start offset, and are recorded.
#[derive(Default)]
struct SlowRemote {
    inner: MemoryRemote,
    delay_ms: AtomicU64,
    fail_at: Mutex<Option<u64>>,
    ranges: Mutex<Vec<Range<u64>>>,
}

impl SlowRemote {
    fn set_delay(&self, delay: Duration) {
        self.delay_ms
            .store(delay.as_millis() as u64, Ordering::SeqCst);
    }

    fn range_reads(&self) -> usize {
        self.ranges.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl Remote for SlowRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        self.inner.create(key, data).await
    }

    async fn get(&self, key: &str, max_len: u64) -> Result<Option<Bytes>, RemoteError> {
        self.inner.get(key, max_len).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        self.ranges.lock().unwrap().push(range.clone());
        let delay = self.delay_ms.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(delay)).await;
        if *self.fail_at.lock().unwrap() == Some(range.start) {
            return Err(RemoteError::Io(std::io::Error::other(
                "injected range fault",
            )));
        }
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        self.inner.list(prefix).await
    }
}

struct Proxy {
    _dir: TempDir,
    engine: Engine<SlowRemote>,
}

async fn proxy(remote: &Arc<SlowRemote>, seed: u8, config: Config) -> Proxy {
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
    Proxy { _dir: dir, engine }
}

/// No cache: every piece comes from the remote.
fn depth(read_ahead: usize) -> Config {
    Config {
        cache_bytes: 0,
        read_ahead,
        ..Config::default()
    }
}

fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut out);
    out
}

/// A remote that holds `data` at `key`, flushed by a writer proxy.
async fn remote_with(objects: &[(&str, &[u8])]) -> Arc<SlowRemote> {
    let remote = Arc::new(SlowRemote::default());
    let writer = proxy(&remote, 1, depth(0)).await;
    writer.engine.create_bucket(BUCKET, None).await.unwrap();
    for (key, data) in objects {
        writer
            .engine
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
    writer.engine.flush().await.unwrap();
    remote
}

async fn open(proxy: &Proxy, key: &str) -> ObjectReader {
    proxy.engine.get_reader(BUCKET, key, None).await.unwrap()
}

/// Reads as a GET body does: room for each piece, the piece, then `gap` before the next one.
async fn read_paced(proxy: &Proxy, key: &str, gap: Duration) -> Vec<u8> {
    let mut reader = open(proxy, key).await;
    let mut data = Vec::new();
    loop {
        let room = proxy.engine.piece_room(&mut reader).await.unwrap();
        let Some(piece) = proxy.engine.next_piece(&mut reader).await.unwrap() else {
            return data;
        };
        data.extend_from_slice(&piece);
        drop(room);
        tokio::time::sleep(gap).await;
    }
}

/// The time of one cold piece: the remote delay and the CPU of its checks, which a debug build
/// makes long. Gaps in these tests are multiples of it.
async fn piece_time(remote: &Arc<SlowRemote>, key: &str) -> Duration {
    let probe = proxy(remote, 9, depth(0)).await;
    let mut reader = open(&probe, key).await;
    let started = Instant::now();
    probe.engine.next_piece(&mut reader).await.unwrap().unwrap();
    started.elapsed()
}

/// Waits until no read-ahead task runs, then checks that every room and slot came back.
async fn assert_all_given_back(proxy: &Proxy, budget: u64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while proxy.engine.read_state().tasks_running > 0 {
        assert!(Instant::now() < deadline, "a read-ahead task still runs");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let state = proxy.engine.read_state();
    assert_eq!(state.budget_free, budget, "{state:?}");
    assert_eq!(state.fetch_slots_free, READ_AHEAD_IN_FLIGHT, "{state:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_read_ahead_reads_a_cold_object_in_fewer_rounds() {
    let data = random_bytes(1, 64 * MIB);
    let remote = remote_with(&[("k", &data)]).await;
    let one = proxy(&remote, 2, depth(0)).await;
    let three = proxy(&remote, 3, depth(3)).await;
    one.engine.head(BUCKET, "k").await.unwrap();
    three.engine.head(BUCKET, "k").await.unwrap();
    remote.set_delay(Duration::from_millis(200));

    let started = Instant::now();
    let slow = read_paced(&one, "k", Duration::ZERO).await;
    let depth_one = started.elapsed();
    let started = Instant::now();
    let fast = read_paced(&three, "k", Duration::ZERO).await;
    let depth_three = started.elapsed();

    assert!(slow == data && fast == data);
    eprintln!("64 MiB at 200 ms: depth 1 {depth_one:?}, depth 3 {depth_three:?}");
    assert!(
        depth_three * 2 < depth_one,
        "depth 1 {depth_one:?}, depth 3 {depth_three:?}"
    );
    assert!(three.engine.read_state().tasks_started > 0);
    assert_eq!(one.engine.read_state().tasks_started, 0);
    assert_all_given_back(&three, Config::default().read_budget).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_slow_reader_starts_no_task_and_a_fast_reader_does() {
    let data = random_bytes(2, 16 * MIB);
    let remote = remote_with(&[("k", &data)]).await;
    let slow = proxy(&remote, 2, depth(3)).await;
    let fast = proxy(&remote, 3, depth(3)).await;
    remote.set_delay(Duration::from_millis(20));
    // Far over READ_AHEAD_SLOW_FACTOR times a fetch, also when other tests load the CPU.
    let slow_gap = 10 * piece_time(&remote, "k").await;

    let slow_data = read_paced(&slow, "k", slow_gap).await;
    let fast_data = read_paced(&fast, "k", Duration::ZERO).await;

    assert!(slow_data == data && fast_data == data);
    assert_eq!(slow.engine.read_state().tasks_started, 0);
    assert!(fast.engine.read_state().tasks_started > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reader_that_slows_down_gives_back_its_surplus_room() {
    let data = random_bytes(3, 32 * MIB);
    let remote = remote_with(&[("k", &data)]).await;
    let reader_proxy = proxy(&remote, 2, depth(3)).await;
    let engine = &reader_proxy.engine;
    let budget = Config::default().read_budget;
    remote.set_delay(Duration::from_millis(50));
    let slow_gap = 10 * piece_time(&remote, "k").await;
    let mut reader = open(&reader_proxy, "k").await;

    let mut got = Vec::new();
    for _ in 0..4 {
        got.extend_from_slice(&engine.next_piece(&mut reader).await.unwrap().unwrap());
    }
    let ahead = engine.read_state();
    tokio::time::sleep(slow_gap).await;
    got.extend_from_slice(&engine.next_piece(&mut reader).await.unwrap().unwrap());
    while engine.read_state().tasks_running > 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let after = engine.read_state();
    while let Some(piece) = engine.next_piece(&mut reader).await.unwrap() {
        got.extend_from_slice(&piece);
    }

    assert!(
        ahead.budget_free < budget,
        "the fast pieces read ahead: {ahead:?}"
    );
    assert_eq!(after.budget_free, budget, "the slow gap gave all back");
    assert!(got == data, "the pieces put back are read in turn");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_dropped_reader_stops_its_tasks_and_gives_back_all_room() {
    let data = random_bytes(4, 48 * MIB);
    let remote = remote_with(&[("k", &data)]).await;
    let reader_proxy = proxy(&remote, 2, depth(3)).await;
    let engine = &reader_proxy.engine;
    let budget = Config::default().read_budget;
    reader_proxy.engine.head(BUCKET, "k").await.unwrap();
    remote.set_delay(Duration::from_millis(100));

    // Queue empty: no piece read yet.
    drop(open(&reader_proxy, "k").await);
    assert_all_given_back(&reader_proxy, budget).await;

    // Queue full: tasks wait in the remote, and the reader holds the room of one piece.
    let mut reader = open(&reader_proxy, "k").await;
    let mut room = None;
    for _ in 0..4 {
        room = Some(engine.piece_room(&mut reader).await.unwrap());
        engine.next_piece(&mut reader).await.unwrap().unwrap();
    }
    let full = engine.read_state();
    drop(reader);
    drop(room);
    assert!(full.tasks_running > 0, "{full:?}");
    assert_all_given_back(&reader_proxy, budget).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reader_dropped_at_any_time_with_cache_writes_gives_back_all_room() {
    let objects: Vec<(String, Vec<u8>)> = (0..6)
        .map(|i| (format!("k{i}"), random_bytes(10 + i, 24 * MIB)))
        .collect();
    let refs: Vec<(&str, &[u8])> = objects
        .iter()
        .map(|(key, data)| (key.as_str(), data.as_slice()))
        .collect();
    let remote = remote_with(&refs).await;
    let config = Config {
        cache_bytes: 1 << 30,
        read_ahead: 3,
        ..Config::default()
    };
    let reader_proxy = proxy(&remote, 2, config).await;
    let budget = Config::default().read_budget;
    reader_proxy.engine.head(BUCKET, "k0").await.unwrap();

    // Tasks end in the remote read or in the cache write at a time that each drop changes.
    for (i, (key, _)) in objects.iter().enumerate() {
        let engine = &reader_proxy.engine;
        let mut reader = open(&reader_proxy, key).await;
        for _ in 0..3 {
            engine.next_piece(&mut reader).await.unwrap().unwrap();
        }
        tokio::time::sleep(Duration::from_millis(i as u64 * 3)).await;
        drop(reader);
        assert_all_given_back(&reader_proxy, budget).await;
    }
    assert!(reader_proxy.engine.read_state().tasks_started > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cached_pieces_start_no_task() {
    let data = random_bytes(5, 32 * MIB);
    let remote = remote_with(&[("k", &data)]).await;
    let config = Config {
        cache_bytes: 1 << 30,
        read_ahead: 3,
        ..Config::default()
    };
    let reader_proxy = proxy(&remote, 2, config).await;
    remote.set_delay(Duration::from_millis(20));
    assert!(read_paced(&reader_proxy, "k", Duration::ZERO).await == data);
    let started = reader_proxy.engine.read_state().tasks_started;
    let reads = remote.range_reads();

    let again = read_paced(&reader_proxy, "k", Duration::ZERO).await;

    assert!(again == data);
    assert!(started > 0, "the cold read read ahead");
    assert_eq!(reader_proxy.engine.read_state().tasks_started, started);
    assert_eq!(remote.range_reads(), reads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_fetch_failure_ends_the_body_when_its_piece_is_due() {
    let data = random_bytes(6, 32 * MIB);
    let remote = remote_with(&[("k", &data)]).await;
    let learner = proxy(&remote, 2, depth(0)).await;
    assert!(read_paced(&learner, "k", Duration::ZERO).await == data);
    let ranges: Vec<Range<u64>> = remote
        .ranges
        .lock()
        .unwrap()
        .iter()
        .filter(|range| !range.is_empty())
        .cloned()
        .collect();
    let reader_proxy = proxy(&remote, 3, depth(3)).await;
    reader_proxy.engine.head(BUCKET, "k").await.unwrap();
    // Pieces 0 and 1 start no read-ahead; at piece 2, tasks read 3, 4 and 5. Piece 4 fails.
    *remote.fail_at.lock().unwrap() = Some(ranges[4].start);
    remote.set_delay(Duration::from_millis(20));
    let engine = &reader_proxy.engine;
    let mut reader = open(&reader_proxy, "k").await;

    let mut got = Vec::new();
    for _ in 0..4 {
        got.extend_from_slice(&engine.next_piece(&mut reader).await.unwrap().unwrap());
    }
    let failed = engine.next_piece(&mut reader).await;

    assert!(engine.read_state().tasks_started >= 2);
    assert!(got[..] == data[..got.len()], "pieces 0 to 3 are right");
    assert!(failed.is_err(), "piece 4 fails when it is due");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_many_readers_on_a_small_budget_all_finish() {
    let data = Arc::new(random_bytes(7, 16 * MIB));
    let remote = remote_with(&[("k", &data)]).await;
    let config = Config {
        read_budget: engine::MIN_READ_BUDGET,
        ..depth(3)
    };
    let reader_proxy = Arc::new(proxy(&remote, 2, config).await);
    reader_proxy.engine.head(BUCKET, "k").await.unwrap();
    remote.set_delay(Duration::from_millis(5));

    // Starts spread over time: early readers hold read-ahead room while later ones wait.
    let readers: Vec<_> = (0..100u64)
        .map(|i| {
            let (reader_proxy, data) = (reader_proxy.clone(), data.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(400 * i)).await;
                let got = read_paced(&reader_proxy, "k", Duration::from_millis(5)).await;
                assert!(got == *data);
            })
        })
        .collect();
    let all = async {
        for reader in readers {
            reader.await.unwrap();
        }
    };
    tokio::time::timeout(Duration::from_secs(300), all)
        .await
        .expect("the readers do not wait for each other in a cycle");

    assert!(reader_proxy.engine.read_state().tasks_started > 0);
    assert_all_given_back(&reader_proxy, engine::MIN_READ_BUDGET).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reader_with_pieces_ahead_takes_their_room_with_a_full_budget() {
    let data = random_bytes(8, 32 * MIB);
    let remote = remote_with(&[("k", &data)]).await;
    let reader_proxy = proxy(&remote, 2, depth(3)).await;
    let engine = &reader_proxy.engine;
    remote.set_delay(Duration::from_millis(20));
    let mut reader = open(&reader_proxy, "k").await;
    let mut got = Vec::new();
    for _ in 0..3 {
        got.extend_from_slice(&engine.next_piece(&mut reader).await.unwrap().unwrap());
    }
    assert!(engine.read_state().tasks_started > 0);
    // Other GETs take all the room that is left.
    let mut others = Vec::new();
    while let Ok(room) = engine.read_room(Some(Duration::from_millis(10))).await {
        others.push(room);
    }

    let room = tokio::time::timeout(Duration::from_secs(5), engine.piece_room(&mut reader))
        .await
        .expect("a piece that read-ahead holds gives its own room")
        .unwrap();
    got.extend_from_slice(&engine.next_piece(&mut reader).await.unwrap().unwrap());

    assert!(got[..] == data[..got.len()]);
    drop((room, others, reader));
    assert_all_given_back(&reader_proxy, Config::default().read_budget).await;
}

#[tokio::test]
async fn test_read_ahead_over_the_maximum_is_refused() {
    let remote = Arc::new(SlowRemote::default());
    let dir = tempfile::tempdir().unwrap();

    let opened = Engine::open(
        dir.path(),
        remote,
        SigningKey::from_bytes(&[1; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        depth(engine::MAX_READ_AHEAD + 1),
    )
    .await;

    assert!(matches!(opened, Err(engine::EngineError::Config(_))));
}
