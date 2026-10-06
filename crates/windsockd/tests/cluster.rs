//! Two daemons on one local directory remote, as processes.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{Daemon, Reply, call, chains, cluster_config, count, start, test_keys};
use hyper::StatusCode;
use tempfile::TempDir;

/// One cluster at a time: two debug daemons hashing tens of MB slow the others down.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Cluster {
    root: TempDir,
}

impl Cluster {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn remote(&self) -> PathBuf {
        self.root.path().join("remote")
    }

    /// The configuration of proxy `name`, with a 3 s GC horizon.
    fn config(&self, name: &str, flush_delay_ms: u64, gc_enabled: bool) -> PathBuf {
        let gc = format!(
            "enabled = {gc_enabled}\ninterval_secs = 1\nhorizon_secs = 3\nretention_secs = 0"
        );
        self.config_with(name, flush_delay_ms, &gc)
    }

    fn config_with(&self, name: &str, flush_delay_ms: u64, gc: &str) -> PathBuf {
        let dir = self.root.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        cluster_config(&dir, &self.remote(), flush_delay_ms, gc)
    }
}

async fn put(daemon: &Daemon, path: &str, body: &[u8]) -> Reply {
    call(daemon, &test_keys(), "PUT", path, body).await
}

async fn get(daemon: &Daemon, path: &str) -> Reply {
    call(daemon, &test_keys(), "GET", path, b"").await
}

/// A creates the bucket `shared`; B sees it before the test goes on.
async fn share_bucket(a: &Daemon, b: &Daemon) {
    assert_eq!(put(a, "/shared", b"").await.status, StatusCode::OK);
    eventually(
        b,
        "/shared?list-type=2",
        &get(a, "/shared?list-type=2").await.body,
        Duration::from_secs(30),
    )
    .await;
}

/// Polls `path` on `daemon` until it returns `body`, or fails after `limit`.
async fn eventually(daemon: &Daemon, path: &str, body: &[u8], limit: Duration) {
    let deadline = Instant::now() + limit;

    loop {
        let reply = get(daemon, path).await;
        if reply.status == StatusCode::OK && reply.body == body {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{path} on {}: {} {}",
            daemon.address,
            reply.status,
            reply.text()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Every chain is seqs 0, 1, 2... with no gap: no fork, no lost entry.
fn assert_chains_whole(remote: &Path) {
    for seqs in chains(remote) {
        let expected: Vec<u64> = (0..seqs.len() as u64).collect();
        assert_eq!(seqs, expected);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_write_on_one_proxy_reads_on_the_other() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let cluster = Cluster::new();
    let a = start(&cluster.config("a", 100, false), "info");
    let b = start(&cluster.config("b", 100, false), "info");

    share_bucket(&a, &b).await;
    put(&a, "/shared/from-a", b"written on a").await;
    eventually(
        &b,
        "/shared/from-a",
        b"written on a",
        Duration::from_secs(30),
    )
    .await;
    put(&b, "/shared/from-b", b"written on b").await;
    eventually(
        &a,
        "/shared/from-b",
        b"written on b",
        Duration::from_secs(30),
    )
    .await;

    assert!(a.stop() && b.stop());
    assert_chains_whole(&cluster.remote());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_puts_to_one_key_converge() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let cluster = Cluster::new();
    let a = start(&cluster.config("a", 100, false), "info");
    let b = start(&cluster.config("b", 100, false), "info");
    put(&a, "/shared", b"").await;
    eventually(
        &b,
        "/shared?list-type=2",
        &get(&a, "/shared?list-type=2").await.body,
        Duration::from_secs(30),
    )
    .await;

    let (from_a, from_b) = tokio::join!(
        put(&a, "/shared/k", b"value of a"),
        put(&b, "/shared/k", b"value of b")
    );
    assert_eq!(
        (from_a.status, from_b.status),
        (StatusCode::OK, StatusCode::OK)
    );

    // Both proxies settle on one value: the last writer by HLC.
    let deadline = Instant::now() + Duration::from_secs(15);
    let winner = loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (on_a, on_b) = (get(&a, "/shared/k").await, get(&b, "/shared/k").await);
        if on_a.body == on_b.body && on_a.etag() == on_b.etag() {
            break on_a.body;
        }
        assert!(Instant::now() < deadline, "a and b do not converge");
    };

    assert!(winner == b"value of a" || winner == b"value of b");
    assert!(a.stop() && b.stop());
    assert_chains_whole(&cluster.remote());
    assert_eq!(chains(&cluster.remote()).len(), 2);
}

/// A runs the GC with a 3 s horizon while B overwrites keys, writes content
/// that a condemned pack held, and reads all the time.
#[tokio::test(flavor = "multi_thread")]
async fn test_gc_on_one_proxy_while_the_other_writes() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let cluster = Cluster::new();
    let mut a = start(&cluster.config("a", 100, true), "info");
    let b = start(&cluster.config("b", 100, false), "info");
    put(&a, "/shared", b"").await;
    eventually(
        &b,
        "/shared?list-type=2",
        &get(&a, "/shared?list-type=2").await.body,
        Duration::from_secs(30),
    )
    .await;
    put(&b, "/shared/stable", b"never changes").await;
    eventually(
        &a,
        "/shared/stable",
        b"never changes",
        Duration::from_secs(30),
    )
    .await;

    let recurring = random_bytes(7, 20_000);
    let start_time = Instant::now();
    let mut round = 0u64;
    while start_time.elapsed() < Duration::from_secs(30) {
        round += 1;
        let hot = random_bytes(round, 20_000);
        assert_eq!(put(&b, "/shared/hot", &hot).await.status, StatusCode::OK);
        let read = get(&b, "/shared/hot").await;
        assert_eq!(
            (read.status, read.body == hot),
            (StatusCode::OK, true),
            "round {round}"
        );

        // The same content comes back after its first copy died: a dedup candidate.
        let key = format!("/shared/recurring-{}", round % 2);
        let other = format!("/shared/recurring-{}", (round + 1) % 2);
        put(&b, &key, &recurring).await;
        call(&b, &test_keys(), "DELETE", &other, b"").await;

        let on_a = get(&a, "/shared/stable").await;
        assert_eq!(
            on_a.status,
            StatusCode::OK,
            "round {round}: {}",
            on_a.text()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut deleted = 0;
    while let Some(line) = a.wait_for("gc run", Duration::from_secs(5)) {
        deleted += line
            .split("deleted_packs: ")
            .nth(1)
            .and_then(|rest| rest.split(',').next()?.parse::<u32>().ok())
            .unwrap_or(0);
        if deleted > 0 {
            break;
        }
    }
    assert!(deleted > 0, "the GC deleted dead packs");

    let last_hot = random_bytes(round, 20_000);
    let last_recurring = format!("/shared/recurring-{}", round % 2);
    tokio::time::sleep(Duration::from_secs(5)).await;
    for daemon in [&a, &b] {
        eventually(daemon, "/shared/hot", &last_hot, Duration::from_secs(30)).await;
        eventually(daemon, &last_recurring, &recurring, Duration::from_secs(30)).await;
        eventually(
            daemon,
            "/shared/stable",
            b"never changes",
            Duration::from_secs(30),
        )
        .await;
    }
    assert!(a.stop() && b.stop());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proxy_killed_in_the_middle_of_a_flush() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let cluster = Cluster::new();
    // The default horizon: a 3 s one is shorter than this flush, which then never commits.
    let a = start(&cluster.config_with("a", 100, ""), "info");
    // No timer flush during the puts: the fifth put fills a pack target and starts one flush.
    let b_config = cluster.config_with("b", 60_000, "");
    let mut b = start(&b_config, "info,engine=debug");
    share_bucket(&a, &b).await;
    let objects: Vec<Vec<u8>> = (0..5)
        .map(|i| random_bytes(100 + i, 14 * 1024 * 1024))
        .collect();
    let mut entries_before = 0;
    let mut packs_before = 0;

    for (i, data) in objects.iter().enumerate() {
        if i == objects.len() - 1 {
            entries_before = chains(&cluster.remote())
                .iter()
                .map(Vec::len)
                .sum::<usize>();
            packs_before = count(&cluster.remote(), "packs");
        }
        assert_eq!(
            put(&b, &format!("/shared/big-{i}"), data).await.status,
            StatusCode::OK
        );
    }
    // Packs upload one at a time: at the second line, the first pack is whole in the remote.
    for _ in 0..2 {
        assert!(
            b.wait_for("uploading pack", Duration::from_secs(30))
                .is_some()
        );
    }
    b.crash();

    let entries_after = chains(&cluster.remote())
        .iter()
        .map(Vec::len)
        .sum::<usize>();
    assert!(
        count(&cluster.remote(), "packs") > packs_before,
        "a pack reached the remote"
    );
    assert_eq!(
        entries_after, entries_before,
        "the kill came before the entry"
    );

    let b = start(&b_config, "info");
    for (i, data) in objects.iter().enumerate() {
        eventually(
            &a,
            &format!("/shared/big-{i}"),
            data,
            Duration::from_secs(30),
        )
        .await;
    }
    assert!(a.stop() && b.stop());
    assert_chains_whole(&cluster.remote());
}

/// The entries of one chain directory, in seq order, without the temporary files of a create.
fn entries(chain: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(chain)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<u64>()
                .is_ok()
        })
        .collect();
    entries.sort();
    entries
}

fn chain_sizes(remote: &Path) -> Vec<(PathBuf, usize)> {
    std::fs::read_dir(remote.join("log"))
        .unwrap()
        .map(|node| {
            let path = node.unwrap().path();
            let size = entries(&path).len();
            (path, size)
        })
        .collect()
}

/// Waits for a flush to add an entry, and returns the path of that entry.
async fn newest_entry_of_the_chain_that_grows(
    remote: &Path,
    before: &[(PathBuf, usize)],
) -> PathBuf {
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        for (chain, size) in chain_sizes(remote) {
            let old = before
                .iter()
                .find(|(c, _)| *c == chain)
                .map_or(0, |(_, s)| *s);
            if size > old {
                return entries(&chain).pop().unwrap();
            }
        }
        assert!(Instant::now() < deadline, "no new entry");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A create writes a temporary file in the chain directory before the entry.
#[tokio::test]
async fn test_new_entry_is_not_a_temporary_file() {
    let remote = tempfile::tempdir().unwrap();
    let chain = remote.path().join("log").join("n");
    std::fs::create_dir_all(&chain).unwrap();
    std::fs::write(chain.join("00000000000000000001"), b"old").unwrap();
    let before = chain_sizes(remote.path());

    std::fs::write(chain.join(".tmp.1.2"), b"new").unwrap();
    let late = chain.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::fs::write(late.join("00000000000000000002"), b"new").unwrap();
    });

    assert_eq!(
        newest_entry_of_the_chain_that_grows(remote.path(), &before).await,
        chain.join("00000000000000000002")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_broken_chain_seen_from_the_other_proxy() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let cluster = Cluster::new();
    let a_config = cluster.config("a", 100, true);
    let a = start(&a_config, "info");
    let b = start(&cluster.config("b", 100, false), "info");
    share_bucket(&a, &b).await;
    assert_eq!(
        put(&b, "/shared/first", b"first").await.status,
        StatusCode::OK
    );
    eventually(&a, "/shared/first", b"first", Duration::from_secs(30)).await;
    assert!(a.stop());

    let before = chain_sizes(&cluster.remote());
    assert_eq!(
        put(&b, "/shared/second", b"second").await.status,
        StatusCode::OK
    );
    let newest = newest_entry_of_the_chain_that_grows(&cluster.remote(), &before).await;
    let good = std::fs::read(&newest).unwrap();
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    std::fs::write(&newest, &bad).unwrap();

    let mut a = start(&a_config, "info");
    assert!(
        a.wait_for("chain is broken", Duration::from_secs(30))
            .is_some()
    );
    assert!(a.wait_for("gc refused", Duration::from_secs(30)).is_some());
    assert_eq!(
        put(&a, "/shared/own", b"a still works").await.status,
        StatusCode::OK
    );
    assert_eq!(get(&a, "/shared/own").await.text(), "a still works");
    assert_eq!(get(&a, "/shared/first").await.text(), "first");
    assert_eq!(
        get(&a, "/shared/second").await.status,
        StatusCode::NOT_FOUND
    );

    std::fs::write(&newest, &good).unwrap();
    eventually(&a, "/shared/second", b"second", Duration::from_secs(30)).await;
    assert!(a.wait_for("gc run", Duration::from_secs(30)).is_some());
    assert!(a.stop() && b.stop());
}
