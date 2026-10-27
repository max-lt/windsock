//! Two or three proxies on one remote: clock skew, races, restarts, lag and broken chains.
//! Each case ends with the same visible state on every proxy, or with a clear error.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, EngineError, WriteMode};
use journal::{Action, Entry};
use remote::{MemoryRemote, Remote, Sweep};
use tempfile::TempDir;

const BUCKET: &str = "bkt";
const HORIZON: Duration = Duration::from_secs(3600);

struct Proxy {
    dir: TempDir,
    engine: Engine<MemoryRemote>,
}

fn keys() -> engine::Keys {
    engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys()
}

async fn open_in(remote: &Arc<MemoryRemote>, seed: u8, dir: TempDir) -> Proxy {
    let config = Config {
        gc_horizon: HORIZON,
        ..Config::default()
    };
    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[seed; 32]),
        keys(),
        config,
    )
    .await
    .unwrap();
    Proxy { dir, engine }
}

async fn proxy(remote: &Arc<MemoryRemote>, seed: u8) -> Proxy {
    open_in(remote, seed, tempfile::tempdir().unwrap()).await
}

async fn put(engine: &Engine<MemoryRemote>, key: &str, data: &str) {
    engine
        .put(
            BUCKET,
            key,
            Bytes::copy_from_slice(data.as_bytes()),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
}

/// What a client sees for each key: its data, or nothing.
async fn view(engine: &Engine<MemoryRemote>, keys: &[&str]) -> Vec<Option<String>> {
    let mut out = Vec::new();
    for key in keys {
        out.push(match engine.get(BUCKET, key, None).await {
            Ok(object) => Some(String::from_utf8(object.data.to_vec()).unwrap()),
            Err(EngineError::NoSuchKey { .. }) => None,
            Err(e) => panic!("{key}: {e}"),
        });
    }
    out
}

/// Syncs every proxy, then checks that they all show `expected`.
async fn assert_all_see(proxies: &[&Proxy], keys: &[&str], expected: &[Option<&str>]) {
    let expected: Vec<Option<String>> = expected.iter().map(|v| v.map(String::from)).collect();
    for proxy in proxies {
        proxy.engine.sync().await.unwrap();
        assert_eq!(
            view(&proxy.engine, keys).await,
            expected,
            "node {}",
            proxy.engine.node()
        );
    }
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Writes entry 0 of a new chain for node `seed` at `hlc`, as a proxy with that clock would.
async fn forged_entry(remote: &MemoryRemote, seed: u8, hlc: u64, actions: Vec<Action>) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let entry = Entry::sign(
        &key,
        0,
        [0u8; 32],
        hlc,
        BTreeMap::new(),
        actions,
        keys().sealer(),
    );
    remote
        .create(&entry.remote_key(), Bytes::from(entry.to_wire()))
        .await
        .unwrap();
    remote
        .put(&journal::node_key(entry.node), Bytes::new())
        .await
        .unwrap();
}

/// The entries in the remote, opened.
async fn entries(remote: &MemoryRemote) -> Vec<Entry> {
    let mut out = Vec::new();
    for key in remote.list(journal::LOG_PREFIX).await.unwrap() {
        let bytes = remote.get(&key).await.unwrap().unwrap();
        out.push(Entry::from_wire(&bytes, keys().sealer()).unwrap());
    }
    out
}

fn delete(key: &str) -> Action {
    Action::Delete {
        bucket: BUCKET.into(),
        key: key.into(),
    }
}

async fn with_bucket(remote: &Arc<MemoryRemote>) -> (Proxy, Proxy) {
    let a = proxy(remote, 1).await;
    let b = proxy(remote, 2).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();
    (a, b)
}

/// A proxy with a clock 2H ahead deletes a key. The others apply the delete, witness its time,
/// and a later write of theirs still wins.
#[tokio::test]
async fn test_proxy_clock_ahead_by_more_than_h_does_not_block_later_writes() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "one").await;
    a.engine.flush().await.unwrap();
    let ahead = now_nanos() + 2 * HORIZON.as_nanos() as u64;

    forged_entry(&remote, 9, ahead, vec![delete("k")]).await;

    assert_all_see(&[&a, &b], &["k"], &[None]).await;
    put(&a.engine, "k", "two").await;
    a.engine.flush().await.unwrap();
    assert_all_see(&[&a, &b], &["k"], &[Some("two")]).await;
}

/// A proxy with a clock 2H behind deletes a key after a newer write. LWW by HLC keeps the newer
/// write on every proxy: the clock assumption says no clock is this far off.
#[tokio::test]
async fn test_proxy_clock_behind_by_more_than_h_loses_to_newer_writes_everywhere() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "one").await;
    a.engine.flush().await.unwrap();
    let behind = now_nanos() - 2 * HORIZON.as_nanos() as u64;

    forged_entry(&remote, 9, behind, vec![delete("k")]).await;

    let c = proxy(&remote, 3).await;
    assert_all_see(&[&a, &b, &c], &["k"], &[Some("one")]).await;
}

/// A put on one proxy and a delete on another, flushed at the same time.
#[tokio::test]
async fn test_put_and_delete_of_one_key_on_two_proxies_converge() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "old").await;
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();

    put(&a.engine, "k", "new").await;
    b.engine.delete(BUCKET, "k").await.unwrap();
    let (fa, fb) = tokio::join!(a.engine.flush(), b.engine.flush());
    fa.unwrap();
    fb.unwrap();

    let c = proxy(&remote, 3).await;
    c.engine.sync().await.unwrap();
    let winner = view(&c.engine, &["k"]).await;
    let winner: Vec<Option<&str>> = winner.iter().map(|v| v.as_deref()).collect();
    assert!(winner == [Some("new")] || winner == [None], "{winner:?}");
    assert_all_see(&[&a, &b, &c], &["k"], &winner).await;
}

/// Two puts of one key with the same HLC from two nodes. The node ID breaks the tie, the same
/// way on every proxy.
#[tokio::test]
async fn test_two_puts_of_one_key_with_the_same_hlc_converge() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "from a").await;
    a.engine.flush().await.unwrap();
    put(&a.engine, "other", "from c").await;
    a.engine.flush().await.unwrap();
    let entries = entries(&remote).await;
    let put_k = entries
        .iter()
        .find(|e| matches!(e.actions.as_deref(), Some([Action::Put { key, .. }]) if key == "k"))
        .unwrap();
    let Some(
        [
            Action::Put {
                manifest_id,
                inline_manifest,
                ..
            },
        ],
    ) = entries.iter().find_map(|e| match e.actions.as_deref() {
        Some(actions @ [Action::Put { key, .. }]) if key == "other" => Some(actions),
        _ => None,
    })
    else {
        panic!("no put of other");
    };
    let same_hlc = Action::Put {
        bucket: BUCKET.into(),
        key: "k".into(),
        manifest_id: *manifest_id,
        inline_manifest: inline_manifest.clone(),
    };

    forged_entry(&remote, 9, put_k.hlc, vec![same_hlc]).await;

    let c = proxy(&remote, 3).await;
    c.engine.sync().await.unwrap();
    let winner = view(&c.engine, &["k"]).await;
    let winner: Vec<Option<&str>> = winner.iter().map(|v| v.as_deref()).collect();
    assert!(
        winner == [Some("from a")] || winner == [Some("from c")],
        "{winner:?}"
    );
    assert_all_see(&[&a, &b, &c], &["k"], &winner).await;
}

/// A proxy stops with an acknowledged write in its buffer. At restart it replays and flushes the
/// write. A stop after the entry create is in remote_faults.rs (lost answer on the journal).
#[tokio::test]
async fn test_proxy_that_restarts_before_its_flush_loses_no_write() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "kept").await;
    let dir = a.dir;
    drop(a.engine);

    let a = open_in(&remote, 1, dir).await;
    put(&a.engine, "j", "after").await;
    a.engine.flush().await.unwrap();

    assert_all_see(&[&a, &b], &["k", "j"], &[Some("kept"), Some("after")]).await;
}

/// A proxy offline for longer than H, with a buffered write, comes back after a GC pruned the
/// journal. It loads the snapshot, keeps its write, and every proxy sees all writes.
#[tokio::test]
async fn test_proxy_offline_past_a_prune_keeps_its_buffered_write() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "early", "a").await;
    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();
    put(&b.engine, "offline", "b").await;

    for n in 0..3 {
        put(&a.engine, &format!("late{n}"), "a").await;
        a.engine.flush().await.unwrap();
    }
    let report = a.engine.gc().await.unwrap();
    assert!(report.redacted_entries > 0);
    b.engine.flush().await.unwrap();

    let c = proxy(&remote, 3).await;
    let keys = ["early", "offline", "late0", "late2"];
    let all = [Some("a"), Some("b"), Some("a"), Some("a")];
    assert_all_see(&[&a, &b, &c], &keys, &all).await;
}

/// A reader of a chain with a gap names the chain as broken, applies nothing after the gap,
/// and reads the other chains.
#[tokio::test]
async fn test_chain_with_a_gap_is_broken_alone() {
    let remote = Arc::new(MemoryRemote::default());
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    b.engine.create_bucket(BUCKET, None).await.unwrap();
    b.engine.flush().await.unwrap();
    a.engine.sync().await.unwrap();
    for key in ["k0", "k1", "k2"] {
        put(&a.engine, key, "a").await;
        a.engine.flush().await.unwrap();
    }
    put(&b.engine, "from-b", "b").await;
    b.engine.flush().await.unwrap();
    // Seqs 0 to 2 of a put k0 to k2: seq 1 is k1.
    let gap = journal::entry_key(a.engine.node(), 1);
    remote.delete(&gap).await.unwrap();

    let c = proxy(&remote, 3).await;
    let report = c.engine.sync().await.unwrap();

    assert_eq!(report.broken, vec![a.engine.node()]);
    assert_eq!(
        view(&c.engine, &["k0", "k1", "k2", "from-b"]).await,
        [None, None, None, Some("b".into())]
    );
    assert!(matches!(
        c.engine.gc().await,
        Err(EngineError::BrokenChains(_))
    ));
}
