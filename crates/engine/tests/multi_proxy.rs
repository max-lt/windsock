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

/// A delete acked at `hlc`.
fn delete(key: &str, hlc: u64) -> Action {
    Action::Delete {
        bucket: BUCKET.into(),
        key: key.into(),
        hlc,
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

    forged_entry(&remote, 9, ahead, vec![delete("k", ahead)]).await;

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

    forged_entry(&remote, 9, behind, vec![delete("k", behind)]).await;

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
    let Some([Action::Put { hlc: ack, .. }]) = put_k.actions.as_deref() else {
        panic!("the put of k is one action");
    };
    let same_hlc = Action::Put {
        hlc: *ack,
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

/// Puts k0..k(n-1) on a new proxy 1, in one entry each, after proxy 2 made the bucket.
async fn chain_of(remote: &Arc<MemoryRemote>, n: usize) -> (Proxy, Proxy) {
    let a = proxy(remote, 1).await;
    let b = proxy(remote, 2).await;
    b.engine.create_bucket(BUCKET, None).await.unwrap();
    b.engine.flush().await.unwrap();
    a.engine.sync().await.unwrap();
    for i in 0..n {
        put(&a.engine, &format!("k{i}"), "a").await;
        a.engine.flush().await.unwrap();
    }
    (a, b)
}

/// A gap of two entries: the probe of the next seq does not see it, the listing at open does.
#[tokio::test]
async fn test_gap_of_two_entries_is_found_by_the_listing_at_open() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, _b) = chain_of(&remote, 4).await;
    for seq in [1, 2] {
        remote
            .delete(&journal::entry_key(a.engine.node(), seq))
            .await
            .unwrap();
    }

    let c = proxy(&remote, 3).await;
    let report = c.engine.sync().await.unwrap();

    assert_eq!(report.broken, vec![a.engine.node()]);
    assert!(matches!(
        c.engine.gc().await,
        Err(EngineError::BrokenChains(_))
    ));
}

/// A gap that appears after a proxy read the chain is found at the next GC run.
#[tokio::test]
async fn test_gap_of_two_entries_is_found_by_the_listing_at_the_gc() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = chain_of(&remote, 1).await;
    b.engine.sync().await.unwrap();
    for i in 1..4 {
        put(&a.engine, &format!("k{i}"), "a").await;
        a.engine.flush().await.unwrap();
    }
    for seq in [1, 2] {
        remote
            .delete(&journal::entry_key(a.engine.node(), seq))
            .await
            .unwrap();
    }

    assert!(
        b.engine.sync().await.unwrap().broken.is_empty(),
        "no list at a sync"
    );
    let error = b.engine.gc().await.unwrap_err();

    assert!(matches!(error, EngineError::BrokenChains(ref nodes) if nodes == &[a.engine.node()]));
}

/// The remote gives a changed copy of an entry that a proxy read. The GC run names the chain.
#[tokio::test]
async fn test_changed_copy_of_a_read_entry_is_found_at_the_gc() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = chain_of(&remote, 2).await;
    b.engine.sync().await.unwrap();
    let last = journal::entry_key(a.engine.node(), 1);
    let read =
        Entry::from_wire(&remote.get(&last).await.unwrap().unwrap(), keys().sealer()).unwrap();
    let changed = Entry::sign(
        &SigningKey::from_bytes(&[1; 32]),
        1,
        read.prev,
        read.hlc,
        read.seen.clone(),
        vec![delete("k0", read.hlc)],
        keys().sealer(),
    );
    remote
        .put(&last, Bytes::from(changed.to_wire()))
        .await
        .unwrap();

    let error = b.engine.gc().await.unwrap_err();

    assert!(matches!(error, EngineError::BrokenChains(ref nodes) if nodes == &[a.engine.node()]));
}

/// Writes an entry of node `seed` at `seq`, with `prev`, and no node marker.
async fn entry_at(
    remote: &MemoryRemote,
    seed: u8,
    seq: u64,
    prev: journal::EntryHash,
    seen: journal::Seen,
    actions: Vec<Action>,
) -> Entry {
    let entry = Entry::sign(
        &SigningKey::from_bytes(&[seed; 32]),
        seq,
        prev,
        now_nanos(),
        seen,
        actions,
        keys().sealer(),
    );
    remote
        .put(&entry.remote_key(), Bytes::from(entry.to_wire()))
        .await
        .unwrap();
    entry
}

/// Node 9 wrote an entry and no marker. Node 8 has a marker, and its delete names node 9 in
/// `seen`, so it applies only after the entry of node 9. The readers must find node 9 through
/// that link, or the acknowledged delete of node 8 never applies.
#[tokio::test]
async fn test_node_with_no_marker_is_found_through_a_seen_link() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "one").await;
    a.engine.flush().await.unwrap();
    let hidden = entry_at(
        &remote,
        9,
        0,
        [0u8; 32],
        BTreeMap::new(),
        vec![delete("x", now_nanos())],
    )
    .await;
    let link = journal::Link {
        seq: 0,
        hash: hidden.hash(),
    };
    let now = now_nanos();
    let entry = Entry::sign(
        &SigningKey::from_bytes(&[8; 32]),
        0,
        [0u8; 32],
        now,
        BTreeMap::from([(hidden.node, link)]),
        vec![delete("k", now)],
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

    let c = proxy(&remote, 3).await;

    assert_all_see(&[&a, &b, &c], &["k"], &[None]).await;
}

/// A bad signature in the middle of a chain: the sync names the node and the seq, the other
/// chains go on, and the GC refuses to run.
#[tokio::test]
async fn test_bad_signature_mid_chain_names_node_and_seq() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = chain_of(&remote, 3).await;
    let key = journal::entry_key(a.engine.node(), 1);
    let read =
        Entry::from_wire(&remote.get(&key).await.unwrap().unwrap(), keys().sealer()).unwrap();
    let forged = Entry::sign(
        &SigningKey::from_bytes(&[7; 32]),
        1,
        read.prev,
        read.hlc,
        read.seen.clone(),
        read.actions.clone().unwrap(),
        keys().sealer(),
    );
    let mut wire = forged.to_wire();
    // The node ID leads the wire form: give the entry the node of a, with the signature of 7.
    wire[..32].copy_from_slice(a.engine.node().as_bytes());
    remote.put(&key, Bytes::from(wire)).await.unwrap();
    put(&b.engine, "from-b", "b").await;
    b.engine.flush().await.unwrap();

    let c = proxy(&remote, 3).await;
    let report = c.engine.sync().await.unwrap();

    assert_eq!(report.broken, vec![a.engine.node()]);
    let cause = &report.broken_causes[0];
    assert!(cause.contains(&a.engine.node().to_string()), "{cause}");
    assert!(cause.contains("entry 1"), "{cause}");
    assert_eq!(view(&c.engine, &["from-b"]).await, [Some("b".into())]);
    assert!(matches!(
        c.engine.gc().await,
        Err(EngineError::BrokenChains(_))
    ));
}

/// Seqs at the end of the u64 range, a seq far ahead, and an entry copied to another seq.
#[tokio::test]
async fn test_extreme_and_duplicate_seqs_break_the_chain_with_no_panic() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, _b) = chain_of(&remote, 2).await;
    let node = a.engine.node();
    let first = remote
        .get(&journal::entry_key(node, 0))
        .await
        .unwrap()
        .unwrap();
    // A duplicate: entry 0 again at seq 2.
    remote
        .put(&journal::entry_key(node, 2), first.clone())
        .await
        .unwrap();
    let c = proxy(&remote, 3).await;
    let report = c.engine.sync().await.unwrap();
    assert_eq!(report.broken, vec![node], "duplicate seq");

    for seq in [u64::MAX, u64::MAX - 1, 1_000_000] {
        let remote = Arc::new(MemoryRemote::default());
        let (a, _b) = chain_of(&remote, 1).await;
        let node = a.engine.node();
        let bytes = remote
            .get(&journal::entry_key(node, 0))
            .await
            .unwrap()
            .unwrap();
        remote
            .put(&journal::entry_key(node, seq), bytes)
            .await
            .unwrap();

        let c = proxy(&remote, 3).await;
        let report = c.engine.sync().await.unwrap();

        assert_eq!(report.broken, vec![node], "seq {seq}");
    }
}

/// A proxy saw an HLC 1 h ahead of its wall clock, then restarts. Its next ack must still rank
/// above what it saw: the clock never goes down across a restart.
#[tokio::test]
async fn test_ack_after_a_restart_ranks_above_an_hlc_seen_before() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "one").await;
    a.engine.flush().await.unwrap();
    let ahead = now_nanos() + HORIZON.as_nanos() as u64;
    forged_entry(&remote, 9, ahead, vec![delete("k", ahead)]).await;
    a.engine.sync().await.unwrap();
    let Proxy { dir, engine } = a;
    drop(engine);

    let a = open_in(&remote, 1, dir).await;
    put(&a.engine, "k", "two").await;
    a.engine.flush().await.unwrap();

    assert_all_see(&[&a, &b], &["k"], &[Some("two")]).await;
}
/// A client writes a key on proxy a, then writes it again on proxy b after the first ack. The
/// second write must win, also when proxy a flushes after proxy b.
#[tokio::test]
async fn test_later_acked_write_wins_when_the_earlier_one_flushes_last() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "first").await;
    put(&b.engine, "k", "second").await;

    b.engine.flush().await.unwrap();
    a.engine.flush().await.unwrap();

    assert_all_see(&[&a, &b], &["k"], &[Some("second")]).await;
}

/// Two writes to one key in one flush: the later ack wins on every proxy.
#[tokio::test]
async fn test_later_write_in_the_same_flush_wins() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "first").await;
    put(&a.engine, "k", "second").await;

    a.engine.flush().await.unwrap();

    assert_all_see(&[&a, &b], &["k"], &[Some("second")]).await;
}

/// Last-Modified is the ack time: the same before and after the flush.
#[tokio::test]
async fn test_last_modified_stays_the_same_across_the_flush() {
    let remote = Arc::new(MemoryRemote::default());
    let (a, b) = with_bucket(&remote).await;
    put(&a.engine, "k", "v").await;
    let buffered = a.engine.head(BUCKET, "k").await.unwrap().last_modified;

    a.engine.flush().await.unwrap();
    b.engine.sync().await.unwrap();

    assert_eq!(
        a.engine.head(BUCKET, "k").await.unwrap().last_modified,
        buffered
    );
    assert_eq!(
        b.engine.head(BUCKET, "k").await.unwrap().last_modified,
        buffered
    );
}

async fn open_config(remote: &Arc<MemoryRemote>, seed: u8, dir: TempDir, config: Config) -> Proxy {
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

/// A new proxy, with no chain yet, acks a put and stays away. Another proxy deletes the key,
/// and after R the GC prunes the tombstone. The late put has a lower ack HLC than the delete:
/// a commit would bring the key back. The proxy must refuse it and keep the record aside.
#[tokio::test]
async fn test_late_put_after_a_tombstone_prune_is_quarantined() {
    let remote = Arc::new(MemoryRemote::default());
    let retention = Duration::from_millis(300);
    // H far above R: the late limit is R - M, not a value that grows with H.
    let config = Config {
        gc_horizon: HORIZON,
        retention,
        late_margin: Duration::from_millis(50),
        ..Config::default()
    };
    let a = open_config(&remote, 1, tempfile::tempdir().unwrap(), config.clone()).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    let late = open_config(&remote, 5, tempfile::tempdir().unwrap(), config.clone()).await;
    put(&late.engine, "k", "late").await;
    let gc = open_config(&remote, 6, tempfile::tempdir().unwrap(), config.clone()).await;
    gc.engine.sync().await.unwrap();
    a.engine.delete(BUCKET, "k").await.unwrap();
    a.engine.flush().await.unwrap();
    tokio::time::sleep(retention * 2).await;
    put(&a.engine, "other", "x").await;
    a.engine.flush().await.unwrap();
    let report = gc.engine.gc().await.unwrap();
    assert!(report.pruned_keys > 0, "{report:?}");

    let flushed = late.engine.flush().await;

    let Err(error) = flushed else {
        panic!("a put older than R is committed");
    };
    assert!(error.to_string().contains("bkt/k"), "{error}");
    assert_all_see(&[&a, &gc], &["k"], &[None]).await;
    let Proxy { dir, engine } = late;
    drop(engine);
    let reopened = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[5; 32]),
        keys(),
        config,
    )
    .await;
    let Err(error) = reopened else {
        panic!("a proxy with a quarantine opens");
    };
    assert!(error.to_string().contains("quarantine"), "{error}");
    assert!(dir.path().join("quarantine").exists());
}
