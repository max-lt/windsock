//! A remote that fails once on a pack upload, a journal append or a snapshot read.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use std::sync::Mutex;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, RepoKey, WriteMode};
use remote::{MemoryRemote, Remote, RemoteError, Sweep};
use tempfile::TempDir;

const BUCKET: &str = "bkt";

/// What the next write under a prefix does.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    /// Fails and stores nothing.
    Refuse,
    /// Stores, then fails: the answer is lost.
    LoseAnswer,
}

#[derive(Default)]
struct FaultRemote {
    inner: MemoryRemote,
    next: Mutex<Option<(&'static str, Fault)>>,
    failing_reads: Mutex<Option<&'static str>>,
    /// Reads of journal entries.
    log_gets: std::sync::atomic::AtomicUsize,
}

impl FaultRemote {
    fn fail_next(&self, prefix: &'static str, fault: Fault) {
        *self.next.lock().unwrap() = Some((prefix, fault));
    }

    fn take(&self, key: &str) -> Option<Fault> {
        let mut next = self.next.lock().unwrap();
        match *next {
            Some((prefix, fault)) if key.starts_with(prefix) => {
                *next = None;
                Some(fault)
            }
            _ => None,
        }
    }
}

fn unavailable() -> RemoteError {
    RemoteError::Service {
        status: 503,
        code: "SlowDown".into(),
        message: "injected".into(),
    }
}

#[async_trait::async_trait]
impl Remote for FaultRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        match self.take(key) {
            Some(Fault::Refuse) => Err(unavailable()),
            Some(Fault::LoseAnswer) => {
                self.inner.put(key, data).await?;
                Err(unavailable())
            }
            None => self.inner.put(key, data).await,
        }
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        match self.take(key) {
            Some(Fault::Refuse) => Err(unavailable()),
            Some(Fault::LoseAnswer) => {
                self.inner.create(key, data).await?;
                Err(unavailable())
            }
            None => self.inner.create(key, data).await,
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        if key.starts_with("log/") {
            self.log_gets
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let failing = *self.failing_reads.lock().unwrap();
        if failing.is_some_and(|prefix| key.starts_with(prefix)) {
            return Err(unavailable());
        }
        self.inner.get(key).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        let failing = *self.failing_reads.lock().unwrap();
        if failing.is_some_and(|prefix| key.starts_with(prefix)) {
            return Err(unavailable());
        }
        self.inner.get_range(key, range).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        self.inner.list(prefix).await
    }
}

#[async_trait::async_trait]
impl Sweep for FaultRemote {
    async fn delete(&self, key: &str) -> Result<(), RemoteError> {
        self.inner.delete(key).await
    }
}

struct Proxy {
    _dir: TempDir,
    engine: Engine<FaultRemote>,
}

async fn proxy(remote: &Arc<FaultRemote>, seed: u8) -> Proxy {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[seed; 32]),
        RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        Config::default(),
    )
    .await
    .unwrap();
    Proxy { _dir: dir, engine }
}

fn data() -> Vec<u8> {
    let mut out = vec![0; 300 * 1024];
    blake3::Hasher::new().finalize_xof().fill(&mut out);
    out
}

/// A writer that puts one object, with `fault` on its first `prefix` write, then flushes until
/// the flush passes.
async fn write_through(remote: &Arc<FaultRemote>, prefix: &'static str, fault: Fault) {
    let writer = proxy(remote, 1).await;
    writer.engine.create_bucket(BUCKET, None).await.unwrap();
    writer.engine.flush().await.unwrap();
    writer
        .engine
        .put(
            BUCKET,
            "k",
            Bytes::from(data()),
            BTreeMap::new(),
            WriteMode::Overwrite,
        )
        .await
        .unwrap();
    remote.fail_next(prefix, fault);

    assert!(
        writer.engine.flush().await.is_err(),
        "the injected fault fails the flush"
    );
    writer.engine.flush().await.unwrap();
}

/// The seqs of each chain on the remote.
async fn chains(remote: &FaultRemote) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for key in remote.inner.list("log/").await.unwrap() {
        let (node, seq) = key.trim_start_matches("log/").split_once('/').unwrap();
        out.entry(node.to_string())
            .or_default()
            .push(seq.to_string());
    }
    out
}

async fn read_back(remote: &Arc<FaultRemote>) {
    let reader = proxy(remote, 2).await;
    let report = reader.engine.sync().await.unwrap();
    assert!(report.broken.is_empty());
    let object = reader.engine.get(BUCKET, "k", None).await.unwrap();
    assert_eq!(object.data, data());
}

#[tokio::test]
async fn test_refused_pack_upload_is_retried_with_no_duplicate() {
    let remote = Arc::new(FaultRemote::default());

    write_through(&remote, "packs/", Fault::Refuse).await;

    read_back(&remote).await;
    assert_eq!(remote.inner.list("packs/").await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_lost_answer_on_a_pack_upload_loses_no_object() {
    let remote = Arc::new(FaultRemote::default());

    write_through(&remote, "packs/", Fault::LoseAnswer).await;

    read_back(&remote).await;
    // The retry plans again with a new nonce. The first pack stays with no manifest, so the GC
    // condemns it.
    assert_eq!(remote.inner.list("packs/").await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_refused_journal_append_is_retried_and_the_chain_stays_whole() {
    let remote = Arc::new(FaultRemote::default());

    write_through(&remote, "log/", Fault::Refuse).await;

    read_back(&remote).await;
    for seqs in chains(&remote).await.values() {
        let expected: Vec<String> = (0..seqs.len()).map(|n| format!("{n:020}")).collect();
        assert_eq!(seqs, &expected, "a chain has a gap");
    }
}

#[tokio::test]
async fn test_lost_answer_on_a_journal_append_writes_no_second_entry() {
    let remote = Arc::new(FaultRemote::default());

    write_through(&remote, "log/", Fault::LoseAnswer).await;

    read_back(&remote).await;
    let chains = chains(&remote).await;
    assert_eq!(chains.len(), 1);
    assert_eq!(
        chains.values().next().unwrap().len(),
        2,
        "bucket and put, each once"
    );
}

#[tokio::test]
async fn test_unreadable_snapshot_names_its_key() {
    let remote = Arc::new(FaultRemote::default());
    let writer = proxy(&remote, 1).await;
    writer.engine.create_bucket(BUCKET, None).await.unwrap();
    writer.engine.flush().await.unwrap();
    let key = writer.engine.snapshot().await.unwrap();
    *remote.failing_reads.lock().unwrap() = Some("snapshots/");

    let error = writer.engine.gc().await.unwrap_err();

    assert!(error.to_string().contains(&key), "{error}");
}

/// A sync that fails on one chain returns no entry of the chains it read before. The next sync
/// must read those entries again.
#[tokio::test]
async fn test_sync_that_fails_on_one_chain_reads_the_other_chains_again() {
    let remote = Arc::new(FaultRemote::default());
    let reader = proxy(&remote, 3).await;
    let a = proxy(&remote, 1).await;
    let b = proxy(&remote, 2).await;
    a.engine.create_bucket(BUCKET, None).await.unwrap();
    a.engine.flush().await.unwrap();
    for (writer, key) in [(&a, "from-a"), (&b, "from-b")] {
        writer.engine.sync().await.unwrap();
        let put = writer.engine.put(
            BUCKET,
            key,
            Bytes::from_static(b"v"),
            BTreeMap::new(),
            WriteMode::Overwrite,
        );
        put.await.unwrap();
        writer.engine.flush().await.unwrap();
    }
    let last = a.engine.node().max(b.engine.node());
    let prefix: &'static str = format!("log/{last}/").leak();
    *remote.failing_reads.lock().unwrap() = Some(prefix);

    assert!(reader.engine.sync().await.is_err());
    *remote.failing_reads.lock().unwrap() = None;
    reader.engine.sync().await.unwrap();

    for key in ["from-a", "from-b"] {
        let object = reader.engine.get(BUCKET, key, None).await.unwrap();
        assert_eq!(&object.data[..], b"v");
    }
}

/// Recover applies the actions that the remote holds, not the clear copy in the intent file.
#[tokio::test]
async fn test_recover_ignores_changed_clear_actions_in_the_intent() {
    let remote = Arc::new(FaultRemote::default());
    let writer = proxy(&remote, 1).await;
    writer.engine.create_bucket(BUCKET, None).await.unwrap();
    writer.engine.flush().await.unwrap();
    let put = writer.engine.put(
        BUCKET,
        "key-AAAA",
        Bytes::from_static(b"v"),
        BTreeMap::new(),
        WriteMode::Overwrite,
    );
    put.await.unwrap();
    remote.fail_next("log/", Fault::LoseAnswer);
    assert!(writer.engine.flush().await.is_err());
    let intent = writer._dir.path().join("buffer").join("intent");
    let bytes = std::fs::read(&intent).unwrap();
    let at = bytes
        .windows(8)
        .position(|w| w == b"key-AAAA")
        .expect("the intent holds the clear key");
    let mut changed = bytes.clone();
    changed[at..at + 8].copy_from_slice(b"key-BBBB");
    std::fs::write(&intent, changed).unwrap();

    writer.engine.flush().await.unwrap();

    assert!(writer.engine.get(BUCKET, "key-BBBB", None).await.is_err());
    let object = writer.engine.get(BUCKET, "key-AAAA", None).await.unwrap();
    assert_eq!(&object.data[..], b"v");
}

/// An entry whose seen link names another hash fails the apply at every sync. The sync must not
/// read every chain again each time: the entries are already in the index, waiting.
#[tokio::test]
async fn test_apply_error_does_not_read_the_chains_again_at_each_sync() {
    let remote = Arc::new(FaultRemote::default());
    let reader = proxy(&remote, 2).await;
    let writer = proxy(&remote, 1).await;
    writer.engine.create_bucket(BUCKET, None).await.unwrap();
    writer.engine.flush().await.unwrap();
    for n in 0..5 {
        let key = format!("k{n}");
        let put = writer.engine.put(
            BUCKET,
            &key,
            Bytes::from_static(b"v"),
            BTreeMap::new(),
            WriteMode::Overwrite,
        );
        put.await.unwrap();
        writer.engine.flush().await.unwrap();
    }
    let bad_link = journal::Link {
        seq: 0,
        hash: [9u8; 32],
    };
    let forged = journal::Entry::sign(
        &SigningKey::from_bytes(&[9; 32]),
        0,
        [0u8; 32],
        1,
        BTreeMap::from([(writer.engine.node(), bad_link)]),
        vec![journal::Action::Delete {
            bucket: BUCKET.into(),
            key: "k0".into(),
            hlc: 1,
        }],
        RepoKey::from_hex(&"07".repeat(32)).unwrap().keys().sealer(),
    );
    remote
        .inner
        .create(&forged.remote_key(), Bytes::from(forged.to_wire()))
        .await
        .unwrap();
    remote
        .inner
        .put(&journal::node_key(forged.node), Bytes::new())
        .await
        .unwrap();
    let _ = reader.engine.sync().await;
    let gets = || remote.log_gets.load(std::sync::atomic::Ordering::SeqCst);

    let before = gets();
    let second = reader.engine.sync().await;
    let read = gets() - before;

    // Two chains, and for each one the read of the next seq and the gap probe.
    assert_eq!(read, 4, "entry reads at one sync; {second:?}");
}

/// Two processes share one identity. The second one commits after the first, so its commit reads
/// the first one's entry. When the manifest of that entry does not read, the own write of the
/// second process must still become visible at the next sync.
#[tokio::test]
async fn test_own_write_stays_visible_when_the_commit_reads_a_bad_manifest() {
    let remote = Arc::new(FaultRemote::default());
    let first = proxy(&remote, 1).await;
    let second = proxy(&remote, 1).await;
    first.engine.create_bucket(BUCKET, None).await.unwrap();
    first.engine.flush().await.unwrap();
    second.engine.sync().await.unwrap();
    let big = BTreeMap::from([("x-amz-meta-a".to_string(), "m".repeat(6000))]);
    let put = first.engine.put(
        BUCKET,
        "big",
        Bytes::from_static(b"v"),
        big,
        WriteMode::Overwrite,
    );
    put.await.unwrap();
    first.engine.flush().await.unwrap();
    assert!(!remote.inner.list("manifests/").await.unwrap().is_empty());

    let put = second.engine.put(
        BUCKET,
        "own",
        Bytes::from_static(b"mine"),
        BTreeMap::new(),
        WriteMode::Overwrite,
    );
    put.await.unwrap();
    *remote.failing_reads.lock().unwrap() = Some("manifests/");
    let _ = second.engine.flush().await;
    *remote.failing_reads.lock().unwrap() = None;
    let _ = second.engine.flush().await;
    second.engine.sync().await.unwrap();

    let object = second.engine.get(BUCKET, "own", None).await.unwrap();
    assert_eq!(&object.data[..], b"mine");
}
