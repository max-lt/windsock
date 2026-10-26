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
        let failing = *self.failing_reads.lock().unwrap();
        if failing.is_some_and(|prefix| key.starts_with(prefix)) {
            return Err(unavailable());
        }
        self.inner.get(key).await
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
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
