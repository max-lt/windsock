//! A remote with changed, moved or swapped sealed objects: every read fails closed.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, EngineError, RepoKey, WriteMode};
use remote::{MemoryRemote, Remote, Sweep};
use tempfile::TempDir;

const BUCKET: &str = "bkt";

struct Proxy {
    _dir: TempDir,
    engine: Engine<MemoryRemote>,
}

async fn proxy(remote: &Arc<MemoryRemote>, seed: u8) -> Proxy {
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

fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut out);
    out
}

/// A writer with two large objects: each has its own packs and a manifest on the remote.
/// Returns the data of `a`.
async fn written(remote: &Arc<MemoryRemote>) -> Vec<u8> {
    let writer = proxy(remote, 1).await;
    writer.engine.create_bucket(BUCKET, None).await.unwrap();
    for (seed, key) in [(1, "a"), (2, "b")] {
        writer
            .engine
            .put(
                BUCKET,
                key,
                Bytes::from(random_bytes(seed, 8 * 1024 * 1024)),
                BTreeMap::new(),
                WriteMode::Overwrite,
            )
            .await
            .unwrap();
        writer.engine.flush().await.unwrap();
    }
    random_bytes(1, 8 * 1024 * 1024)
}

async fn keys(remote: &MemoryRemote, prefix: &str) -> Vec<String> {
    remote.list(prefix).await.unwrap()
}

async fn flip(remote: &MemoryRemote, key: &str, at: impl Fn(usize) -> usize) {
    let mut bytes = remote.get(key).await.unwrap().unwrap().to_vec();
    let i = at(bytes.len());
    bytes[i] ^= 1;
    remote.put(key, Bytes::from(bytes)).await.unwrap();
}

async fn get(engine: &Engine<MemoryRemote>, key: &str) -> Result<Bytes, EngineError> {
    engine.get(BUCKET, key, None).await.map(|o| o.data)
}

#[tokio::test]
async fn test_changed_byte_in_a_sealed_chunk_fails_the_read() {
    let remote = Arc::new(MemoryRemote::default());
    written(&remote).await;
    for pack in keys(&remote, "packs/").await {
        flip(&remote, &pack, |len| len / 2).await;
    }

    let reader = proxy(&remote, 2).await;

    let error = get(&reader.engine, "a").await.unwrap_err();
    assert!(error.to_string().contains("does not open"), "{error}");
    assert!(error.to_string().contains("pack "), "{error}");
}

#[tokio::test]
async fn test_changed_byte_in_a_pack_footer_does_not_change_a_read() {
    let remote = Arc::new(MemoryRemote::default());
    let data = written(&remote).await;
    for pack in keys(&remote, "packs/").await {
        flip(&remote, &pack, |len| len - 9).await;
    }

    let reader = proxy(&remote, 2).await;

    assert_eq!(get(&reader.engine, "a").await.unwrap(), data);
}

#[tokio::test]
async fn test_changed_byte_in_a_manifest_fails_the_read() {
    let remote = Arc::new(MemoryRemote::default());
    written(&remote).await;
    for manifest in keys(&remote, "manifests/").await {
        flip(&remote, &manifest, |len| len - 1).await;
    }

    let reader = proxy(&remote, 2).await;

    let error = get(&reader.engine, "a").await.unwrap_err();
    assert!(error.to_string().contains("does not open"), "{error}");
    assert!(error.to_string().contains("manifest "), "{error}");
}

#[tokio::test]
async fn test_changed_byte_in_journal_actions_breaks_that_chain_and_stops_the_gc() {
    let remote = Arc::new(MemoryRemote::default());
    written(&remote).await;
    let entry = keys(&remote, "log/").await.remove(0);
    // The last 64 bytes are the signature: the byte before them is in the sealed actions.
    flip(&remote, &entry, |len| len - 65).await;

    let reader = proxy(&remote, 2).await;
    let report = reader.engine.sync().await.unwrap();

    assert_eq!(report.broken.len(), 1);
    let error = reader.engine.gc().await.unwrap_err();
    assert!(matches!(error, EngineError::BrokenChains(_)));
}

#[tokio::test]
async fn test_manifest_moved_to_another_key_does_not_open() {
    let remote = Arc::new(MemoryRemote::default());
    written(&remote).await;
    let manifests = keys(&remote, "manifests/").await;
    let first = remote.get(&manifests[0]).await.unwrap().unwrap();
    remote.put(&manifests[1], first).await.unwrap();

    let reader = proxy(&remote, 2).await;
    let results = [
        get(&reader.engine, "a").await,
        get(&reader.engine, "b").await,
    ];

    assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
    for error in results.iter().filter_map(|r| r.as_ref().err()) {
        assert!(error.to_string().contains("does not open"), "{error}");
    }
}

#[tokio::test]
async fn test_pack_moved_to_another_key_does_not_open() {
    let remote = Arc::new(MemoryRemote::default());
    written(&remote).await;
    let packs = keys(&remote, "packs/").await;
    let first = remote.get(&packs[0]).await.unwrap().unwrap();
    remote.put(&packs[1], first).await.unwrap();

    let reader = proxy(&remote, 2).await;
    let results = [
        get(&reader.engine, "a").await,
        get(&reader.engine, "b").await,
    ];

    assert!(results.iter().any(|r| r.is_err()));
    for error in results.iter().filter_map(|r| r.as_ref().err()) {
        assert!(error.to_string().contains("does not open"), "{error}");
    }
}

#[tokio::test]
async fn test_journal_entry_moved_to_another_seq_breaks_the_chain() {
    let remote = Arc::new(MemoryRemote::default());
    written(&remote).await;
    let entries = keys(&remote, "log/").await;
    let first = remote.get(&entries[0]).await.unwrap().unwrap();
    remote.put(&entries[1], first).await.unwrap();

    let reader = proxy(&remote, 2).await;

    assert_eq!(reader.engine.sync().await.unwrap().broken.len(), 1);
}

/// How a test changes the key check.
#[derive(Clone, Copy, Debug)]
enum KeyCheckChange {
    FirstByte,
    LastByte,
    /// Another sealed object of the remote takes its place.
    Moved,
}

#[tokio::test]
async fn test_key_check_moved_or_changed_refuses_the_open() {
    for change in [
        KeyCheckChange::FirstByte,
        KeyCheckChange::LastByte,
        KeyCheckChange::Moved,
    ] {
        let remote = Arc::new(MemoryRemote::default());
        written(&remote).await;
        match change {
            KeyCheckChange::FirstByte => flip(&remote, "repo/key-check", |_| 0).await,
            KeyCheckChange::LastByte => flip(&remote, "repo/key-check", |len| len - 1).await,
            KeyCheckChange::Moved => {
                let pack = keys(&remote, "packs/").await.remove(0);
                let other = remote.get(&pack).await.unwrap().unwrap();
                remote.put("repo/key-check", other).await.unwrap();
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let result = Engine::open(
            dir.path(),
            remote.clone(),
            SigningKey::from_bytes(&[2; 32]),
            RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
            Config::default(),
        )
        .await;

        let Err(error) = result else {
            panic!("a key check with {change:?} opens");
        };
        assert!(
            matches!(error, EngineError::WrongRepoKey(_)),
            "{change:?}: {error}"
        );
    }
}

#[test]
fn test_repo_key_of_the_wrong_length_or_not_hex_is_refused() {
    let good = "07".repeat(32);
    for bad in [
        &good[..63],
        &good[..62],
        &format!("{good}00"),
        &"zz".repeat(32),
        "",
    ] {
        assert!(RepoKey::from_hex(bad).is_err(), "{bad:?} is accepted");
    }
}

#[tokio::test]
async fn test_repo_key_with_one_flipped_bit_is_refused_at_open() {
    let remote = Arc::new(MemoryRemote::default());
    written(&remote).await;
    let dir = tempfile::tempdir().unwrap();

    let result = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[2; 32]),
        RepoKey::from_hex(&format!("06{}", "07".repeat(31)))
            .unwrap()
            .keys(),
        Config::default(),
    )
    .await;

    assert!(matches!(result, Err(EngineError::WrongRepoKey(_))));
}

/// How a store answers a ranged read.
#[derive(Clone, Copy)]
enum Answer {
    Short,
    Long,
}

/// A store that answers a ranged read with fewer or more bytes than it asked.
struct ShortRanges(MemoryRemote, Answer);

#[async_trait::async_trait]
impl Remote for ShortRanges {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), remote::RemoteError> {
        self.0.put(key, data).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), remote::RemoteError> {
        self.0.create(key, data).await
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, remote::RemoteError> {
        self.0.get(key).await
    }

    async fn get_range(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<Option<Bytes>, remote::RemoteError> {
        let read = self.0.get_range(key, range).await?;
        Ok(read.map(|bytes| match self.1 {
            Answer::Short => bytes.slice(..bytes.len() / 2),
            Answer::Long => [bytes.as_ref(), b"extra"].concat().into(),
        }))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, remote::RemoteError> {
        self.0.list(prefix).await
    }
}

async fn ranged_read_with(answer: Answer) -> Result<engine::Object, EngineError> {
    let memory = Arc::new(MemoryRemote::default());
    written(&memory).await;
    let short = Arc::new(ShortRanges(MemoryRemote::default(), answer));
    for key in memory.list("").await.unwrap() {
        let bytes = memory.get(&key).await.unwrap().unwrap();
        short.0.put(&key, bytes).await.unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let reader = Engine::open(
        dir.path(),
        short,
        SigningKey::from_bytes(&[2; 32]),
        RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        Config::default(),
    )
    .await
    .unwrap();

    reader.get(BUCKET, "a", None).await
}

#[tokio::test]
async fn test_short_ranged_read_from_the_remote_fails_the_read() {
    let result = ranged_read_with(Answer::Short).await;

    assert!(matches!(result, Err(EngineError::Corrupt(_))));
}

#[tokio::test]
async fn test_long_ranged_read_from_the_remote_fails_the_read() {
    let result = ranged_read_with(Answer::Long).await;

    assert!(matches!(result, Err(EngineError::Corrupt(_))));
}

#[tokio::test]
async fn test_empty_objects_on_the_remote_fail_closed() {
    let remote = Arc::new(MemoryRemote::default());
    written(&remote).await;
    for prefix in ["manifests/", "log/"] {
        for key in keys(&remote, prefix).await {
            remote.put(&key, Bytes::new()).await.unwrap();
        }
    }

    let reader = proxy(&remote, 2).await;

    assert_eq!(reader.engine.sync().await.unwrap().broken.len(), 1);
}

/// Every sealed kind on its way through the remote: chunks and footers, manifests, journal
/// actions, and the snapshot that a new proxy loads.
#[tokio::test]
async fn test_objects_at_size_limits_roundtrip_through_a_sealed_remote() {
    const MAX: usize = 256 * 1024;
    let sizes = [0, 1, 4095, 4096, 4097, MAX - 1, MAX, MAX + 1, (8 << 20) + 1];
    let remote = Arc::new(MemoryRemote::default());
    let writer = proxy(&remote, 1).await;
    writer.engine.create_bucket(BUCKET, None).await.unwrap();
    for (i, size) in sizes.iter().enumerate() {
        writer
            .engine
            .put(
                BUCKET,
                &format!("s{size}"),
                Bytes::from(random_bytes(i as u8, *size)),
                BTreeMap::new(),
                WriteMode::Overwrite,
            )
            .await
            .unwrap();
    }
    writer.engine.flush().await.unwrap();
    writer.engine.snapshot().await.unwrap();

    let reader = proxy(&remote, 2).await;

    for (i, size) in sizes.iter().enumerate() {
        let data = get(&reader.engine, &format!("s{size}")).await.unwrap();
        assert_eq!(data, random_bytes(i as u8, *size), "size {size}");
    }
}

#[tokio::test]
async fn test_remote_with_a_journal_and_no_key_check_is_refused_at_open() {
    let remote = Arc::new(MemoryRemote::default());
    written(&remote).await;
    remote.delete("repo/key-check").await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let result = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[2; 32]),
        RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        Config::default(),
    )
    .await;

    let Err(EngineError::WrongRepoKey(reason)) = result else {
        panic!("a journal with no key check opens");
    };
    assert!(reason.contains("without encryption"), "{reason}");
}

/// A remote of format 1 has a key check with no format line. The open refuses it and names both
/// formats: its journal actions have no ack HLC and must not decode.
#[tokio::test]
async fn test_remote_of_another_format_is_refused_at_open() {
    let remote = Arc::new(MemoryRemote::default());
    let keys = RepoKey::from_hex(&"07".repeat(32)).unwrap().keys();
    let text = b"windsock repository key check";
    let old = keys.sealer().seal(seal::Kind::KeyCheck, text, text);
    remote
        .create("repo/key-check", Bytes::from(old))
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let result = Engine::open(
        dir.path(),
        remote.clone(),
        SigningKey::from_bytes(&[2; 32]),
        keys,
        Config::default(),
    )
    .await;

    let Err(error) = result else {
        panic!("a remote of format 1 opens");
    };
    let error = error.to_string();
    assert!(error.contains("remote has format 1"), "{error}");
    assert!(error.contains("reads format 2"), "{error}");
}

/// R and M are rules of the remote: the first proxy writes them, and a proxy with others refuses
/// to open. A proxy with the same values opens.
#[tokio::test]
async fn test_proxy_with_another_retention_refuses_to_open() {
    let remote = Arc::new(MemoryRemote::default());
    let keys = || RepoKey::from_hex(&"07".repeat(32)).unwrap().keys();
    let open = |seed: u8, retention: u64| {
        let remote = remote.clone();
        async move {
            let dir = tempfile::tempdir().unwrap();
            let config = Config {
                retention: std::time::Duration::from_secs(retention),
                ..Config::default()
            };
            let result = Engine::open(
                dir.path(),
                remote,
                SigningKey::from_bytes(&[seed; 32]),
                keys(),
                config,
            )
            .await;
            (dir, result)
        }
    };
    let (_a, first) = open(1, 7200).await;
    first.unwrap();

    let (_b, same) = open(2, 7200).await;
    let (_c, other) = open(3, 9000).await;

    same.unwrap();
    let Err(error) = other else {
        panic!("a proxy with another retention opens");
    };
    let error = error.to_string();
    assert!(
        error.contains("remote holds retention_ns 7200000000000"),
        "{error}"
    );
    assert!(
        error.contains("this proxy has retention_ns 9000000000000"),
        "{error}"
    );
}
