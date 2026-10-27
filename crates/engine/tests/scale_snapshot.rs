//! Snapshot write and load times at scale. Run in release on a quiet machine:
//! `cargo test --release -p engine --test scale_snapshot -- --ignored --nocapture`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use engine::{Config, Engine, WriteMode};
use remote::{DirRemote, Remote, Sweep};

const KEYS: usize = 200_000;

fn rss_mib() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .unwrap()
        / 1024
}

async fn open(
    dir: &std::path::Path,
    remote: &Arc<DirRemote>,
    seed: u8,
    object: u64,
) -> Engine<DirRemote> {
    Engine::open(
        dir,
        remote.clone(),
        SigningKey::from_bytes(&[seed; 32]),
        engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
        Config {
            snapshot_object: object,
            ..Config::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_snapshot_scale_by_part_size() {
    let root = tempfile::tempdir().unwrap();
    let remote = Arc::new(DirRemote::open(root.path().join("remote")).unwrap());
    let writer = Arc::new(open(&root.path().join("w"), &remote, 1, 1 << 30).await);
    writer.create_bucket("bkt", None).await.unwrap();
    let start = Instant::now();
    for batch in 0..KEYS / 1000 {
        let mut tasks = Vec::new();
        for n in 0..1000 {
            let writer = writer.clone();
            let key = format!("k{:06}", batch * 1000 + n);
            tasks.push(tokio::spawn(async move {
                let data = Bytes::from(vec![b'v'; 100]);
                writer
                    .put("bkt", &key, data, BTreeMap::new(), WriteMode::Overwrite)
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        if batch % 20 == 19 {
            writer.flush().await.unwrap();
        }
    }
    writer.flush().await.unwrap();
    println!("puts: {KEYS} in {:.1?}", start.elapsed());

    for (name, object) in [("1 GiB", 1u64 << 30), ("4 MiB", 4 << 20)] {
        let w = open(&root.path().join(format!("w-{name}")), &remote, 3, object).await;
        w.sync().await.unwrap();
        let start = Instant::now();
        let head = w.snapshot().await.unwrap();
        let write = start.elapsed();
        let base = head.strip_suffix("/head").unwrap();
        let parts = remote.list(&format!("{base}/")).await.unwrap().len() - 1;
        let mut bytes = 0;
        for n in 0..parts {
            bytes += remote
                .get(&format!("{base}/{n:06}"))
                .await
                .unwrap()
                .unwrap()
                .len();
        }

        let before = rss_mib();
        let start = Instant::now();
        let fresh = open(&root.path().join(format!("r-{name}")), &remote, 4, object).await;
        let load = start.elapsed();
        let info = fresh.head("bkt", &format!("k{:06}", KEYS - 1)).await;
        assert!(info.is_ok());
        println!(
            "snapshot_object {name}: {:.1} MiB, write {write:.2?} (sync done before), {parts} parts, \
             load at open {load:.2?}, RSS {before} -> {} MiB",
            bytes as f64 / 1048576.0,
            rss_mib()
        );
        for key in remote.list(&format!("{base}/")).await.unwrap() {
            remote.delete(&key).await.unwrap();
        }
    }
}
