//! windsockd in the process of its caller, with the keys of a KeyStore, as a console starts it.

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::StatusCode;
use s3api::{KeyStore, KeyStoreError, Secret};

/// Keys that the test changes while the daemon runs.
#[derive(Default)]
struct Keys(Mutex<HashMap<String, String>>);

#[async_trait::async_trait]
impl KeyStore for Keys {
    async fn secret(&self, access_key: &str) -> Result<Option<Secret>, KeyStoreError> {
        let keys = self.0.lock().unwrap();
        Ok(keys
            .get(access_key)
            .map(|secret| Secret::new(secret.clone())))
    }
}

/// A free local port. Another process can take it before the daemon binds it: rare in a test.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// A configuration with no [[keys]] entry, listening on `port`.
fn config_without_keys(dir: &Path, port: u16) -> windsockd::Config {
    let path = common::cluster_config(dir, &dir.join("remote"), 100, "enabled = false");
    let text = std::fs::read_to_string(&path).unwrap();
    let (head, rest) = text.split_once("[[keys]]").unwrap();
    let (_, tail) = rest.split_once("[engine]").unwrap();
    let text = format!("{head}[engine]{tail}").replace("127.0.0.1:0", &format!("127.0.0.1:{port}"));
    std::fs::write(&path, text).unwrap();
    windsockd::Config::load(&path).unwrap()
}

async fn wait_until_listening(address: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::net::TcpStream::connect(address).await.is_err() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no listener on {address}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_serve_with_refuses_keys_in_the_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let path = common::cluster_config(dir.path(), &dir.path().join("remote"), 100, "");
    let config = windsockd::Config::load(&path).unwrap();

    let result = windsockd::serve_with(
        &config,
        Arc::new(Keys::default()),
        std::future::pending(),
        drop,
    )
    .await;

    let error = result.unwrap_err().to_string();
    assert!(error.contains("[[keys]]"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_serve_with_signs_with_the_store_and_flushes_at_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let address = format!("127.0.0.1:{port}");
    let config = config_without_keys(dir.path(), port);
    let keys = common::test_keys();
    let store = Arc::new(Keys::default());
    store
        .0
        .lock()
        .unwrap()
        .insert(keys.0.clone(), keys.1.clone());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = store.clone();
    let daemon = tokio::spawn(async move {
        let shutdown = async {
            let _ = stopped.await;
        };
        windsockd::serve_with(&config, served, shutdown, drop).await
    });
    wait_until_listening(&address).await;

    let bucket = common::call_at(&address, &keys, "PUT", "/demo", b"").await;
    let object = common::call_at(&address, &keys, "PUT", "/demo/k", b"data").await;
    store.0.lock().unwrap().clear();
    let revoked = common::call_at(&address, &keys, "GET", "/demo/k", b"").await;
    stop.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(60), daemon)
        .await
        .expect("the daemon stops after the shutdown future")
        .unwrap();

    assert_eq!(bucket.status, StatusCode::OK, "{}", bucket.text());
    assert_eq!(object.status, StatusCode::OK, "{}", object.text());
    assert_eq!(revoked.status, StatusCode::FORBIDDEN);
    result.unwrap();
    assert!(!common::chains(&dir.path().join("remote")).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_node_handle_reads_state_and_sets_the_cache_limit() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let address = format!("127.0.0.1:{port}");
    let config = config_without_keys(dir.path(), port);
    let keys = common::test_keys();
    let store = Arc::new(Keys::default());
    store
        .0
        .lock()
        .unwrap()
        .insert(keys.0.clone(), keys.1.clone());
    let (node_tx, node_rx) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(async move {
        let shutdown = async {
            let _ = stopped.await;
        };
        let on_open = move |node| {
            let _ = node_tx.send(node);
        };
        windsockd::serve_with(&config, store, shutdown, on_open).await
    });
    let node: windsockd::Node = node_rx.await.unwrap();
    wait_until_listening(&address).await;
    common::call_at(&address, &keys, "PUT", "/demo", b"").await;
    common::call_at(&address, &keys, "PUT", "/demo/a", b"first").await;
    common::call_at(&address, &keys, "PUT", "/demo/b", b"second").await;

    let status = node.status().await;
    let buckets = node.buckets().await.unwrap();
    let first = node.list("demo", "", None, 1).await.unwrap();
    let second = node
        .list("demo", "", first.next.as_deref(), 1)
        .await
        .unwrap();
    let trimmed = node.set_cache_limit(0).await.unwrap();
    let too_high = node.set_cache_limit(status.cache.max + 1).await;
    stop.send(()).unwrap();
    daemon.await.unwrap().unwrap();

    assert!(status.buffered_bytes > 0);
    assert!(!status.quarantined && !status.index_poisoned && !status.draining);
    assert!(!status.gc_enabled);
    assert!(status.admin_socket);
    assert_eq!(status.other_gc_node, None);
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].name, "demo");
    let keys = |page: &windsockd::Page| {
        page.objects
            .iter()
            .map(|object| object.key.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(&first), ["a"]);
    assert_eq!(first.next.as_deref(), Some("a"));
    assert_eq!(keys(&second), ["b"]);
    assert_eq!(second.next, None);
    assert_eq!((trimmed.limit, trimmed.bytes), (0, 0));
    assert!(too_high.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_list_page_is_capped_whatever_max_the_caller_asks() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let address = format!("127.0.0.1:{port}");
    let config = config_without_keys(dir.path(), port);
    let keys = common::test_keys();
    let store = Arc::new(Keys::default());
    store
        .0
        .lock()
        .unwrap()
        .insert(keys.0.clone(), keys.1.clone());
    let (node_tx, node_rx) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(async move {
        let on_open = move |node| {
            let _ = node_tx.send(node);
        };
        windsockd::serve_with(&config, store, std::future::pending(), on_open).await
    });
    let node: windsockd::Node = node_rx.await.unwrap();
    wait_until_listening(&address).await;
    common::call_at(&address, &keys, "PUT", "/demo", b"").await;
    for i in 0..=windsockd::MAX_PAGE {
        let path = format!("/demo/k{i:05}");
        common::call_at(&address, &keys, "PUT", &path, b"x").await;
    }

    let first = node.list("demo", "", None, usize::MAX).await.unwrap();
    let rest = node
        .list("demo", "", first.next.as_deref(), usize::MAX)
        .await
        .unwrap();
    let empty = node.list("demo", "", None, 0).await;
    daemon.abort();

    assert_eq!(windsockd::MAX_PAGE, 1000);
    assert_eq!(first.objects.len(), windsockd::MAX_PAGE);
    assert_eq!(first.next.as_deref(), Some("k00999"));
    assert_eq!(rest.objects.len(), 1);
    assert_eq!(rest.next, None);
    // A page of 0 objects with no next key would look like the end of the listing.
    assert!(empty.is_err(), "{empty:?}");
}
