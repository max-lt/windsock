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

/// A start that fails after the engine opened stops its background tasks: a second start in the
/// same process opens the same data_dir.
#[tokio::test(flavor = "multi_thread")]
async fn test_failed_start_frees_the_engine_for_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config_without_keys(dir.path(), port);
    let taken = std::net::TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();

    let failed = windsockd::serve_with(
        &config,
        Arc::new(Keys::default()),
        std::future::pending(),
        drop,
    )
    .await;
    drop(taken);
    let (node_tx, node_rx) = tokio::sync::oneshot::channel();
    let retry = tokio::spawn(async move {
        let on_open = move |node| {
            let _ = node_tx.send(node);
        };
        windsockd::serve_with(
            &config,
            Arc::new(Keys::default()),
            std::future::pending(),
            on_open,
        )
        .await
    });
    let opened = tokio::time::timeout(Duration::from_secs(30), node_rx).await;
    retry.abort();

    let error = failed.unwrap_err().to_string();
    assert!(error.contains("cannot listen"), "{error}");
    assert!(matches!(opened, Ok(Ok(_))), "the retry did not open");
}

/// Starts `config` until its engine opens: the tasks of an aborted serve stop at their next await.
/// Ok once a serve opens within 10 s.
async fn serve_again(config: &windsockd::Config) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let config = config.clone();
        let serve = tokio::spawn(async move {
            let on_open = move |node| {
                let _ = tx.send(node);
            };
            windsockd::serve_with(
                &config,
                Arc::new(Keys::default()),
                std::future::pending(),
                on_open,
            )
            .await
        });
        if rx.await.is_ok() {
            serve.abort();
            return Ok(());
        }
        let error = serve
            .await
            .unwrap()
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        if tokio::time::Instant::now() > deadline {
            return Err(error);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// An aborted serve frees its engine once the host drops its Node, and a Node kept past the
/// stop gets a named error.
#[tokio::test(flavor = "multi_thread")]
async fn test_aborted_serve_frees_the_engine_and_stops_its_node() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config_without_keys(dir.path(), port);
    let (node_tx, node_rx) = tokio::sync::oneshot::channel();
    let first_config = config.clone();
    let daemon = tokio::spawn(async move {
        let on_open = move |node| {
            let _ = node_tx.send(node);
        };
        windsockd::serve_with(
            &first_config,
            Arc::new(Keys::default()),
            std::future::pending(),
            on_open,
        )
        .await
    });
    let node: windsockd::Node = node_rx.await.unwrap();
    wait_until_listening(&format!("127.0.0.1:{port}")).await;

    daemon.abort();
    let _ = daemon.await;
    let after_stop = node.buckets().await;
    drop(node);
    let opened = serve_again(&config).await;

    assert!(
        matches!(after_stop, Err(engine::EngineError::Stopped)),
        "{after_stop:?}"
    );
    assert!(opened.is_ok(), "the second serve did not open: {opened:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aborted_serve_stops_the_requests_in_progress() {
    use tokio::io::AsyncWriteExt;
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
    let first_config = config.clone();
    let daemon = tokio::spawn(async move {
        let on_open = move |node| {
            let _ = node_tx.send(node);
        };
        windsockd::serve_with(&first_config, store, std::future::pending(), on_open).await
    });
    let node: windsockd::Node = node_rx.await.unwrap();
    wait_until_listening(&address).await;
    let bucket = common::call_at(&address, &keys, "PUT", "/demo", b"").await;
    // A signed upload of 1000 bytes that sends 10 of them and stops.
    let body = [7u8; 1000];
    let headers = common::signed_headers_at(&address, &keys, "PUT", "/demo/k", &body);
    let mut request = String::from("PUT /demo/k HTTP/1.1\r\n");
    for (name, value) in &headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("content-length: 1000\r\n\r\n");
    let mut upload = tokio::net::TcpStream::connect(&address).await.unwrap();
    upload.write_all(request.as_bytes()).await.unwrap();
    upload.write_all(&body[..10]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    daemon.abort();
    let _ = daemon.await;
    drop(node);
    let opened = serve_again(&config).await;

    assert_eq!(bucket.status, StatusCode::OK, "{}", bucket.text());
    assert!(opened.is_ok(), "the second serve did not open: {opened:?}");
    drop(upload);
}
