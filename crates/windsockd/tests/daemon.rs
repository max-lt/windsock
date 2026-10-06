//! One daemon as a process: init, run, S3 calls, stop, restart.

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use common::{BIN, call, start};
use hyper::StatusCode;
use tempfile::TempDir;

/// `windsockd init`, then a free port instead of 9000.
fn init() -> (TempDir, PathBuf, (String, String)) {
    let dir = tempfile::tempdir().unwrap();
    let status = Command::new(BIN)
        .arg("init")
        .arg(dir.path())
        .status()
        .unwrap();
    assert!(status.success());

    let path = dir.path().join("windsock.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("127.0.0.1:9000", "127.0.0.1:0");
    std::fs::write(&path, &text).unwrap();
    let value = |name: &str| {
        let line = text.lines().find(|l| l.starts_with(name)).unwrap();
        line.split('"').nth(1).unwrap().to_string()
    };

    (dir, path, (value("access_key"), value("secret_key")))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_object_survives_a_stop_and_a_restart() {
    let (dir, config, keys) = init();
    let daemon = start(&config, "info");

    assert_eq!(
        call(&daemon, &keys, "PUT", "/demo", b"").await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(&daemon, &keys, "PUT", "/demo/hello.txt", b"hello")
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        call(&daemon, &keys, "GET", "/demo/hello.txt", b"")
            .await
            .text(),
        "hello"
    );
    assert!(daemon.stop(), "a clean stop exits with success");
    assert!(
        !common::chains(&dir.path().join("remote")).is_empty(),
        "the stop flushed the buffer to the remote"
    );

    let daemon = start(&config, "info");
    let reply = call(&daemon, &keys, "GET", "/demo/hello.txt", b"").await;

    assert_eq!(
        (reply.status, reply.text().as_str()),
        (StatusCode::OK, "hello")
    );
    assert!(daemon.stop());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_acknowledged_write_survives_a_crash() {
    let (_dir, config, keys) = init();
    let daemon = start(&config, "info");
    call(&daemon, &keys, "PUT", "/demo", b"").await;

    assert_eq!(
        call(&daemon, &keys, "PUT", "/demo/k", b"acked")
            .await
            .status,
        StatusCode::OK
    );
    daemon.crash();
    let daemon = start(&config, "info");

    assert_eq!(
        call(&daemon, &keys, "GET", "/demo/k", b"").await.text(),
        "acked"
    );
    assert!(daemon.stop());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wrong_key_is_refused() {
    let (_dir, config, _) = init();
    let daemon = start(&config, "info");

    let reply = call(&daemon, &("WSNOBODY".into(), "x".into()), "GET", "/", b"").await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(reply.text().contains("InvalidAccessKeyId"));
    assert!(daemon.stop());
}

/// Entries in all the chains of a local directory remote.
fn entries(remote: &std::path::Path) -> usize {
    common::chains(remote).iter().map(Vec::len).sum()
}

async fn wait_for_more_entries(remote: &std::path::Path, than: usize) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while entries(remote) <= than {
        assert!(Instant::now() < deadline, "no flush reached the remote");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_flush_succeeds_while_clients_hold_more_connections_than_descriptors() {
    let dir = tempfile::tempdir().unwrap();
    let remote = dir.path().join("remote");
    let config = common::cluster_config(dir.path(), &remote, 1000, "enabled = false");
    let keys = common::test_keys();
    let daemon = common::start_with_fd_limit(&config, "info", 128);
    call(&daemon, &keys, "PUT", "/demo", b"").await;
    wait_for_more_entries(&remote, 0).await;
    let before = entries(&remote);

    assert_eq!(
        call(&daemon, &keys, "PUT", "/demo/k", b"value")
            .await
            .status,
        StatusCode::OK
    );
    let mut held = Vec::new();
    for _ in 0..150 {
        held.push(
            tokio::net::TcpStream::connect(&daemon.address)
                .await
                .unwrap(),
        );
    }
    wait_for_more_entries(&remote, before).await;
    drop(held);

    assert_eq!(
        call(&daemon, &keys, "GET", "/demo/k", b"").await.text(),
        "value"
    );
    assert!(daemon.stop());
}

/// A daemon with 2 connection slots and an idle timeout of 1 s.
fn small_daemon(dir: &std::path::Path) -> common::Daemon {
    let config = common::cluster_config(dir, &dir.join("remote"), 1000, "enabled = false");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!("max_connections = 2\nidle_timeout_secs = 1\n{text}"),
    )
    .unwrap();
    start(&config, "info")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_idle_connections_close_and_free_their_slots() {
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().unwrap();
    let daemon = small_daemon(dir.path());
    let keys = common::test_keys();
    let mut idle = [
        tokio::net::TcpStream::connect(&daemon.address)
            .await
            .unwrap(),
        tokio::net::TcpStream::connect(&daemon.address)
            .await
            .unwrap(),
    ];

    let put = tokio::time::timeout(
        Duration::from_secs(10),
        call(&daemon, &keys, "PUT", "/demo", b""),
    )
    .await
    .expect("the idle connections give their slots back");

    assert_eq!(put.status, StatusCode::OK);
    for stream in &mut idle {
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte)).await;
        assert!(
            matches!(read, Ok(Ok(0))),
            "the daemon closes an idle connection"
        );
    }
    assert!(daemon.stop());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_a_request_in_progress_outlives_the_idle_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = small_daemon(dir.path());
    let keys = common::test_keys();
    call(&daemon, &keys, "PUT", "/demo", b"").await;

    let reply = common::call_with_pause(
        &daemon,
        &keys,
        "/demo/slow",
        b"0123456789",
        Duration::from_millis(2500),
    )
    .await;

    assert!(reply.starts_with("HTTP/1.1 200"), "reply: {reply}");
    assert_eq!(
        call(&daemon, &keys, "GET", "/demo/slow", b"").await.text(),
        "0123456789"
    );
    assert!(daemon.stop());
}

/// A daemon with 1 connection slot and a request timeout of `secs`.
fn upload_daemon(dir: &std::path::Path, secs: u64) -> common::Daemon {
    let config = common::cluster_config(dir, &dir.join("remote"), 1000, "enabled = false");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!("max_connections = 1\nrequest_timeout_secs = {secs}\n{text}"),
    )
    .unwrap();
    start(&config, "info")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_stalled_upload_is_cut_and_its_slot_comes_back() {
    use tokio::io::AsyncWriteExt;

    let dir = tempfile::tempdir().unwrap();
    let daemon = upload_daemon(dir.path(), 1);
    let keys = common::test_keys();
    call(&daemon, &keys, "PUT", "/demo", b"").await;

    let body = b"0123456789";
    let mut stalled = common::send_head(&daemon, &keys, "/demo/stalled", body).await;
    stalled.write_all(&body[..5]).await.unwrap();
    let cut = tokio::time::timeout(Duration::from_secs(10), common::read_reply(&mut stalled)).await;
    assert!(cut.is_ok(), "the daemon cuts a stalled upload");

    let put = tokio::time::timeout(
        Duration::from_secs(10),
        call(&daemon, &keys, "PUT", "/demo/after", b"after"),
    )
    .await
    .expect("the slot of the stalled upload comes back");
    assert_eq!(put.status, StatusCode::OK);
    assert!(daemon.stop());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_slow_upload_that_makes_progress_is_not_cut() {
    use tokio::io::AsyncWriteExt;

    let dir = tempfile::tempdir().unwrap();
    let daemon = upload_daemon(dir.path(), 1);
    let keys = common::test_keys();
    call(&daemon, &keys, "PUT", "/demo", b"").await;

    let body = b"0123456789";
    let mut slow = common::send_head(&daemon, &keys, "/demo/slow", body).await;
    for byte in body {
        tokio::time::sleep(Duration::from_millis(400)).await;
        slow.write_all(&[*byte]).await.unwrap();
    }
    let reply = common::read_reply(&mut slow).await;
    drop(slow);

    assert!(reply.starts_with("HTTP/1.1 200"), "reply: {reply}");
    assert_eq!(
        call(&daemon, &keys, "GET", "/demo/slow", b"").await.text(),
        "0123456789"
    );
    assert!(daemon.stop());
}

#[test]
fn test_init_does_not_overwrite_a_configuration() {
    let (dir, _, _) = init();

    let again = Command::new(BIN)
        .arg("init")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(!again.status.success());
}
