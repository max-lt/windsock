//! One daemon as a process: init, run, S3 calls, stop, restart.

mod common;

use std::path::PathBuf;
use std::process::Command;

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
