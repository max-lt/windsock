//! One daemon as a process: init, run, S3 calls, stop, restart.

mod common;

use std::path::{Path, PathBuf};
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
fn test_diagnose_reports_that_a_directory_remote_keeps_the_storage_contract() {
    let (_dir, config, _) = init();

    let output = Command::new(BIN)
        .arg("diagnose")
        .arg(&config)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ok storage contract"));
}

#[test]
fn test_init_writes_a_repository_key_that_only_the_owner_reads() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, _, _) = init();
    let key = dir.path().join("repo.key");

    assert_eq!(std::fs::read_to_string(&key).unwrap().trim().len(), 64);
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn test_run_without_the_repository_key_stops_with_a_message() {
    let (dir, config, _) = init();
    std::fs::remove_file(dir.path().join("repo.key")).unwrap();

    let output = Command::new(BIN).arg("run").arg(&config).output().unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read the repository key"));
}

#[test]
fn test_run_refuses_a_repository_key_that_other_users_can_read() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, config, _) = init();
    let key = dir.path().join("repo.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = Command::new(BIN).arg("run").arg(&config).output().unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("chmod 600"));
}

#[test]
fn test_run_refuses_a_node_key_that_other_users_can_read() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, config, _) = init();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let key = data.join("node.key");
    std::fs::write(&key, "01".repeat(32)).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = Command::new(BIN).arg("run").arg(&config).output().unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("node.key can be read by other users")
    );
}

#[test]
fn test_bad_repository_key_file_names_the_path_and_not_the_content() {
    let (dir, config, _) = init();
    let key = dir.path().join("repo.key");
    std::fs::write(&key, "secret-but-not-hex").unwrap();

    let output = Command::new(BIN).arg("run").arg(&config).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(
        stderr.contains("repo.key is not a repository key"),
        "{stderr}"
    );
    assert!(!stderr.contains("secret-but-not-hex"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_restart_after_a_torn_buffer_record_keeps_whole_writes_and_logs_the_cut() {
    let (dir, config, keys) = init();
    let daemon = start(&config, "info");
    call(&daemon, &keys, "PUT", "/demo", b"").await;
    call(&daemon, &keys, "PUT", "/demo/whole", b"kept").await;
    call(&daemon, &keys, "PUT", "/demo/torn", b"cut off").await;
    daemon.crash();
    let buffer = dir.path().join("data/engine/buffer");
    let mut segments: Vec<_> = std::fs::read_dir(&buffer)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .filter(|p| std::fs::metadata(p).unwrap().len() > 0)
        .collect();
    segments.sort();
    let last = segments.pop().expect("a segment holds the writes");
    let len = std::fs::metadata(&last).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&last)
        .unwrap()
        .set_len(len - 2)
        .unwrap();

    let daemon = start(&config, "info");

    assert!(daemon.logged("cut a torn record"));
    assert_eq!(
        call(&daemon, &keys, "GET", "/demo/whole", b"").await.text(),
        "kept"
    );
    assert_eq!(
        call(&daemon, &keys, "GET", "/demo/torn", b"").await.status,
        StatusCode::NOT_FOUND
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

fn run_fails_with(config: &Path) -> String {
    let output = Command::new(BIN).arg("run").arg(config).output().unwrap();
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn test_run_names_a_data_dir_it_cannot_make() {
    let (dir, config, _) = init();
    let data = dir.path().join("data");
    std::fs::write(&data, "a file").unwrap();

    let stderr = run_fails_with(&config);

    assert!(stderr.contains(&data.display().to_string()), "{stderr}");
}

#[test]
fn test_run_names_a_node_key_it_cannot_read() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, config, _) = init();
    let key = dir.path().join("data").join("node.key");
    std::fs::create_dir_all(&key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o700)).unwrap();

    let stderr = run_fails_with(&config);

    assert!(stderr.contains(&key.display().to_string()), "{stderr}");
}

#[test]
fn test_run_names_an_engine_dir_it_cannot_open() {
    let (dir, config, _) = init();
    let engine = dir.path().join("data").join("engine");
    std::fs::create_dir_all(engine.parent().unwrap()).unwrap();
    std::fs::write(&engine, "a file").unwrap();

    let stderr = run_fails_with(&config);

    assert!(stderr.contains(&engine.display().to_string()), "{stderr}");
}

/// A stop with late writes in the buffer cannot flush them: it must not report a flushed buffer,
/// and it exits with a failure so that the supervisor and the operator see it.
#[tokio::test(flavor = "multi_thread")]
async fn test_stop_with_late_writes_exits_with_a_failure() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, config, keys) = init();
    let text = std::fs::read_to_string(&config)
        .unwrap()
        .replace("retention_secs = 86400", "retention_secs = 3")
        .replace("late_margin_secs = 3600", "late_margin_secs = 1");
    std::fs::write(&config, text).unwrap();
    let daemon = start(&config, "info");
    assert_eq!(
        call(&daemon, &keys, "PUT", "/demo", b"").await.status,
        StatusCode::OK
    );
    let log = dir.path().join("remote").join("log");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let read_only = std::fs::Permissions::from_mode(0o555);
    for entry in std::fs::read_dir(&log).unwrap() {
        std::fs::set_permissions(entry.unwrap().path(), read_only.clone()).unwrap();
    }
    call(&daemon, &keys, "PUT", "/demo/late", b"late").await;
    tokio::time::sleep(Duration::from_secs(4)).await;

    let flushed = daemon.stop();

    for entry in std::fs::read_dir(&log).unwrap() {
        let writable = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(entry.unwrap().path(), writable).unwrap();
    }
    assert!(
        !flushed,
        "a stop that left late writes in the buffer exits with success"
    );
}

/// `windsockd quarantine list` and `export` on a real quarantine. The key holds a newline, a tab
/// and an escape byte: no output line may break on it, and export never overwrites.
#[tokio::test(flavor = "multi_thread")]
async fn test_quarantine_list_and_export_escape_the_keys() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, config, keys) = init();
    let text = std::fs::read_to_string(&config)
        .unwrap()
        .replace("retention_secs = 86400", "retention_secs = 3")
        .replace("late_margin_secs = 3600", "late_margin_secs = 1");
    std::fs::write(&config, text).unwrap();
    let daemon = start(&config, "info");
    assert_eq!(
        call(&daemon, &keys, "PUT", "/demo", b"").await.status,
        StatusCode::OK
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let log = dir.path().join("remote").join("log");
    let set_mode = |mode: u32| {
        for entry in std::fs::read_dir(&log).unwrap() {
            let path = entry.unwrap().path();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    };
    set_mode(0o555);
    let put = call(&daemon, &keys, "PUT", "/demo/a%0Ab%09c%1Bd", b"late body").await;
    assert_eq!(put.status, StatusCode::OK);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!daemon.stop());
    set_mode(0o755);
    let started = Command::new(BIN).arg("run").arg(&config).output().unwrap();
    assert!(
        !started.status.success(),
        "the start moves the late write and fails"
    );

    let listed = Command::new(BIN)
        .args(["quarantine", "list"])
        .arg(&config)
        .output()
        .unwrap();
    let out = dir.path().join("export");
    let exported = Command::new(BIN)
        .args(["quarantine", "export"])
        .arg(&config)
        .arg(&out)
        .output()
        .unwrap();
    let again = Command::new(BIN)
        .args(["quarantine", "export"])
        .arg(&config)
        .arg(&out)
        .output()
        .unwrap();

    let listed = String::from_utf8(listed.stdout).unwrap();
    // The record, and the intent of the flush whose create failed: no line from the key itself.
    assert_eq!(listed.lines().count(), 2, "{listed}");
    assert!(
        listed.contains("intent: interrupted flush, plan only"),
        "{listed}"
    );
    assert!(listed.contains("demo/a\\x0ab\\x09c\\x1bd"), "{listed}");
    assert!(exported.status.success(), "{exported:?}");
    let index = std::fs::read_to_string(out.join("index.tsv")).unwrap();
    assert_eq!(index.lines().count(), 2, "{index}");
    assert_eq!(std::fs::read(out.join("0001.body")).unwrap(), b"late body");
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&out), 0o700);
    assert_eq!(mode(&out.join("0001.body")), 0o600);
    assert!(
        !again.status.success(),
        "a second export into the same directory"
    );
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &link).unwrap();
    let to_link = Command::new(BIN)
        .args(["quarantine", "export"])
        .arg(&config)
        .arg(&link)
        .output()
        .unwrap();
    assert!(!to_link.status.success(), "an export through a symlink");
    assert!(
        dir.path()
            .join("data/engine/quarantine")
            .read_dir()
            .unwrap()
            .count()
            > 0
    );
}
