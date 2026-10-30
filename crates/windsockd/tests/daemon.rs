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
    let daemon = common::start_with_fd_limit(&config, "info", 600);
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
    // 600 descriptors give (600 - 256) / 2 = 172 connections: hold more than that.
    for _ in 0..300 {
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

/// Runs `windsockd run` under a soft and hard descriptor limit of `fds`, to its exit.
fn run_with_fd_limit(config: &Path, fds: u64) -> std::process::Output {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("ulimit -n {fds} && exec \"$0\" run \"$1\""))
        .arg(BIN)
        .arg(config)
        .output()
        .unwrap()
}

#[test]
fn test_start_under_512_descriptors_is_refused() {
    let (_dir, config, _keys) = init();

    let output = run_with_fd_limit(&config, 300);

    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(text.contains("ulimit -n"), "{text}");
}

#[test]
fn test_max_connections_over_the_descriptors_is_refused() {
    let (_dir, config, _keys) = init();
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, format!("max_connections = 400\n{text}")).unwrap();

    let output = run_with_fd_limit(&config, 600);

    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(text.contains("max_connections = 400 needs 1056"), "{text}");
}

/// The open descriptors of a process, from lsof.
fn open_fds(pid: u32) -> usize {
    let output = Command::new("lsof")
        .args(["-n", "-P", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .count()
        .saturating_sub(1)
}

/// Every connection holds a GET of a buffered object that its client does not read: each one
/// keeps its socket and the open buffer segment, 2 descriptors. The daemon stays under its
/// soft limit.
#[tokio::test(flavor = "multi_thread")]
async fn test_all_connections_stay_under_the_descriptor_limit() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let remote = dir.path().join("remote");
    // No flush during the test: the object stays in the buffer.
    let config = common::cluster_config(dir.path(), &remote, 3_600_000, "enabled = false");
    let keys = common::test_keys();
    let daemon = common::start_with_fd_limit(&config, "info", 600);
    call(&daemon, &keys, "PUT", "/demo", b"").await;
    call(&daemon, &keys, "PUT", "/demo/k", &vec![7u8; 16 << 20]).await;
    // (600 - 256) / 2 connections.
    let connections = 172;

    let mut held = Vec::new();
    for _ in 0..connections {
        let mut stream = tokio::net::TcpStream::connect(&daemon.address)
            .await
            .unwrap();
        let mut request = "GET /demo/k HTTP/1.1\r\n".to_string();
        for (name, value) in common::signed_headers(&daemon, &keys, "GET", "/demo/k", b"") {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut head = [0u8; 12];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 200");
        held.push(stream);
    }
    let mut peak = 0;
    for _ in 0..10 {
        peak = peak.max(open_fds(daemon.pid()));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(held);

    assert!(
        peak > 2 * connections,
        "lsof saw {peak} descriptors: not 2 per connection"
    );
    assert!(
        peak < 600,
        "{peak} descriptors at the peak for a soft limit of 600"
    );
    assert!(daemon.stop());
}

/// A client that stops reading a GET body holds its stream until the idle timeout, counted from
/// the last write that made progress. Then the daemon closes the connection, and the client gets
/// fewer bytes than the length.
#[tokio::test(flavor = "multi_thread")]
async fn test_reader_that_stops_reading_is_cut_after_the_idle_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let remote = dir.path().join("remote");
    let config = common::cluster_config(dir.path(), &remote, 1000, "enabled = false");
    let text = std::fs::read_to_string(&config).unwrap();
    let text = text.replace(
        "sync_interval_secs = 1\n",
        "sync_interval_secs = 1\nidle_timeout_secs = 2\n",
    );
    std::fs::write(&config, text).unwrap();
    let keys = common::test_keys();
    let daemon = common::start(&config, "info");
    let size = 64 << 20;
    call(&daemon, &keys, "PUT", "/demo", b"").await;
    call(&daemon, &keys, "PUT", "/demo/k", &vec![7u8; size]).await;

    let mut stream = tokio::net::TcpStream::connect(&daemon.address)
        .await
        .unwrap();
    let mut request = "GET /demo/k HTTP/1.1\r\n".to_string();
    for (name, value) in common::signed_headers(&daemon, &keys, "GET", "/demo/k", b"") {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    // The client reads nothing for longer than the idle timeout: both socket buffers fill.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let mut received = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut received)).await;

    assert!(read.is_ok(), "the daemon kept a stalled stream open");
    assert!(received.starts_with(b"HTTP/1.1 200"));
    assert!(received.len() < size, "{} bytes of {size}", received.len());
    assert!(daemon.stop());
}

/// The text of a signed GET request.
fn get_request(daemon: &common::Daemon, keys: &(String, String), path: &str) -> String {
    let mut request = format!("GET {path} HTTP/1.1\r\n");
    for (name, value) in common::signed_headers(daemon, keys, "GET", path, b"") {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request
}

/// Sends a request on a new connection and reads its status line, nothing more.
async fn send_and_hold(address: &str, request: &str) -> tokio::net::TcpStream {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut status = [0u8; 12];
    stream.read_exact(&mut status).await.unwrap();
    assert_eq!(&status, b"HTTP/1.1 200");
    stream
}

async fn held_get(
    daemon: &common::Daemon,
    keys: &(String, String),
    path: &str,
) -> tokio::net::TcpStream {
    send_and_hold(&daemon.address, &get_request(daemon, keys, path)).await
}

/// A daemon with an idle timeout of `idle_secs`, the smallest read budget, and no flush during
/// the test.
fn small_budget_daemon(dir: &Path, idle_secs: u64) -> common::Daemon {
    let remote = dir.join("remote");
    let config = common::cluster_config(dir, &remote, 3_600_000, "enabled = false");
    let text = std::fs::read_to_string(&config)
        .unwrap()
        .replace(
            "sync_interval_secs = 1\n",
            &format!("sync_interval_secs = 1\nidle_timeout_secs = {idle_secs}\n"),
        )
        .replace(
            "flush_delay_ms = 3600000\n",
            "flush_delay_ms = 3600000\nread_budget_bytes = 67108864\n",
        );
    std::fs::write(&config, text).unwrap();
    common::start(&config, "info")
}

/// GETs whose clients stop reading take the whole read budget: a stream that waits for room or
/// for the socket makes no progress. The idle timeout cuts each one, and the room comes back.
#[tokio::test(flavor = "multi_thread")]
async fn test_stalled_gets_that_hold_the_read_budget_are_cut_and_free_it() {
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().unwrap();
    let mut daemon = small_budget_daemon(dir.path(), 2);
    let keys = common::test_keys();
    let size = 64 << 20;
    call(&daemon, &keys, "PUT", "/demo", b"").await;
    call(&daemon, &keys, "PUT", "/demo/k", &vec![7u8; size]).await;

    // 16 pieces of room: one per stalled GET.
    let mut stalled = Vec::new();
    for _ in 0..16 {
        stalled.push(held_get(&daemon, &keys, "/demo/k").await);
    }
    // No client reads for longer than the idle timeout of 2 s.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut cut = 0;
    for stream in &mut stalled {
        let mut received = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut received));
        if read.await.is_ok() && received.len() < size {
            cut += 1;
        }
    }
    let after = call(&daemon, &keys, "GET", "/demo/k", b"").await;

    assert_eq!(cut, 16, "stalled GETs cut");
    assert_eq!(after.status, StatusCode::OK);
    assert_eq!(after.body.len(), size);
    assert_eq!(
        daemon.count_after("read budget", Duration::from_millis(100)),
        0
    );
    assert!(daemon.stop());
}

/// While the GETs in flight hold the read budget, each new GET gets 503 SlowDown. The daemon logs
/// one WARN for the streak, and one INFO when a GET gets room again.
#[tokio::test(flavor = "multi_thread")]
async fn test_read_budget_503_streak_logs_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut daemon = small_budget_daemon(dir.path(), 60);
    let keys = common::test_keys();
    call(&daemon, &keys, "PUT", "/demo", b"").await;
    call(&daemon, &keys, "PUT", "/demo/k", &vec![7u8; 64 << 20]).await;
    let mut held = Vec::new();
    for _ in 0..16 {
        held.push(held_get(&daemon, &keys, "/demo/k").await);
    }
    // Room comes back only from a stream that the socket lets on: with no reader, none.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let first = call(&daemon, &keys, "GET", "/demo/k", b"").await;
    let second = call(&daemon, &keys, "GET", "/demo/k", b"").await;
    drop(held);
    let after = call(&daemon, &keys, "GET", "/demo/k", b"").await;

    assert_eq!(first.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(second.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(after.status, StatusCode::OK);
    let warns = daemon.count_after("GETs get 503", Duration::from_millis(500));
    assert_eq!(warns, 1, "one WARN for the streak");
    assert!(daemon.logged("GETs get room in the read budget again"));
    assert!(daemon.stop());
}

/// The query of a presigned GET of `path`, valid for 300 s from now.
fn presigned_query(
    daemon: &common::Daemon,
    keys: &(String, String),
    path: &str,
    expires: &str,
) -> String {
    use s3api::sigv4;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp = sigv4::timestamp(now);
    let date = &timestamp[..8];
    let credential = format!("{}/{date}/us-east-1/s3/aws4_request", keys.0);
    let query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Date={timestamp}\
         &X-Amz-Expires={expires}&X-Amz-SignedHeaders=host",
        sigv4::uri_encode(credential.as_bytes(), sigv4::Slash::Encode),
    );
    let headers = [("host".to_string(), daemon.address.clone())];
    let canonical = sigv4::canonical_request(
        "GET",
        path,
        &query,
        &headers,
        &["host".to_string()],
        sigv4::UNSIGNED_PAYLOAD,
    );
    let key = sigv4::signing_key(&keys.1, date, "us-east-1");
    let scope = format!("{date}/us-east-1/s3/aws4_request");
    let signature = sigv4::signature(&key, &timestamp, &scope, &canonical);
    format!("{query}&X-Amz-Signature={signature}")
}

/// A GET with only a host header, and the status of its answer.
async fn raw_status(daemon: &common::Daemon, uri: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(&daemon.address)
        .await
        .unwrap();
    let request = format!(
        "GET {uri} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n\r\n",
        daemon.address
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    String::from_utf8_lossy(&answer[9..12]).parse().unwrap()
}

/// The query of a presigned URL holds its signature: no log line shows it, also at debug level,
/// for an accepted request, a refused signature, and a parameter that does not parse.
#[tokio::test(flavor = "multi_thread")]
async fn test_presigned_signature_is_never_logged() {
    let dir = tempfile::tempdir().unwrap();
    let remote = dir.path().join("remote");
    let config = common::cluster_config(dir.path(), &remote, 1000, "enabled = false");
    let mut daemon = common::start(&config, "debug");
    let keys = common::test_keys();
    call(&daemon, &keys, "PUT", "/demo", b"").await;
    call(&daemon, &keys, "PUT", "/demo/k", b"data").await;

    let good = presigned_query(&daemon, &keys, "/demo/k", "300");
    let signature = good.rsplit_once('=').unwrap().1.to_string();
    // The last digit always changes: a signature that ends in 0 must not stay valid.
    let other = if good.ends_with('0') { '1' } else { '0' };
    let flipped = format!("{}{other}", &good[..good.len() - 1]);
    let flipped_signature = flipped.rsplit_once('=').unwrap().1.to_string();
    let malformed = presigned_query(&daemon, &keys, "/demo/k", "0");
    let malformed_signature = malformed.rsplit_once('=').unwrap().1.to_string();

    let accepted = raw_status(&daemon, &format!("/demo/k?{good}")).await;
    let refused = raw_status(&daemon, &format!("/demo/k?{flipped}")).await;
    let unparsed = raw_status(&daemon, &format!("/demo/k?{malformed}")).await;

    assert_eq!((accepted, refused, unparsed), (200, 403, 400));
    for secret in [&signature, &flipped_signature, &malformed_signature] {
        assert_eq!(daemon.count_after(secret, Duration::from_millis(500)), 0);
    }
    assert!(daemon.stop());
}

/// Files under `dir`, at any depth.
fn files_under(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .map(|entry| entry.unwrap().path())
        .map(|path| match path.is_dir() {
            true => files_under(&path),
            false => 1,
        })
        .sum()
}

fn cache_trim(config: &Path, size: Option<&str>) -> std::process::Output {
    let mut command = Command::new(BIN);
    command.arg("cache-trim").arg(config);
    if let Some(size) = size {
        command.arg(size);
    }
    command.output().unwrap()
}

#[tokio::test]
async fn test_cache_trim_empties_the_cache_of_the_running_daemon() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let remote = dir.path().join("remote");
    let config = common::cluster_config(dir.path(), &remote, 100, "enabled = false");
    let daemon = start(&config, "info");
    let keys = common::test_keys();
    call(&daemon, &keys, "PUT", "/demo", b"").await;
    call(&daemon, &keys, "PUT", "/demo/k", &vec![7; 300_000]).await;
    let cache = dir.path().join("data/engine/cache");
    let admin = dir.path().join("data/admin");
    // The flush puts the written chunks in the cache.
    let deadline = Instant::now() + Duration::from_secs(10);
    while files_under(&cache) == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let cached = files_under(&cache);

    let refused = cache_trim(&config, Some("1000000000000000"));
    let trimmed = cache_trim(&config, None);
    let read = call(&daemon, &keys, "GET", "/demo/k", b"").await;

    assert!(cached > 0);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("cache_bytes"));
    assert!(
        trimmed.status.success(),
        "{}",
        String::from_utf8_lossy(&trimmed.stderr)
    );
    assert!(String::from_utf8_lossy(&trimmed.stderr).contains("limit=0"));
    assert_eq!(files_under(&cache), 0);
    assert_eq!(read.body, vec![7; 300_000]);
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&admin), 0o700);
    assert_eq!(mode(&admin.join("admin.sock")), 0o600);
    assert!(daemon.stop());
    assert!(!admin.join("admin.sock").exists());
}

#[tokio::test]
async fn test_daemon_replaces_the_socket_that_a_crash_left() {
    let dir = tempfile::tempdir().unwrap();
    let remote = dir.path().join("remote");
    let config = common::cluster_config(dir.path(), &remote, 100, "enabled = false");
    start(&config, "info").crash();
    let left = dir.path().join("data/admin/admin.sock").exists();

    let daemon = start(&config, "info");
    let trimmed = cache_trim(&config, Some("0"));

    assert!(left);
    assert!(
        trimmed.status.success(),
        "{}",
        String::from_utf8_lossy(&trimmed.stderr)
    );
    assert!(daemon.stop());
}
