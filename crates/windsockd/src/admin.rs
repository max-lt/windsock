//! The admin socket: a local Unix socket that `windsockd cache-trim` uses to reach the running
//! daemon. The directory has mode 0700 and the socket 0600: only the user of the daemon gets in.
//!
//! One request per connection, one line each way: `cache-trim <bytes>`, then
//! `ok limit=<l> bytes=<b> max=<m>` or `error <text>`.

use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use crate::Node;

const ADMIN_DIR: &str = "admin";
const SOCKET: &str = "admin.sock";
/// The longest socket path: macOS keeps 104 bytes for it with the final NUL, Linux 108.
const MAX_SOCKET_PATH: usize = 103;
/// A request or a reply is one short line.
const MAX_LINE: u64 = 128;
/// A client that sends no full line in this time is dropped.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
/// The client waits this long: a trim of a large cache removes many files.
const REPLY_DEADLINE: Duration = Duration::from_secs(300);

pub(crate) fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ADMIN_DIR).join(SOCKET)
}

/// One admin request.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    CacheTrim(u64),
}

fn parse(line: &str) -> Result<Request, String> {
    match line.trim_end_matches('\n').split(' ').collect::<Vec<_>>()[..] {
        ["cache-trim", bytes] if !bytes.is_empty() && bytes.bytes().all(|b| b.is_ascii_digit()) => {
            bytes
                .parse()
                .map(Request::CacheTrim)
                .map_err(|_| format!("{bytes} is not a number of bytes"))
        }
        _ => Err("the request must be: cache-trim <bytes>".to_string()),
    }
}

/// Makes the admin directory with mode 0700, and removes the socket that a stopped daemon left.
/// Call it once the engine is open: the engine lock keeps a second daemon out of this data
/// directory, so the socket found here is never the one of a live daemon. `None` when the socket
/// path is over the Unix limit: an optional feature must not stop a store that holds data, so
/// the daemon runs with no admin socket, and one WARN says why.
pub(crate) fn prepare(data_dir: &Path) -> Result<Option<PathBuf>> {
    let path = socket_path(data_dir);
    let length = path.as_os_str().len();
    if length > MAX_SOCKET_PATH {
        warn!(
            socket = %path.display(),
            length,
            limit = MAX_SOCKET_PATH,
            "the admin socket path is over the Unix limit: no admin socket, so cache-trim does not \
             work. Use a shorter data_dir"
        );
        return Ok(None);
    }
    let dir = data_dir.join(ADMIN_DIR);
    let uid = rustix::process::getuid().as_raw();
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("cannot make {}", dir.display()))?,
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
        Ok(meta) if !meta.file_type().is_dir() => {
            bail!(
                "{} must be a directory, not a link or a file",
                dir.display()
            )
        }
        Ok(meta) if meta.uid() != uid => {
            bail!("{} belongs to another user", dir.display())
        }
        Ok(meta) if meta.permissions().mode() & 0o077 != 0 => bail!(
            "{} can be opened by other users. Run: chmod 700 {}",
            dir.display(),
            dir.display()
        ),
        Ok(_) => {}
    }

    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == uid => {
            std::fs::remove_file(&path)
                .with_context(|| format!("cannot remove the old socket {}", path.display()))?;
        }
        Ok(_) => bail!("{} is not a socket of this user: remove it", path.display()),
    }
    Ok(Some(path))
}

/// Listens on `path` with mode 0600.
pub(crate) fn bind(path: &Path) -> Result<UnixListener> {
    let listener =
        UnixListener::bind(path).with_context(|| format!("cannot listen on {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot set the mode of {}", path.display()))?;
    Ok(listener)
}

/// Answers admin requests one at a time, until the task is aborted: the socket holds at most two
/// descriptors of the reserve that the flush needs.
pub(crate) async fn serve(listener: UnixListener, node: Node) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                warn!(%e, "admin socket: accept failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if let Err(e) = answer(stream, &node).await {
            warn!(%e, "admin socket: request failed");
        }
    }
}

async fn answer(stream: UnixStream, node: &Node) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    let mut reader = BufReader::new(read).take(MAX_LINE);
    match tokio::time::timeout(REQUEST_DEADLINE, reader.read_line(&mut line)).await {
        Ok(result) => result?,
        Err(_) => return Ok(()),
    };
    let reply = match parse(&line) {
        Ok(Request::CacheTrim(bytes)) => match node.set_cache_limit(bytes).await {
            Ok(state) => format!(
                "ok limit={} bytes={} max={}\n",
                state.limit, state.bytes, state.max
            ),
            Err(e) => format!("error {e}\n"),
        },
        Err(e) => format!("error {e}\n"),
    };
    write.write_all(reply.as_bytes()).await
}

/// Sets the cache limit of the daemon that runs on `data_dir`.
pub(crate) async fn cache_trim(data_dir: &Path, bytes: u64) -> Result<()> {
    let path = socket_path(data_dir);
    let length = path.as_os_str().len();
    if length > MAX_SOCKET_PATH {
        bail!(
            "no admin socket: data_dir is too long (the socket path {} is {length} bytes, the Unix \
             limit is {MAX_SOCKET_PATH})",
            path.display()
        );
    }
    let stream = UnixStream::connect(&path).await.with_context(|| {
        format!(
            "cannot reach the daemon at {}: is it running on this data_dir?",
            path.display()
        )
    })?;
    let (read, mut write) = stream.into_split();
    write
        .write_all(format!("cache-trim {bytes}\n").as_bytes())
        .await?;
    let mut reply = String::new();
    let mut reader = BufReader::new(read).take(MAX_LINE);
    tokio::time::timeout(REPLY_DEADLINE, reader.read_line(&mut reply))
        .await
        .context("the daemon did not answer in time")??;
    let reply = reply.trim_end();
    match reply.strip_prefix("ok ") {
        Some(state) => {
            info!(state, "cache limit set");
            Ok(())
        }
        None => bail!("{}", reply.strip_prefix("error ").unwrap_or(reply)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_takes_only_a_number_of_bytes() {
        assert_eq!(parse("cache-trim 0\n"), Ok(Request::CacheTrim(0)));
        assert_eq!(parse("cache-trim 4096"), Ok(Request::CacheTrim(4096)));
        for refused in [
            "cache-trim",
            "cache-trim ",
            "cache-trim -1",
            "cache-trim 1G",
            "cache-trim 99999999999999999999999",
            "cache-trim 1 2",
            "flush",
        ] {
            assert!(parse(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn test_prepare_makes_a_private_directory_and_removes_an_old_socket() {
        let data = tempfile::tempdir().unwrap();
        let path = prepare(data.path()).unwrap().unwrap();
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());

        let again = prepare(data.path()).unwrap().unwrap();

        let mode = std::fs::metadata(data.path().join(ADMIN_DIR))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        assert_eq!(again, path);
        assert!(!path.exists());
    }

    #[test]
    fn test_prepare_refuses_an_open_directory_a_link_and_a_file_at_the_socket() {
        let open = tempfile::tempdir().unwrap();
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(open.path().join(ADMIN_DIR))
            .unwrap();
        let linked = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), linked.path().join(ADMIN_DIR)).unwrap();
        let file = tempfile::tempdir().unwrap();
        let path = prepare(file.path()).unwrap().unwrap();
        std::fs::write(&path, b"not a socket").unwrap();

        let errors = [open.path(), linked.path(), file.path()].map(|dir| {
            prepare(dir)
                .expect_err(&dir.display().to_string())
                .to_string()
        });

        assert!(errors[0].contains("chmod 700"), "{}", errors[0]);
        assert!(errors[1].contains("not a link"), "{}", errors[1]);
        assert!(errors[2].contains("not a socket"), "{}", errors[2]);
        assert!(path.exists());
    }
    #[test]
    fn test_socket_path_over_the_limit_gives_no_socket_and_the_client_names_the_cause() {
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("d".repeat(MAX_SOCKET_PATH));
        std::fs::create_dir_all(&data).unwrap();

        let socket = prepare(&data).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let client = runtime
            .block_on(cache_trim(&data, 0))
            .unwrap_err()
            .to_string();

        assert_eq!(socket, None);
        assert!(!data.join(ADMIN_DIR).exists());
        assert!(
            client.contains("no admin socket: data_dir is too long"),
            "{client}"
        );
    }
}
