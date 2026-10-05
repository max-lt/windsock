//! Remote object stores. The remote holds the only durable copy of the data.
//!
//! [`Remote`] has no delete operation. Only the GC deletes, and only through [`Sweep`].

#[cfg(any(test, feature = "contract"))]
pub mod contract;
mod dir;
mod memory;

use std::ops::Range;

use bytes::Bytes;

pub use dir::DirRemote;
pub use memory::MemoryRemote;

/// A remote operation failed.
#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("invalid key: {0:?}")]
    InvalidKey(String),
    #[error("range {start}..{end} is outside {key:?} ({len} bytes)")]
    InvalidRange {
        key: String,
        start: u64,
        end: u64,
        len: u64,
    },
    #[error("object already exists: {0:?}")]
    AlreadyExists(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A remote service answered with an error that a retry does not fix.
    #[error("remote service error {status} {code}: {message}")]
    Service {
        status: u16,
        code: String,
        message: String,
    },
}

/// A blob store with `/`-separated string keys, such as `packs/<pack_id>`.
///
/// A key segment is not empty and does not start with `.`, so a key cannot leave the remote.
#[async_trait::async_trait]
pub trait Remote: Send + Sync {
    /// Stores `data` at `key`. Replaces an existing object.
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError>;

    /// Stores `data` at `key` when no object exists there. Two concurrent creates have one winner.
    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError>;

    /// Returns the object at `key`, or `None` if it does not exist.
    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError>;

    /// Returns `range` of the object at `key`, or `None` if it does not exist.
    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError>;

    /// Returns the keys that start with `prefix`, in lexicographic order.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError>;
}

/// A remote that can delete. Only the GC takes this bound: the write path uses [`Remote`].
#[async_trait::async_trait]
pub trait Sweep: Remote {
    /// Deletes the object at `key`. A missing object is not an error, so a sweep can run again.
    async fn delete(&self, key: &str) -> Result<(), RemoteError>;
}

/// Checks the key rules of [`Remote`]. Backends call it before any I/O.
pub fn check_key(key: &str) -> Result<(), RemoteError> {
    let valid = !key.is_empty()
        && key
            .split('/')
            .all(|segment| !segment.is_empty() && !segment.starts_with('.'));

    if !valid {
        return Err(RemoteError::InvalidKey(key.to_string()));
    }

    Ok(())
}

/// Checks a list prefix: empty, or a key, with or without a trailing `/`.
pub fn check_prefix(prefix: &str) -> Result<(), RemoteError> {
    if prefix.is_empty() {
        return Ok(());
    }

    let trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
    check_key(trimmed).map_err(|_| RemoteError::InvalidKey(prefix.to_string()))
}

fn check_range(key: &str, range: &Range<u64>, len: u64) -> Result<(), RemoteError> {
    if range.start > range.end || range.end > len {
        return Err(RemoteError::InvalidRange {
            key: key.to_string(),
            start: range.start,
            end: range.end,
            len,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_memory_remote_meets_the_contract() {
        contract::check(|| async { MemoryRemote::default() }).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dir_remote_meets_the_contract() {
        let dirs = std::sync::Mutex::new(Vec::new());

        contract::check(|| {
            let dir = tempfile::tempdir().unwrap();
            let remote = DirRemote::open(dir.path()).unwrap();
            dirs.lock().unwrap().push(dir);
            async move { remote }
        })
        .await;
    }

    #[tokio::test]
    async fn test_dir_remote_persists_across_open() {
        let dir = tempfile::tempdir().unwrap();
        DirRemote::open(dir.path())
            .unwrap()
            .put("packs/a", Bytes::from("data"))
            .await
            .unwrap();

        let reopened = DirRemote::open(dir.path()).unwrap();

        assert_eq!(reopened.get("packs/a").await.unwrap().unwrap(), "data");
    }

    #[tokio::test]
    async fn test_dir_remote_list_ignores_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::open(dir.path()).unwrap();
        remote.put("heads/a", Bytes::from("data")).await.unwrap();
        std::fs::write(dir.path().join("heads/.tmp.1.1"), "partial").unwrap();

        assert_eq!(remote.list("heads/").await.unwrap(), ["heads/a"]);
    }
}
