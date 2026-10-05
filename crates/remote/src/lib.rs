//! Remote object stores. The remote holds the only durable copy of the data.
//!
//! [`Remote`] has no delete operation. Only the GC deletes, and only through [`Sweep`].

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

fn check_key(key: &str) -> Result<(), RemoteError> {
    let valid = !key.is_empty()
        && key
            .split('/')
            .all(|segment| !segment.is_empty() && !segment.starts_with('.'));

    if !valid {
        return Err(RemoteError::InvalidKey(key.to_string()));
    }

    Ok(())
}

fn check_prefix(prefix: &str) -> Result<(), RemoteError> {
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

    /// One test per remote behavior, run on every backend.
    macro_rules! contract_tests {
        ($backend:ident, $make:expr) => {
            mod $backend {
                use super::*;

                #[tokio::test]
                async fn test_put_get_roundtrip() {
                    let (_guard, remote) = $make;
                    remote.put("packs/a", Bytes::from("data")).await.unwrap();

                    assert_eq!(remote.get("packs/a").await.unwrap().unwrap(), "data");
                }

                #[tokio::test]
                async fn test_missing_object_is_none() {
                    let (_guard, remote) = $make;

                    assert!(remote.get("packs/a").await.unwrap().is_none());
                    assert!(remote.get_range("packs/a", 0..1).await.unwrap().is_none());
                }

                #[tokio::test]
                async fn test_put_replaces_object() {
                    let (_guard, remote) = $make;
                    remote.put("heads/a", Bytes::from("old")).await.unwrap();
                    remote.put("heads/a", Bytes::from("new")).await.unwrap();

                    assert_eq!(remote.get("heads/a").await.unwrap().unwrap(), "new");
                }

                #[tokio::test]
                async fn test_get_range_returns_slice() {
                    let (_guard, remote) = $make;
                    remote
                        .put("packs/a", Bytes::from("0123456789"))
                        .await
                        .unwrap();

                    let middle = remote.get_range("packs/a", 2..5).await.unwrap().unwrap();
                    let empty = remote.get_range("packs/a", 10..10).await.unwrap().unwrap();

                    assert_eq!(middle, "234");
                    assert!(empty.is_empty());
                }

                #[tokio::test]
                async fn test_get_range_outside_object_is_rejected() {
                    let (_guard, remote) = $make;
                    remote.put("packs/a", Bytes::from("0123")).await.unwrap();

                    assert!(matches!(
                        remote.get_range("packs/a", 2..5).await,
                        Err(RemoteError::InvalidRange { len: 4, .. })
                    ));
                    #[allow(clippy::reversed_empty_ranges)]
                    let reversed = remote.get_range("packs/a", 3..1).await;
                    assert!(matches!(reversed, Err(RemoteError::InvalidRange { .. })));
                }

                #[tokio::test]
                async fn test_list_returns_sorted_keys_under_prefix() {
                    let (_guard, remote) = $make;
                    for key in ["heads/b", "heads/a", "packs/x", "headsx", "log/a/b"] {
                        remote.put(key, Bytes::from(key)).await.unwrap();
                    }

                    assert_eq!(remote.list("heads/").await.unwrap(), ["heads/a", "heads/b"]);
                    assert_eq!(
                        remote.list("heads").await.unwrap(),
                        ["heads/a", "heads/b", "headsx"]
                    );
                    assert_eq!(
                        remote.list("").await.unwrap(),
                        ["heads/a", "heads/b", "headsx", "log/a/b", "packs/x"]
                    );
                    assert!(remote.list("snapshots/").await.unwrap().is_empty());
                }

                #[tokio::test]
                async fn test_create_writes_a_new_key() {
                    let (_guard, remote) = $make;
                    remote.create("log/a", Bytes::from("data")).await.unwrap();

                    assert_eq!(remote.get("log/a").await.unwrap().unwrap(), "data");
                }

                #[tokio::test]
                async fn test_create_keeps_the_existing_object() {
                    let (_guard, remote) = $make;
                    remote.put("log/a", Bytes::from("old")).await.unwrap();

                    let result = remote.create("log/a", Bytes::from("new")).await;

                    assert!(matches!(result, Err(RemoteError::AlreadyExists(_))));
                    assert_eq!(remote.get("log/a").await.unwrap().unwrap(), "old");
                }

                #[tokio::test(flavor = "multi_thread")]
                async fn test_concurrent_creates_have_one_winner() {
                    let (_guard, remote) = $make;
                    let remote = std::sync::Arc::new(remote);
                    let mut tasks = tokio::task::JoinSet::new();

                    for i in 0..8u8 {
                        let remote = remote.clone();
                        tasks.spawn(async move {
                            remote
                                .create("log/a", Bytes::from(vec![i]))
                                .await
                                .map(|()| i)
                        });
                    }

                    let mut winners = Vec::new();
                    while let Some(result) = tasks.join_next().await {
                        match result.unwrap() {
                            Ok(i) => winners.push(i),
                            Err(RemoteError::AlreadyExists(_)) => {}
                            Err(e) => panic!("{e}"),
                        }
                    }

                    assert_eq!(winners.len(), 1);
                    assert_eq!(
                        remote.get("log/a").await.unwrap().unwrap(),
                        vec![winners[0]]
                    );
                }

                #[tokio::test]
                async fn test_delete_removes_the_object() {
                    let (_guard, remote) = $make;
                    remote.put("packs/a", Bytes::from("data")).await.unwrap();
                    remote.put("packs/b", Bytes::from("data")).await.unwrap();

                    remote.delete("packs/a").await.unwrap();

                    assert!(remote.get("packs/a").await.unwrap().is_none());
                    assert_eq!(remote.list("packs/").await.unwrap(), ["packs/b"]);
                }

                #[tokio::test]
                async fn test_delete_of_a_missing_key_is_ok() {
                    let (_guard, remote) = $make;

                    remote.delete("packs/a").await.unwrap();
                }

                #[tokio::test]
                async fn test_invalid_key_is_rejected() {
                    let (_guard, remote) = $make;

                    for key in ["", "/abs", "a//b", "a/", "../x", "a/../b", ".tmp", "a/.b"] {
                        assert!(
                            matches!(
                                remote.put(key, Bytes::new()).await,
                                Err(RemoteError::InvalidKey(_))
                            ),
                            "{key:?} was accepted by put"
                        );
                        assert!(
                            matches!(
                                remote.create(key, Bytes::new()).await,
                                Err(RemoteError::InvalidKey(_))
                            ),
                            "{key:?} was accepted by create"
                        );
                        assert!(
                            matches!(remote.delete(key).await, Err(RemoteError::InvalidKey(_))),
                            "{key:?} was accepted by delete"
                        );
                    }

                    for prefix in ["/", "../", "a//"] {
                        assert!(
                            matches!(remote.list(prefix).await, Err(RemoteError::InvalidKey(_))),
                            "{prefix:?} was accepted"
                        );
                    }
                }
            }
        };
    }

    contract_tests!(memory, ((), MemoryRemote::default()));

    contract_tests!(dir, {
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::open(dir.path()).unwrap();
        (dir, remote)
    });

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
