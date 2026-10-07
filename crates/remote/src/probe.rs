//! A startup check: the remote must refuse a second create of one key.
//!
//! The journal writes each entry with a create. A store that overwrites instead lets two
//! processes write one seq, and an acknowledged write can then be lost.

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::{RemoteError, Sweep};

/// Prefix of the probe keys. Each probe deletes its key after the check.
pub const PROBE_PREFIX: &str = "probe/";

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error(
        "the remote accepted a second create of {key:?}: it ignores If-None-Match: *, \
         and the journal needs create-only writes"
    )]
    NotCreateOnly { key: String },
    #[error("the create-only probe on {key:?} failed: {source}")]
    Failed {
        key: String,
        #[source]
        source: RemoteError,
    },
}

/// Creates a dated probe key, creates it again, and expects `AlreadyExists` the second time.
pub async fn check_create_only(remote: &impl Sweep) -> Result<(), ProbeError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let key = format!("{PROBE_PREFIX}create-only-{nanos}-{}", std::process::id());

    if let Err(source) = remote.create(&key, Bytes::from_static(b"first")).await {
        return Err(ProbeError::Failed { key, source });
    }
    let second = remote.create(&key, Bytes::from_static(b"second")).await;
    // The probe key holds no data. If the delete fails, only a dated probe key stays.
    remote.delete(&key).await.ok();

    match second {
        Err(RemoteError::AlreadyExists(_)) => Ok(()),
        Ok(()) => Err(ProbeError::NotCreateOnly { key }),
        Err(source) => Err(ProbeError::Failed { key, source }),
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use crate::{DirRemote, MemoryRemote, Remote};

    /// A store that overwrites on create, as Garage 2.4.1 does.
    struct Overwrites(MemoryRemote);

    #[async_trait::async_trait]
    impl Remote for Overwrites {
        async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
            self.0.put(key, data).await
        }

        async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
            self.0.put(key, data).await
        }

        async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
            self.0.get(key).await
        }

        async fn get_range(
            &self,
            key: &str,
            range: Range<u64>,
        ) -> Result<Option<Bytes>, RemoteError> {
            self.0.get_range(key, range).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
            self.0.list(prefix).await
        }
    }

    #[async_trait::async_trait]
    impl Sweep for Overwrites {
        async fn delete(&self, key: &str) -> Result<(), RemoteError> {
            self.0.delete(key).await
        }
    }

    #[tokio::test]
    async fn test_memory_and_directory_remotes_pass_and_leave_no_probe_key() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DirRemote::open(dir.path()).unwrap();
        let memory = MemoryRemote::default();

        check_create_only(&disk).await.unwrap();
        check_create_only(&memory).await.unwrap();

        assert!(disk.list(PROBE_PREFIX).await.unwrap().is_empty());
        assert!(memory.list(PROBE_PREFIX).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_remote_that_overwrites_on_create_is_refused() {
        let remote = Overwrites(MemoryRemote::default());

        let result = check_create_only(&remote).await;

        assert!(matches!(result, Err(ProbeError::NotCreateOnly { .. })));
    }
}
