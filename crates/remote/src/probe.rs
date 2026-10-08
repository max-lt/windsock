//! The storage contract check. A store can accept a header and ignore it. No store publishes
//! what it keeps. Thus the probe asks the store.
//!
//! See `docs/storage.md` for the contract and for the stores that keep it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tracing::warn;

use crate::{RemoteError, Sweep};

/// Prefix of the probe keys. Each probe deletes its keys after the check.
pub const PROBE_PREFIX: &str = "probe/";

/// Complete probes that end in an ambiguous error before a node starts with no check.
pub const STARTUP_ATTEMPTS: usize = 3;

const RANGE_BODY: &[u8] = b"windsock-range-probe";
const RANGE: std::ops::Range<u64> = 9..14;

/// What one complete probe found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The store gave every answer that the contract requires.
    Conformant,
    /// The store gave a wrong answer, and the string says which. A retry does not clear it.
    Violation(String),
}

/// What a node does before it serves.
#[derive(Debug)]
pub enum Startup {
    Conformant,
    /// Every attempt ended in an ambiguous error. The node starts, and this is the last error.
    Unverified(RemoteError),
    Violation(String),
}

/// Runs the complete probe up to [`STARTUP_ATTEMPTS`] times while it ends in an ambiguous error.
pub async fn check_before_serving(remote: &impl Sweep) -> Startup {
    let mut attempt = 1;
    loop {
        match probe(remote).await {
            Ok(Verdict::Conformant) => return Startup::Conformant,
            Ok(Verdict::Violation(reason)) => return Startup::Violation(reason),
            Err(error) if attempt < STARTUP_ATTEMPTS => {
                warn!(attempt, %error, "could not check the storage contract: retrying");
                attempt += 1;
            }
            Err(error) => return Startup::Unverified(error),
        }
    }
}

/// One complete probe with new keys. An `Err` is ambiguous, such as a network fault or a
/// refused credential. A retry can clear it.
pub async fn probe(remote: &impl Sweep) -> Result<Verdict, RemoteError> {
    let create = probe_key("create");
    let verdict = create_contract(remote, &create).await;
    retire(remote, &create).await;
    match verdict {
        Ok(Verdict::Conformant) => {}
        other => return other,
    }

    let range = probe_key("range");
    let verdict = range_contract(remote, &range).await;
    retire(remote, &range).await;
    verdict
}

/// Create, reject a second create, read after write, list after write.
async fn create_contract(remote: &impl Sweep, key: &str) -> Result<Verdict, RemoteError> {
    match remote.create(key, Bytes::from_static(b"first")).await {
        Ok(()) => {}
        Err(RemoteError::AlreadyExists(_)) => {
            return violation("the store refused a create of an object that does not exist");
        }
        Err(error) => return unsupported_or(error, "the store does not support a create"),
    }

    match remote.create(key, Bytes::from_static(b"second")).await {
        Err(RemoteError::AlreadyExists(_)) => {}
        Ok(()) => {
            return violation(
                "the store accepted a second create of one key. It ignores If-None-Match: *, \
                 so two processes can write one journal entry",
            );
        }
        Err(error) => return Err(error),
    }

    if remote.get(key).await?.as_deref() != Some(b"first".as_slice()) {
        return violation("a read after a write did not return the first write");
    }

    if !remote.list(key).await?.iter().any(|listed| listed == key) {
        return violation("a list after a write did not show the written object");
    }

    Ok(Verdict::Conformant)
}

/// A ranged read must return the requested range and the bytes of that range.
async fn range_contract(remote: &impl Sweep, key: &str) -> Result<Verdict, RemoteError> {
    remote.put(key, Bytes::from_static(RANGE_BODY)).await?;

    let read = match remote.get_range(key, RANGE).await {
        Ok(read) => read,
        Err(error) => return unsupported_or(error, "the store does not support ranged reads"),
    };
    let expected = &RANGE_BODY[RANGE.start as usize..RANGE.end as usize];
    if read.as_deref() != Some(expected) {
        return violation("a ranged read returned another range or other bytes");
    }

    Ok(Verdict::Conformant)
}

fn violation(reason: &str) -> Result<Verdict, RemoteError> {
    Ok(Verdict::Violation(reason.to_string()))
}

/// A clear "not supported" answer never clears, so it is a violation. Other errors are ambiguous.
fn unsupported_or(error: RemoteError, reason: &str) -> Result<Verdict, RemoteError> {
    match error {
        RemoteError::Service {
            status: 405 | 501, ..
        } => violation(reason),
        other => Err(other),
    }
}

async fn retire(remote: &impl Sweep, key: &str) {
    // A failed delete leaves one small object under probe/ that nothing reads.
    if let Err(error) = remote.delete(key).await {
        warn!(key, %error, "the storage probe could not delete its object");
    }
}

/// A key per probe, so two nodes that probe at the same time use different objects.
fn probe_key(kind: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("{PROBE_PREFIX}{kind}-{nanos}-{}-{n}", std::process::id())
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use crate::{DirRemote, MemoryRemote, Remote};

    /// A store with one fault on top of a memory store.
    enum Fault {
        CreateOverwrites,
        RangeReturnsAll,
        ListMisses,
        CreateFails,
    }

    struct Faulty(MemoryRemote, Fault);

    #[async_trait::async_trait]
    impl Remote for Faulty {
        async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
            self.0.put(key, data).await
        }

        async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
            match self.1 {
                Fault::CreateOverwrites => self.0.put(key, data).await,
                Fault::CreateFails => Err(RemoteError::Io(std::io::Error::other("unreachable"))),
                _ => self.0.create(key, data).await,
            }
        }

        async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
            self.0.get(key).await
        }

        async fn get_range(
            &self,
            key: &str,
            range: Range<u64>,
        ) -> Result<Option<Bytes>, RemoteError> {
            match self.1 {
                Fault::RangeReturnsAll => self.0.get(key).await,
                _ => self.0.get_range(key, range).await,
            }
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
            match self.1 {
                Fault::ListMisses => Ok(Vec::new()),
                _ => self.0.list(prefix).await,
            }
        }
    }

    #[async_trait::async_trait]
    impl Sweep for Faulty {
        async fn delete(&self, key: &str) -> Result<(), RemoteError> {
            self.0.delete(key).await
        }
    }

    fn faulty(fault: Fault) -> Faulty {
        Faulty(MemoryRemote::default(), fault)
    }

    #[tokio::test]
    async fn test_memory_and_directory_remotes_conform_and_keep_no_probe_object() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DirRemote::open(dir.path()).unwrap();
        let memory = MemoryRemote::default();

        assert_eq!(probe(&disk).await.unwrap(), Verdict::Conformant);
        assert_eq!(probe(&memory).await.unwrap(), Verdict::Conformant);

        assert!(disk.list(PROBE_PREFIX).await.unwrap().is_empty());
        assert!(memory.list(PROBE_PREFIX).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_create_that_overwrites_is_a_violation() {
        let verdict = probe(&faulty(Fault::CreateOverwrites)).await.unwrap();

        assert!(matches!(verdict, Verdict::Violation(reason) if reason.contains("If-None-Match")));
    }

    #[tokio::test]
    async fn test_ranged_read_that_returns_the_whole_object_is_a_violation() {
        let verdict = probe(&faulty(Fault::RangeReturnsAll)).await.unwrap();

        assert!(matches!(verdict, Verdict::Violation(reason) if reason.contains("ranged read")));
    }

    #[tokio::test]
    async fn test_list_that_misses_a_written_object_is_a_violation() {
        let verdict = probe(&faulty(Fault::ListMisses)).await.unwrap();

        assert!(matches!(verdict, Verdict::Violation(reason) if reason.contains("list")));
    }

    #[tokio::test]
    async fn test_startup_refuses_a_violation() {
        let startup = check_before_serving(&faulty(Fault::CreateOverwrites)).await;

        assert!(matches!(startup, Startup::Violation(_)));
    }

    #[tokio::test]
    async fn test_startup_goes_on_unverified_after_ambiguous_errors() {
        let startup = check_before_serving(&faulty(Fault::CreateFails)).await;

        assert!(matches!(startup, Startup::Unverified(RemoteError::Io(_))));
    }
}
