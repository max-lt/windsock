//! Puts that stream their body: the body goes to a spool file in pieces, and the file becomes a
//! segment of the buffer at the commit. The memory of such a put does not grow with its object.
//!
//! Durability order: the data is fsynced, then the head is written after it and fsynced, then the
//! file is renamed to a segment and the directory is fsynced. Only then the put is acknowledged.
//! A valid head on disk always follows durable data. The commit holds the buffer lock from the head write to
//! the directory fsync: the other writes and the reads of the buffer wait for it.

use std::sync::atomic::AtomicU64;

use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use super::*;
use crate::buffer::{SPOOL_DIR, encode_head};

/// Makes spool file names unique inside one process.
static SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A put whose body goes to a spool file. Dropped before its commit, it removes the file and
/// gives its bytes back to the buffer limit.
pub struct PutSpool {
    file: tokio::fs::File,
    path: PathBuf,
    hasher: blake3::Hasher,
    len: u64,
    bucket: String,
    key: String,
    metadata: BTreeMap<String, String>,
    mode: WriteMode,
    spooled: Arc<AtomicU64>,
    /// Room of the buffer limit taken at the start, for a body of a known size.
    reserved: u64,
    #[cfg(test)]
    fail_head_write: bool,
}

impl PutSpool {
    /// Bytes of the body so far.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// The blake3 hash of the body so far: the content hash of the put once the body is whole.
    pub fn content_hash(&self) -> [u8; 32] {
        *self.hasher.clone().finalize().as_bytes()
    }

    /// The bytes that count against the buffer limit.
    fn counted(&self) -> u64 {
        self.len.max(self.reserved)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for PutSpool {
    fn drop(&mut self) {
        // Once its commit hands the file to the buffer, the path is empty, and len is 0 after it.
        let _ = std::fs::remove_file(&self.path);
        let len = self.counted();
        let _ = self
            .spooled
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |spooled| {
                Some(spooled.saturating_sub(len))
            });
    }
}

impl<R: Remote + 'static> Engine<R> {
    /// Starts a put whose body comes in pieces. The checks of the commit run here first, on local
    /// state, so a put that the commit would refuse does not write its body.
    pub async fn begin_put(
        &self,
        bucket: &str,
        key: &str,
        metadata: BTreeMap<String, String>,
        mode: WriteMode,
    ) -> Result<PutSpool> {
        self.begin_put_sized(bucket, key, metadata, mode, 0).await
    }

    /// [`Engine::begin_put`] for a body of `size` bytes: its room of the buffer limit is taken at
    /// once, so puts that start together cannot pass the limit together. The room comes back when
    /// the spool goes.
    pub async fn begin_put_sized(
        &self,
        bucket: &str,
        key: &str,
        metadata: BTreeMap<String, String>,
        mode: WriteMode,
        size: u64,
    ) -> Result<PutSpool> {
        crate::write::check_key(key)?;
        self.check_writes()?;
        let head = Head {
            time: u64::MAX,
            op: Op::Put {
                bucket: bucket.to_string(),
                key: key.to_string(),
                metadata: metadata.clone(),
                content_hash: [0; 32],
            },
        };
        buffer::check_head(&head)?;
        {
            let buffer = self.buffer.lock().await;
            self.require_bucket(&buffer, bucket)?;
            let current = self.current(&buffer, bucket, key)?;
            let policy = self.config.policy(bucket, key);
            let create_only = mode == WriteMode::CreateOnly || policy.create_only;
            let needs_object = matches!(mode, WriteMode::IfExists | WriteMode::IfMatch(_));
            if needs_object && !current.exists() {
                return Err(read::no_such_key(bucket, key));
            }
            let refused = match &mode {
                _ if create_only => current.exists(),
                // An index miss waits for the commit, which reads the manifest.
                WriteMode::IfMatch(hashes) => self
                    .local_content_hash(&current)?
                    .is_some_and(|hash| !hashes.contains(&hash)),
                _ => false,
            };
            if refused {
                return Err(EngineError::PreconditionFailed {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }
            let limit = self.config.buffer_limit;
            let used = buffer.bytes() + self.spooled.load(Ordering::SeqCst);
            if used >= limit || used + size > limit {
                return Err(EngineError::BufferFull { limit });
            }
            // Under the buffer lock: two puts that start together see each other.
            self.spooled.fetch_add(size, Ordering::SeqCst);
        }

        let n = SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = self
            .buffer_dir
            .join(SPOOL_DIR)
            .join(format!("{}.{n}", std::process::id()));
        let file = match tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await
        {
            Ok(file) => file,
            Err(e) => {
                self.spooled.fetch_sub(size, Ordering::SeqCst);
                return Err(e.into());
            }
        };
        let mut spool = PutSpool {
            file,
            path,
            hasher: blake3::Hasher::new(),
            len: 0,
            bucket: bucket.to_string(),
            key: key.to_string(),
            metadata,
            mode,
            spooled: self.spooled.clone(),
            reserved: size,
            #[cfg(test)]
            fail_head_write: false,
        };
        // The record starts with the data length: it is known only at the end, so it goes at
        // offset 0 then.
        spool.file.write_all(&0u64.to_le_bytes()).await?;
        Ok(spool)
    }

    /// Writes one piece of the body. The spool counts against the buffer limit as it grows.
    pub async fn spool_write(&self, spool: &mut PutSpool, piece: &[u8]) -> Result<()> {
        let size = spool.len + piece.len() as u64;
        let largest = self.max_object_size();
        if size > largest {
            return Err(EngineError::ObjectTooLarge {
                size,
                limit: largest,
            });
        }
        // Only the bytes past the room taken at the start count again.
        let extra = size.saturating_sub(spool.counted());
        let limit = self.config.buffer_limit;
        {
            let buffer = self.buffer.lock().await;
            if buffer.bytes() + self.spooled.load(Ordering::SeqCst) + extra > limit {
                return Err(EngineError::BufferFull { limit });
            }
            self.spooled.fetch_add(extra, Ordering::SeqCst);
        }
        if let Err(e) = spool.file.write_all(piece).await {
            self.spooled.fetch_sub(extra, Ordering::SeqCst);
            return Err(e.into());
        }
        spool.hasher.update(piece);
        spool.len = size;
        Ok(())
    }

    /// Commits a spooled put, and returns once it survives a crash of this proxy.
    pub async fn finish_put(&self, mut spool: PutSpool) -> Result<ObjectInfo> {
        // The data length goes at offset 0. Then the data is durable before any head exists.
        spool.file.seek(std::io::SeekFrom::Start(0)).await?;
        spool.file.write_all(&spool.len.to_le_bytes()).await?;
        spool.file.flush().await?;
        spool.file.sync_data().await?;
        crate::sim::crash_point(crate::sim::Point::SpoolData)?;

        let content_hash = *spool.hasher.finalize().as_bytes();
        let policy = self.config.policy(&spool.bucket, &spool.key);
        let create_only = spool.mode == WriteMode::CreateOnly || policy.create_only;
        let (bucket, key, mode) = (&spool.bucket, &spool.key, &spool.mode);
        let mut buffer = self
            .retry_after_sync(|| self.lock_for_put(bucket, key, mode, create_only))
            .await?;
        self.check_writes()?;

        let time = self.tick()?;
        let head = Head {
            time,
            op: Op::Put {
                bucket: spool.bucket.clone(),
                key: spool.key.clone(),
                metadata: spool.metadata.clone(),
                content_hash,
            },
        };
        #[cfg(test)]
        if spool.fail_head_write {
            // A read-only handle fails the next write in the background, as a full disk does.
            spool.file = tokio::fs::File::open(&spool.path).await?;
        }
        spool.file.seek(std::io::SeekFrom::End(0)).await?;
        spool.file.write_all(&encode_head(&head)).await?;
        // A tokio file drops a failed background write on sync: only flush returns it.
        spool.file.flush().await?;
        spool.file.sync_data().await?;
        crate::sim::crash_point(crate::sim::Point::SpoolHead)?;

        let len = spool.len;
        buffer.adopt(&mut spool.path, &head, len).await?;
        // The bytes count in the segments of the buffer.
        let counted = spool.counted();
        spool.len = 0;
        spool.reserved = 0;
        self.spooled.fetch_sub(counted, Ordering::SeqCst);
        self.wake_flusher_when_full(&buffer);
        drop(buffer);
        crate::sim::crash_point(crate::sim::Point::SpoolAck)?;

        Ok(ObjectInfo {
            key: spool.key.clone(),
            size: len,
            content_hash,
            metadata: spool.metadata.clone(),
            last_modified: time,
            conflicted: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use remote::MemoryRemote;

    use super::*;

    /// A client that goes away drops the commit of its put at any await point. A dropped commit
    /// either leaves no record or a record that the buffer tracks: after a flush, a reopen finds
    /// nothing buffered, so no record waits for the late limit.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_dropped_commit_leaves_no_record_that_the_buffer_does_not_track() {
        let dir = tempfile::tempdir().unwrap();
        let remote = Arc::new(MemoryRemote::default());
        let open = || async {
            Engine::open(
                dir.path(),
                remote.clone(),
                SigningKey::from_bytes(&[3; 32]),
                crate::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
                Config::default(),
            )
            .await
            .unwrap()
        };
        let engine = open().await;
        engine.create_bucket("demo", None).await.unwrap();

        for n in 0..80u32 {
            let key = format!("k{n}");
            let mut spool = engine
                .begin_put_sized("demo", &key, BTreeMap::new(), WriteMode::Overwrite, 4)
                .await
                .unwrap();
            engine.spool_write(&mut spool, b"data").await.unwrap();
            let mut commit = std::pin::pin!(engine.finish_put(spool));
            for _ in 0..n {
                let done = std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(commit.as_mut().poll(cx).is_ready())
                })
                .await;
                if done {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        engine.flush().await.unwrap();
        drop(engine);
        let spool_dir = dir.path().join(crate::BUFFER_DIR).join(SPOOL_DIR);
        let left: Vec<_> = std::fs::read_dir(&spool_dir).unwrap().collect();
        assert!(left.is_empty(), "spool files that nothing tracks: {left:?}");

        let reopened = open().await;
        assert_eq!(reopened.buffered_bytes().await, 0);
    }

    /// After its rename, a spooled record is durable only once the directory is fsynced. A commit
    /// dropped in between leaves that fsync to the next reader, which must not see the record
    /// first.
    #[tokio::test]
    async fn test_record_of_a_commit_dropped_before_its_directory_fsync_waits_for_one() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            dir.path(),
            Arc::new(MemoryRemote::default()),
            SigningKey::from_bytes(&[3; 32]),
            crate::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
            Config::default(),
        )
        .await
        .unwrap();
        engine.create_bucket("demo", None).await.unwrap();
        let mut spool = engine
            .begin_put_sized("demo", "k", BTreeMap::new(), WriteMode::Overwrite, 4)
            .await
            .unwrap();
        engine.spool_write(&mut spool, b"data").await.unwrap();
        engine.buffer.lock().await.stall_dir_sync = true;

        let commit = tokio::time::timeout(Duration::from_millis(200), engine.finish_put(spool));
        assert!(commit.await.is_err(), "the commit passed its stall");
        let pending = engine.buffer.lock().await.pending();
        let syncs = engine.buffer.lock().await.syncs;
        engine.buffer.lock().await.stall_dir_sync = false;
        let read = engine.get("demo", "k", None).await;

        assert!(pending.is_some(), "a reader sees the record with no fsync");
        assert_eq!(read.unwrap().data, Bytes::from_static(b"data"));
        let buffer = engine.buffer.lock().await;
        assert!(buffer.syncs > syncs);
        assert_eq!(buffer.pending(), None);
        assert!(!buffer.dir_unsynced(), "no directory fsync");
    }

    #[tokio::test]
    async fn test_put_whose_head_write_fails_gets_no_ack() {
        let dir = tempfile::tempdir().unwrap();
        let open = || async {
            Engine::open(
                dir.path(),
                Arc::new(MemoryRemote::default()),
                SigningKey::from_bytes(&[3; 32]),
                crate::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
                Config::default(),
            )
            .await
            .unwrap()
        };
        let engine = open().await;
        engine.create_bucket("demo", None).await.unwrap();
        let mut spool = engine
            .begin_put_sized("demo", "k", BTreeMap::new(), WriteMode::Overwrite, 4)
            .await
            .unwrap();
        engine.spool_write(&mut spool, b"data").await.unwrap();
        spool.fail_head_write = true;

        let finished = engine.finish_put(spool).await;

        assert!(finished.is_err(), "a put with no head got an ack");
        assert!(engine.get("demo", "k", None).await.is_err());
        let later = engine
            .put(
                "demo",
                "j",
                Bytes::from_static(b"x"),
                BTreeMap::new(),
                WriteMode::Overwrite,
            )
            .await;
        assert!(later.is_ok(), "{later:?}");
    }
}
