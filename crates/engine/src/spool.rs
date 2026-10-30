//! Puts that stream their body: the body goes to a spool file in pieces, and the file becomes a
//! segment of the buffer at the commit. The memory of such a put does not grow with its object.
//!
//! Durability order: the data is fsynced, then the head is written after it and fsynced, then the
//! file is renamed to a segment and the directory is fsynced. Only then the put is acknowledged.
//! A valid head on disk always follows durable data.

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
}

impl PutSpool {
    /// Bytes of the body so far.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for PutSpool {
    fn drop(&mut self) {
        // After the commit the file is a segment: the path no longer exists, and len is 0.
        let _ = std::fs::remove_file(&self.path);
        let len = self.len;
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
            if buffer.bytes() + self.spooled.load(Ordering::SeqCst) >= limit {
                return Err(EngineError::BufferFull { limit });
            }
        }

        let n = SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = self
            .buffer_dir
            .join(SPOOL_DIR)
            .join(format!("{}.{n}", std::process::id()));
        let file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await?;
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
        let limit = self.config.buffer_limit;
        let buffered = self.buffer.lock().await.bytes();
        if buffered + self.spooled.load(Ordering::SeqCst) + piece.len() as u64 > limit {
            return Err(EngineError::BufferFull { limit });
        }
        spool.file.write_all(piece).await?;
        spool.hasher.update(piece);
        spool.len = size;
        self.spooled.fetch_add(piece.len() as u64, Ordering::SeqCst);
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
        spool.file.seek(std::io::SeekFrom::End(0)).await?;
        spool.file.write_all(&encode_head(&head)).await?;
        spool.file.sync_data().await?;
        crate::sim::crash_point(crate::sim::Point::SpoolHead)?;

        let len = spool.len;
        buffer.adopt(&spool.path, &head, len).await?;
        // The bytes now count in the segments of the buffer.
        spool.len = 0;
        self.spooled.fetch_sub(len, Ordering::SeqCst);
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
