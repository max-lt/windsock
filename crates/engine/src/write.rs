//! Puts and deletes: each one is fsynced in the buffer before it is acknowledged.

use super::*;

impl<R: Remote + 'static> Engine<R> {
    /// Stores an object. Returns once the write survives a crash of this proxy.
    pub async fn put(
        &self,
        bucket: &str,
        key: &str,
        data: Bytes,
        metadata: BTreeMap<String, String>,
        mode: WriteMode,
    ) -> Result<ObjectInfo> {
        check_key(key)?;
        let policy = self.config.policy(bucket, key);
        let create_only = mode == WriteMode::CreateOnly || policy.create_only;
        let content_hash = *blake3::hash(&data).as_bytes();
        let (data, metadata) = (&data, &metadata);

        self.retry_after_sync(|| async move {
            let mut buffer = self.buffer.lock().await;
            self.require_bucket(&buffer, bucket)?;

            if create_only && self.current(&buffer, bucket, key)?.exists() {
                return Err(EngineError::PreconditionFailed {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }

            let time = buffer::unix_nanos();
            let op = Op::Put {
                bucket: bucket.to_string(),
                key: key.to_string(),
                metadata: metadata.clone(),
                content_hash,
            };
            self.append_at(&mut buffer, time, op, data).await?;

            Ok(ObjectInfo {
                key: key.to_string(),
                size: data.len() as u64,
                content_hash,
                metadata: metadata.clone(),
                last_modified: time,
                conflicted: false,
            })
        })
        .await
    }

    /// Deletes a key. A missing key is not an error, as in S3.
    pub async fn delete(&self, bucket: &str, key: &str) -> Result<()> {
        check_key(key)?;

        self.retry_after_sync(|| async move {
            let mut buffer = self.buffer.lock().await;
            self.require_bucket(&buffer, bucket)?;

            let op = Op::Delete {
                bucket: bucket.to_string(),
                key: key.to_string(),
            };
            self.append(&mut buffer, op, &[]).await
        })
        .await
    }

    pub(crate) async fn append(&self, buffer: &mut Buffer, op: Op, data: &[u8]) -> Result<()> {
        self.append_at(buffer, buffer::unix_nanos(), op, data).await
    }

    pub(crate) async fn append_at(
        &self,
        buffer: &mut Buffer,
        time: u64,
        op: Op,
        data: &[u8],
    ) -> Result<()> {
        let limit = self.config.buffer_limit;

        if buffer.bytes() + data.len() as u64 > limit {
            return Err(EngineError::BufferFull { limit });
        }

        buffer.append(Head { time, op }, data).await?;

        if buffer.bytes() >= self.config.pack_target as u64 {
            self.flush_wanted.notify_one();
        }

        Ok(())
    }
}

/// S3 rules: 1 to 1024 bytes of UTF-8.
pub(crate) fn check_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 1024 {
        return Err(EngineError::InvalidKey(key.to_string()));
    }

    Ok(())
}
