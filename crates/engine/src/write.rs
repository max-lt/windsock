//! Puts and deletes: each one is fsynced in the buffer before it is acknowledged.
//! The fsync runs outside the buffer lock. The writes that arrive during an fsync share the next one.

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

        let (info, record) = self
            .retry_after_sync(|| async move {
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
                let record = self.append_at(&mut buffer, time, op, data).await?;

                let info = ObjectInfo {
                    key: key.to_string(),
                    size: data.len() as u64,
                    content_hash,
                    metadata: metadata.clone(),
                    last_modified: time,
                    conflicted: false,
                };
                Ok((info, record))
            })
            .await?;

        self.acknowledge(record).await?;
        Ok(info)
    }

    /// Deletes a key. A missing key is not an error, as in S3.
    pub async fn delete(&self, bucket: &str, key: &str) -> Result<()> {
        check_key(key)?;

        let record = self
            .retry_after_sync(|| async move {
                let mut buffer = self.buffer.lock().await;
                self.require_bucket(&buffer, bucket)?;

                let op = Op::Delete {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                };
                self.append(&mut buffer, op, &[]).await
            })
            .await?;

        self.acknowledge(record).await
    }

    /// Returns when buffer record `record` is on disk.
    pub(crate) async fn acknowledge(&self, record: u64) -> Result<()> {
        match self.wait_durable(record).await? {
            Durability::Durable => Ok(()),
            Durability::Pending | Durability::Lost => Err(EngineError::WriteLost),
        }
    }

    /// Waits for an fsync that covers `record`. Runs the fsync if no other task runs one.
    pub(crate) async fn wait_durable(&self, record: u64) -> Result<Durability> {
        let _one = self.syncing.lock().await;
        let job = {
            let mut buffer = self.buffer.lock().await;
            match buffer.durability(record) {
                Durability::Pending if buffer.is_broken() => return Err(EngineError::BufferBroken),
                Durability::Pending => buffer.sync_job(),
                done => return Ok(done),
            }
        };

        let result = job.run().await;
        let mut buffer = self.buffer.lock().await;
        buffer.finish_sync(job, result).await?;
        Ok(buffer.durability(record))
    }

    /// Appends a record. Returns its number for [`Engine::acknowledge`].
    pub(crate) async fn append(&self, buffer: &mut Buffer, op: Op, data: &[u8]) -> Result<u64> {
        self.append_at(buffer, buffer::unix_nanos(), op, data).await
    }

    pub(crate) async fn append_at(
        &self,
        buffer: &mut Buffer,
        time: u64,
        op: Op,
        data: &[u8],
    ) -> Result<u64> {
        let limit = self.config.buffer_limit;

        if buffer.bytes() + data.len() as u64 > limit {
            return Err(EngineError::BufferFull { limit });
        }

        let record = buffer.append(Head { time, op }, data).await?;

        if buffer.bytes() >= self.config.pack_target as u64 {
            self.flush_wanted.notify_one();
        }

        Ok(record)
    }
}

/// S3 rules: 1 to 1024 bytes of UTF-8.
pub(crate) fn check_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 1024 {
        return Err(EngineError::InvalidKey(key.to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use remote::MemoryRemote;

    use super::*;

    async fn open(dir: &Path) -> Arc<Engine<MemoryRemote>> {
        let engine = Engine::open(
            dir,
            Arc::new(MemoryRemote::default()),
            SigningKey::from_bytes(&[3; 32]),
            Config::default(),
        )
        .await
        .unwrap();
        Arc::new(engine)
    }

    async fn put(engine: &Engine<MemoryRemote>, key: &str, value: &'static [u8]) -> Result<()> {
        let data = Bytes::from_static(value);
        engine
            .put("demo", key, data, BTreeMap::new(), WriteMode::Overwrite)
            .await
            .map(|_| ())
    }

    async fn get(engine: &Engine<MemoryRemote>, key: &str) -> Result<Bytes> {
        engine
            .get("demo", key, None)
            .await
            .map(|object| object.data)
    }

    fn spawn_put(engine: &Arc<Engine<MemoryRemote>>, key: &str) -> JoinHandle<Result<()>> {
        let (engine, key) = (Arc::clone(engine), key.to_string());
        tokio::spawn(async move { put(&engine, &key, b"new").await })
    }

    /// Waits until the buffer holds `last` records. The last records are not on disk yet.
    async fn wait_written(engine: &Engine<MemoryRemote>, last: u64) {
        for _ in 0..500 {
            if engine.buffer.lock().await.pending() == Some(last) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the writes did not reach the buffer");
    }

    async fn syncs(engine: &Engine<MemoryRemote>) -> u64 {
        engine.buffer.lock().await.syncs
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_a_lone_write_takes_one_fsync_and_waits_for_no_other() {
        let dir = tempfile::tempdir().unwrap();
        let engine = open(dir.path()).await;
        engine.create_bucket("demo", None).await.unwrap();
        let before = syncs(&engine).await;

        put(&engine, "k", b"v").await.unwrap();

        assert_eq!(syncs(&engine).await, before + 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_writes_that_wait_during_an_fsync_share_the_next_one() {
        let dir = tempfile::tempdir().unwrap();
        let engine = open(dir.path()).await;
        engine.create_bucket("demo", None).await.unwrap();
        let before = syncs(&engine).await;

        let running = engine.syncing.lock().await;
        let puts: Vec<_> = (0..8)
            .map(|i| spawn_put(&engine, &format!("k{i}")))
            .collect();
        wait_written(&engine, 9).await;
        drop(running);

        for put in puts {
            put.await.unwrap().unwrap();
        }
        assert_eq!(syncs(&engine).await, before + 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_put_is_not_acknowledged_before_its_fsync() {
        let dir = tempfile::tempdir().unwrap();
        let engine = open(dir.path()).await;
        engine.create_bucket("demo", None).await.unwrap();

        let running = engine.syncing.lock().await;
        let put = spawn_put(&engine, "k");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!put.is_finished());

        drop(running);
        put.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_read_waits_for_the_fsync_of_a_write_it_can_see() {
        let dir = tempfile::tempdir().unwrap();
        let engine = open(dir.path()).await;
        engine.create_bucket("demo", None).await.unwrap();
        put(&engine, "k", b"old").await.unwrap();

        let running = engine.syncing.lock().await;
        let put = spawn_put(&engine, "k");
        wait_written(&engine, 3).await;
        let reader = Arc::clone(&engine);
        let read = tokio::spawn(async move { get(&reader, "k").await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !read.is_finished(),
            "the read saw a write that is not on disk"
        );

        drop(running);
        put.await.unwrap().unwrap();
        assert_eq!(read.await.unwrap().unwrap(), Bytes::from_static(b"new"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_failed_fsync_loses_only_the_writes_it_covers() {
        let dir = tempfile::tempdir().unwrap();
        let engine = open(dir.path()).await;
        engine.create_bucket("demo", None).await.unwrap();
        put(&engine, "a", b"a").await.unwrap();

        engine.buffer.lock().await.fail_next_sync = true;
        let running = engine.syncing.lock().await;
        let lost = [spawn_put(&engine, "b"), spawn_put(&engine, "c")];
        wait_written(&engine, 4).await;
        drop(running);

        for put in lost {
            assert!(matches!(put.await.unwrap(), Err(EngineError::WriteLost)));
        }
        assert!(matches!(
            get(&engine, "b").await,
            Err(EngineError::NoSuchKey { .. })
        ));
        put(&engine, "d", b"d").await.unwrap();

        drop(engine);
        let reopened = open(dir.path()).await;
        assert_eq!(get(&reopened, "a").await.unwrap(), Bytes::from_static(b"a"));
        assert_eq!(get(&reopened, "d").await.unwrap(), Bytes::from_static(b"d"));
        for key in ["b", "c"] {
            assert!(matches!(
                get(&reopened, key).await,
                Err(EngineError::NoSuchKey { .. })
            ));
        }
    }
}
