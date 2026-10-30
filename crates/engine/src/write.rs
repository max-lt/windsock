//! Puts and deletes: each one is fsynced in the buffer before it is acknowledged.
//! The fsync runs outside the buffer lock. The writes that arrive during an fsync share the next one.

use super::*;

/// A conditional put reads a missing manifest at most this many times, then fails with 412: the
/// version changes under it each time.
const MATCH_ATTEMPTS: usize = 3;

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
        // Before the hash: an object that the buffer refuses costs no work.
        let limit = self.max_object_size();
        if data.len() as u64 > limit {
            return Err(EngineError::ObjectTooLarge {
                size: data.len() as u64,
                limit,
            });
        }
        let policy = self.config.policy(bucket, key);
        let create_only = mode == WriteMode::CreateOnly || policy.create_only;
        let content_hash = *blake3::hash(&data).as_bytes();
        let (data, metadata, mode) = (&data, &metadata, &mode);

        let (info, record) = self
            .retry_after_sync(|| async move {
                let mut buffer = self.lock_for_put(bucket, key, mode, create_only).await?;
                let time = self.tick()?;
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

        crate::sim::crash_point(crate::sim::Point::Appended)?;
        self.acknowledge(record).await?;
        Ok(info)
    }

    /// The buffer, locked, once the current object passes the check of `mode`. The check and the
    /// write that follows are one step on this proxy.
    pub(crate) async fn lock_for_put(
        &self,
        bucket: &str,
        key: &str,
        mode: &WriteMode,
        create_only: bool,
    ) -> Result<tokio::sync::MutexGuard<'_, Buffer>> {
        let mut attempts = 0;
        loop {
            let buffer = self.buffer.lock().await;
            self.require_bucket(&buffer, bucket)?;

            let current = self.current(&buffer, bucket, key)?;
            let needs_object = matches!(mode, WriteMode::IfExists | WriteMode::IfMatch(_));
            if needs_object && !current.exists() {
                return Err(read::no_such_key(bucket, key));
            }
            let allowed = match mode {
                _ if create_only => !current.exists(),
                WriteMode::IfExists => true,
                WriteMode::IfMatch(hashes) => match self.local_content_hash(&current)? {
                    Some(hash) => hashes.contains(&hash),
                    // A remote read under the buffer lock would hold every write.
                    None if attempts < MATCH_ATTEMPTS => {
                        drop(buffer);
                        attempts += 1;
                        self.content_hash(current).await?;
                        continue;
                    }
                    None => false,
                },
                WriteMode::Overwrite | WriteMode::CreateOnly => true,
            };
            if !allowed {
                return Err(EngineError::PreconditionFailed {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }
            return Ok(buffer);
        }
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

    /// Refuses every write from now on. A write that holds the buffer lock still lands.
    pub fn drain(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    /// The largest object that a put takes: the buffer limit, or 5 GiB.
    pub fn max_object_size(&self) -> u64 {
        self.config.buffer_limit.min(buffer::MAX_DATA_LEN)
    }

    /// The last HLC that this proxy issued or saw. Right after an ack, its HLC.
    pub fn last_hlc(&self) -> u64 {
        self.clock.last()
    }

    /// True when a buffered write is older than the late limit, or its data does not match its
    /// head: no flush until a restart.
    pub fn is_quarantined(&self) -> bool {
        self.quarantined.load(Ordering::SeqCst) || self.bad_data.load(Ordering::SeqCst)
    }

    /// True after [`Engine::drain`]: writes get refused.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// True when the local index refuses every call until a restart, as after a full disk.
    pub fn index_is_poisoned(&self) -> bool {
        self.index().is_poisoned()
    }

    /// Fails while the clock is more than R ahead of the wall clock. A reader refuses an entry
    /// that far ahead, so this proxy takes no write and signs no entry until the wall catches up.
    pub fn check_clock(&self) -> Result<()> {
        let wall = journal::wall_clock_nanos();
        let limit = wall.saturating_add(self.config.retention.as_nanos() as u64);
        let last = self.clock.last();
        if last <= limit {
            if self.clock_ahead.swap(false, Ordering::SeqCst) {
                info!("the wall clock caught up with the clock: writes resume");
            }
            return Ok(());
        }
        let wait_secs = (last - limit).div_ceil(1_000_000_000);
        if !self.clock_ahead.swap(true, Ordering::SeqCst) {
            let (hlc, source) = *self
                .own_high
                .lock()
                .expect("no panic while the lock is held");
            warn!(
                clock = last,
                wall,
                wait_secs,
                own_hlc = hlc,
                source,
                "the clock is more than R ahead of the wall clock: no write and no flush until \
                 the wall catches up"
            );
        }
        Err(EngineError::ClockAhead { wait_secs })
    }

    /// Bytes on the local disk, by use.
    pub async fn local_usage(&self) -> Result<LocalUsage> {
        let index = self.index().disk_bytes()?;
        Ok(LocalUsage {
            index,
            cache: self.cache.as_ref().map_or(0, |cache| cache.bytes()),
            buffer: self.buffered_bytes().await,
        })
    }

    pub fn cache_state(&self) -> CacheState {
        let (limit, bytes) = self
            .cache
            .as_ref()
            .map_or((0, 0), |cache| (cache.limit(), cache.bytes()));
        CacheState {
            limit,
            bytes,
            max: self.config.cache_bytes,
        }
    }

    /// Sets the bound of the chunk cache and evicts the oldest chunks above it. 0 empties the
    /// cache. The bound stays at most `cache_bytes`: the start checked the free disk for that.
    /// A restart goes back to `cache_bytes`.
    pub async fn set_cache_limit(&self, bytes: u64) -> Result<CacheState> {
        let max = self.config.cache_bytes;
        if bytes > max {
            return Err(EngineError::CacheLimit {
                requested: bytes,
                max,
            });
        }
        if let Some(cache) = &self.cache {
            cache.set_limit(bytes).await;
        }
        let state = self.cache_state();
        info!(limit = state.limit, bytes = state.bytes, "cache limit set");
        Ok(state)
    }

    /// Bytes in the buffer that are not in the remote yet.
    pub async fn buffered_bytes(&self) -> u64 {
        self.buffer.lock().await.bytes()
    }

    /// The HLC of a new ack. Fails at the end of the u64 range instead of a wrap to 0.
    pub(crate) fn tick(&self) -> Result<u64> {
        self.clock
            .tick()
            .ok_or(EngineError::Journal(JournalError::ClockOverflow))
    }

    /// Appends a record. Returns its number for [`Engine::acknowledge`].
    pub(crate) async fn append(&self, buffer: &mut Buffer, op: Op, data: &[u8]) -> Result<u64> {
        self.append_at(buffer, self.tick()?, op, data).await
    }

    /// Fails when the buffer takes no write now: a stop, a quarantine, or a clock far ahead.
    pub fn check_writes(&self) -> Result<()> {
        if self.draining.load(Ordering::SeqCst) {
            return Err(EngineError::Draining);
        }
        if self.quarantined.load(Ordering::SeqCst) {
            return Err(EngineError::Quarantined(
                "restart the proxy to move the buffer to quarantine".to_string(),
            ));
        }
        self.check_clock()
    }

    pub(crate) async fn append_at(
        &self,
        buffer: &mut Buffer,
        time: u64,
        op: Op,
        data: &[u8],
    ) -> Result<u64> {
        self.check_writes()?;

        let limit = self.config.buffer_limit;

        // A record that the buffer cannot hold or read back would block the flush for ever.
        let largest = self.max_object_size();
        if data.len() as u64 > largest {
            return Err(EngineError::ObjectTooLarge {
                size: data.len() as u64,
                limit: largest,
            });
        }

        if buffer.bytes() + self.spooled.load(Ordering::SeqCst) + data.len() as u64 > limit {
            return Err(EngineError::BufferFull { limit });
        }

        let record = match buffer.append(Head { time, op }, data).await {
            Ok(record) => record,
            Err(e) => {
                if !self.buffer_failing.swap(true, Ordering::SeqCst) {
                    warn!(%e, "buffer writes fail: writes get 503 until the buffer disk works");
                }
                return Err(e);
            }
        };
        if self.buffer_failing.swap(false, Ordering::SeqCst) {
            info!("buffer writes work again");
        }

        self.wake_flusher_when_full(buffer);
        Ok(record)
    }

    /// A buffer that holds a pack target flushes now, not at the next flush delay.
    pub(crate) fn wake_flusher_when_full(&self, buffer: &Buffer) {
        if buffer.bytes() >= self.config.pack_target as u64 {
            self.flush_wanted.notify_one();
        }
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
            crate::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
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

    /// The late write rule moves a prefix of the buffer: acks must rise in buffer order, also
    /// for parallel puts and across a restart.
    #[tokio::test]
    async fn test_ack_times_rise_in_buffer_order_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let engine = open(dir.path()).await;
        engine.create_bucket("demo", None).await.unwrap();
        let tasks: Vec<_> = (0..20)
            .map(|n| spawn_put(&engine, &format!("k{n}")))
            .collect();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        drop(engine);
        let engine = open(dir.path()).await;
        put(&engine, "after", b"v").await.unwrap();

        let buffer_dir = dir.path().join(crate::BUFFER_DIR);
        let mut times = Vec::new();
        for seq in buffer::segment_seqs(&buffer_dir).await {
            let path = buffer::segment_path(&buffer_dir, seq);
            let mut reader = buffer::SegmentReader::open(&path).await.unwrap();
            while let Some((record, _)) = reader.next_held(&path).await.unwrap() {
                times.push(record.head.time);
            }
        }

        assert_eq!(times.len(), 22);
        assert!(times.windows(2).all(|w| w[0] < w[1]), "{times:?}");
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
