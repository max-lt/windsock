//! The flush: plan packs, upload them, commit one journal entry for the batch.

use chunking::{Cuts, OwnedChunk, StreamChunker};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::*;
use crate::buffer::Read;
use crate::plan::OpenObject;

/// Upper bound on the buffered data that one journal entry covers.
const SEGMENTS_PER_ENTRY: usize = 16;

/// Commits that lose the seq to another process before a flush gives up.
const MAX_COMMIT_ATTEMPTS: u32 = 8;

/// The pause of the flusher after a header check fails.
const HEADER_FULL_PAUSE: Duration = Duration::from_secs(60);

#[derive(PartialEq)]
pub(crate) enum Flushed {
    Committed,
    /// The actions are over `max_entry_actions`: flush fewer segments. Nothing is committed.
    TooLarge,
}

/// A flushed record, in buffer order.
enum Planned {
    /// The n-th object given to the planner.
    Put {
        bucket: String,
        key: String,
        object: usize,
        hlc: u64,
    },
    Other(Action),
}

impl<R: Remote + 'static> Engine<R> {
    /// Uploads every buffered write and commits it to the journal.
    pub async fn flush(&self) -> Result<()> {
        let _flushing = self.flushing.lock().await;
        self.check_clock()?;
        self.recover().await?;

        let sealed = self.buffer.lock().await.seal().await?;

        for batch in sealed.chunks(SEGMENTS_PER_ENTRY) {
            let mut todo = vec![batch.to_vec()];
            while let Some(segments) = todo.pop() {
                if self.flush_segments(&segments).await? == Flushed::TooLarge {
                    let (first, rest) = segments.split_at(segments.len() / 2);
                    todo.push(rest.to_vec());
                    todo.push(first.to_vec());
                }
            }
        }

        Ok(())
    }

    /// Flushes at once, then every `flush_delay`, or sooner once a pack worth of data is buffered.
    pub fn spawn_flusher(self: &Arc<Self>) -> JoinHandle<()> {
        let engine = Arc::clone(self);

        tokio::spawn(async move {
            loop {
                // A quarantine needs a restart: a retry would only fail again.
                if engine.is_quarantined() {
                    error!("buffered writes older than the late limit: the flusher stops");
                    return;
                }
                // The first pass runs at once: writes replayed after a crash do not wait.
                if let Err(e) = engine.flush().await {
                    let header_full =
                        matches!(e, EngineError::Journal(JournalError::HeaderTooLarge { .. }));
                    // check_clock and check_header log their own lines.
                    if !matches!(e, EngineError::ClockAhead { .. }) && !header_full {
                        warn!(%e, "flush failed");
                    }
                    // Without a pause, a full buffer retries on every put while the remote is down.
                    let pause = match header_full {
                        // Only fewer chains can make it pass: no fast retry.
                        true => HEADER_FULL_PAUSE.max(engine.config.flush_delay),
                        false => engine.config.flush_delay,
                    };
                    tokio::time::sleep(pause).await;
                }

                tokio::select! {
                    () = tokio::time::sleep(engine.config.flush_delay) => {}
                    () = engine.flush_wanted.notified() => {}
                }
            }
        })
    }

    /// Pass 2 of a put: reads its data `(segment, offset, length)` again in pieces, cuts it into
    /// chunks, places them, and uploads each pack as it fills. The memory is one pack target and
    /// one piece, not the object. Returns the blake3 hash of the data that it read.
    async fn plan_data(
        &self,
        planner: &mut Planner,
        mut object: OpenObject,
        (path, offset, len): (&Path, u64, u64),
        policy: Policy,
        dedup: bool,
    ) -> Result<[u8; 32]> {
        let mut file = tokio::fs::File::open(path).await?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let cuts = match policy.chunking {
            Chunking::ContentDefined => Cuts::ContentDefined,
            Chunking::Fixed => Cuts::Fixed,
        };
        let mut chunker = StreamChunker::new(self.keys.clone(), cuts);
        let mut hasher = blake3::Hasher::new();
        let mut piece = vec![0u8; len.min(buffer::READ_PIECE) as usize];
        let mut left = len;
        while left > 0 {
            let size = left.min(buffer::READ_PIECE) as usize;
            file.read_exact(&mut piece[..size]).await?;
            hasher.update(&piece[..size]);
            left -= size as u64;
            for chunk in chunker.push(&piece[..size]) {
                self.plan_chunk(planner, &mut object, chunk, policy, dedup)
                    .await?;
            }
        }
        for chunk in chunker.finish() {
            self.plan_chunk(planner, &mut object, chunk, policy, dedup)
                .await?;
        }
        if let Some(pack) = planner.end(object) {
            self.upload_packs(vec![pack]).await?;
        }
        Ok(*hasher.finalize().as_bytes())
    }

    async fn plan_chunk(
        &self,
        planner: &mut Planner,
        object: &mut OpenObject,
        chunk: OwnedChunk,
        policy: Policy,
        dedup: bool,
    ) -> Result<()> {
        let view = chunking::Chunk {
            id: chunk.id,
            offset: chunk.offset,
            data: &chunk.data,
        };
        let full = planner.add_chunk(object, view, |id| {
            if !dedup {
                return Ok(None);
            }
            let stored = self.stored_chunk(id);
            if let Ok(Some(_)) = &stored {
                crate::sim::count_dedup();
            }
            stored
        })?;
        if let Some(pack) = full {
            self.upload_packs(vec![pack]).await?;
        }
        if policy.cache == CacheMode::ReadWrite
            && let Some(cache) = &self.cache
        {
            crate::read::keep(cache, chunk.id, &chunk.data).await;
        }
        Ok(())
    }

    /// The commit refuses a header over MAX_HEADER after the uploads: check it before them. One
    /// ERROR per streak.
    async fn check_header(&self) -> Result<()> {
        let seen = self.index().seen(self.node)?;
        let Err(e) = self.journal.lock().await.check_header(&seen) else {
            self.header_full.store(false, Ordering::SeqCst);
            return Ok(());
        };
        if !self.header_full.swap(true, Ordering::SeqCst) {
            error!(
                %e,
                chains = seen.len(),
                "the next journal entry cannot list every other chain: no flush and no upload"
            );
        }
        Err(e.into())
    }

    /// A put whose data does not match its head: no pack of it and no log entry. One ERROR per
    /// streak; the flusher stops until a restart moves it to the quarantine, and writes go on.
    fn bad_data_found(&self, target: &str) -> EngineError {
        if !self.bad_data.swap(true, Ordering::SeqCst) {
            error!(
                key = target,
                "buffered data does not match its head: no flush until a restart moves it to \
                 quarantine"
            );
        }
        EngineError::Corrupt(format!(
            "{target}: its buffered data does not match its head. No flush until a restart \
             moves it to the quarantine"
        ))
    }

    /// Finishes the commit of a flush that a crash or an error interrupted.
    /// GC rule 2: an old plan is only looked for in the remote, never written.
    pub(crate) async fn recover(&self) -> Result<()> {
        let Some(intent) = buffer::read_intent(&self.buffer_dir).await? else {
            return Ok(());
        };
        // The signature covers the sealed actions only: apply what they hold, not the clear copy.
        let entry = Entry::from_wire(&intent.entry.to_wire(), self.keys.sealer()).map_err(|e| {
            EngineError::Corrupt(format!(
                "{}: the entry does not open: {e:?}",
                self.buffer_dir.join("intent").display()
            ))
        })?;
        if entry.actions != intent.entry.actions {
            warn!(
                seq = entry.seq,
                "the clear actions of the intent differ: applied the sealed ones"
            );
        }

        let mut journal = self.journal.lock().await;
        // The entry was prepared before a crash: its acks are older now than at the prepare.
        if !journal.is_written(&intent.entry).await? {
            self.refuse_late(&entry, buffer::unix_nanos().max(entry.hlc))?;
        }
        // An intent of an earlier process has a plan of unknown age: look it up, never commit it.
        let ours = *self
            .own_plan
            .lock()
            .expect("no panic while the lock is held");
        let ours = ours.filter(|plan| plan.mono() == intent.planned_at);
        let written = if ours.is_none_or(|plan| self.plan_is_stale(plan)) {
            journal.is_written(&intent.entry).await?
        } else {
            journal.commit(&intent.entry).await? == Commit::Written
        };

        if written {
            info!(seq = entry.seq, "recovered an interrupted flush");
            self.apply_own(&mut journal, entry).await?;
            self.buffer.lock().await.release(&intent.segments).await?;
        } else {
            warn!(
                seq = intent.entry.seq,
                "interrupted flush is not in the remote: flushing again"
            );
        }

        buffer::remove_intent(&self.buffer_dir).await
    }

    pub(crate) async fn flush_segments(&self, segments: &[u64]) -> Result<Flushed> {
        // A late record stops the flush before any plan or upload: it can never commit.
        let now = self.clock.last().max(buffer::unix_nanos());
        let limit = now.saturating_sub(self.config.late_limit().as_nanos() as u64);
        let late = {
            let buffer = self.buffer.lock().await;
            match buffer.oldest_in(segments) {
                Some(oldest) if oldest < limit => Some(buffer.late_targets(limit).join(", ")),
                _ => None,
            }
        };
        if let Some(keys) = late {
            self.quarantined.store(true, Ordering::SeqCst);
            error!(keys, "buffered writes older than the late limit: no flush");
            return Err(EngineError::Quarantined(format!(
                "{keys}. Restart the proxy to move them to quarantine"
            )));
        }
        let dedup = self.ensure_fresh_sync().await?;
        self.check_header().await?;
        // A local elapsed time: a wall clock step must not make an old plan look young.
        let planned_at = Stamp::now();
        let seed = blake3::Hasher::new()
            .update(self.node.as_bytes())
            .update(&buffer::unix_nanos().to_le_bytes())
            .finalize();
        let nonces = Nonces::new(*seed.as_bytes());
        let mut planner = Planner::new(
            self.config.pack_target,
            self.config.own_pack_threshold,
            nonces,
            self.keys.clone(),
        );
        let mut planned = Vec::new();
        let mut objects = 0;

        for &seq in segments {
            let path = buffer::segment_path(&self.buffer_dir, seq);
            crate::sim::crash_point(crate::sim::Point::SegmentRead)?;
            let mut reader = SegmentReader::open(&path).await?;

            loop {
                let record = match reader.read().await? {
                    Read::Record(record) => record,
                    Read::End => break,
                    // Pass 1: the reader hashed the data against its head. No pack of it goes up.
                    Read::BadData(record) => {
                        return Err(self.bad_data_found(&record.head.op.target()));
                    }
                    Read::BadHead { start, .. } => {
                        return Err(EngineError::Corrupt(format!(
                            "{}: invalid record at offset {start}",
                            path.display()
                        )));
                    }
                };
                let (data_offset, data_len) = (record.data_offset, record.data_len);
                let next = match record.head.op {
                    Op::Put {
                        bucket,
                        key,
                        metadata,
                        content_hash,
                    } => {
                        crate::sim::action_point(crate::sim::Point::FlushVerified);
                        let target = format!("{bucket}/{key}");
                        let policy = self.config.policy(&bucket, &key);
                        let object = planner.begin(data_len, content_hash, metadata, policy);
                        let data = (path.as_path(), data_offset, data_len);
                        let hash = self
                            .plan_data(&mut planner, object, data, policy, dedup)
                            .await?;
                        // Pass 2 hashed what it planned: a change since pass 1 gets no log entry.
                        if hash != content_hash {
                            return Err(self.bad_data_found(&target));
                        }
                        objects += 1;
                        Planned::Put {
                            bucket,
                            key,
                            object: objects - 1,
                            hlc: record.head.time,
                        }
                    }
                    Op::Delete { bucket, key } => Planned::Other(Action::Delete {
                        bucket,
                        key,
                        hlc: record.head.time,
                    }),
                    Op::CreateBucket { bucket, owner } => Planned::Other(Action::CreateBucket {
                        bucket,
                        owner,
                        hlc: record.head.time,
                    }),
                    Op::DeleteBucket { bucket } => Planned::Other(Action::DeleteBucket {
                        bucket,
                        hlc: record.head.time,
                    }),
                };
                planned.push(next);
            }
        }

        let (last, manifests) = planner.finish();
        crate::sim::crash_point(crate::sim::Point::Plan)?;
        self.upload_packs(last.into_iter().collect()).await?;
        crate::sim::crash_point(crate::sim::Point::PackUpload)?;

        let mut actions = Vec::with_capacity(planned.len());
        for next in planned {
            actions.push(match next {
                Planned::Put {
                    bucket,
                    key,
                    object,
                    hlc,
                } => {
                    self.manifest_action(bucket, key, &manifests[object], hlc)
                        .await?
                }
                Planned::Other(action) => action,
            });
        }

        let size = postcard::to_allocvec(&actions)
            .expect("actions always serialize")
            .len() as u64;
        if size > self.config.max_entry_actions && segments.len() > 1 {
            debug!(
                size,
                segments = segments.len(),
                "entry too large: split the segments"
            );
            return Ok(Flushed::TooLarge);
        }

        let mut journal = self.journal.lock().await;
        let entry = self
            .commit(&mut journal, actions, segments, planned_at)
            .await?;
        debug!(seq = entry.seq, segments = segments.len(), "flushed");
        crate::sim::crash_point(crate::sim::Point::Commit)?;
        self.apply_own(&mut journal, entry).await?;
        crate::sim::crash_point(crate::sim::Point::Apply)?;
        drop(journal);

        self.buffer.lock().await.release(segments).await?;
        crate::sim::crash_point(crate::sim::Point::Release)?;
        buffer::remove_intent(&self.buffer_dir).await?;
        Ok(Flushed::Committed)
    }

    pub(crate) fn stored_chunk(&self, id: ChunkId) -> Result<Option<ChunkRef>> {
        Ok(self.index().chunk(id)?.map(|location| ChunkRef {
            pack: location.pack,
            entry: location.entry,
        }))
    }

    pub(crate) async fn upload_packs(&self, packs: Vec<Pack>) -> Result<()> {
        for pack in packs {
            debug!(pack = %pack.id, bytes = pack.bytes.len(), "uploading pack");
            self.remote
                .put(&pack_key(pack.id), Bytes::from(pack.bytes))
                .await?;
        }

        Ok(())
    }

    /// The put action of a manifest. A large manifest goes to the remote first.
    pub(crate) async fn manifest_action(
        &self,
        bucket: String,
        key: String,
        manifest: &Manifest,
        hlc: u64,
    ) -> Result<Action> {
        let bytes = manifest.encode();
        let manifest_id = manifest_id(&bytes);

        let inline_manifest = if bytes.len() <= INLINE_MAX {
            Some(bytes)
        } else {
            let sealed =
                self.keys
                    .sealer()
                    .seal(seal::Kind::Manifest, manifest_id.as_bytes(), &bytes);
            self.remote
                .put(&manifest_key(manifest_id), Bytes::from(sealed))
                .await?;
            self.index().put_manifest(manifest_id, &bytes)?;
            None
        };

        Ok(Action::Put {
            bucket,
            key,
            manifest_id,
            inline_manifest,
            hlc,
        })
    }

    /// Refuses to commit `entry` at HLC `at` when an ack in it is older than the late limit.
    /// A prune can have removed a newer delete of its key, and the commit would bring it back.
    fn refuse_late(&self, entry: &Entry, at: u64) -> Result<()> {
        let oldest = at.saturating_sub(self.config.late_limit().as_nanos() as u64);
        let late: Vec<String> = entry
            .actions
            .iter()
            .flatten()
            .filter(|action| action.hlc().is_some_and(|hlc| hlc < oldest))
            .map(|action| match action {
                Action::Put { bucket, key, .. } | Action::Delete { bucket, key, .. } => {
                    format!("{bucket}/{key}")
                }
                Action::CreateBucket { bucket, .. } | Action::DeleteBucket { bucket, .. } => {
                    bucket.clone()
                }
                Action::Condemn { .. } => String::new(),
            })
            .collect();
        if late.is_empty() {
            return Ok(());
        }
        self.quarantined.store(true, Ordering::SeqCst);
        let keys = late.join(", ");
        error!(
            keys,
            seq = entry.seq,
            "buffered writes older than the late limit: no commit"
        );
        Err(EngineError::Quarantined(format!(
            "{keys}. Restart the proxy to move them to quarantine"
        )))
    }

    /// Writes the intent, then the entry. A crash in between leaves the intent for `recover`.
    pub(crate) async fn commit(
        &self,
        journal: &mut Journal<R>,
        actions: Vec<Action>,
        segments: &[u64],
        planned_at: Stamp,
    ) -> Result<Entry> {
        for _ in 0..MAX_COMMIT_ATTEMPTS {
            // GC rule 2: a dedup decision older than H/2 can name a pack that the GC deleted.
            if self.plan_is_stale(planned_at) {
                return Err(EngineError::StalePlan);
            }

            let seen = self.index().seen(self.node)?;
            let intent = Intent {
                entry: journal.prepare(actions.clone(), seen)?,
                segments: segments.to_vec(),
                planned_at: planned_at.mono(),
            };
            self.refuse_late(&intent.entry, intent.entry.hlc)?;
            *self
                .own_plan
                .lock()
                .expect("no panic while the lock is held") = Some(planned_at);
            buffer::write_intent(&self.buffer_dir, &intent).await?;
            crate::sim::crash_point(crate::sim::Point::Intent)?;

            match journal.commit(&intent.entry).await? {
                Commit::Written => return Ok(intent.entry),
                Commit::SeqTaken => continue,
            }
        }

        Err(EngineError::Contended(MAX_COMMIT_ATTEMPTS))
    }

    /// Applies an own entry, with the own-chain entries the commit read, and
    /// persists the index: the buffer may drop the writes after this.
    pub(crate) async fn apply_own(&self, journal: &mut Journal<R>, entry: Entry) -> Result<()> {
        let mut entries = journal.take_stashed();
        // A pruned copy of the entry can come back from the remote: keep the whole one.
        entries.retain(|stashed| (stashed.node, stashed.seq) != (entry.node, entry.seq));

        // Another process with this identity wrote entries that a prune redacted.
        if entries.iter().any(|stashed| stashed.actions.is_none()) {
            let loaded = self.bootstrap(journal).await;
            if !matches!(loaded, Ok(Ok(()))) {
                self.reset_journal(journal);
            }
            if let Err(none) = loaded? {
                return Err(EngineError::Corrupt(format!("redacted entries and {none}")));
            }
            entries.clear();
        }

        entries.push(entry);

        if let Err(e) = self.ingest(&entries).await {
            // The journal is past these entries and the index never got them: read them again.
            self.reset_journal(journal);
            return Err(e);
        }
        let mut index = self.index();
        index.apply(entries)?;
        index.persist()?;
        Ok(())
    }
}
