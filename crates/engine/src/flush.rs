//! The flush: plan packs, upload them, commit one journal entry for the batch.

use super::*;

/// Upper bound on the buffered data that one journal entry covers.
const SEGMENTS_PER_ENTRY: usize = 16;

/// Commits that lose the seq to another process before a flush gives up.
const MAX_COMMIT_ATTEMPTS: u32 = 8;

/// A flushed record, in buffer order.
enum Planned {
    /// The n-th object given to the planner.
    Put {
        bucket: String,
        key: String,
        object: usize,
    },
    Other(Action),
}

impl<R: Remote + 'static> Engine<R> {
    /// Uploads every buffered write and commits it to the journal.
    pub async fn flush(&self) -> Result<()> {
        let _flushing = self.flushing.lock().await;
        self.recover().await?;

        let sealed = self.buffer.lock().await.seal().await?;

        for batch in sealed.chunks(SEGMENTS_PER_ENTRY) {
            self.flush_segments(batch).await?;
        }

        Ok(())
    }

    /// Flushes at once, then every `flush_delay`, or sooner once a pack worth of data is buffered.
    pub fn spawn_flusher(self: &Arc<Self>) -> JoinHandle<()> {
        let engine = Arc::clone(self);

        tokio::spawn(async move {
            loop {
                // The first pass runs at once: writes replayed after a crash do not wait.
                if let Err(e) = engine.flush().await {
                    warn!(%e, "flush failed");
                    // Without a pause, a full buffer retries on every put while the remote is down.
                    tokio::time::sleep(engine.config.flush_delay).await;
                }

                tokio::select! {
                    () = tokio::time::sleep(engine.config.flush_delay) => {}
                    () = engine.flush_wanted.notified() => {}
                }
            }
        })
    }

    /// Finishes the commit of a flush that a crash or an error interrupted.
    /// GC rule 2: an old plan is only looked for in the remote, never written.
    pub(crate) async fn recover(&self) -> Result<()> {
        let Some(intent) = buffer::read_intent(&self.buffer_dir).await? else {
            return Ok(());
        };

        let mut journal = self.journal.lock().await;
        let written = if self.plan_is_stale(intent.planned_at) {
            journal.is_written(&intent.entry).await?
        } else {
            journal.commit(&intent.entry).await? == Commit::Written
        };

        if written {
            info!(seq = intent.entry.seq, "recovered an interrupted flush");
            self.apply_own(&mut journal, intent.entry).await?;
            self.buffer.lock().await.release(&intent.segments).await?;
        } else {
            warn!(
                seq = intent.entry.seq,
                "interrupted flush is not in the remote: flushing again"
            );
        }

        buffer::remove_intent(&self.buffer_dir).await
    }

    pub(crate) async fn flush_segments(&self, segments: &[u64]) -> Result<()> {
        let dedup = self.ensure_fresh_sync().await?;
        let planned_at = buffer::unix_nanos();
        let seed = blake3::Hasher::new()
            .update(self.node.as_bytes())
            .update(&buffer::unix_nanos().to_le_bytes())
            .finalize();
        let nonces = Nonces::new(*seed.as_bytes());
        let mut planner = Planner::new(
            self.config.pack_target,
            self.config.own_pack_threshold,
            nonces,
        );
        let mut planned = Vec::new();
        let mut objects = 0;

        for &seq in segments {
            let path = buffer::segment_path(&self.buffer_dir, seq);
            let mut reader = SegmentReader::open(&path).await?;

            while let Some(record) = reader.next(&path).await? {
                let next = match record.head.op {
                    Op::Put {
                        bucket,
                        key,
                        metadata,
                        content_hash,
                    } => {
                        let policy = self.config.policy(&bucket, &key);
                        let added =
                            planner.add(&record.data, content_hash, metadata, policy, |id| {
                                if !dedup {
                                    return Ok(None);
                                }
                                self.stored_chunk(id)
                            })?;
                        self.upload_packs(added.closed).await?;
                        if policy.cache == CacheMode::ReadWrite {
                            self.cache_written(&record.data, &added.chunks).await;
                        }
                        objects += 1;
                        Planned::Put {
                            bucket,
                            key,
                            object: objects - 1,
                        }
                    }
                    Op::Delete { bucket, key } => Planned::Other(Action::Delete { bucket, key }),
                    Op::CreateBucket { bucket, owner } => {
                        Planned::Other(Action::CreateBucket { bucket, owner })
                    }
                    Op::DeleteBucket { bucket } => Planned::Other(Action::DeleteBucket { bucket }),
                };
                planned.push(next);
            }
        }

        let (last, manifests) = planner.finish();
        self.upload_packs(last.into_iter().collect()).await?;

        let mut actions = Vec::with_capacity(planned.len());
        for next in planned {
            actions.push(match next {
                Planned::Put {
                    bucket,
                    key,
                    object,
                } => {
                    self.manifest_action(bucket, key, &manifests[object])
                        .await?
                }
                Planned::Other(action) => action,
            });
        }

        let mut journal = self.journal.lock().await;
        let entry = self
            .commit(&mut journal, actions, segments, planned_at)
            .await?;
        debug!(seq = entry.seq, segments = segments.len(), "flushed");
        self.apply_own(&mut journal, entry).await?;
        drop(journal);

        self.buffer.lock().await.release(segments).await?;
        buffer::remove_intent(&self.buffer_dir).await
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
    ) -> Result<Action> {
        let bytes = manifest.encode();
        let manifest_id = manifest_id(&bytes);

        let inline_manifest = if bytes.len() <= INLINE_MAX {
            Some(bytes)
        } else {
            self.remote
                .put(&manifest_key(manifest_id), Bytes::from(bytes.clone()))
                .await?;
            self.index().put_manifest(manifest_id, &bytes)?;
            None
        };

        Ok(Action::Put {
            bucket,
            key,
            manifest_id,
            inline_manifest,
        })
    }

    /// Writes the intent, then the entry. A crash in between leaves the intent for `recover`.
    pub(crate) async fn commit(
        &self,
        journal: &mut Journal<R>,
        actions: Vec<Action>,
        segments: &[u64],
        planned_at: u64,
    ) -> Result<Entry> {
        for _ in 0..MAX_COMMIT_ATTEMPTS {
            // GC rule 2: a dedup decision older than H/2 can name a pack that the GC deleted.
            if self.plan_is_stale(planned_at) {
                return Err(EngineError::StalePlan);
            }

            let seen = self.index().seen(self.node)?;
            let intent = Intent {
                entry: journal.prepare(actions.clone(), seen),
                segments: segments.to_vec(),
                planned_at,
            };
            buffer::write_intent(&self.buffer_dir, &intent).await?;

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
            if !self.bootstrap(journal).await? {
                return Err(EngineError::Corrupt(
                    "redacted entries and no snapshot".to_string(),
                ));
            }
            entries.clear();
        }

        entries.push(entry);

        self.ingest(&entries).await?;
        let mut index = self.index();
        index.apply(entries)?;
        index.persist()?;
        Ok(())
    }
}
