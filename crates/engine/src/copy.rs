//! Copies of an object to another key.
//!
//! A copy by reference writes a new manifest of the chunks that the index locates, and commits
//! its entry before the ack: it is a dedup of every chunk, under GC rules 1 and 2. Else the data
//! of the source goes through a spool file, as a streamed put, and takes room in the read budget
//! piece by piece, as a GET.

use std::sync::atomic::AtomicU64;

use super::*;

/// The largest write to the spool of a copy.
const COPY_PIECE: usize = 1024 * 1024;

/// Copies by reference that run at one time.
pub const MAX_REF_COPIES: usize = 4;

/// Past this wait for its sync, a copy takes the spool: no remote write started yet.
const COPY_SYNC_DEADLINE: Duration = Duration::from_secs(10);

/// Chunk lookups in one blocking task, so the lookups of a large object do not hold a worker.
const LOOKUP_BATCH: usize = 4096;

/// Makes the nonces of copies unique inside one process.
static COPY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// How a copy went.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CopyPath {
    /// A new manifest names the stored chunks of the source: no data moves.
    Reference,
    /// The data went through a spool file.
    Spool(SpoolReason),
}

/// Why a copy did not go by reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpoolReason {
    /// `copy_ref_min` is 0.
    Off,
    /// The source is under `copy_ref_min`.
    Small,
    /// The source is in the buffer of this proxy: it has no manifest yet.
    BufferedSource,
    /// The target has a buffered write on this proxy, which a read gives before the index.
    BufferedTarget,
    /// No complete sync younger than H/2: GC rule 1 allows no dedup.
    NoFreshSync,
    /// The sync before the copy failed on the remote or passed its deadline.
    RemoteDown,
    /// A chunk of the source has no location in the index: its pack can be condemned.
    MissingChunk,
    /// The target prefix cuts or compresses its chunks in another way than the source prefix.
    Policy,
}

/// A copy and the way it went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Copied {
    pub info: ObjectInfo,
    pub path: CopyPath,
}

impl<R: Remote + 'static> Engine<R> {
    /// Copies `source` (bucket, key) to `target`. `metadata` replaces the metadata of the source,
    /// and `None` keeps it. With no room in the read budget after `wait`, fails with ReadBudget.
    pub async fn copy(
        &self,
        source: (&str, &str),
        target: (&str, &str),
        metadata: Option<BTreeMap<String, String>>,
        mode: WriteMode,
        wait: Duration,
    ) -> Result<Copied> {
        let reason = match self
            .copy_by_reference(source, target, metadata.clone(), &mode, wait)
            .await?
        {
            Ok(info) => {
                return Ok(Copied {
                    info,
                    path: CopyPath::Reference,
                });
            }
            Err(reason) => reason,
        };
        debug!(?reason, "copy through the spool");
        let info = self
            .copy_by_spool(source, target, metadata, mode, wait)
            .await?;
        Ok(Copied {
            info,
            path: CopyPath::Spool(reason),
        })
    }

    /// The copy by reference, or the reason to take the spool. A reason comes only before the
    /// first remote write: after it, the entry can be in the remote, and a spool copy would
    /// write the object twice.
    async fn copy_by_reference(
        &self,
        source: (&str, &str),
        target: (&str, &str),
        metadata: Option<BTreeMap<String, String>>,
        mode: &WriteMode,
        wait: Duration,
    ) -> Result<std::result::Result<ObjectInfo, SpoolReason>> {
        if self.config.copy_ref_min == 0 {
            return Ok(Err(SpoolReason::Off));
        }
        crate::write::check_key(target.1)?;
        self.check_writes()?;
        let Some(manifest_id) = self.retry_after_sync(|| self.stored_source(source)).await? else {
            return Ok(Err(SpoolReason::BufferedSource));
        };
        // The decoded source is outside the read budget until its room is taken: the slots bound
        // how many copies hold one.
        let _slot = self
            .ref_copies
            .acquire()
            .await
            .expect("the copy slots are never closed");
        let (from, encoded) = self.sized_manifest(manifest_id).await?;
        crate::sim::count_copy_source();
        if from.size < self.config.copy_ref_min {
            return Ok(Err(SpoolReason::Small));
        }
        let limit = self.max_object_size();
        if from.size > limit {
            return Err(EngineError::ObjectTooLarge {
                size: from.size,
                limit,
            });
        }
        let (policy, target_policy) = (
            self.config.policy(source.0, source.1),
            self.config.policy(target.0, target.1),
        );
        if (policy.chunking, policy.compression)
            != (target_policy.chunking, target_policy.compression)
        {
            return Ok(Err(SpoolReason::Policy));
        }
        let metadata = metadata.unwrap_or_else(|| from.metadata.clone());
        buffer::check_head(&Head {
            time: u64::MAX,
            op: Op::Put {
                bucket: target.0.to_string(),
                key: target.1.to_string(),
                metadata: metadata.clone(),
                content_hash: [0; 32],
            },
        })?;

        // At most two manifests in memory, then the new one with its encoding and its sealed form.
        let decoded = (from.chunks.len() * std::mem::size_of::<ChunkRef>()) as u64;
        let _room = self
            .room_for((2 * decoded).max(decoded + 2 * encoded), Some(wait))
            .await?;
        let fresh = match tokio::time::timeout(COPY_SYNC_DEADLINE, self.ensure_fresh_sync()).await {
            Err(_) => return Ok(Err(SpoolReason::RemoteDown)),
            Ok(Err(EngineError::Remote(e) | EngineError::Journal(JournalError::Remote(e)))) => {
                debug!(%e, "the sync before a copy failed");
                return Ok(Err(SpoolReason::RemoteDown));
            }
            Ok(result) => result?,
        };
        if !fresh {
            return Ok(Err(SpoolReason::NoFreshSync));
        }
        self.check_header().await?;
        // GC rule 2 counts from here: the lookups below are the dedup decision.
        let planned_at = Stamp::now();
        let Some(chunks) = self.locate(&from).await? else {
            return Ok(Err(SpoolReason::MissingChunk));
        };

        let create_only = *mode == WriteMode::CreateOnly || target_policy.create_only;
        let Some((time, _in_flight)) = self
            .retry_after_sync(|| self.claim_target(target, mode, create_only))
            .await?
        else {
            return Ok(Err(SpoolReason::BufferedTarget));
        };
        let manifest = Manifest {
            nonce: copy_nonce(self.node),
            size: from.size,
            content_hash: from.content_hash,
            metadata,
            chunks,
        };
        drop(from);
        crate::sim::crash_point(crate::sim::Point::CopyRefPlan)?;

        let action = self
            .manifest_action(target.0.to_string(), target.1.to_string(), &manifest, time)
            .await?;
        crate::sim::action_point(crate::sim::Point::CopyRefManifest);
        crate::sim::crash_point(crate::sim::Point::CopyRefManifest)?;
        // One intent file: a flush and a copy commit one at a time, each after the recover.
        let _flushing = self.flushing.lock().await;
        self.recover().await?;
        let mut journal = self.journal.lock().await;
        let entry = self
            .commit(&mut journal, vec![action], &[], planned_at)
            .await?;
        crate::sim::crash_point(crate::sim::Point::CopyRefCommit)?;
        self.apply_own(&mut journal, entry).await?;
        drop(journal);
        crate::sim::crash_point(crate::sim::Point::CopyRefApply)?;
        buffer::remove_intent(&self.buffer_dir).await?;

        Ok(Ok(ObjectInfo {
            key: target.1.to_string(),
            size: manifest.size,
            content_hash: manifest.content_hash,
            metadata: manifest.metadata,
            last_modified: time,
            conflicted: false,
        }))
    }

    /// The manifest of the source, or `None` when the source is a buffered write.
    async fn stored_source(&self, (bucket, key): (&str, &str)) -> Result<Option<ObjectId>> {
        let current = self
            .read_settled(|buffer| {
                self.require_bucket(buffer, bucket)?;
                self.current(buffer, bucket, key)
            })
            .await?;
        match current {
            Current::Absent => Err(read::no_such_key(bucket, key)),
            Current::Buffered(_) => Ok(None),
            Current::Stored { manifest_id, .. } => Ok(Some(manifest_id)),
        }
    }

    /// The location of each chunk of `manifest` in the index, or `None` when one has none.
    async fn locate(&self, manifest: &Manifest) -> Result<Option<Vec<ChunkRef>>> {
        let locations = self.index().chunk_locations();
        let mut chunks = Vec::with_capacity(manifest.chunks.len());
        for batch in manifest.chunks.chunks(LOOKUP_BATCH) {
            let wanted: Vec<PackEntry> = batch.iter().map(|chunk| chunk.entry).collect();
            let locations = locations.clone();
            let found = tokio::task::spawn_blocking(move || {
                wanted
                    .into_iter()
                    .map(|entry| Ok(locations.get(entry.chunk_id)?.map(|at| (entry, at))))
                    .collect::<Result<Vec<_>>>()
            })
            .await
            .map_err(|e| std::io::Error::other(format!("a chunk lookup task failed: {e}")))??;
            for found in found {
                let Some((wanted, at)) = found else {
                    return Ok(None);
                };
                if at.entry.raw_len != wanted.raw_len {
                    return Err(EngineError::Corrupt(format!(
                        "chunk {}: the index and the manifest give other sizes",
                        wanted.chunk_id
                    )));
                }
                chunks.push(ChunkRef {
                    pack: at.pack,
                    entry: at.entry,
                });
            }
        }
        Ok(Some(chunks))
    }

    /// Checks `mode` on the target under the buffer lock and takes the HLC of the copy. Until
    /// the guard goes, a conditional write to the target gets Conflict. `None` when the target
    /// has a buffered write.
    async fn claim_target(
        &self,
        (bucket, key): (&str, &str),
        mode: &WriteMode,
        create_only: bool,
    ) -> Result<Option<(u64, RefTarget<'_>)>> {
        let buffer = self.lock_for_put(bucket, key, mode, create_only).await?;
        if buffer.object(bucket, key).is_some() {
            return Ok(None);
        }
        self.check_writes()?;
        let time = self.tick()?;
        let target = (bucket.to_string(), key.to_string());
        self.ref_targets
            .lock()
            .expect("no panic while the lock is held")
            .entry(target.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);
        Ok(Some((
            time,
            RefTarget {
                targets: &self.ref_targets,
                target,
            },
        )))
    }

    pub(crate) fn ref_target_in_flight(&self, bucket: &str, key: &str) -> bool {
        self.ref_targets
            .lock()
            .expect("no panic while the lock is held")
            .contains_key(&(bucket.to_string(), key.to_string()))
    }

    pub(crate) fn ref_target_in_bucket(&self, bucket: &str) -> bool {
        self.ref_targets
            .lock()
            .expect("no panic while the lock is held")
            .keys()
            .any(|(target, _)| target == bucket)
    }

    async fn copy_by_spool(
        &self,
        source: (&str, &str),
        target: (&str, &str),
        metadata: Option<BTreeMap<String, String>>,
        mode: WriteMode,
        wait: Duration,
    ) -> Result<ObjectInfo> {
        let mut room = Some(self.read_room(Some(wait)).await?);
        // The reader fixes the source version now: a later delete or overwrite of the source does
        // not change what the copy reads.
        let mut reader = self.get_reader(source.0, source.1, None).await?;
        let metadata = metadata.unwrap_or_else(|| reader.info.metadata.clone());
        let mut spool = self
            .begin_put_sized(target.0, target.1, metadata, mode, reader.info.size)
            .await?;
        loop {
            let held = match room.take() {
                Some(room) => room,
                None => self.piece_room(&mut reader).await?,
            };
            let Some(piece) = self.next_piece(&mut reader).await? else {
                break;
            };
            for part in piece.chunks(COPY_PIECE) {
                self.spool_write(&mut spool, part).await?;
            }
            crate::sim::crash_point(crate::sim::Point::CopyPiece)?;
            drop(held);
        }
        if spool.content_hash() != reader.info.content_hash {
            return Err(EngineError::Corrupt(
                "the copied data does not match the hash of its source".to_string(),
            ));
        }
        self.finish_put(spool).await
    }
}

/// A target of a copy by reference that is not applied yet. Two copies can share one target.
pub(crate) struct RefTarget<'a> {
    targets: &'a Mutex<BTreeMap<(String, String), usize>>,
    target: (String, String),
}

impl Drop for RefTarget<'_> {
    fn drop(&mut self) {
        let mut targets = self
            .targets
            .lock()
            .expect("no panic while the lock is held");
        if let Some(count) = targets.get_mut(&self.target) {
            *count -= 1;
            if *count == 0 {
                targets.remove(&self.target);
            }
        }
    }
}

/// A nonce that no other write of any node gives: the GC never sees a manifest key again.
fn copy_nonce(node: NodeId) -> [u8; 16] {
    let seed = blake3::Hasher::new()
        .update(b"copy")
        .update(node.as_bytes())
        .update(&buffer::unix_nanos().to_le_bytes())
        .update(&COPY_COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes())
        .finalize();
    Nonces::new(*seed.as_bytes()).next()
}
