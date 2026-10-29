//! Reads: the buffer first, then the index, the cache and the remote.

use super::*;

use std::collections::VecDeque;

use tokio::io::AsyncReadExt;

use crate::plan::Fetch;

/// The largest piece that [`Engine::next_piece`] gives, so a read holds this much data at a time.
pub const READ_STEP: usize = 4 * 1024 * 1024;

/// An open read of an object. [`Engine::next_piece`] gives its data.
pub struct ObjectReader {
    pub info: ObjectInfo,
    source: Source,
}

enum Source {
    /// The open segment of a buffered put, at the next byte to give.
    Buffered {
        file: tokio::fs::File,
        remaining: u64,
    },
    /// The fetches still to read, the bytes to drop before the range, and the bytes to give.
    Stored {
        fetches: VecDeque<Fetch>,
        skip: u64,
        remaining: u64,
        mode: CacheMode,
    },
}

impl<R: Remote + 'static> Engine<R> {
    /// Reads `range` of an object, or all of it, into one buffer. [`Engine::get_reader`] reads it
    /// in pieces.
    pub async fn get(&self, bucket: &str, key: &str, range: Option<Range<u64>>) -> Result<Object> {
        let mut reader = self.get_reader(bucket, key, range).await?;
        let mut data = Vec::new();
        while let Some(piece) = self.next_piece(&mut reader).await? {
            data.extend_from_slice(&piece);
        }
        Ok(Object {
            info: reader.info,
            data: Bytes::from(data),
        })
    }

    /// A reader of the object, or of `range` of it. [`Engine::next_piece`] gives the data.
    pub async fn get_reader(
        &self,
        bucket: &str,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<ObjectReader> {
        self.retry_after_sync(|| self.reader_once(bucket, key, range.clone()))
            .await
    }

    /// The next piece of the data, at most [`READ_STEP`] bytes. `None` at the end.
    pub async fn next_piece(&self, reader: &mut ObjectReader) -> Result<Option<Bytes>> {
        match &mut reader.source {
            Source::Buffered { file, remaining } => {
                if *remaining == 0 {
                    return Ok(None);
                }
                let mut piece = vec![0u8; (*remaining).min(READ_STEP as u64) as usize];
                file.read_exact(&mut piece).await?;
                *remaining -= piece.len() as u64;
                Ok(Some(Bytes::from(piece)))
            }
            Source::Stored {
                fetches,
                skip,
                remaining,
                mode,
            } => loop {
                if *remaining == 0 {
                    return Ok(None);
                }
                let Some(fetch) = fetches.pop_front() else {
                    return Err(EngineError::Corrupt(
                        "the chunks of a manifest end before its size".to_string(),
                    ));
                };
                let mut raw = Vec::new();
                for chunk in self.read_fetch(&fetch, *mode).await? {
                    raw.extend(chunk);
                }
                let start = (*skip).min(raw.len() as u64);
                *skip -= start;
                let end = (start + *remaining).min(raw.len() as u64);
                *remaining -= end - start;
                if end > start {
                    return Ok(Some(Bytes::from(raw).slice(start as usize..end as usize)));
                }
            },
        }
    }

    pub async fn head(&self, bucket: &str, key: &str) -> Result<ObjectInfo> {
        self.retry_after_sync(|| async move {
            let current = self
                .read_settled(|buffer| {
                    self.require_bucket(buffer, bucket)?;
                    self.current(buffer, bucket, key)
                })
                .await?;
            self.info(bucket, key, current).await
        })
        .await
    }

    /// Runs `read` on the buffer. Returns the result only when all writes that `read` saw are on disk.
    /// A crash can lose a write that is not on disk, so a reader must not see it.
    pub(crate) async fn read_settled<T>(&self, read: impl Fn(&Buffer) -> Result<T>) -> Result<T> {
        loop {
            let (result, pending) = {
                let buffer = self.buffer.lock().await;
                (read(&buffer), buffer.pending())
            };

            let Some(record) = pending else {
                return result;
            };
            match self.wait_durable(record).await? {
                Durability::Durable => return result,
                // A failed fsync dropped writes that `read` saw. Read the repaired buffer.
                Durability::Pending | Durability::Lost => continue,
            }
        }
    }

    /// Every journaled version of a key. Buffered writes are not versions yet.
    pub fn versions(&self, bucket: &str, key: &str) -> Result<Option<ObjectState>> {
        Ok(self.index().object(bucket, key)?)
    }

    async fn reader_once(
        &self,
        bucket: &str,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<ObjectReader> {
        loop {
            let current = self
                .read_settled(|buffer| {
                    self.require_bucket(buffer, bucket)?;
                    self.current(buffer, bucket, key)
                })
                .await?;

            match current {
                Current::Absent => return Err(no_such_key(bucket, key)),
                Current::Buffered(put) => {
                    let range = check_range(range.clone(), put.size)?;
                    let Some(file) =
                        buffer::open_put(&self.buffer_dir, &put, range.clone()).await?
                    else {
                        // A flush released the segment: the index already holds the write.
                        continue;
                    };
                    let remaining = range.end - range.start;
                    return Ok(ObjectReader {
                        info: buffered_info(key, put),
                        source: Source::Buffered { file, remaining },
                    });
                }
                Current::Stored {
                    manifest_id,
                    hlc,
                    conflicted,
                } => {
                    let manifest = self.manifest(manifest_id).await?;
                    let range = check_range(range, manifest.size)?;
                    let mode = self.config.policy(bucket, key).cache;
                    let remaining = range.end - range.start;
                    let (fetches, skip) = plan::plan_read(&manifest.chunks, range);
                    return Ok(ObjectReader {
                        info: stored_info(key, manifest, hlc, conflicted),
                        source: Source::Stored {
                            fetches: split_fetches(fetches),
                            skip,
                            remaining,
                            mode,
                        },
                    });
                }
            }
        }
    }

    pub(crate) fn current(&self, buffer: &Buffer, bucket: &str, key: &str) -> Result<Current> {
        match buffer.object(bucket, key) {
            Some(BufferedObject::Put(put)) => return Ok(Current::Buffered(put.clone())),
            Some(BufferedObject::Delete { .. }) => return Ok(Current::Absent),
            None => {}
        }

        let state = self.index().object(bucket, key)?;
        Ok(state.map_or(Current::Absent, |state| stored(&state)))
    }

    pub(crate) async fn info(
        &self,
        bucket: &str,
        key: &str,
        current: Current,
    ) -> Result<ObjectInfo> {
        match current {
            Current::Absent => Err(no_such_key(bucket, key)),
            Current::Buffered(put) => Ok(buffered_info(key, put)),
            Current::Stored {
                manifest_id,
                hlc,
                conflicted,
            } => {
                let manifest = self.manifest(manifest_id).await?;
                Ok(stored_info(key, manifest, hlc, conflicted))
            }
        }
    }

    /// The content hash of the current object, or `None` when there is none.
    pub(crate) async fn content_hash(&self, current: Current) -> Result<Option<[u8; 32]>> {
        match current {
            Current::Absent => Ok(None),
            Current::Buffered(put) => Ok(Some(put.content_hash)),
            Current::Stored { manifest_id, .. } => {
                Ok(Some(self.manifest(manifest_id).await?.content_hash))
            }
        }
    }

    /// The manifest from the index, or from the remote on a miss.
    pub(crate) async fn manifest(&self, id: ObjectId) -> Result<Manifest> {
        if let Some(bytes) = self.index().manifest(id)? {
            return Manifest::decode(id, &bytes);
        }

        let Some(sealed) = self.remote.get(&manifest_key(id)).await? else {
            return Err(EngineError::Corrupt(format!("manifest {id} is missing")));
        };

        let bytes = self
            .keys
            .sealer()
            .open(seal::Kind::Manifest, id.as_bytes(), &sealed)
            .map_err(|e| EngineError::Corrupt(format!("manifest {id}: {e}")))?;
        let manifest = Manifest::decode(id, &bytes)?;
        self.index().put_manifest(id, &bytes)?;
        Ok(manifest)
    }

    pub(crate) async fn entry_manifest(
        &self,
        id: ObjectId,
        inline: Option<&[u8]>,
    ) -> Result<Manifest> {
        let Some(bytes) = inline else {
            return self.manifest(id).await;
        };

        let manifest = Manifest::decode(id, bytes)?;
        self.index().put_manifest(id, bytes)?;
        Ok(manifest)
    }

    /// The raw chunks of one fetch, in order: from the cache when it holds
    /// them, else from one range read of the chunks it lacks.
    pub(crate) async fn read_fetch(&self, fetch: &Fetch, mode: CacheMode) -> Result<Vec<Vec<u8>>> {
        let Some(cache) = self.cache.as_ref().filter(|_| mode != CacheMode::Off) else {
            return self.fetch_chunks(fetch.pack, &fetch.entries).await;
        };

        let mut chunks = Vec::with_capacity(fetch.entries.len());
        for entry in &fetch.entries {
            chunks.push(cached(cache, entry.chunk_id).await);
        }

        if chunks.iter().all(Option::is_some) {
            return Ok(chunks.into_iter().flatten().collect());
        }

        // Concurrent readers of a missing chunk wait here, then find it cached.
        let mut ids: Vec<ChunkId> = fetch
            .entries
            .iter()
            .zip(&chunks)
            .filter(|(_, chunk)| chunk.is_none())
            .map(|(entry, _)| entry.chunk_id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        let mut flights = Vec::with_capacity(ids.len());
        for id in ids {
            flights.push(cache.lock(id).await);
        }

        for (entry, chunk) in fetch.entries.iter().zip(chunks.iter_mut()) {
            if chunk.is_none() {
                *chunk = cached(cache, entry.chunk_id).await;
            }
        }

        let missing: Vec<PackEntry> = fetch
            .entries
            .iter()
            .zip(&chunks)
            .filter(|(_, chunk)| chunk.is_none())
            .map(|(entry, _)| *entry)
            .collect();

        if !missing.is_empty() {
            let fetched = self.fetch_chunks(fetch.pack, &missing).await?;
            let mut fetched = missing.iter().zip(fetched);

            for chunk in chunks.iter_mut().filter(|chunk| chunk.is_none()) {
                let (entry, raw) = fetched.next().expect("one fetched chunk per missing chunk");
                keep(cache, entry.chunk_id, &raw).await;
                *chunk = Some(raw);
            }
        }

        drop(flights);
        Ok(chunks.into_iter().flatten().collect())
    }

    /// Reads `entries` of `pack` with one range read. The entries lie in pack order.
    pub(crate) async fn fetch_chunks(
        &self,
        pack: PackId,
        entries: &[PackEntry],
    ) -> Result<Vec<Vec<u8>>> {
        let (Some(first), Some(last)) = (entries.first(), entries.last()) else {
            return Ok(Vec::new());
        };

        let start = first.offset;
        let range = start..last.range().end;
        let Some(bytes) = self
            .remote
            .get_range(&pack_key(pack), range.clone())
            .await?
        else {
            return Err(EngineError::Corrupt(format!("pack {pack} is missing")));
        };
        // The remote is not trusted: a short answer must fail the read, not the process.
        if bytes.len() as u64 != range.end - range.start {
            return Err(EngineError::Corrupt(format!(
                "pack {pack}: the remote returned {} bytes for {range:?}",
                bytes.len()
            )));
        }

        entries
            .iter()
            .map(|entry| {
                let offset = (entry.offset - start) as usize;
                let stored = &bytes[offset..offset + entry.stored_len as usize];
                pack::read_chunk(&self.keys, entry, stored).map_err(|e| {
                    EngineError::Corrupt(format!("pack {pack}, chunk {}: {e}", entry.chunk_id))
                })
            })
            .collect()
    }

    /// Keeps the chunks of a flushed object, for a prefix whose policy keeps writes.
    pub(crate) async fn cache_written(&self, data: &[u8], chunks: &[(ChunkId, Range<usize>)]) {
        let Some(cache) = &self.cache else {
            return;
        };

        for (id, range) in chunks {
            keep(cache, *id, &data[range.clone()]).await;
        }
    }
}

pub(crate) fn stored(state: &ObjectState) -> Current {
    match (state.head(), state.current()) {
        (Some(head), Some(manifest_id)) => Current::Stored {
            manifest_id,
            hlc: head.hlc,
            conflicted: state.is_conflicted(),
        },
        _ => Current::Absent,
    }
}

/// A cache read. A failing cache is a miss: the remote has the data.
pub(crate) async fn cached(cache: &ChunkCache, id: ChunkId) -> Option<Vec<u8>> {
    match cache.get(id).await {
        Ok(chunk) => chunk.map(|bytes| bytes.to_vec()),
        Err(e) => {
            warn!(chunk = %id, %e, "cache read failed");
            None
        }
    }
}

pub(crate) async fn keep(cache: &ChunkCache, id: ChunkId, raw: &[u8]) {
    cache.keep(id, raw).await;
}

pub(crate) fn no_such_key(bucket: &str, key: &str) -> EngineError {
    EngineError::NoSuchKey {
        bucket: bucket.to_string(),
        key: key.to_string(),
    }
}

pub(crate) fn buffered_info(key: &str, put: BufferedPut) -> ObjectInfo {
    ObjectInfo {
        key: key.to_string(),
        size: put.size,
        content_hash: put.content_hash,
        metadata: put.metadata,
        last_modified: put.time,
        conflicted: false,
    }
}

pub(crate) fn stored_info(key: &str, manifest: Manifest, hlc: u64, conflicted: bool) -> ObjectInfo {
    ObjectInfo {
        key: key.to_string(),
        size: manifest.size,
        content_hash: manifest.content_hash,
        metadata: manifest.metadata,
        last_modified: hlc,
        conflicted,
    }
}

pub(crate) fn check_range(range: Option<Range<u64>>, size: u64) -> Result<Range<u64>> {
    let range = range.unwrap_or(0..size);

    if range.start > range.end || range.end > size {
        return Err(EngineError::InvalidRange {
            start: range.start,
            end: range.end,
            size,
        });
    }

    Ok(range)
}

/// Splits each fetch into fetches of at most [`READ_STEP`] raw bytes. A chunk is never larger.
fn split_fetches(fetches: Vec<Fetch>) -> VecDeque<Fetch> {
    let mut out = VecDeque::new();
    for fetch in fetches {
        let mut entries: Vec<PackEntry> = Vec::new();
        let mut raw = 0;
        for entry in fetch.entries {
            if !entries.is_empty() && raw + entry.raw_len as usize > READ_STEP {
                out.push_back(fetch_of(fetch.pack, std::mem::take(&mut entries)));
                raw = 0;
            }
            raw += entry.raw_len as usize;
            entries.push(entry);
        }
        if !entries.is_empty() {
            out.push_back(fetch_of(fetch.pack, entries));
        }
    }
    out
}

fn fetch_of(pack: PackId, entries: Vec<PackEntry>) -> Fetch {
    let start = entries.first().expect("a fetch has entries").offset;
    let end = entries.last().expect("a fetch has entries").range().end;
    Fetch {
        pack,
        range: start..end,
        entries,
    }
}
