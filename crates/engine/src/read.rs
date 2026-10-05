//! Reads: the buffer first, then the index, the cache and the remote.

use super::*;

impl<R: Remote + 'static> Engine<R> {
    /// Reads `range` of an object, or all of it.
    pub async fn get(&self, bucket: &str, key: &str, range: Option<Range<u64>>) -> Result<Object> {
        self.retry_after_sync(|| self.get_once(bucket, key, range.clone()))
            .await
    }

    pub async fn head(&self, bucket: &str, key: &str) -> Result<ObjectInfo> {
        self.retry_after_sync(|| async move {
            let current = {
                let buffer = self.buffer.lock().await;
                self.require_bucket(&buffer, bucket)?;
                self.current(&buffer, bucket, key)?
            };
            self.info(bucket, key, current).await
        })
        .await
    }

    /// Every key of `bucket` under `prefix` that exists, in key order.
    pub async fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<ObjectInfo>> {
        self.retry_after_sync(|| async move {
            let keys = {
                let buffer = self.buffer.lock().await;
                self.require_bucket(&buffer, bucket)?;
                self.keys_in(&buffer, bucket, prefix)?
            };

            let mut out = Vec::with_capacity(keys.len());
            for (key, current) in keys {
                if current.exists() {
                    out.push(self.info(bucket, &key, current).await?);
                }
            }
            Ok(out)
        })
        .await
    }

    /// Every journaled version of a key. Buffered writes are not versions yet.
    pub fn versions(&self, bucket: &str, key: &str) -> Result<Option<ObjectState>> {
        Ok(self.index().object(bucket, key)?)
    }

    pub(crate) async fn get_once(
        &self,
        bucket: &str,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<Object> {
        loop {
            let current = {
                let buffer = self.buffer.lock().await;
                self.require_bucket(&buffer, bucket)?;
                self.current(&buffer, bucket, key)?
            };

            match current {
                Current::Absent => return Err(no_such_key(bucket, key)),
                Current::Buffered(put) => {
                    let range = check_range(range.clone(), put.size)?;
                    let Some(data) = buffer::read_put(&self.buffer_dir, &put, range).await? else {
                        // A flush released the segment: the index already holds the write.
                        continue;
                    };
                    return Ok(Object {
                        info: buffered_info(key, put),
                        data: Bytes::from(data),
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
                    let data = self.read_range(&manifest, range, mode).await?;
                    return Ok(Object {
                        info: stored_info(key, manifest, hlc, conflicted),
                        data: Bytes::from(data),
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

    /// The current state of every key of `bucket` under `prefix`, deleted ones included.
    pub(crate) fn keys_in(
        &self,
        buffer: &Buffer,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<(String, Current)>> {
        let mut keys: BTreeMap<String, Current> = self
            .index()
            .list(bucket, prefix)?
            .into_iter()
            .map(|(key, state)| (key, stored(&state)))
            .collect();

        for (key, object) in buffer.objects(bucket, prefix) {
            let current = match object {
                BufferedObject::Put(put) => Current::Buffered(put.clone()),
                BufferedObject::Delete { .. } => Current::Absent,
            };
            keys.insert(key.to_string(), current);
        }

        Ok(keys.into_iter().collect())
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

    /// The manifest from the index, or from the remote on a miss.
    pub(crate) async fn manifest(&self, id: ObjectId) -> Result<Manifest> {
        if let Some(bytes) = self.index().manifest(id)? {
            return Manifest::decode(id, &bytes);
        }

        let Some(bytes) = self.remote.get(&manifest_key(id)).await? else {
            return Err(EngineError::Corrupt(format!("manifest {id} is missing")));
        };

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

    pub(crate) async fn read_range(
        &self,
        manifest: &Manifest,
        range: Range<u64>,
        mode: CacheMode,
    ) -> Result<Vec<u8>> {
        let len = (range.end - range.start) as usize;
        let (fetches, skip) = plan::plan_read(&manifest.chunks, range);
        let mut raw = Vec::new();

        for fetch in &fetches {
            for chunk in self.read_fetch(fetch, mode).await? {
                raw.extend(chunk);
            }
        }

        let skip = skip as usize;
        Ok(raw[skip..skip + len].to_vec())
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
        let Some(bytes) = self.remote.get_range(&pack_key(pack), range).await? else {
            return Err(EngineError::Corrupt(format!("pack {pack} is missing")));
        };

        entries
            .iter()
            .map(|entry| {
                let offset = (entry.offset - start) as usize;
                let stored = &bytes[offset..offset + entry.stored_len as usize];
                Ok(pack::read_chunk(entry, stored)?)
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
    if let Err(e) = cache.insert(id, raw).await {
        warn!(chunk = %id, %e, "cache write failed");
    }
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
