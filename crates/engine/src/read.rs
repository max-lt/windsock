//! Reads: the buffer first, then the index, the cache and the remote.

use super::*;

use std::collections::VecDeque;
use std::time::Instant;

use tokio::io::AsyncReadExt;

use crate::plan::Fetch;

/// The largest piece that [`Engine::next_piece`] gives, so a read holds this much data at a time.
pub const READ_STEP: usize = 4 * 1024 * 1024;

/// The largest read-ahead depth that the configuration accepts.
pub const MAX_READ_AHEAD: usize = 8;

/// Remote reads that read-ahead runs at one time on all GETs, under the limit of the remote
/// client, so the flush keeps connections.
pub const READ_AHEAD_IN_FLIGHT: usize = 32;

/// A client that takes more than this many fetch times to ask for its next piece gets no
/// read-ahead: one piece ahead would save it less than a fifth of its time.
pub const READ_AHEAD_SLOW_FACTOR: u32 = 4;

/// Read-ahead takes room only while the room in use stays within 1/N of the read budget, so a
/// first piece finds room.
pub const READ_AHEAD_BUDGET_PART: u64 = 2;

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
        /// The pieces after the head that tasks read now, in plan order.
        ahead: VecDeque<Ahead>,
        pace: Pace,
    },
}

/// A piece that a task reads ahead, and its room in the read budget until the reader takes it.
struct Ahead {
    fetch: Fetch,
    task: AheadTask,
    room: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// A read-ahead task: the raw piece and the time of its fetch. It stops when it drops, so a
/// reader that goes away stops its fetches.
struct AheadTask(tokio::task::JoinHandle<Result<(Vec<u8>, Duration)>>);

impl AheadTask {
    async fn join(mut self) -> Result<(Vec<u8>, Duration)> {
        match (&mut self.0).await {
            Ok(piece) => piece,
            Err(e) => Err(std::io::Error::other(format!("a read-ahead task failed: {e}")).into()),
        }
    }
}

impl Drop for AheadTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What the depth rule knows of one reader: its last two gaps and its last two fetch times.
#[derive(Default)]
struct Pace {
    /// When the last piece left [`Engine::next_piece`].
    returned: Option<Instant>,
    gaps_seen: u32,
    gaps: [Duration; 2],
    fetches: [Duration; 2],
}

impl Pace {
    fn asked(&mut self, now: Instant) {
        let Some(returned) = self.returned.take() else {
            return;
        };
        self.gaps_seen += 1;
        // The socket buffer can take a whole first piece: its gap says nothing of the client.
        if self.gaps_seen > 1 {
            self.gaps = [self.gaps[1], now - returned];
        }
    }

    fn fetched(&mut self, took: Duration) {
        self.fetches = [self.fetches[1], took];
    }

    fn depth(&self, cap: usize) -> usize {
        if self.gaps_seen < 2 {
            return 0;
        }
        let gap = self.gaps[0].max(self.gaps[1]);
        let fetch = self.fetches[0].max(self.fetches[1]);
        read_ahead_depth(fetch, gap, cap)
    }
}

/// The pieces to read ahead so the remote stays busy while the client takes a piece.
fn read_ahead_depth(fetch: Duration, gap: Duration, cap: usize) -> usize {
    if cap == 0 || gap > fetch * READ_AHEAD_SLOW_FACTOR {
        return 0;
    }
    if gap.is_zero() {
        return cap;
    }
    let depth = fetch.as_nanos().div_ceil(gap.as_nanos());
    usize::try_from(depth).unwrap_or(cap).clamp(1, cap)
}

/// Read-ahead tasks: those that run now, and all that started since the open.
#[derive(Default)]
pub(crate) struct TaskCounts {
    running: AtomicU64,
    started: AtomicU64,
}

/// Counts one task from its spawn to the drop of its future, which an abort also drops.
struct TaskCount(Arc<TaskCounts>);

impl TaskCount {
    fn start(counts: &Arc<TaskCounts>) -> Self {
        counts.running.fetch_add(1, Ordering::SeqCst);
        counts.started.fetch_add(1, Ordering::SeqCst);
        Self(counts.clone())
    }
}

impl Drop for TaskCount {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The free room of the reads and the read-ahead tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadState {
    pub budget_free: u64,
    pub fetch_slots_free: usize,
    pub tasks_running: u64,
    pub tasks_started: u64,
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
                ahead,
                pace,
            } => loop {
                if *remaining == 0 {
                    return Ok(None);
                }
                pace.asked(Instant::now());
                let depth = pace.depth(self.config.read_ahead);
                let (raw, took) = match ahead.pop_front() {
                    Some(head) => {
                        shrink(fetches, ahead, depth);
                        self.read_ahead(fetches, ahead, *mode, depth);
                        head.task.join().await?
                    }
                    None => {
                        let Some(fetch) = fetches.pop_front() else {
                            return Err(EngineError::Corrupt(
                                "the chunks of a manifest end before its size".to_string(),
                            ));
                        };
                        self.read_ahead(fetches, ahead, *mode, depth);
                        let started = Instant::now();
                        let raw = self.chunks.read_piece(&fetch, *mode).await?;
                        (raw, started.elapsed())
                    }
                };
                pace.fetched(took);
                let start = (*skip).min(raw.len() as u64);
                *skip -= start;
                let end = (start + *remaining).min(raw.len() as u64);
                *remaining -= end - start;
                if end > start {
                    pace.returned = Some(Instant::now());
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
                            ahead: VecDeque::new(),
                            pace: Pace::default(),
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

    /// The content hash of the current object from local state only. `None` when the manifest
    /// of a stored version is not in the index.
    pub(crate) fn local_content_hash(&self, current: &Current) -> Result<Option<[u8; 32]>> {
        match current {
            Current::Absent => Ok(None),
            Current::Buffered(put) => Ok(Some(put.content_hash)),
            Current::Stored { manifest_id, .. } => match self.index().manifest(*manifest_id)? {
                Some(bytes) => Ok(Some(Manifest::decode(*manifest_id, &bytes)?.content_hash)),
                None => Ok(None),
            },
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

        let Some(sealed) = self
            .remote
            .get(&manifest_key(id), manifest::MAX_MANIFEST)
            .await?
        else {
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
}

/// What a fetch reads: the remote, the keys and the cache. A read-ahead task holds a handle.
pub(crate) struct Chunks<R> {
    pub(crate) remote: Arc<R>,
    pub(crate) keys: Keys,
    pub(crate) cache: Option<Arc<ChunkCache>>,
}

impl<R: Remote + 'static> Chunks<R> {
    /// The raw bytes of one fetch.
    async fn read_piece(&self, fetch: &Fetch, mode: CacheMode) -> Result<Vec<u8>> {
        // One size for every piece: buffers of many sizes stay with the allocator after their
        // free.
        let mut raw = Vec::with_capacity(READ_STEP);
        for chunk in self.read_fetch(fetch, mode).await? {
            raw.extend(chunk);
        }
        Ok(raw)
    }

    /// True when the cache holds every chunk of `fetch` for a read in `mode`.
    fn all_cached(&self, fetch: &Fetch, mode: CacheMode) -> bool {
        let Some(cache) = self.cache.as_ref().filter(|_| mode != CacheMode::Off) else {
            return false;
        };
        fetch
            .entries
            .iter()
            .all(|entry| cache.contains(entry.chunk_id))
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

/// Room in the read budget for one piece of a GET. The room comes back when it drops.
pub struct ReadRoom {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<R: Remote + 'static> Engine<R> {
    /// Takes room for one piece of READ_STEP bytes. With `wait`, fails with ReadBudget after it.
    /// With none, waits until a GET gives room back.
    pub async fn read_room(&self, wait: Option<Duration>) -> Result<ReadRoom> {
        let piece = READ_STEP as u32;
        let take = self.read_budget.clone().acquire_many_owned(piece);
        let permit = match wait {
            None => take.await,
            Some(wait) => match tokio::time::timeout(wait, take).await {
                Ok(permit) => permit,
                Err(_) => {
                    let budget = self.config.read_budget;
                    if !self.read_budget_short.swap(true, Ordering::SeqCst) {
                        warn!(
                            budget,
                            "GETs get 503: the GETs in flight hold the read budget"
                        );
                    }
                    return Err(EngineError::ReadBudget { budget });
                }
            },
        };
        let permit = permit.expect("the read budget is never closed");
        if wait.is_some() && self.read_budget_short.swap(false, Ordering::SeqCst) {
            info!("GETs get room in the read budget again");
        }
        Ok(ReadRoom { _permit: permit })
    }

    /// Room for the next piece of `reader`. A piece that read-ahead holds gives its own room.
    pub async fn piece_room(&self, reader: &mut ObjectReader) -> Result<ReadRoom> {
        if let Source::Stored { ahead, .. } = &mut reader.source
            && let Some(room) = ahead.front_mut().and_then(|head| head.room.take())
        {
            return Ok(ReadRoom { _permit: room });
        }
        // The queue of this reader is empty here: a reader that waits for room holds none, so
        // readers never wait for each other in a cycle.
        self.read_room(None).await
    }

    /// Starts tasks for the pieces after the head, up to `depth`. It never waits: with no room or
    /// no fetch slot it starts nothing, and the read goes on one piece at a time.
    fn read_ahead(
        &self,
        fetches: &mut VecDeque<Fetch>,
        ahead: &mut VecDeque<Ahead>,
        mode: CacheMode,
        depth: usize,
    ) {
        while ahead.len() < depth {
            let Some(fetch) = fetches.front() else {
                return;
            };
            // A cached piece is fast to read in turn.
            if self.chunks.all_cached(fetch, mode) {
                return;
            }
            let Some(room) = self.try_ahead_room() else {
                return;
            };
            let Ok(slot) = self.read_ahead_fetches.clone().try_acquire_owned() else {
                return;
            };
            let fetch = fetches.pop_front().expect("the front fetch exists");
            let (chunks, task_fetch) = (self.chunks.clone(), fetch.clone());
            let count = TaskCount::start(&self.read_ahead_tasks);
            let task = tokio::spawn(async move {
                let _count = count;
                let started = Instant::now();
                let piece = chunks.read_piece(&task_fetch, mode).await;
                // The slot is for the remote read only; the piece keeps its room until it leaves.
                drop(slot);
                piece.map(|raw| (raw, started.elapsed()))
            });
            ahead.push_back(Ahead {
                fetch,
                task: AheadTask(task),
                room: Some(room),
            });
        }
    }

    /// Room for one read-ahead piece, while the room in use stays within its part of the budget.
    fn try_ahead_room(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let piece = READ_STEP as u64;
        let budget = self.config.read_budget;
        let _one = self
            .read_ahead_lock
            .lock()
            .expect("no panic while the lock is held");
        let in_use = budget - self.read_budget.available_permits() as u64;
        if in_use + piece > budget / READ_AHEAD_BUDGET_PART {
            return None;
        }
        self.read_budget
            .clone()
            .try_acquire_many_owned(piece as u32)
            .ok()
    }

    pub fn read_state(&self) -> ReadState {
        ReadState {
            budget_free: self.read_budget.available_permits() as u64,
            fetch_slots_free: self.read_ahead_fetches.available_permits(),
            tasks_running: self.read_ahead_tasks.running.load(Ordering::SeqCst),
            tasks_started: self.read_ahead_tasks.started.load(Ordering::SeqCst),
        }
    }
}

/// Stops the pieces past `depth` and puts their fetches back: a client that slows down gives
/// their room back at once.
fn shrink(fetches: &mut VecDeque<Fetch>, ahead: &mut VecDeque<Ahead>, depth: usize) {
    while ahead.len() > depth {
        let surplus = ahead
            .pop_back()
            .expect("the queue is longer than the depth");
        fetches.push_front(surplus.fetch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn test_read_ahead_depth_follows_the_gap_and_the_fetch() {
        let cases = [
            // (fetch, gap, cap, depth)
            (200 * MS, Duration::ZERO, 3, 3),
            (200 * MS, Duration::ZERO, 8, 8),
            (200 * MS, MS, 3, 3),
            (200 * MS, 70 * MS, 8, 3),
            (200 * MS, 100 * MS, 8, 2),
            (200 * MS, 200 * MS, 3, 1),
            (200 * MS, 800 * MS, 3, 1),
            (200 * MS, 801 * MS, 3, 0),
            (200 * MS, 20_000 * MS, 3, 0),
            (Duration::ZERO, MS, 3, 0),
            (200 * MS, 100 * MS, 0, 0),
        ];
        for (fetch, gap, cap, depth) in cases {
            assert_eq!(
                read_ahead_depth(fetch, gap, cap),
                depth,
                "fetch {fetch:?}, gap {gap:?}, cap {cap}"
            );
        }
    }

    #[test]
    fn test_read_ahead_depth_never_passes_the_cap() {
        for cap in 0..=MAX_READ_AHEAD {
            for gap in [0, 1, 10, 100, 1000, 10_000] {
                let depth = read_ahead_depth(1000 * MS, gap * MS, cap);
                assert!(depth <= cap, "cap {cap}, gap {gap} ms: depth {depth}");
            }
        }
    }

    #[test]
    fn test_pace_ignores_the_first_gap_and_takes_the_larger_of_two() {
        let mut pace = Pace::default();
        let start = Instant::now();
        pace.fetched(200 * MS);
        assert_eq!(pace.depth(3), 0, "the first piece starts no read-ahead");

        pace.returned = Some(start);
        pace.asked(start + 10_000 * MS);
        assert_eq!(pace.depth(3), 0, "the first gap is not a sample");

        pace.returned = Some(start);
        pace.asked(start);
        assert_eq!(pace.depth(3), 3, "a client that asks at once gets the cap");

        pace.returned = Some(start);
        pace.asked(start + 900 * MS);
        pace.returned = Some(start);
        pace.asked(start);
        assert_eq!(
            pace.depth(3),
            0,
            "one slow gap of the last two stops read-ahead"
        );
    }
}
