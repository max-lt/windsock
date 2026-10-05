//! Disk cache of raw chunks, keyed by ChunkId.
//!
//! A chunk never changes for a given ChunkId, so the cache never goes stale and
//! the GC never needs to touch it. Every read checks the blake3 hash: a torn or
//! corrupt file is a miss. Eviction is LRU by size. After a restart, the LRU
//! order comes from the file modification times.

use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use model::ChunkId;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

/// Makes temporary file names unique inside one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, CacheError>;

/// LRU order and sizes. No I/O.
#[derive(Default)]
struct Lru {
    entries: HashMap<ChunkId, (u64, u64)>,
    /// Tick to chunk, oldest first.
    order: BTreeMap<u64, ChunkId>,
    bytes: u64,
    next_tick: u64,
}

impl Lru {
    fn tick(&mut self) -> u64 {
        self.next_tick += 1;
        self.next_tick
    }

    /// Marks `id` as just used. Returns `false` when the cache does not hold it.
    fn touch(&mut self, id: ChunkId) -> bool {
        let tick = self.tick();
        let Some((_, old)) = self.entries.get_mut(&id) else {
            return false;
        };

        self.order.remove(old);
        *old = tick;
        self.order.insert(tick, id);
        true
    }

    fn insert(&mut self, id: ChunkId, size: u64) {
        self.remove(id);
        let tick = self.tick();
        self.entries.insert(id, (size, tick));
        self.order.insert(tick, id);
        self.bytes += size;
    }

    fn remove(&mut self, id: ChunkId) {
        if let Some((size, tick)) = self.entries.remove(&id) {
            self.order.remove(&tick);
            self.bytes -= size;
        }
    }

    /// Drops the least recently used chunks until at most `max` bytes remain.
    fn evict_over(&mut self, max: u64) -> Vec<ChunkId> {
        let mut evicted = Vec::new();

        while self.bytes > max {
            let Some((_, id)) = self.order.pop_first() else {
                break;
            };
            let (size, _) = self
                .entries
                .remove(&id)
                .expect("order and entries hold the same chunks");
            self.bytes -= size;
            evicted.push(id);
        }

        evicted
    }
}

type Flights = Mutex<HashMap<ChunkId, Arc<tokio::sync::Mutex<()>>>>;

/// Held while one task fetches a chunk. Other tasks that want the chunk wait for it.
pub struct Flight<'a> {
    flights: &'a Flights,
    id: ChunkId,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        let mut flights = self
            .flights
            .lock()
            .expect("no panic while the lock is held");

        // The map and this guard hold the last two references: nobody waits.
        if flights
            .get(&self.id)
            .is_some_and(|lock| Arc::strong_count(lock) == 2)
        {
            flights.remove(&self.id);
        }
    }
}

pub struct ChunkCache {
    dir: PathBuf,
    max_bytes: u64,
    lru: Mutex<Lru>,
    flights: Flights,
}

impl ChunkCache {
    /// Opens the cache in `dir`, takes the chunks a previous process left, and
    /// evicts the oldest ones above `max_bytes`.
    pub async fn open(dir: impl Into<PathBuf>, max_bytes: u64) -> Result<Self> {
        let dir = dir.into();
        tokio::fs::create_dir_all(&dir).await?;

        let mut found = scan(&dir).await?;
        found.sort_unstable();

        let mut lru = Lru::default();
        for (_, id, size) in found {
            lru.insert(id, size);
        }
        let evicted = lru.evict_over(max_bytes);

        let cache = Self {
            dir,
            max_bytes,
            lru: Mutex::new(lru),
            flights: Mutex::new(HashMap::new()),
        };
        cache.remove_files(&evicted).await;
        Ok(cache)
    }

    fn lru(&self) -> std::sync::MutexGuard<'_, Lru> {
        self.lru.lock().expect("no panic while the lock is held")
    }

    /// Bytes the cache holds.
    pub fn bytes(&self) -> u64 {
        self.lru().bytes
    }

    fn path(&self, id: ChunkId) -> PathBuf {
        path_of(&self.dir, id)
    }

    /// The raw chunk, or `None` on a miss. A file that fails the hash check is removed.
    pub async fn get(&self, id: ChunkId) -> Result<Option<Bytes>> {
        if !self.lru().touch(id) {
            return Ok(None);
        }

        let data = match tokio::fs::read(self.path(id)).await {
            Ok(data) => data,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                self.lru().remove(id);
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        if blake3::hash(&data).as_bytes() != id.as_bytes() {
            warn!(chunk = %id, "cached chunk fails its hash check: removed");
            self.lru().remove(id);
            self.remove_files(&[id]).await;
            return Ok(None);
        }

        Ok(Some(Bytes::from(data)))
    }

    /// Stores a raw chunk and evicts the least recently used ones above the bound.
    /// The caller checks that `data` is the chunk `id`.
    pub async fn insert(&self, id: ChunkId, data: &[u8]) -> Result<()> {
        let size = data.len() as u64;

        if size > self.max_bytes || self.lru().touch(id) {
            return Ok(());
        }

        let path = self.path(id);
        let parent = path.parent().expect("a chunk path has a parent");
        tokio::fs::create_dir_all(parent).await?;

        // The dot prefix keeps a partial write out of the scan at open.
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(".tmp.{}.{seq}", std::process::id()));
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(data).await?;
        file.flush().await?;
        tokio::fs::rename(&tmp, &path).await?;

        let evicted = {
            let mut lru = self.lru();
            lru.insert(id, size);
            lru.evict_over(self.max_bytes)
        };
        self.remove_files(&evicted).await;
        Ok(())
    }

    /// Waits until no other task fetches `id`. Check the cache again after this.
    pub async fn lock(&self, id: ChunkId) -> Flight<'_> {
        let lock = {
            let mut flights = self
                .flights
                .lock()
                .expect("no panic while the lock is held");
            flights.entry(id).or_default().clone()
        };

        Flight {
            flights: &self.flights,
            id,
            _guard: lock.lock_owned().await,
        }
    }

    async fn remove_files(&self, ids: &[ChunkId]) {
        for id in ids {
            match tokio::fs::remove_file(self.path(*id)).await {
                Ok(()) => debug!(chunk = %id, "evicted"),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => warn!(chunk = %id, %e, "failed to remove a cache file"),
            }
        }
    }
}

fn path_of(dir: &Path, id: ChunkId) -> PathBuf {
    let name = id.to_string();
    dir.join(&name[..2]).join(name)
}

/// Every chunk file under `dir`, with its modification time and size.
/// Temporary files from a crash are removed.
async fn scan(dir: &Path) -> Result<Vec<(std::time::SystemTime, ChunkId, u64)>> {
    let mut found = Vec::new();
    let mut subdirs = tokio::fs::read_dir(dir).await?;

    while let Some(subdir) = subdirs.next_entry().await? {
        if !subdir.file_type().await?.is_dir() {
            continue;
        }

        let mut files = tokio::fs::read_dir(subdir.path()).await?;
        while let Some(file) = files.next_entry().await? {
            let name = file.file_name();
            let name = name.to_string_lossy();

            if name.starts_with(".tmp.") {
                tokio::fs::remove_file(file.path()).await?;
                continue;
            }

            let Ok(id) = name.parse::<ChunkId>() else {
                continue;
            };
            let metadata = file.metadata().await?;
            found.push((metadata.modified()?, id, metadata.len()));
        }
    }

    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn chunk(n: u8, len: usize) -> (ChunkId, Vec<u8>) {
        let data = vec![n; len];
        (ChunkId::from_bytes(*blake3::hash(&data).as_bytes()), data)
    }

    #[test]
    fn test_lru_evicts_the_least_recently_used() {
        let ids: Vec<_> = (0..3).map(|n| ChunkId::from_bytes([n; 32])).collect();
        let mut lru = Lru::default();
        lru.insert(ids[0], 10);
        lru.insert(ids[1], 10);
        lru.touch(ids[0]);
        lru.insert(ids[2], 10);

        assert_eq!(lru.evict_over(20), [ids[1]]);
        assert_eq!(lru.bytes, 20);
        assert!(lru.touch(ids[0]) && lru.touch(ids[2]) && !lru.touch(ids[1]));
    }

    #[tokio::test]
    async fn test_insert_then_get() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ChunkCache::open(dir.path(), 1 << 20).await.unwrap();
        let (id, data) = chunk(1, 100);

        assert!(cache.get(id).await.unwrap().is_none());
        cache.insert(id, &data).await.unwrap();

        assert_eq!(cache.get(id).await.unwrap().unwrap(), data);
        assert_eq!(cache.bytes(), 100);
    }

    #[tokio::test]
    async fn test_bound_evicts_the_least_recently_used_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ChunkCache::open(dir.path(), 250).await.unwrap();
        let chunks: Vec<_> = (0..3).map(|n| chunk(n, 100)).collect();
        cache.insert(chunks[0].0, &chunks[0].1).await.unwrap();
        cache.insert(chunks[1].0, &chunks[1].1).await.unwrap();
        cache.get(chunks[0].0).await.unwrap();

        cache.insert(chunks[2].0, &chunks[2].1).await.unwrap();

        assert!(cache.get(chunks[1].0).await.unwrap().is_none());
        assert!(!path_of(dir.path(), chunks[1].0).exists());
        assert!(cache.get(chunks[0].0).await.unwrap().is_some());
        assert_eq!(cache.bytes(), 200);
    }

    #[tokio::test]
    async fn test_chunk_larger_than_the_bound_is_not_cached() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ChunkCache::open(dir.path(), 50).await.unwrap();
        let (id, data) = chunk(1, 100);

        cache.insert(id, &data).await.unwrap();

        assert!(cache.get(id).await.unwrap().is_none());
        assert_eq!(cache.bytes(), 0);
    }

    #[tokio::test]
    async fn test_corrupt_file_is_a_miss_and_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ChunkCache::open(dir.path(), 1 << 20).await.unwrap();
        let (id, data) = chunk(1, 100);
        cache.insert(id, &data).await.unwrap();
        std::fs::write(path_of(dir.path(), id), b"torn").unwrap();

        assert!(cache.get(id).await.unwrap().is_none());
        assert!(!path_of(dir.path(), id).exists());
        assert_eq!(cache.bytes(), 0);
    }

    #[tokio::test]
    async fn test_reopen_keeps_the_newest_chunks_within_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let chunks: Vec<_> = (0..3).map(|n| chunk(n, 100)).collect();
        {
            let cache = ChunkCache::open(dir.path(), 1 << 20).await.unwrap();
            for (id, data) in &chunks {
                cache.insert(*id, data).await.unwrap();
                // Modification times order the chunks at the next open.
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        std::fs::write(dir.path().join(".tmp.left"), b"x").ok();
        let tmp = path_of(dir.path(), chunks[0].0).with_file_name(".tmp.1.1");
        std::fs::write(&tmp, b"partial").unwrap();

        let cache = ChunkCache::open(dir.path(), 250).await.unwrap();

        assert_eq!(cache.bytes(), 200);
        assert!(cache.get(chunks[0].0).await.unwrap().is_none());
        assert!(cache.get(chunks[2].0).await.unwrap().is_some());
        assert!(!tmp.exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_second_fetch_of_a_chunk_waits_for_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(ChunkCache::open(dir.path(), 1 << 20).await.unwrap());
        let (id, data) = chunk(1, 100);
        let first = cache.lock(id).await;

        let waiter = {
            let cache = cache.clone();
            tokio::spawn(async move {
                let _flight = cache.lock(id).await;
                cache.get(id).await.unwrap()
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished());

        cache.insert(id, &data).await.unwrap();
        drop(first);

        assert_eq!(waiter.await.unwrap().unwrap(), data);
        assert!(cache.flights.lock().unwrap().is_empty());
    }
}
