//! Multipart uploads, with the parts on local disk until the complete.
//!
//! An upload lives on the proxy that started it. Its parts survive a restart:
//! `<dir>/<upload id>/meta`, and one file per part named `<number>-<etag>`.

use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use engine::{Engine, EngineError};
use remote::Remote;
use tracing::{info, warn};

use crate::S3Error;
use crate::xml::PartInfo;

/// Makes upload ids and temporary names unique inside one process.
static COUNTER: AtomicU64 = AtomicU64::new(0);
/// A file that a crash can leave in an upload directory: it never got its name.
const TEMP_PREFIX: &str = ".tmp.";

const META: &str = "meta";
/// In a claimed upload: the hex blake3 hash of the object that its complete commits next.
const MARKER: &str = "committing";
/// Completes that run at one time. Each one holds a part file, a spool file and 1 MiB of
/// memory; more get 503 SlowDown.
pub const MAX_COMPLETES: usize = 4;
const MAX_PART: u16 = 10_000;

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

fn io(e: std::io::Error) -> S3Error {
    S3Error::internal(format!("multipart storage: {e}"))
}

#[derive(Serialize, Deserialize)]
struct UploadMeta {
    bucket: String,
    key: String,
    metadata: BTreeMap<String, String>,
    initiated: u64,
}

/// Why a call takes an upload away from the others.
#[derive(Clone, Copy)]
pub(crate) enum Claim {
    /// The upload goes back when the complete fails.
    Complete,
    Remove,
}

impl Claim {
    fn suffix(self) -> &'static str {
        match self {
            Claim::Complete => ".completing",
            Claim::Remove => ".removing",
        }
    }
}

fn is_upload_id(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The part files of a complete in object order, their size, and the metadata given at
/// initiation.
pub(crate) struct CompletePlan {
    pub parts: Vec<PathBuf>,
    pub size: u64,
    pub metadata: BTreeMap<String, String>,
}

/// The multipart uploads of one proxy, and the bytes that their parts hold on disk.
pub struct Uploads {
    dir: PathBuf,
    /// The parts of all uploads together hold at most this many bytes.
    limit: u64,
    held: AtomicU64,
    /// When this process first saw each upload, on its monotonic clock.
    first_seen: Mutex<HashMap<String, Instant>>,
    completes: tokio::sync::Semaphore,
    /// One part takes its name at a time: the last rename of a part number wins, and the room
    /// of the part it replaces comes back once.
    naming: tokio::sync::Mutex<()>,
}

impl Uploads {
    /// Call [`Uploads::start`] before the first request.
    pub fn new(dir: impl Into<PathBuf>, limit: u64) -> Self {
        Self {
            dir: dir.into(),
            limit,
            held: AtomicU64::new(0),
            first_seen: Mutex::new(HashMap::new()),
            completes: tokio::sync::Semaphore::new(MAX_COMPLETES),
            naming: tokio::sync::Mutex::new(()),
        }
    }

    /// Call once before the first request. A complete that a crash stopped gives its upload
    /// back, a removal that a crash stopped ends, and the parts on disk count. Returns the
    /// bytes that the parts hold.
    pub async fn start(&self) -> Result<u64, S3Error> {
        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(io(e)),
        };
        while let Some(entry) = entries.next_entry().await.map_err(io)? {
            let name = entry.file_name().to_string_lossy().into_owned();
            // A part that a crash stopped never got its name: the part before it stays. A part
            // that got its name before the removal of the part it replaced wins over it.
            if entry.file_type().await.map_err(io)?.is_dir() {
                remove_part_temps(&entry.path()).await?;
                keep_newest_parts(&entry.path()).await?;
            }
            // A marked complete may have committed: [`Uploads::settle`] decides with the engine.
            if let Some(id) = name.strip_suffix(Claim::Complete.suffix())
                && !entry.path().join(MARKER).exists()
            {
                tokio::fs::rename(entry.path(), self.dir.join(id))
                    .await
                    .map_err(io)?;
            } else if name.ends_with(Claim::Remove.suffix()) {
                remove_dir(&entry.path()).await?;
            }
        }
        self.rescan().await
    }

    /// Call after [`Uploads::start`], once the engine is open. A complete that a crash stopped
    /// after its mark ends here: its parts go when the engine holds its object, else its upload
    /// comes back for another complete.
    pub async fn settle<R: Remote + 'static>(&self, engine: &Engine<R>) -> Result<(), S3Error> {
        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io(e)),
        };
        while let Some(entry) = entries.next_entry().await.map_err(io)? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(Claim::Complete.suffix()) else {
                continue;
            };
            let claimed = entry.path();
            let marked = tokio::fs::read_to_string(claimed.join(MARKER))
                .await
                .map_err(io)?;
            let bytes = tokio::fs::read(claimed.join(META)).await.map_err(io)?;
            let meta: UploadMeta = postcard::from_bytes(&bytes)
                .map_err(|e| S3Error::internal(format!("{}: {e}", claimed.display())))?;
            let committed = match engine.head(&meta.bucket, &meta.key).await {
                Ok(info) => hex::encode(info.content_hash) == marked.trim(),
                Err(EngineError::NoSuchKey { .. } | EngineError::NoSuchBucket(_)) => false,
                Err(e) => return Err(e.into()),
            };
            info!(
                upload_id = id,
                committed, "ended a complete that a crash stopped"
            );
            match committed {
                true => {
                    self.remove(&claimed).await?;
                }
                false => self.unclaim(id, &claimed).await?,
            }
        }
        Ok(())
    }

    /// Writes the hash of the object that the complete of `claimed` commits next, durably: a
    /// start after a crash compares it with the engine.
    pub(crate) async fn mark(&self, claimed: &Path, content_hash: [u8; 32]) -> Result<(), S3Error> {
        let path = claimed.join(MARKER);
        let mut file = tokio::fs::File::create(&path).await.map_err(io)?;
        file.write_all(hex::encode(content_hash).as_bytes())
            .await
            .map_err(io)?;
        file.flush().await.map_err(io)?;
        file.sync_all().await.map_err(io)?;
        tokio::fs::File::open(claimed)
            .await
            .map_err(io)?
            .sync_all()
            .await
            .map_err(io)
    }

    /// A slot for one complete, or 503 SlowDown when [`MAX_COMPLETES`] run.
    pub(crate) fn complete_slot(&self) -> Result<tokio::sync::SemaphorePermit<'_>, S3Error> {
        self.completes.try_acquire().map_err(|_| {
            S3Error::new(
                "SlowDown",
                StatusCode::SERVICE_UNAVAILABLE,
                format!("{MAX_COMPLETES} completes run at once: try again"),
            )
        })
    }

    /// Sets the held bytes to the parts on disk, and returns them.
    async fn rescan(&self) -> Result<u64, S3Error> {
        let bytes = self.all_bytes().await?;
        self.held.store(bytes, Ordering::SeqCst);
        Ok(bytes)
    }

    /// Bytes that the parts hold.
    pub fn held(&self) -> u64 {
        self.held.load(Ordering::SeqCst)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    fn reserve(&self, bytes: u64) -> Result<(), S3Error> {
        let limit = self.limit;
        self.held
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                (held + bytes <= limit).then_some(held + bytes)
            })
            .map(|_| ())
            .map_err(|held| {
                S3Error::new(
                    "SlowDown",
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "multipart parts hold {held} bytes, and the limit is {limit} bytes \
                         (parts_limit_bytes): complete or abort the uploads"
                    ),
                )
            })
    }

    fn release(&self, bytes: u64) {
        let _ = self
            .held
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                Some(held.saturating_sub(bytes))
            });
    }

    /// The directory of an upload. Only 32 hex digits are an id, so no path can leave `dir`.
    fn upload_dir(&self, upload_id: &str) -> Result<PathBuf, S3Error> {
        if !is_upload_id(upload_id) {
            return Err(S3Error::no_such_upload(upload_id));
        }
        Ok(self.dir.join(upload_id))
    }

    async fn meta(&self, upload_id: &str, bucket: &str, key: &str) -> Result<UploadMeta, S3Error> {
        let path = self.upload_dir(upload_id)?.join(META);
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(S3Error::no_such_upload(upload_id));
            }
            Err(e) => return Err(io(e)),
        };
        let meta: UploadMeta = postcard::from_bytes(&bytes)
            .map_err(|e| S3Error::internal(format!("upload {upload_id}: {e}")))?;

        if meta.bucket != bucket || meta.key != key {
            return Err(S3Error::no_such_upload(upload_id));
        }

        Ok(meta)
    }

    pub(crate) async fn initiate(
        &self,
        bucket: &str,
        key: &str,
        metadata: BTreeMap<String, String>,
    ) -> Result<String, S3Error> {
        let initiated = unix_nanos();
        let mut hasher = blake3::Hasher::new();
        hasher
            .update(&initiated.to_le_bytes())
            .update(&COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes())
            .update(&std::process::id().to_le_bytes())
            .update(bucket.as_bytes())
            .update(key.as_bytes());
        let upload_id = hex::encode(&hasher.finalize().as_bytes()[..16]);

        let meta = UploadMeta {
            bucket: bucket.to_string(),
            key: key.to_string(),
            metadata,
            initiated,
        };
        let dir = self.upload_dir(&upload_id)?;
        tokio::fs::create_dir_all(&dir).await.map_err(io)?;
        let bytes = postcard::to_allocvec(&meta).expect("upload metadata always serializes");
        write_file(&dir, META, &bytes).await?;

        Ok(upload_id)
    }

    /// Starts a part whose body comes in pieces. The upload, the part number and the room of
    /// `declared` bytes are checked first, so a part that cannot be stored writes nothing.
    pub(crate) async fn begin_part(
        &self,
        upload_id: &str,
        (bucket, key): (&str, &str),
        number: &str,
        declared: u64,
    ) -> Result<PartWriter<'_>, S3Error> {
        let number: u16 = number
            .parse()
            .ok()
            .filter(|n| (1..=MAX_PART).contains(n))
            .ok_or_else(|| S3Error::invalid_argument("partNumber must be between 1 and 10000"))?;
        self.meta(upload_id, bucket, key).await?;
        let dir = self.upload_dir(upload_id)?;
        self.reserve(declared)?;
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!("{TEMP_PREFIX}{}.{seq}", std::process::id()));
        let file = match tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .await
        {
            Ok(file) => file,
            Err(e) => {
                self.release(declared);
                return Err(io(e));
            }
        };
        Ok(PartWriter {
            uploads: self,
            dir,
            number,
            tmp,
            file,
            hasher: blake3::Hasher::new(),
            len: 0,
            reserved: declared,
            named: false,
        })
    }

    /// Stores a part and returns its ETag. A part sent again replaces the old one.
    #[cfg(test)]
    pub(crate) async fn put_part(
        &self,
        upload_id: &str,
        bucket: &str,
        key: &str,
        number: &str,
        data: &[u8],
    ) -> Result<String, S3Error> {
        let mut part = self
            .begin_part(upload_id, (bucket, key), number, data.len() as u64)
            .await?;
        part.write(data).await?;
        part.finish().await
    }

    /// Takes an upload away from every other call: a rename of its directory. A second
    /// complete, abort or expiry of the same upload then finds no upload, so the bytes of the
    /// parts are freed once.
    pub(crate) async fn claim(
        &self,
        upload_id: &str,
        bucket: &str,
        key: &str,
        claim: Claim,
    ) -> Result<PathBuf, S3Error> {
        self.meta(upload_id, bucket, key).await?;
        self.take(upload_id, claim).await
    }

    async fn take(&self, upload_id: &str, claim: Claim) -> Result<PathBuf, S3Error> {
        // No part is between its rename and the removal of the part it replaces: a complete
        // never sees two parts of one number.
        let _naming = self.naming.lock().await;
        let from = self.upload_dir(upload_id)?;
        let to = self.dir.join(format!("{upload_id}{}", claim.suffix()));
        match tokio::fs::rename(&from, &to).await {
            Ok(()) => Ok(to),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(S3Error::no_such_upload(upload_id)),
            Err(e) => Err(io(e)),
        }
    }

    /// Gives a claimed upload back, after a complete that failed: the client can try again.
    pub(crate) async fn unclaim(&self, upload_id: &str, claimed: &Path) -> Result<(), S3Error> {
        match tokio::fs::remove_file(claimed.join(MARKER)).await {
            Err(e) if e.kind() != ErrorKind::NotFound => return Err(io(e)),
            _ => {}
        }
        // A mark that a crash brings back would let a later complete look committed.
        sync_dir(claimed).await?;
        tokio::fs::rename(claimed, self.upload_dir(upload_id)?)
            .await
            .map_err(io)
    }

    /// Removes a claimed upload and frees the bytes of its parts.
    pub(crate) async fn remove(&self, claimed: &Path) -> Result<u64, S3Error> {
        let parts = part_files(claimed).await?;
        let freed = parts.values().map(|(size, _)| size).sum();
        remove_dir(claimed).await?;
        self.release(freed);
        Ok(freed)
    }

    /// Removes the uploads with no initiate and no part for `max_age`, and frees their bytes.
    /// This process must also have seen the upload for `max_age` of its monotonic clock: a wall
    /// clock that steps forward does not expire a fresh upload. Returns the number of uploads
    /// and the bytes of their parts. An upload that fails is logged and kept for the next pass.
    pub async fn expire(&self, max_age: Duration) -> Result<(usize, u64), S3Error> {
        let cutoff = unix_nanos().saturating_sub(max_age.as_nanos() as u64);
        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(io(e)),
        };
        let mut ids = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(io)? {
            if let Some(id) = entry.file_name().to_str().filter(|name| is_upload_id(name)) {
                ids.push(id.to_string());
            }
        }
        let now = Instant::now();
        let (mut count, mut bytes) = (0, 0);
        for id in &ids {
            match self.expire_one(id, cutoff, now, max_age).await {
                Ok(Some(freed)) => {
                    count += 1;
                    bytes += freed;
                }
                Ok(None) => {}
                Err(e) => warn!(upload_id = id, %e, "an upload did not expire: next pass"),
            }
        }
        self.seen().retain(|id, _| ids.contains(id));
        self.rescan().await?;
        Ok((count, bytes))
    }

    async fn expire_one(
        &self,
        upload_id: &str,
        cutoff: u64,
        now: Instant,
        max_age: Duration,
    ) -> Result<Option<u64>, S3Error> {
        let dir = self.upload_dir(upload_id)?;
        // An initiate writes the directory, then the meta: with no meta, it is in progress.
        let meta = match tokio::fs::read(dir.join(META)).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let initiated = postcard::from_bytes::<UploadMeta>(&meta)
            .map_err(|e| S3Error::internal(format!("upload {upload_id}: {e}")))?
            .initiated;
        let last = part_files(&dir)
            .await?
            .values()
            .map(|(_, time)| *time)
            .fold(initiated, u64::max);
        let first_seen = *self.seen().entry(upload_id.to_string()).or_insert(now);
        if last >= cutoff || now.duration_since(first_seen) < max_age {
            return Ok(None);
        }
        let claimed = match self.take(upload_id, Claim::Remove).await {
            Ok(claimed) => claimed,
            // A complete or an abort took it first.
            Err(e) if e.code == "NoSuchUpload" => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(Some(self.remove(&claimed).await?))
    }

    fn seen(&self) -> std::sync::MutexGuard<'_, HashMap<String, Instant>> {
        self.first_seen
            .lock()
            .expect("no panic while the lock is held")
    }

    /// Bytes that the parts of all uploads hold on disk.
    pub(crate) async fn all_bytes(&self) -> Result<u64, S3Error> {
        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(io(e)),
        };
        let mut total = 0;
        while let Some(entry) = entries.next_entry().await.map_err(io)? {
            if !entry.file_type().await.map_err(io)?.is_dir() {
                continue;
            }
            let parts = part_files(&entry.path()).await?;
            total += parts.values().map(|(size, _)| size).sum::<u64>();
        }
        Ok(total)
    }

    pub(crate) async fn parts(
        &self,
        upload_id: &str,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<PartInfo>, S3Error> {
        self.meta(upload_id, bucket, key).await?;
        let dir = self.upload_dir(upload_id)?;
        let mut out = Vec::new();

        for ((number, etag), (size, time)) in part_files(&dir).await? {
            out.push((number, size, etag, time));
        }

        Ok(out)
    }

    /// Aborting an upload that does not exist is not an error, as in S3.
    pub(crate) async fn abort(
        &self,
        upload_id: &str,
        bucket: &str,
        key: &str,
    ) -> Result<(), S3Error> {
        match self.claim(upload_id, bucket, key, Claim::Remove).await {
            Ok(claimed) => self.remove(&claimed).await.map(|_| ()),
            Err(e) if e.code == "NoSuchUpload" => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Checks the requested parts, in ascending order, each with the ETag it was given, and
    /// gives their files and their size. Refuses when they hold more than `limit` bytes together.
    /// Reads no part.
    pub(crate) async fn plan(
        &self,
        claimed: &Path,
        requested: &[(u16, String)],
        limit: u64,
    ) -> Result<CompletePlan, S3Error> {
        let bytes = tokio::fs::read(claimed.join(META)).await.map_err(io)?;
        let meta: UploadMeta = postcard::from_bytes(&bytes)
            .map_err(|e| S3Error::internal(format!("{}: {e}", claimed.display())))?;

        if requested.is_empty() {
            return Err(S3Error::malformed_xml());
        }
        if requested.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(S3Error::new(
                "InvalidPartOrder",
                StatusCode::BAD_REQUEST,
                "the parts are not in ascending order",
            ));
        }

        let dir = claimed;
        let stored: BTreeMap<u16, (String, u64)> = part_files(dir)
            .await?
            .into_iter()
            .map(|((number, etag), (len, _))| (number, (etag, len)))
            .collect();

        let mut size = 0u64;
        for (number, etag) in requested {
            match stored.get(number) {
                Some((stored_etag, len)) if stored_etag == etag => size += len,
                _ => {
                    return Err(S3Error::new(
                        "InvalidPart",
                        StatusCode::BAD_REQUEST,
                        format!("part {number} is missing or has another ETag"),
                    ));
                }
            }
        }
        if size > limit {
            return Err(S3Error::new(
                "EntityTooLarge",
                StatusCode::BAD_REQUEST,
                format!("the parts hold {size} bytes, over the limit of {limit} bytes"),
            ));
        }

        Ok(CompletePlan {
            parts: requested
                .iter()
                .map(|(number, etag)| dir.join(part_name(*number, etag)))
                .collect(),
            size,
            metadata: meta.metadata,
        })
    }

    /// Uploads in progress for `bucket`: key, id, initiation time.
    pub(crate) async fn list(&self, bucket: &str) -> Result<Vec<(String, String, u64)>, S3Error> {
        let mut out = Vec::new();
        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(io(e)),
        };

        while let Some(entry) = entries.next_entry().await.map_err(io)? {
            let Some(upload_id) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(bytes) = tokio::fs::read(entry.path().join(META)).await else {
                continue;
            };
            let Ok(meta) = postcard::from_bytes::<UploadMeta>(&bytes) else {
                continue;
            };
            if meta.bucket == bucket {
                out.push((meta.key, upload_id, meta.initiated));
            }
        }

        out.sort();
        Ok(out)
    }
}

fn part_name(number: u16, etag: &str) -> String {
    format!("{number:05}-{etag}")
}

/// Every part in an upload directory: (number, ETag) to (size, modification time).
async fn part_files(dir: &Path) -> Result<BTreeMap<(u16, String), (u64, u64)>, S3Error> {
    let mut out = BTreeMap::new();
    let mut entries = tokio::fs::read_dir(dir).await.map_err(io)?;

    while let Some(entry) = entries.next_entry().await.map_err(io)? {
        let name = entry.file_name();
        let Some((number, etag)) = name.to_str().and_then(|n| n.split_once('-')) else {
            continue;
        };
        let Ok(number) = number.parse::<u16>() else {
            continue;
        };
        let metadata = entry.metadata().await.map_err(io)?;
        let time = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos() as u64);
        out.insert((number, etag.to_string()), (metadata.len(), time));
    }

    Ok(out)
}

/// Writes a temporary file, then renames it: a reader never sees a partial file.
async fn write_file(dir: &Path, name: &str, data: &[u8]) -> Result<(), S3Error> {
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!("{TEMP_PREFIX}{}.{seq}", std::process::id()));
    let mut file = tokio::fs::File::create(&tmp).await.map_err(io)?;
    file.write_all(data).await.map_err(io)?;
    file.flush().await.map_err(io)?;
    tokio::fs::rename(&tmp, dir.join(name)).await.map_err(io)
}

async fn remove_if_present(path: &Path) -> Result<(), S3Error> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(e)),
    }
}

/// Keeps one part per part number in `dir`: the newest by modification time. A crash after the
/// rename of a part and before the removal of the part it replaced leaves two.
async fn keep_newest_parts(dir: &Path) -> Result<(), S3Error> {
    let mut newest: BTreeMap<u16, (u64, String)> = BTreeMap::new();
    let mut older = Vec::new();
    for ((number, etag), (_, time)) in part_files(dir).await? {
        let name = part_name(number, &etag);
        match newest.get(&number) {
            Some((kept, _)) if *kept >= time => older.push(name),
            _ => {
                if let Some((_, replaced)) = newest.insert(number, (time, name)) {
                    older.push(replaced);
                }
            }
        }
    }
    for name in older {
        warn!(part = name, dir = %dir.display(), "removed a part that a newer one replaced");
        remove_if_present(&dir.join(name)).await?;
    }
    Ok(())
}

/// Removes the files of `dir` that never got their name.
async fn remove_part_temps(dir: &Path) -> Result<(), S3Error> {
    let mut entries = tokio::fs::read_dir(dir).await.map_err(io)?;
    while let Some(entry) = entries.next_entry().await.map_err(io)? {
        if entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            remove_if_present(&entry.path()).await?;
        }
    }
    Ok(())
}

async fn sync_dir(dir: &Path) -> Result<(), S3Error> {
    tokio::fs::File::open(dir)
        .await
        .map_err(io)?
        .sync_all()
        .await
        .map_err(io)
}

/// A part whose body goes to a temporary file in its upload directory. Dropped before it takes
/// its name, it removes the file and gives its room back.
pub(crate) struct PartWriter<'a> {
    uploads: &'a Uploads,
    dir: PathBuf,
    number: u16,
    tmp: PathBuf,
    file: tokio::fs::File,
    hasher: blake3::Hasher,
    len: u64,
    /// Room of the parts limit taken at the start, for the declared body.
    reserved: u64,
    named: bool,
}

impl PartWriter<'_> {
    /// The bytes that count against the parts limit.
    fn counted(&self) -> u64 {
        self.len.max(self.reserved)
    }

    /// Writes one piece. Only the bytes past the room taken at the start need more room.
    pub(crate) async fn write(&mut self, piece: &[u8]) -> Result<(), S3Error> {
        let size = self.len + piece.len() as u64;
        let extra = size.saturating_sub(self.counted());
        self.uploads.reserve(extra)?;
        if let Err(e) = self.file.write_all(piece).await {
            self.uploads.release(extra);
            return Err(io(e));
        }
        self.hasher.update(piece);
        self.len = size;
        Ok(())
    }

    /// Fsyncs the part, then gives it its name, which replaces a part of the same number, and
    /// fsyncs the directory. Returns its ETag: the blake3 hash made as the part was written.
    pub(crate) async fn finish(mut self) -> Result<String, S3Error> {
        // A tokio file drops a failed background write on sync: only flush returns it.
        self.file.flush().await.map_err(io)?;
        self.file.sync_all().await.map_err(io)?;
        let etag = self.hasher.finalize().to_hex().to_string();
        let name = part_name(self.number, &etag);
        engine::sim::crash_point(engine::sim::Point::PartRename)?;
        let _naming = self.uploads.naming.lock().await;
        let old: Vec<(String, u64)> = part_files(&self.dir)
            .await?
            .into_iter()
            .filter(|((number, _), _)| *number == self.number)
            .map(|((number, etag), (size, _))| (part_name(number, &etag), size))
            .collect();
        tokio::fs::rename(&self.tmp, self.dir.join(&name))
            .await
            .map_err(io)?;
        // The part holds its length now; the room past it comes back.
        self.named = true;
        self.uploads.release(self.counted() - self.len);
        self.len = 0;
        self.reserved = 0;
        engine::sim::crash_point(engine::sim::Point::PartReplace)?;
        for (old_name, size) in &old {
            if *old_name != name {
                remove_if_present(&self.dir.join(old_name)).await?;
            }
            // The rename replaced a part of the same name.
            self.uploads.release(*size);
        }
        sync_dir(&self.dir).await?;
        Ok(etag)
    }
}

impl Drop for PartWriter<'_> {
    fn drop(&mut self) {
        if !self.named {
            let _ = std::fs::remove_file(&self.tmp);
        }
        self.uploads.release(self.counted());
    }
}

async fn remove_dir(path: &Path) -> Result<(), S3Error> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn uploads() -> (tempfile::TempDir, Uploads) {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new(dir.path(), u64::MAX);
        (dir, uploads)
    }

    /// Claims the upload, plans the complete, reads the planned parts in order, and gives the
    /// upload back.
    async fn join(
        uploads: &Uploads,
        id: &str,
        requested: &[(u16, String)],
        limit: u64,
    ) -> Result<Vec<u8>, S3Error> {
        let claimed = uploads.claim(id, "b", "k", Claim::Complete).await?;
        let joined = uploads.plan(&claimed, requested, limit).await.map(|plan| {
            let data: Vec<u8> = plan
                .parts
                .iter()
                .flat_map(|part| std::fs::read(part).unwrap())
                .collect();
            assert_eq!(data.len() as u64, plan.size);
            data
        });
        uploads.unclaim(id, &claimed).await.unwrap();
        joined
    }

    #[tokio::test]
    async fn test_part_whose_last_write_fails_gets_no_name() {
        let (_dir, uploads) = uploads().await;
        let id = uploads.initiate("b", "k", BTreeMap::new()).await.unwrap();
        let mut part = uploads.begin_part(&id, ("b", "k"), "1", 12).await.unwrap();
        part.write(b"hello ").await.unwrap();
        // A read-only handle fails the next write in the background, as a full disk does.
        part.file = tokio::fs::File::open(&part.tmp).await.unwrap();
        part.write(b"world!").await.unwrap();

        let finished = part.finish().await;

        assert!(finished.is_err(), "a short part got the ETag {finished:?}");
        let parts = uploads.parts(&id, "b", "k").await.unwrap();
        assert!(parts.is_empty(), "{parts:?}");
    }

    #[tokio::test]
    async fn test_parts_over_the_limit_are_refused_before_a_read() {
        let (_dir, uploads) = uploads().await;
        let id = uploads.initiate("b", "k", BTreeMap::new()).await.unwrap();
        let first = uploads
            .put_part(&id, "b", "k", "1", b"hello ")
            .await
            .unwrap();
        let second = uploads
            .put_part(&id, "b", "k", "2", b"world")
            .await
            .unwrap();

        let result = join(&uploads, &id, &[(1, first), (2, second)], 10).await;

        let Err(error) = result else {
            panic!("11 bytes over a limit of 10 are joined");
        };
        assert_eq!(error.code, "EntityTooLarge");
        assert_eq!(uploads.parts(&id, "b", "k").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_parts_join_in_the_requested_order() {
        let (_dir, uploads) = uploads().await;
        let id = uploads.initiate("b", "k", BTreeMap::new()).await.unwrap();
        let second = uploads
            .put_part(&id, "b", "k", "2", b"world")
            .await
            .unwrap();
        let first = uploads
            .put_part(&id, "b", "k", "1", b"hello ")
            .await
            .unwrap();

        let joined = join(&uploads, &id, &[(1, first), (2, second)], u64::MAX)
            .await
            .unwrap();

        assert_eq!(joined, b"hello world");
        assert_eq!(uploads.parts(&id, "b", "k").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_part_sent_again_replaces_the_old_one() {
        let (_dir, uploads) = uploads().await;
        let id = uploads.initiate("b", "k", BTreeMap::new()).await.unwrap();
        let old = uploads.put_part(&id, "b", "k", "1", b"old").await.unwrap();
        let new = uploads.put_part(&id, "b", "k", "1", b"new").await.unwrap();

        let parts = uploads.parts(&id, "b", "k").await.unwrap();
        let stale = join(&uploads, &id, &[(1, old)], u64::MAX).await;

        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].2, new);
        assert_eq!(stale.err().unwrap().code, "InvalidPart");
    }

    #[tokio::test]
    async fn test_bad_requests_are_rejected() {
        let (_dir, uploads) = uploads().await;
        let id = uploads.initiate("b", "k", BTreeMap::new()).await.unwrap();
        let etag = uploads.put_part(&id, "b", "k", "1", b"x").await.unwrap();
        let code = |r: Result<Vec<u8>, S3Error>| r.err().unwrap().code;

        assert_eq!(
            code(join(&uploads, &id, &[(2, etag.clone()), (1, etag)], u64::MAX).await),
            "InvalidPartOrder"
        );
        let other = uploads.claim(&id, "b", "other", Claim::Complete).await;
        assert_eq!(other.err().unwrap().code, "NoSuchUpload");
        assert_eq!(
            uploads
                .put_part(&id, "b", "k", "0", b"x")
                .await
                .err()
                .unwrap()
                .code,
            "InvalidArgument"
        );
        assert_eq!(
            uploads
                .put_part("../../etc", "b", "k", "1", b"x")
                .await
                .err()
                .unwrap()
                .code,
            "NoSuchUpload"
        );
    }

    #[tokio::test]
    async fn test_abort_and_list() {
        let (_dir, uploads) = uploads().await;
        let a = uploads.initiate("b", "k1", BTreeMap::new()).await.unwrap();
        uploads
            .initiate("other", "k2", BTreeMap::new())
            .await
            .unwrap();

        let listed = uploads.list("b").await.unwrap();
        uploads.abort(&a, "b", "k1").await.unwrap();
        uploads.abort(&a, "b", "k1").await.unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1, a);
        assert!(uploads.list("b").await.unwrap().is_empty());
        assert_eq!(
            uploads.parts(&a, "b", "k1").await.err().unwrap().code,
            "NoSuchUpload"
        );
    }

    #[tokio::test]
    async fn test_expire_removes_idle_uploads_and_frees_their_bytes() {
        let (_dir, uploads) = uploads().await;
        let old = uploads.initiate("b", "old", BTreeMap::new()).await.unwrap();
        uploads
            .put_part(&old, "b", "old", "1", b"12345")
            .await
            .unwrap();
        let young = uploads
            .initiate("b", "young", BTreeMap::new())
            .await
            .unwrap();
        uploads
            .put_part(&young, "b", "young", "1", b"xy")
            .await
            .unwrap();

        let kept = uploads.expire(Duration::from_secs(3600)).await.unwrap();
        let held = uploads.held();
        let freed = uploads.expire(Duration::ZERO).await.unwrap();

        assert_eq!(kept, (0, 0), "a part in the last hour keeps its upload");
        assert_eq!(held, 7);
        assert_eq!(freed, (2, 7));
        assert_eq!(uploads.held(), 0);
        assert!(uploads.list("b").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_expire_skips_an_upload_with_no_meta_and_goes_on_after_an_error() {
        let (dir, uploads) = uploads().await;
        let starting = dir.path().join("0".repeat(32));
        std::fs::create_dir_all(&starting).unwrap();
        let broken = uploads
            .initiate("b", "broken", BTreeMap::new())
            .await
            .unwrap();
        std::fs::write(dir.path().join(&broken).join(META), b"not postcard").unwrap();
        let idle = uploads
            .initiate("b", "idle", BTreeMap::new())
            .await
            .unwrap();
        uploads
            .put_part(&idle, "b", "idle", "1", b"xyz")
            .await
            .unwrap();

        let expired = uploads.expire(Duration::ZERO).await.unwrap();

        assert_eq!(expired, (1, 3));
        assert!(starting.exists(), "an initiate in progress stays");
        assert!(
            dir.path().join(&broken).exists(),
            "a failed upload stays for the next pass"
        );
    }

    #[tokio::test]
    async fn test_expire_waits_for_the_monotonic_clock_too() {
        let (_dir, uploads) = uploads().await;
        let id = uploads.initiate("b", "k", BTreeMap::new()).await.unwrap();
        let max_age = Duration::from_millis(100);
        // The wall age passes max_age before this process first looks.
        tokio::time::sleep(max_age * 2).await;

        let first = uploads.expire(max_age).await.unwrap();
        tokio::time::sleep(max_age * 2).await;
        let second = uploads.expire(max_age).await.unwrap();

        assert_eq!(first, (0, 0), "seen for the first time: kept");
        assert_eq!(second, (1, 0));
        assert!(uploads.parts(&id, "b", "k").await.is_err());
    }

    #[tokio::test]
    async fn test_start_gives_back_a_complete_that_a_crash_stopped() {
        let (dir, uploads) = uploads().await;
        let id = uploads.initiate("b", "k", BTreeMap::new()).await.unwrap();
        uploads
            .put_part(&id, "b", "k", "1", b"12345")
            .await
            .unwrap();
        uploads.claim(&id, "b", "k", Claim::Complete).await.unwrap();
        let gone = uploads
            .initiate("b", "gone", BTreeMap::new())
            .await
            .unwrap();
        uploads
            .claim(&gone, "b", "gone", Claim::Remove)
            .await
            .unwrap();

        let held = uploads.start().await.unwrap();

        assert_eq!(held, 5);
        assert_eq!(uploads.parts(&id, "b", "k").await.unwrap().len(), 1);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
