//! Local write-back buffer: an append-only log on NVMe, cut into segments.
//!
//! A write is acknowledged once its record is fsynced. Writes that wait while
//! one fsync runs share the next one (group fsync). A flush seals the
//! segments, uploads their records, and deletes the segments once the journal
//! entry that covers them is in the remote. An intent file holds that entry
//! between its signature and the deletion, so a restart never writes it twice.
//!
//! Record layout:
//!
//! ```text
//! head_len u32 LE | data_len u64 LE | blake3(head) | head (postcard Head) | data
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, SeekFrom};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use journal::Entry;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tracing::{debug, warn};

use crate::EngineError;

/// The data length before the data, then the head length and the head hash after it.
const DATA_LEN_LEN: usize = 8;
const HEAD_PREFIX_LEN: usize = 4 + 32;

/// Larger heads are garbage: keys, bucket names and metadata are small.
const MAX_HEAD_LEN: u32 = 64 * 1024;

/// Larger data is garbage: an S3 PUT holds 5 GiB at most.
pub(crate) const MAX_DATA_LEN: u64 = 5 << 30;
/// The largest piece of data that a read of the buffer holds at once.
const READ_PIECE: u64 = 1 << 20;

const SEGMENT_SUFFIX: &str = ".log";

/// The record format of this build. Segments of another format must not decode.
const FORMAT: u32 = 3;
const FORMAT_FILE: &str = "format";
const INTENT_FILE: &str = "intent";
const INTENT_TEMP: &str = ".intent.tmp";
/// Puts that stream their body write it here first. A spool file becomes a segment at its commit.
pub(crate) const SPOOL_DIR: &str = "spool";

/// Refuses a buffer directory of another record format. A directory with segments or an intent
/// and no format file comes from format 1. An empty directory gets the format of this build,
/// durable before the first segment exists.
async fn check_format(dir: &Path, has_segments: bool) -> Result<(), EngineError> {
    let path = dir.join(FORMAT_FILE);
    let has_data = has_segments || tokio::fs::try_exists(dir.join(INTENT_FILE)).await?;
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound && has_data => "1".to_string(),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return write_durable(dir, &path, format!("{FORMAT}\n").as_bytes()).await;
        }
        Err(e) => return Err(e.into()),
    };
    match text.trim().parse::<u32>() {
        Ok(FORMAT) => Ok(()),
        Ok(found) => Err(EngineError::Corrupt(format!(
            "{}: the buffer has record format {found}, this build reads format {FORMAT}. Start \
             the build that wrote it, stop it with SIGTERM (it flushes the buffer before it \
             exits, and exits 0 when the buffer is empty), then start this build",
            dir.display()
        ))),
        Err(_) => Err(EngineError::Corrupt(format!(
            "{}: the format file does not read. If this build wrote the buffer, write {FORMAT} \
             into it and start again. If another build wrote it, start that build and let it \
             flush the buffer",
            path.display()
        ))),
    }
}

pub(crate) fn unix_nanos() -> u64 {
    journal::wall_clock_nanos()
}

/// The fixed part of a record. The data of a put follows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Head {
    /// HLC of the ack, in unix nanoseconds: never under an earlier ack of this proxy.
    pub time: u64,
    pub op: Op,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Op {
    Put {
        bucket: String,
        key: String,
        metadata: BTreeMap<String, String>,
        content_hash: [u8; 32],
    },
    Delete {
        bucket: String,
        key: String,
    },
    CreateBucket {
        bucket: String,
        owner: Option<String>,
    },
    DeleteBucket {
        bucket: String,
    },
}

/// Refuses a head that the replay would refuse: it would block the flush for ever.
pub(crate) fn check_head(head: &Head) -> Result<(), EngineError> {
    let head_len = postcard::to_allocvec(head)
        .expect("a record head always serializes")
        .len() as u64;
    if head_len > u64::from(MAX_HEAD_LEN) {
        return Err(EngineError::MetadataTooLarge {
            size: head_len,
            limit: u64::from(MAX_HEAD_LEN),
        });
    }
    Ok(())
}

/// Encodes a record: the data length, the data, then the head length, the head hash and the head.
/// A streamed put knows its head only at the end. Pure, so the format has a golden test.
pub(crate) fn encode_record(head: &Head, data: &[u8]) -> Vec<u8> {
    let tail = encode_head(head);
    let mut out = Vec::with_capacity(DATA_LEN_LEN + data.len() + tail.len());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&tail);
    out
}

/// The part of a record after its data: the head length, the head hash and the head.
pub(crate) fn encode_head(head: &Head) -> Vec<u8> {
    let head_bytes = postcard::to_allocvec(head).expect("a record head always serializes");
    let head_len = u32::try_from(head_bytes.len()).expect("a record head is smaller than 4 GiB");
    let mut out = Vec::with_capacity(HEAD_PREFIX_LEN + head_bytes.len());
    out.extend_from_slice(&head_len.to_le_bytes());
    out.extend_from_slice(blake3::hash(&head_bytes).as_bytes());
    out.extend_from_slice(&head_bytes);
    out
}

/// A record read back from a segment.
pub(crate) struct Record {
    pub head: Head,
    /// Position of the data in the segment file, and its length.
    pub data_offset: u64,
    pub data_len: u64,
    /// Where the record starts and ends in the segment file.
    pub span: Range<u64>,
    /// The blake3 hash of the head bytes: the identity of the record.
    pub head_hash: [u8; 32],
}

pub(crate) enum Read {
    Record(Record),
    End,
    /// The head is missing, short or fails its hash. `next` is where the next record would start,
    /// when the lengths stay inside the file.
    BadHead {
        start: u64,
        next: Option<u64>,
    },
    /// The head is valid and the data does not match it: the put may have been acknowledged.
    BadData(Record),
}

/// Reads the records of one segment in order.
pub(crate) struct SegmentReader {
    file: BufReader<File>,
    offset: u64,
    len: u64,
}

impl SegmentReader {
    pub async fn open(path: &Path) -> Result<Self, EngineError> {
        Self::open_at(path, 0).await
    }

    /// A reader whose first record starts at `offset`.
    pub async fn open_at(path: &Path, offset: u64) -> Result<Self, EngineError> {
        let mut file = File::open(path).await?;
        let len = file.metadata().await?.len();
        file.seek(SeekFrom::Start(offset.min(len))).await?;

        Ok(Self {
            file: BufReader::new(file),
            offset: offset.min(len),
            len,
        })
    }

    /// Next record, or `None` at the end. A torn or corrupt record is an error.
    pub async fn next(&mut self, path: &Path) -> Result<Option<Record>, EngineError> {
        match self.read().await? {
            Read::Record(record) => Ok(Some(record)),
            Read::End => Ok(None),
            Read::BadHead { start, .. } => Err(EngineError::Corrupt(format!(
                "{}: invalid record at offset {start}",
                path.display()
            ))),
            Read::BadData(record) => Err(EngineError::Corrupt(format!(
                "{}: the data of {} at offset {} does not match its head",
                path.display(),
                record.head.op.target(),
                record.span.start
            ))),
        }
    }

    /// Next record of a quarantine file, with `true` when its data does not match its head.
    pub async fn next_held(&mut self, path: &Path) -> Result<Option<(Record, bool)>, EngineError> {
        match self.read().await? {
            Read::Record(record) => Ok(Some((record, false))),
            Read::BadData(record) => Ok(Some((record, true))),
            Read::End => Ok(None),
            Read::BadHead { start, .. } => Err(EngineError::Corrupt(format!(
                "{}: invalid record at offset {start}",
                path.display()
            ))),
        }
    }

    /// The next record. Each length is checked against the file and a limit before any
    /// allocation: a length from a file that a crash cut is not trusted.
    pub async fn read(&mut self) -> Result<Read, EngineError> {
        let start = self.offset;
        if start == self.len {
            return Ok(Read::End);
        }
        let bad = |next| Ok(Read::BadHead { start, next });

        let mut len = [0u8; DATA_LEN_LEN];
        if !read_full(&mut self.file, &mut len).await? {
            return bad(None);
        }
        let data_len = u64::from_le_bytes(len);
        let remaining = self.len - start - DATA_LEN_LEN as u64;
        let fits = data_len
            .checked_add(HEAD_PREFIX_LEN as u64)
            .is_some_and(|len| len <= remaining);
        if data_len > MAX_DATA_LEN || !fits {
            return bad(None);
        }
        // The data is hashed in pieces: the memory of a read does not grow with the record.
        let mut hasher = blake3::Hasher::new();
        let mut piece = vec![0u8; data_len.min(READ_PIECE) as usize];
        let mut left = data_len;
        while left > 0 {
            let size = left.min(READ_PIECE) as usize;
            if !read_full(&mut self.file, &mut piece[..size]).await? {
                return bad(None);
            }
            hasher.update(&piece[..size]);
            left -= size as u64;
        }
        let mut prefix = [0u8; HEAD_PREFIX_LEN];
        if !read_full(&mut self.file, &mut prefix).await? {
            return bad(None);
        }
        let head_len = u32::from_le_bytes(prefix[..4].try_into().expect("4 bytes"));
        let head_hash: [u8; 32] = prefix[4..].try_into().expect("32 bytes");
        let fits = u64::from(head_len) <= remaining - data_len - HEAD_PREFIX_LEN as u64;
        if head_len > MAX_HEAD_LEN || !fits {
            return bad(None);
        }
        let mut head_bytes = vec![0u8; head_len as usize];
        if !read_full(&mut self.file, &mut head_bytes).await? {
            return bad(None);
        }

        let data_offset = start + DATA_LEN_LEN as u64;
        let end = data_offset + data_len + HEAD_PREFIX_LEN as u64 + u64::from(head_len);
        self.offset = end;
        let Some(head) = decode_head(&head_hash, &head_bytes) else {
            return bad(Some(end));
        };
        let record = Record {
            head,
            data_offset,
            data_len,
            span: start..end,
            head_hash,
        };
        match data_matches(&record.head, data_len, hasher.finalize().as_bytes()) {
            true => Ok(Read::Record(record)),
            false => Ok(Read::BadData(record)),
        }
    }
}

/// A record with a valid head and data that does not match it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BadRecord {
    pub segment: u64,
    pub span: Range<u64>,
    pub head_hash: [u8; 32],
    /// `bucket/key`, or a bucket name.
    pub target: String,
}

/// True when a record with a valid head starts at `offset`: then a bad head before it is damage
/// in the middle of the segment, not a torn tail.
async fn head_at(path: &Path, offset: Option<u64>) -> Result<bool, EngineError> {
    let Some(offset) = offset else {
        return Ok(false);
    };
    let mut reader = SegmentReader::open_at(path, offset).await?;
    Ok(matches!(
        reader.read().await?,
        Read::Record(_) | Read::BadData(_)
    ))
}

/// A record whose head does not read: its key is unknown, and the records after it cannot be
/// found. The start stops with the steps of the operator.
fn corrupt_head(path: &Path, start: u64) -> EngineError {
    EngineError::Corrupt(format!(
        "{}: corrupt record at offset {start}, key unknown. The proxy does not start. \
         docs/storage.md (A record whose head does not read) gives the steps: copy the segment \
         aside, cut it at offset {start}; the records from that offset to the end of the segment \
         are lost from the buffer",
        path.display()
    ))
}

/// The head, when its hash matches and it decodes.
fn decode_head(head_hash: &[u8; 32], head_bytes: &[u8]) -> Option<Head> {
    if blake3::hash(head_bytes).as_bytes() != head_hash {
        return None;
    }
    postcard::from_bytes(head_bytes).ok()
}

/// A put matches the hash in its head; any other op has no data.
fn data_matches(head: &Head, data_len: u64, data_hash: &[u8; 32]) -> bool {
    match &head.op {
        Op::Put { content_hash, .. } => data_hash == content_hash,
        _ => data_len == 0,
    }
}

/// The data of `record`, read again from its segment.
pub(crate) async fn read_record_data(path: &Path, record: &Record) -> Result<Vec<u8>, EngineError> {
    let mut file = File::open(path).await?;
    file.seek(SeekFrom::Start(record.data_offset)).await?;
    let mut data = vec![0u8; record.data_len as usize];
    file.read_exact(&mut data).await?;
    Ok(data)
}

/// Fills `buf`. Returns `false` when the file ends first.
async fn read_full(reader: &mut (impl AsyncRead + Unpin), buf: &mut [u8]) -> std::io::Result<bool> {
    match reader.read_exact(buf).await {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// A buffered put, readable before the flush.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BufferedPut {
    pub segment: u64,
    pub data_offset: u64,
    pub size: u64,
    pub content_hash: [u8; 32],
    pub metadata: BTreeMap<String, String>,
    pub time: u64,
}

impl Op {
    /// `bucket/key`, or the bucket name: what the record writes.
    pub(crate) fn target(&self) -> String {
        match self {
            Op::Put { bucket, key, .. } | Op::Delete { bucket, key } => format!("{bucket}/{key}"),
            Op::CreateBucket { bucket, .. } | Op::DeleteBucket { bucket } => bucket.clone(),
        }
    }
}

/// The last buffered write to one key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BufferedObject {
    Put(BufferedPut),
    Delete { segment: u64, time: u64 },
}

impl BufferedObject {
    fn segment(&self) -> u64 {
        match self {
            Self::Put(put) => put.segment,
            Self::Delete { segment, .. } => *segment,
        }
    }
}

/// The last buffered write to one bucket name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BufferedBucket {
    pub segment: u64,
    pub exists: bool,
    pub owner: Option<String>,
    pub time: u64,
}

/// What a flush must commit, and the segments to delete once it is in the remote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Intent {
    pub entry: Entry,
    pub segments: Vec<u64>,
    /// Monotonic nanoseconds of this process when the flush started its plan. A plan older
    /// than H/2 is never committed; an intent of another process is never committed either.
    pub planned_at: u64,
}

/// What a replay does with a record that does not read back whole.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnInvalid {
    /// Cut the segment there: the record was never acknowledged.
    CutTail,
    /// Stop: a sealed segment is complete, so the damage is corruption.
    Refuse,
}

struct Active {
    seq: u64,
    file: File,
    len: u64,
    /// Bytes known to be on disk.
    durable_len: u64,
    /// A second open of the segment. Linux reports an fsync error to each open file, not to each fd.
    sync: Arc<std::fs::File>,
}

/// The state of a record. Records get numbers from 1 in write order. Replayed records get 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Durability {
    Durable,
    Pending,
    /// A failed fsync dropped the record.
    Lost,
}

/// One fsync of the active segment, run outside the buffer lock.
pub(crate) struct SyncJob {
    seq: u64,
    len: u64,
    /// The last record that this fsync covers.
    target: u64,
    file: Arc<std::fs::File>,
    #[cfg(test)]
    fail: bool,
}

impl SyncJob {
    pub async fn run(&self) -> std::io::Result<()> {
        #[cfg(test)]
        if self.fail {
            return Err(std::io::Error::other("injected fsync failure"));
        }

        let file = Arc::clone(&self.file);
        tokio::task::spawn_blocking(move || file.sync_data())
            .await
            .map_err(std::io::Error::other)?
    }
}

pub(crate) struct Buffer {
    dir: PathBuf,
    segment_target: u64,
    active: Active,
    /// Sealed segments and their sizes. A sealed segment is on disk.
    sealed: BTreeMap<u64, u64>,
    objects: BTreeMap<(String, String), BufferedObject>,
    buckets: BTreeMap<String, BufferedBucket>,
    /// The lowest ack HLC in each segment that holds records.
    oldest: BTreeMap<u64, u64>,
    written: u64,
    durable: u64,
    lost: Vec<Range<u64>>,
    /// A failed fsync that the buffer could not repair. Only a restart reads the disk again.
    broken: bool,
    /// Records of the replay with a valid head and bad data.
    bad_data: Vec<BadRecord>,
    #[cfg(test)]
    pub syncs: u64,
    #[cfg(test)]
    pub fail_next_sync: bool,
}

impl Buffer {
    /// Opens the buffer in `dir` and replays the segments a previous process left.
    /// A torn record at the end of the last segment is cut off: it was never acknowledged.
    pub async fn open(dir: impl Into<PathBuf>, segment_target: u64) -> Result<Self, EngineError> {
        let dir = dir.into();
        tokio::fs::create_dir_all(&dir).await?;

        let existing = list_segments(&dir).await?;
        check_format(&dir, !existing.is_empty()).await?;
        // A spool file of a put that a crash stopped was never acknowledged.
        let spool = dir.join(SPOOL_DIR);
        match tokio::fs::remove_dir_all(&spool).await {
            Err(e) if e.kind() != ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        tokio::fs::create_dir_all(&spool).await?;
        let mut buffer = Self {
            active: create_segment(&dir, existing.last().map_or(0, |last| last + 1)).await?,
            dir,
            segment_target,
            sealed: BTreeMap::new(),
            objects: BTreeMap::new(),
            buckets: BTreeMap::new(),
            written: 0,
            oldest: BTreeMap::new(),
            durable: 0,
            lost: Vec::new(),
            broken: false,
            bad_data: Vec::new(),
            #[cfg(test)]
            syncs: 0,
            #[cfg(test)]
            fail_next_sync: false,
        };

        for (i, &seq) in existing.iter().enumerate() {
            // Only the last segment can end in a torn record: a crash cut its last write.
            let on_invalid = match i + 1 == existing.len() {
                true => OnInvalid::CutTail,
                false => OnInvalid::Refuse,
            };
            buffer.replay(seq, on_invalid).await?;
        }

        Ok(buffer)
    }
    /// The lowest ack HLC of the buffered records.
    pub fn oldest_time(&self) -> Option<u64> {
        self.oldest.values().min().copied()
    }

    /// The keys and bucket names whose last buffered write is older than `limit`.
    pub fn late_targets(&self, limit: u64) -> Vec<String> {
        let keys = self.objects.iter().filter_map(|((bucket, key), object)| {
            let time = match object {
                BufferedObject::Put(put) => put.time,
                BufferedObject::Delete { time, .. } => *time,
            };
            (time < limit).then(|| format!("{bucket}/{key}"))
        });
        let buckets = self
            .buckets
            .iter()
            .filter(|(_, state)| state.time < limit)
            .map(|(name, _)| name.clone());
        keys.chain(buckets).collect()
    }

    /// The lowest ack HLC of the records in `segments`.
    pub fn oldest_in(&self, segments: &[u64]) -> Option<u64> {
        segments
            .iter()
            .filter_map(|seq| self.oldest.get(seq))
            .min()
            .copied()
    }

    /// The latest ack HLC of the buffered writes. Zero for an empty buffer.
    pub fn latest_time(&self) -> u64 {
        let objects = self.objects.values().map(|object| match object {
            BufferedObject::Put(put) => put.time,
            BufferedObject::Delete { time, .. } => *time,
        });
        let buckets = self.buckets.values().map(|bucket| bucket.time);
        objects.chain(buckets).max().unwrap_or(0)
    }

    async fn replay(&mut self, seq: u64, on_invalid: OnInvalid) -> Result<(), EngineError> {
        let path = self.segment_path(seq);
        let mut reader = SegmentReader::open(&path).await?;
        let mut records = 0;

        let end = loop {
            match reader.read().await? {
                Read::Record(record) => {
                    self.track(seq, &record.head, record.data_offset, record.data_len);
                    records += 1;
                }
                // Not tracked: the open moves it to the quarantine and fails.
                Read::BadData(record) => {
                    self.bad_data.push(BadRecord {
                        segment: seq,
                        span: record.span,
                        head_hash: record.head_hash,
                        target: record.head.op.target(),
                    });
                    records += 1;
                }
                Read::End => break reader.len,
                Read::BadHead { start, next }
                    if on_invalid == OnInvalid::CutTail && !head_at(&path, next).await? =>
                {
                    warn!(
                        segment = seq,
                        offset = start,
                        dropped = reader.len - start,
                        "cut a torn record"
                    );
                    let file = tokio::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .await?;
                    file.set_len(start).await?;
                    file.sync_all().await?;
                    break start;
                }
                Read::BadHead { start, .. } => return Err(corrupt_head(&path, start)),
            }
        };

        if records == 0 {
            tokio::fs::remove_file(&path).await?;
            return Ok(());
        }

        debug!(segment = seq, records, "replayed segment");
        self.sealed.insert(seq, end);
        Ok(())
    }

    /// The records with a valid head and data that does not match it. The open moves them to
    /// the quarantine.
    pub fn bad_data(&self) -> &[BadRecord] {
        &self.bad_data
    }

    pub fn segment_path(&self, seq: u64) -> PathBuf {
        segment_path(&self.dir, seq)
    }

    /// Bytes on disk that wait for a flush.
    pub fn bytes(&self) -> u64 {
        self.active.len + self.sealed.values().sum::<u64>()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes() == 0
    }

    /// Appends a record without an fsync. Returns the number of the record.
    pub async fn append(&mut self, head: Head, data: &[u8]) -> Result<u64, EngineError> {
        if self.broken {
            return Err(EngineError::BufferBroken);
        }

        check_head(&head)?;

        let record = encode_record(&head, data);
        let data_offset = self.active.len + DATA_LEN_LEN as u64;

        if let Err(e) = self.write_active(&record).await {
            // A partial record inside a segment would stop the replay of every record after it.
            self.active.file.set_len(self.active.len).await?;
            return Err(e);
        }

        self.active.len += record.len() as u64;
        self.written += 1;
        self.track(self.active.seq, &head, data_offset, data.len() as u64);

        if self.active.len >= self.segment_target {
            self.rotate().await?;
        }

        Ok(self.written)
    }

    async fn write_active(&mut self, record: &[u8]) -> Result<(), EngineError> {
        self.active.file.write_all(record).await?;
        // The record must reach the kernel before another task fsyncs the segment.
        self.active.file.flush().await?;
        Ok(())
    }

    pub fn durability(&self, record: u64) -> Durability {
        if self.lost.iter().any(|lost| lost.contains(&record)) {
            return Durability::Lost;
        }

        match record <= self.durable {
            true => Durability::Durable,
            false => Durability::Pending,
        }
    }

    /// The last record that a reader can see. `None` when all records are on disk.
    pub fn pending(&self) -> Option<u64> {
        (self.written > self.durable).then_some(self.written)
    }

    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// An fsync of every record written so far.
    pub fn sync_job(&mut self) -> SyncJob {
        SyncJob {
            seq: self.active.seq,
            len: self.active.len,
            target: self.written,
            file: Arc::clone(&self.active.sync),
            #[cfg(test)]
            fail: std::mem::take(&mut self.fail_next_sync),
        }
    }

    /// Records the result of `job`. A failure drops every record that is not on disk.
    pub async fn finish_sync(
        &mut self,
        job: SyncJob,
        result: std::io::Result<()>,
    ) -> Result<(), EngineError> {
        #[cfg(test)]
        {
            self.syncs += 1;
        }

        match result {
            Ok(()) => {
                self.durable = self.durable.max(job.target);
                if job.seq == self.active.seq {
                    self.active.durable_len = self.active.durable_len.max(job.len);
                }
                Ok(())
            }
            // A rotation fsynced these records through the other open file.
            Err(_) if self.durable >= job.target => Ok(()),
            Err(e) => {
                warn!(%e, segment = job.seq, "buffer fsync failed: the writes it covers are dropped");
                self.drop_unsynced().await
            }
        }
    }

    /// Cuts the active segment to its last fsynced size. Then reads the buffer from disk again.
    async fn drop_unsynced(&mut self) -> Result<(), EngineError> {
        self.broken = true;
        let lost = self.durable + 1..self.written + 1;

        self.active.file.set_len(self.active.durable_len).await?;
        self.active.file.sync_all().await?;

        let mut fresh = Self::open(self.dir.clone(), self.segment_target).await?;
        fresh.written = self.written;
        fresh.durable = self.written;
        fresh.lost = std::mem::take(&mut self.lost);
        fresh.lost.push(lost);
        *self = fresh;
        Ok(())
    }

    fn track(&mut self, segment: u64, head: &Head, data_offset: u64, size: u64) {
        let oldest = self.oldest.entry(segment).or_insert(head.time);
        *oldest = (*oldest).min(head.time);
        match &head.op {
            Op::Put {
                bucket,
                key,
                metadata,
                content_hash,
            } => {
                let put = BufferedPut {
                    segment,
                    data_offset,
                    size,
                    content_hash: *content_hash,
                    metadata: metadata.clone(),
                    time: head.time,
                };
                self.objects
                    .insert((bucket.clone(), key.clone()), BufferedObject::Put(put));
            }
            Op::Delete { bucket, key } => {
                let delete = BufferedObject::Delete {
                    segment,
                    time: head.time,
                };
                self.objects.insert((bucket.clone(), key.clone()), delete);
            }
            Op::CreateBucket { bucket, owner } => {
                let state = BufferedBucket {
                    segment,
                    exists: true,
                    owner: owner.clone(),
                    time: head.time,
                };
                self.buckets.insert(bucket.clone(), state);
            }
            Op::DeleteBucket { bucket } => {
                let state = BufferedBucket {
                    segment,
                    exists: false,
                    owner: None,
                    time: head.time,
                };
                self.buckets.insert(bucket.clone(), state);
            }
        }
    }

    pub fn object(&self, bucket: &str, key: &str) -> Option<&BufferedObject> {
        self.objects.get(&(bucket.to_string(), key.to_string()))
    }

    /// The first buffered object of `bucket` under `prefix` whose key is `from` or after it.
    pub fn first_object_from<'a>(
        &'a self,
        bucket: &'a str,
        prefix: &'a str,
        from: &str,
    ) -> Option<(&'a str, &'a BufferedObject)> {
        let start = from.max(prefix);
        self.objects
            .range((bucket.to_string(), start.to_string())..)
            .next()
            .filter(|((b, k), _)| b == bucket && k.starts_with(prefix))
            .map(|((_, k), object)| (k.as_str(), object))
    }

    pub fn bucket(&self, name: &str) -> Option<&BufferedBucket> {
        self.buckets.get(name)
    }

    pub fn buckets(&self) -> impl Iterator<Item = (&str, &BufferedBucket)> {
        self.buckets
            .iter()
            .map(|(name, state)| (name.as_str(), state))
    }

    /// Seals the active segment when it holds records. Returns every sealed segment, oldest first.
    pub async fn seal(&mut self) -> Result<Vec<u64>, EngineError> {
        if self.active.len > 0 {
            self.rotate().await?;
        }

        Ok(self.sealed.keys().copied().collect())
    }

    async fn rotate(&mut self) -> Result<(), EngineError> {
        // Replay refuses a torn record in a segment that is not the last one.
        if self.active.durable_len < self.active.len {
            if let Err(e) = self.active.file.sync_data().await {
                warn!(%e, segment = self.active.seq, "buffer fsync failed: the writes it covers are dropped");
                self.drop_unsynced().await?;
                return Err(EngineError::WriteLost);
            }
            self.active.durable_len = self.active.len;
            self.durable = self.written;
        }

        let next = create_segment(&self.dir, self.active.seq + 1).await?;
        let sealed = std::mem::replace(&mut self.active, next);
        self.sealed.insert(sealed.seq, sealed.len);
        Ok(())
    }

    /// Adds a spooled put as the next segment. The spool file holds the data and then the head,
    /// both fsynced. The active segment is sealed first, so the order of the segments stays the
    /// order of the acks. Returns the record number, durable at once.
    pub async fn adopt(
        &mut self,
        spool: &Path,
        head: &Head,
        data_len: u64,
    ) -> Result<u64, EngineError> {
        if self.broken {
            return Err(EngineError::BufferBroken);
        }
        if self.active.len > 0 {
            self.rotate().await?;
        }
        // The active segment is empty: the spool takes its seq. The next active segment exists
        // first, so a spooled segment is never the last one, which a replay can cut as torn.
        let seq = self.active.seq;
        // After a failed create or directory fsync, the state of the directory is unknown: later
        // acks would depend on it.
        if let Err(e) = self.adopt_steps(spool, seq).await {
            self.broken = true;
            return Err(e);
        }
        self.written += 1;
        self.durable = self.written;
        self.track(seq, head, DATA_LEN_LEN as u64, data_len);
        Ok(self.written)
    }

    async fn adopt_steps(&mut self, spool: &Path, seq: u64) -> Result<(), EngineError> {
        self.active = create_segment(&self.dir, seq + 1).await?;
        crate::sim::crash_point(crate::sim::Point::SpoolNext)?;
        tokio::fs::rename(spool, self.segment_path(seq)).await?;
        crate::sim::crash_point(crate::sim::Point::SpoolDirSync)?;
        sync_dir(&self.dir).await?;
        crate::sim::crash_point(crate::sim::Point::SpoolRename)?;
        let size = tokio::fs::metadata(self.segment_path(seq)).await?.len();
        self.sealed.insert(seq, size);
        Ok(())
    }

    /// Deletes flushed segments and forgets the writes they hold.
    pub async fn release(&mut self, segments: &[u64]) -> Result<(), EngineError> {
        let released: BTreeSet<u64> = segments.iter().copied().collect();

        self.objects
            .retain(|_, object| !released.contains(&object.segment()));
        self.buckets
            .retain(|_, state| !released.contains(&state.segment));

        for seq in &released {
            self.oldest.remove(seq);
            if self.sealed.remove(seq).is_some() {
                remove_if_present(&self.segment_path(*seq)).await?;
            }
        }

        Ok(())
    }
}

pub(crate) async fn read_intent(dir: &Path) -> Result<Option<Intent>, EngineError> {
    let bytes = match tokio::fs::read(dir.join(INTENT_FILE)).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let intent = postcard::from_bytes(&bytes)
        .map_err(|e| EngineError::Corrupt(format!("intent file: {e}")))?;
    Ok(Some(intent))
}

/// Replaces the intent file atomically.
pub(crate) async fn write_intent(dir: &Path, intent: &Intent) -> Result<(), EngineError> {
    let bytes = postcard::to_allocvec(intent).expect("an intent always serializes");
    let tmp = dir.join(INTENT_TEMP);

    let mut file = File::create(&tmp).await?;
    file.write_all(&bytes).await?;
    file.sync_all().await?;
    tokio::fs::rename(&tmp, dir.join(INTENT_FILE)).await?;
    sync_dir(dir).await
}

pub(crate) async fn remove_intent(dir: &Path) -> Result<(), EngineError> {
    remove_if_present(&dir.join(INTENT_FILE)).await?;
    sync_dir(dir).await
}

/// Reads `range` of a buffered put. `None` when a flush deleted the segment.
#[cfg(test)]
pub(crate) async fn read_put(
    dir: &Path,
    put: &BufferedPut,
    range: Range<u64>,
) -> Result<Option<Vec<u8>>, EngineError> {
    let Some(mut file) = open_put(dir, put, range.clone()).await? else {
        return Ok(None);
    };
    let mut data = vec![0u8; (range.end - range.start) as usize];
    file.read_exact(&mut data).await?;
    Ok(Some(data))
}

/// Opens the segment of a buffered put at `range.start` of its data. `None` when a flush released
/// the segment. The open file keeps its data readable after a release.
pub(crate) async fn open_put(
    dir: &Path,
    put: &BufferedPut,
    range: Range<u64>,
) -> Result<Option<File>, EngineError> {
    let mut file = match File::open(segment_path(dir, put.segment)).await {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    file.seek(SeekFrom::Start(put.data_offset + range.start))
        .await?;
    Ok(Some(file))
}

pub(crate) fn segment_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("{seq:020}{SEGMENT_SUFFIX}"))
}

/// The segment numbers in `dir`, in order. Empty when the directory does not read.
#[cfg(test)]
pub(crate) async fn segment_seqs(dir: &Path) -> Vec<u64> {
    list_segments(dir).await.unwrap_or_default()
}

async fn list_segments(dir: &Path) -> Result<Vec<u64>, EngineError> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    let mut seqs = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(SEGMENT_SUFFIX)) else {
            continue;
        };

        // A segment that does not have its exact name could hold acknowledged writes: stop.
        let seq = stem.parse::<u64>().ok().filter(|_| stem.len() == 20);
        let Some(seq) = seq else {
            return Err(EngineError::Corrupt(format!(
                "{}: a segment file name must be 20 digits and {SEGMENT_SUFFIX}. Rename or move \
                 the file",
                entry.path().display()
            )));
        };
        seqs.push(seq);
    }

    seqs.sort_unstable();
    Ok(seqs)
}

async fn create_segment(dir: &Path, seq: u64) -> Result<Active, EngineError> {
    let path = segment_path(dir, seq);
    let file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .await?;
    let sync = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .await?
        .into_std()
        .await;
    sync_dir(dir).await?;
    Ok(Active {
        seq,
        file,
        len: 0,
        durable_len: 0,
        sync: Arc::new(sync),
    })
}

/// Moves every record with an ack HLC under `limit` from the buffer in `dir` to `quarantine`,
/// and keeps the other records in the buffer. Returns the keys and bucket names moved.
///
/// Acks rise in buffer order, so the late records are a prefix. Each step is durable before
/// the next, and a crash between two steps leaves each record in the buffer, in the quarantine,
/// or in both: a second call ends the move. A record in the quarantine never applies.
pub(crate) async fn quarantine_late(
    dir: &Path,
    quarantine: &Path,
    limit: u64,
) -> Result<Vec<String>, EngineError> {
    quarantine_late_until(dir, quarantine, limit, &mut |_| false).await
}

/// [`quarantine_late`], with `stop` called after each durable step: `true` fails the call there.
async fn quarantine_late_until(
    dir: &Path,
    quarantine: &Path,
    limit: u64,
    stop: &mut (dyn FnMut(u32) -> bool + Send),
) -> Result<Vec<String>, EngineError> {
    let mut step = 0;
    let mut check = |step: &mut u32| {
        *step += 1;
        match stop(*step) {
            true => Err(EngineError::Corrupt(format!("stopped after step {step}"))),
            false => Ok(()),
        }
    };
    let mut moved = Vec::new();

    for seq in list_segments(dir).await? {
        let path = segment_path(dir, seq);
        let mut reader = SegmentReader::open(&path).await?;
        // Acks rise in buffer order: the late records are a prefix. The open cut a torn tail.
        let mut late = Vec::new();
        while let Read::Record(record) = reader.read().await? {
            if record.head.time >= limit {
                break;
            }
            moved.push(record.head.op.target());
            late.push(record.span);
        }
        let len = tokio::fs::metadata(&path).await?.len();
        // An empty segment, such as the active one of a past open, holds no boundary.
        if len == 0 {
            continue;
        }
        if late.is_empty() {
            break;
        }
        let young = late.last().is_some_and(|span| span.end < len);

        create_quarantine(quarantine).await?;
        let target = quarantine.join(format!("{seq:020}{SEGMENT_SUFFIX}"));
        copy_spans_durable(&path, &late, quarantine, &target).await?;
        check(&mut step)?;
        match young {
            false => {
                remove_if_present(&path).await?;
                sync_dir(dir).await?;
            }
            true => remove_spans(dir, seq, &late).await?,
        }
        check(&mut step)?;
        if young {
            break;
        }
    }

    Ok(moved)
}

/// Moves the records of `bad` to the quarantine, one segment at a time: first a durable copy in
/// `quarantine/<seq>.<head hash>.log`, then the segment written again without them. A crash
/// between the two leaves the record in both places; [`finish_quarantine_moves`] at the next
/// start ends the move, so no record goes to the quarantine twice. Returns their targets.
pub(crate) async fn quarantine_bad_data(
    dir: &Path,
    quarantine: &Path,
    bad: &[BadRecord],
) -> Result<Vec<String>, EngineError> {
    let mut by_segment: BTreeMap<u64, Vec<&BadRecord>> = BTreeMap::new();
    for record in bad {
        by_segment.entry(record.segment).or_default().push(record);
    }
    for (seq, records) in by_segment {
        let segment = segment_path(dir, seq);
        let spans: Vec<Range<u64>> = records.iter().map(|record| record.span.clone()).collect();
        let name = format!(
            "{seq:020}.{}{SEGMENT_SUFFIX}",
            hex::encode(&records[0].head_hash[..8])
        );
        let target = quarantine.join(name);
        create_quarantine(quarantine).await?;
        copy_spans_durable(&segment, &spans, quarantine, &target).await?;
        crate::sim::crash_point(crate::sim::Point::QuarantineCopy)?;
        remove_spans(dir, seq, &spans).await?;
        crate::sim::crash_point(crate::sim::Point::QuarantineRewrite)?;
    }
    Ok(bad.iter().map(|record| record.target.clone()).collect())
}

/// Ends the moves to the quarantine that a crash stopped. A record of a quarantine file
/// `<seq>.*.log` that buffer segment `<seq>` still holds, found by its head hash, leaves the
/// segment. Temporary files of a stopped move go too: the record is still in its segment.
pub(crate) async fn finish_quarantine_moves(
    dir: &Path,
    quarantine: &Path,
) -> Result<(), EngineError> {
    if !tokio::fs::try_exists(dir).await? {
        return Ok(());
    }
    remove_with_suffix(dir, ".rewrite").await?;
    if !tokio::fs::try_exists(quarantine).await? {
        return Ok(());
    }
    remove_with_suffix(quarantine, ".tmp").await?;
    let mut entries = tokio::fs::read_dir(quarantine).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(seq) = name
            .get(..20)
            .filter(|_| name.ends_with(SEGMENT_SUFFIX))
            .and_then(|digits| digits.parse::<u64>().ok())
        else {
            continue;
        };
        let segment = segment_path(dir, seq);
        if !tokio::fs::try_exists(&segment).await? {
            continue;
        }
        let held: BTreeSet<[u8; 32]> = heads_of(&path)
            .await?
            .into_iter()
            .map(|(_, hash)| hash)
            .collect();
        let spans: Vec<Range<u64>> = heads_of(&segment)
            .await?
            .into_iter()
            .filter(|(_, hash)| held.contains(hash))
            .map(|(span, _)| span)
            .collect();
        if !spans.is_empty() {
            warn!(
                segment = seq,
                records = spans.len(),
                "ended a move to the quarantine that a crash stopped"
            );
            remove_spans(dir, seq, &spans).await?;
        }
    }
    Ok(())
}

/// The span and head hash of each record with a valid head, up to the first bad head.
async fn heads_of(path: &Path) -> Result<Vec<(Range<u64>, [u8; 32])>, EngineError> {
    let mut reader = SegmentReader::open(path).await?;
    let mut out = Vec::new();
    loop {
        match reader.read().await? {
            Read::Record(record) | Read::BadData(record) => {
                out.push((record.span, record.head_hash))
            }
            Read::End | Read::BadHead { .. } => return Ok(out),
        }
    }
}

async fn remove_with_suffix(dir: &Path, suffix: &str) -> Result<(), EngineError> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_name().to_string_lossy().ends_with(suffix) {
            remove_if_present(&entry.path()).await?;
        }
    }
    Ok(())
}

/// Copies the byte ranges `spans` of `source`, in order, to `out`.
async fn copy_spans(
    source: &Path,
    spans: &[Range<u64>],
    out: &mut File,
) -> Result<(), EngineError> {
    let mut file = File::open(source).await?;
    for span in spans {
        file.seek(SeekFrom::Start(span.start)).await?;
        let wanted = span.end - span.start;
        let copied = tokio::io::copy(&mut (&mut file).take(wanted), out).await?;
        if copied != wanted {
            return Err(EngineError::Corrupt(format!(
                "{}: ends before offset {}",
                source.display(),
                span.end
            )));
        }
    }
    out.sync_all().await?;
    Ok(())
}

/// Writes the `spans` of `source` to `target` through a fsynced temporary file and a rename, then
/// fsyncs `dir`. An existing `target` holds them already: a crash stopped the move after it.
async fn copy_spans_durable(
    source: &Path,
    spans: &[Range<u64>],
    dir: &Path,
    target: &Path,
) -> Result<(), EngineError> {
    if tokio::fs::try_exists(target).await? {
        return Ok(());
    }
    let tmp = target.with_extension("tmp");
    copy_spans(source, spans, &mut File::create(&tmp).await?).await?;
    tokio::fs::rename(&tmp, target).await?;
    sync_dir(dir).await
}

/// Writes segment `seq` again without the byte ranges `spans`.
async fn remove_spans(dir: &Path, seq: u64, spans: &[Range<u64>]) -> Result<(), EngineError> {
    let path = segment_path(dir, seq);
    let len = tokio::fs::metadata(&path).await?.len();
    let mut keep = Vec::new();
    let mut at = 0;
    for span in spans {
        keep.push(at..span.start);
        at = span.end;
    }
    keep.push(at..len);
    keep.retain(|span| !span.is_empty());
    let tmp = dir.join(format!("{seq:020}.rewrite"));
    copy_spans(&path, &keep, &mut File::create(&tmp).await?).await?;
    tokio::fs::rename(&tmp, &path).await?;
    sync_dir(dir).await
}

/// A write that the quarantine holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedWrite {
    /// `bucket/key`, or a bucket name.
    pub target: String,
    /// The HLC of its ack.
    pub hlc: u64,
    /// The data does not match the hash in its head: the record left the buffer for that.
    pub corrupt: bool,
}

/// One record of the quarantine, with its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedRecord {
    /// The segment file name in the quarantine.
    pub file: String,
    /// The place of the record in its file, from 1.
    pub number: u64,
    /// `put`, `delete`, `create-bucket` or `delete-bucket`.
    pub op: &'static str,
    pub write: QuarantinedWrite,
    /// The object body of a put; empty for the other ops.
    pub data: Vec<u8>,
}

/// Reads the records of the quarantine directory `dir` one at a time, in order.
pub struct QuarantineReader {
    paths: std::vec::IntoIter<PathBuf>,
    current: Option<(PathBuf, SegmentReader, u64)>,
}

impl QuarantineReader {
    /// The segment files of `dir` (`*.log`). A missing directory has no record.
    pub async fn open(dir: &Path) -> Result<Self, EngineError> {
        let mut paths = Vec::new();
        if tokio::fs::try_exists(dir).await? {
            let mut entries = tokio::fs::read_dir(dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "log") {
                    paths.push(path);
                }
            }
        }
        paths.sort();
        Ok(Self {
            paths: paths.into_iter(),
            current: None,
        })
    }

    pub async fn next(&mut self) -> Result<Option<QuarantinedRecord>, EngineError> {
        loop {
            if self.current.is_none() {
                let Some(path) = self.paths.next() else {
                    return Ok(None);
                };
                let reader = SegmentReader::open(&path).await?;
                self.current = Some((path, reader, 0));
            }
            let (path, reader, number) = self.current.as_mut().expect("set above");
            let Some((record, corrupt)) = reader.next_held(path).await? else {
                self.current = None;
                continue;
            };
            *number += 1;
            let op = match record.head.op {
                Op::Put { .. } => "put",
                Op::Delete { .. } => "delete",
                Op::CreateBucket { .. } => "create-bucket",
                Op::DeleteBucket { .. } => "delete-bucket",
            };
            let file = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let data = read_record_data(path, &record).await?;
            return Ok(Some(QuarantinedRecord {
                file,
                number: *number,
                op,
                write: QuarantinedWrite {
                    target: record.head.op.target(),
                    hlc: record.head.time,
                    corrupt,
                },
                data,
            }));
        }
    }
}

/// The writes in the quarantine directory `dir`, in order.
pub(crate) async fn read_quarantine(dir: &Path) -> Result<Vec<QuarantinedWrite>, EngineError> {
    let mut out = Vec::new();
    let mut paths = Vec::new();
    if tokio::fs::try_exists(dir).await? {
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "log") {
                paths.push(path);
            }
        }
    }
    paths.sort();
    for path in paths {
        let mut reader = SegmentReader::open(&path).await?;
        while let Some((record, corrupt)) = reader.next_held(&path).await? {
            out.push(QuarantinedWrite {
                target: record.head.op.target(),
                hlc: record.head.time,
                corrupt,
            });
        }
    }
    Ok(out)
}

/// Moves the intent file to `quarantine`: its entry never commits.
pub(crate) async fn quarantine_intent(dir: &Path, quarantine: &Path) -> Result<(), EngineError> {
    create_quarantine(quarantine).await?;
    let held = free_name(quarantine, INTENT_FILE, "").await?;
    tokio::fs::rename(dir.join(INTENT_FILE), held).await?;
    sync_dir(quarantine).await?;
    sync_dir(dir).await
}

/// Makes the quarantine directory durable before a record moves there: a power loss must not
/// lose the directory while the buffer copy is already gone.
async fn create_quarantine(quarantine: &Path) -> Result<(), EngineError> {
    tokio::fs::create_dir_all(quarantine).await?;
    if let Some(parent) = quarantine.parent() {
        sync_dir(parent).await?;
    }
    Ok(())
}

/// The first path `<stem><suffix>`, `<stem>.1<suffix>`, ... in `dir` that does not exist.
async fn free_name(dir: &Path, stem: &str, suffix: &str) -> Result<PathBuf, EngineError> {
    let mut n = 0u32;
    loop {
        let name = match n {
            0 => format!("{stem}{suffix}"),
            n => format!("{stem}.{n}{suffix}"),
        };
        let path = dir.join(name);
        if !tokio::fs::try_exists(&path).await? {
            return Ok(path);
        }
        n += 1;
    }
}

/// Writes `bytes` to `path` through a fsynced temporary file and a rename, then fsyncs `dir`.
async fn write_durable(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), EngineError> {
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    tokio::fs::rename(&tmp, path).await?;
    sync_dir(dir).await
}

async fn sync_dir(dir: &Path) -> Result<(), EngineError> {
    File::open(dir).await?.sync_all().await?;
    Ok(())
}

async fn remove_if_present(path: &Path) -> Result<(), EngineError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(key: &str, data: &[u8]) -> Head {
        Head {
            time: 7,
            op: Op::Put {
                bucket: "b".into(),
                key: key.into(),
                metadata: BTreeMap::new(),
                content_hash: *blake3::hash(data).as_bytes(),
            },
        }
    }

    /// A buffer directory of the format of this build, for segments that a test writes.
    fn formatted(dir: &Path) {
        std::fs::write(dir.join(FORMAT_FILE), format!("{FORMAT}\n")).unwrap();
    }

    async fn records(buffer: &Buffer, seq: u64) -> Vec<Record> {
        let path = buffer.segment_path(seq);
        let mut reader = SegmentReader::open(&path).await.unwrap();
        let mut out = Vec::new();
        while let Some(record) = reader.next(&path).await.unwrap() {
            out.push(record);
        }
        out
    }

    fn put_at(key: &str, time: u64) -> Head {
        Head {
            time,
            ..put(key, key.as_bytes())
        }
    }

    /// The (time, key) of each record in the segments of `dir`, in order.
    async fn times(dir: &Path) -> Vec<(u64, String)> {
        let mut out = Vec::new();
        let Ok(seqs) = list_segments(dir).await else {
            return out;
        };
        for seq in seqs {
            let path = segment_path(dir, seq);
            let mut reader = SegmentReader::open(&path).await.unwrap();
            while let Some(record) = reader.next(&path).await.unwrap() {
                out.push((record.head.time, record.head.op.target()));
            }
        }
        out
    }

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }

    /// Times 1 to 3 are late and 10, 11 are young, with `segment_target` bytes per segment. A
    /// stop after each step, then the starts of the operator procedure: a start that finds a
    /// segment in the quarantine is refused, the operator reads and empties it, and the next
    /// start moves the rest. The operator sees every late write, and the young ones stay.
    async fn check_split_survives_a_stop_at_each_step(segment_target: u64) {
        let source = tempfile::tempdir().unwrap();
        {
            let mut buffer = Buffer::open(source.path(), segment_target).await.unwrap();
            for (key, time) in [("a", 1), ("b", 2), ("c", 3), ("d", 10), ("e", 11)] {
                buffer
                    .append(put_at(key, time), key.as_bytes())
                    .await
                    .unwrap();
            }
            buffer.sync_job().run().await.unwrap();
        }
        let late = vec![(1, "b/a".to_string()), (2, "b/b".into()), (3, "b/c".into())];
        let young = vec![(10, "b/d".to_string()), (11, "b/e".into())];

        for stop_at in 1..=8 {
            let run = tempfile::tempdir().unwrap();
            let (dir, quarantine) = (run.path().join("buffer"), run.path().join("quarantine"));
            copy_dir(source.path(), &dir);

            let stopped =
                quarantine_late_until(&dir, &quarantine, 5, &mut |step| step == stop_at).await;
            let mut seen = std::collections::BTreeSet::new();
            for _start in 0..4 {
                let held = times(&quarantine).await;
                if held.is_empty() {
                    quarantine_late(&dir, &quarantine, 5).await.unwrap();
                    continue;
                }
                seen.extend(held);
                std::fs::remove_dir_all(&quarantine).unwrap();
            }

            assert_eq!(times(&dir).await, young, "stop at {stop_at}: {stopped:?}");
            assert_eq!(
                seen.into_iter().collect::<Vec<_>>(),
                late,
                "stop at {stop_at}"
            );
        }
    }

    /// An empty segment between late segments, such as the active segment of an earlier open,
    /// must not stop the move: every late record goes.
    #[tokio::test]
    async fn test_quarantine_split_passes_an_empty_segment() {
        let run = tempfile::tempdir().unwrap();
        let (dir, quarantine) = (run.path().join("buffer"), run.path().join("quarantine"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(segment_path(&dir, 1), encode_record(&put_at("a", 1), b"a")).unwrap();
        std::fs::write(segment_path(&dir, 2), b"").unwrap();
        std::fs::write(segment_path(&dir, 3), encode_record(&put_at("b", 2), b"b")).unwrap();
        std::fs::write(segment_path(&dir, 4), encode_record(&put_at("c", 10), b"c")).unwrap();

        let moved = quarantine_late(&dir, &quarantine, 5).await.unwrap();

        assert_eq!(moved, ["b/a", "b/b"]);
        assert_eq!(times(&dir).await, [(10, "b/c".to_string())]);
    }

    #[tokio::test]
    async fn test_quarantine_split_survives_a_stop_after_each_step() {
        // One segment that holds late and young records, then one segment for each record.
        check_split_survives_a_stop_at_each_step(1 << 20).await;
        check_split_survives_a_stop_at_each_step(1).await;
    }

    #[test]
    fn test_record_format_is_stable() {
        let head = put("k", b"data");
        let bytes = encode_record(&head, b"data");
        let head_bytes = postcard::to_allocvec(&head).unwrap();

        // The data first, then the head: a streamed put knows its head only at the end.
        assert_eq!(bytes[..8], 4u64.to_le_bytes());
        assert_eq!(&bytes[8..12], b"data");
        assert_eq!(bytes[12..16], (head_bytes.len() as u32).to_le_bytes());
        assert_eq!(bytes[16..48], *blake3::hash(&head_bytes).as_bytes());
        assert_eq!(&bytes[48..], &head_bytes[..]);
        assert_eq!(
            blake3::hash(&bytes).to_string(),
            "1aa15ae7cba1a8fb1065ffd5b4ce3f8147e992ffc19bc855986c22cc16c2805f"
        );
    }

    #[tokio::test]
    async fn test_directory_with_only_an_intent_is_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(INTENT_FILE), b"from format 1").unwrap();

        let Err(error) = Buffer::open(dir.path(), 1 << 20).await else {
            panic!("a buffer with an old intent and no format file opens");
        };

        assert!(error.to_string().contains("record format 1"), "{error}");
        assert!(!dir.path().join(FORMAT_FILE).exists());
    }

    /// A power loss after the segments and before the format data reached the disk leaves an
    /// empty format file. The error says what to do.
    #[tokio::test]
    async fn test_empty_format_file_names_the_action() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
            buffer.append(put("k", b"v"), b"v").await.unwrap();
        }
        std::fs::write(dir.path().join(FORMAT_FILE), b"").unwrap();

        let Err(error) = Buffer::open(dir.path(), 1 << 20).await else {
            panic!("a buffer with an empty format file opens");
        };

        let text = error.to_string();
        assert!(text.contains("does not read"), "{text}");
        assert!(text.contains("write 3 into it"), "{text}");
    }

    #[tokio::test]
    async fn test_buffer_of_another_format_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
            buffer.append(put("k", b"v"), b"v").await.unwrap();
        }
        std::fs::remove_file(dir.path().join(FORMAT_FILE)).unwrap();

        let Err(error) = Buffer::open(dir.path(), 1 << 20).await else {
            panic!("a buffer with no format file opens");
        };

        let text = error.to_string();
        assert!(text.contains("record format 1"), "{text}");
        assert!(text.contains("format 3"), "{text}");
    }

    #[tokio::test]
    async fn test_buffer_of_format_2_names_the_steps() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FORMAT_FILE), b"2\n").unwrap();
        std::fs::write(segment_path(dir.path(), 0), b"old records").unwrap();

        let Err(error) = Buffer::open(dir.path(), 1 << 20).await else {
            panic!("a buffer of format 2 opens");
        };

        let text = error.to_string();
        assert!(text.contains("record format 2"), "{text}");
        assert!(text.contains("SIGTERM"), "{text}");
    }

    #[tokio::test]
    async fn test_appended_records_read_back_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
        buffer.append(put("a", b"one"), b"one").await.unwrap();
        buffer.append(put("b", b"two"), b"two").await.unwrap();

        let sealed = buffer.seal().await.unwrap();
        let read = records(&buffer, sealed[0]).await;

        assert_eq!(sealed.len(), 1);
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].head, put("a", b"one"));
        let data = read_record_data(&segment_path(dir.path(), sealed[0]), &read[1])
            .await
            .unwrap();
        assert_eq!(data, b"two");
    }

    #[tokio::test]
    async fn test_buffered_put_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
        buffer.append(put("a", b"one"), b"one").await.unwrap();
        buffer.append(put("b", b"two"), b"two").await.unwrap();

        let Some(BufferedObject::Put(b)) = buffer.object("b", "b") else {
            panic!("b is buffered");
        };

        assert_eq!(
            read_put(dir.path(), b, 0..b.size).await.unwrap().unwrap(),
            b"two"
        );
    }

    #[tokio::test]
    async fn test_reopen_replays_buffered_writes() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
            buffer.append(put("a", b"one"), b"one").await.unwrap();
        }

        let buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();

        assert!(matches!(
            buffer.object("b", "a"),
            Some(BufferedObject::Put(_))
        ));
        assert!(!buffer.is_empty());
    }

    #[tokio::test]
    async fn test_reopen_cuts_a_torn_last_record() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
            buffer.append(put("a", b"one"), b"one").await.unwrap();
            buffer.append(put("b", b"two"), b"two").await.unwrap();
        }
        let path = segment_path(dir.path(), 0);
        let len = std::fs::metadata(&path).unwrap().len();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(len - 1).unwrap();

        let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();

        assert!(buffer.object("b", "a").is_some());
        assert!(buffer.object("b", "b").is_none());
        let sealed = buffer.seal().await.unwrap();
        assert_eq!(records(&buffer, sealed[0]).await.len(), 1);
    }

    #[tokio::test]
    async fn test_flipped_data_byte_in_the_last_segment_lists_the_record_and_keeps_the_others() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
            for key in ["a", "b", "c"] {
                buffer.append(put(key, b"data"), b"data").await.unwrap();
            }
        }
        let path = segment_path(dir.path(), 0);
        let mut bytes = std::fs::read(&path).unwrap();
        let record = bytes.len() / 3;
        // A byte in the data of the second record, after its data length.
        bytes[record + 9] ^= 1;
        std::fs::write(&path, bytes).unwrap();

        let buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();

        assert!(buffer.object("b", "a").is_some());
        assert!(buffer.object("b", "b").is_none());
        assert!(buffer.object("b", "c").is_some());
        let bad: Vec<&str> = buffer
            .bad_data()
            .iter()
            .map(|r| r.target.as_str())
            .collect();
        assert_eq!(bad, ["b/b"]);
    }

    #[tokio::test]
    async fn test_empty_segment_file_is_removed_at_open() {
        let dir = tempfile::tempdir().unwrap();
        formatted(dir.path());
        std::fs::write(segment_path(dir.path(), 4), b"").unwrap();

        let buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();

        assert!(buffer.is_empty());
        assert!(!segment_path(dir.path(), 4).exists());
    }

    /// A segment with one whole record, then a record prefix with a huge data length.
    async fn segment_with_a_huge_length(dir: &Path, seq: u64) {
        let path = segment_path(dir, seq);
        let mut bytes = encode_record(&put("a", b"one"), b"one");
        bytes.extend_from_slice(&(u64::MAX - 4).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        tokio::fs::write(&path, bytes).await.unwrap();
    }

    #[tokio::test]
    async fn test_huge_record_length_in_the_last_segment_is_a_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        formatted(dir.path());
        segment_with_a_huge_length(dir.path(), 0).await;

        let buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();

        assert!(buffer.object("b", "a").is_some());
    }

    #[tokio::test]
    async fn test_huge_record_length_in_an_older_segment_names_the_file_and_offset() {
        let dir = tempfile::tempdir().unwrap();
        formatted(dir.path());
        segment_with_a_huge_length(dir.path(), 0).await;
        tokio::fs::write(
            segment_path(dir.path(), 1),
            encode_record(&put("b", b"two"), b"two"),
        )
        .await
        .unwrap();

        let Err(EngineError::Corrupt(message)) = Buffer::open(dir.path(), 1 << 20).await else {
            panic!("an older damaged segment opens");
        };

        assert!(message.contains("00000000000000000000.log"), "{message}");
        assert!(message.contains("at offset"), "{message}");
        assert!(message.contains("key unknown"), "{message}");
        assert!(message.contains("docs/storage.md"), "{message}");
    }

    #[tokio::test]
    async fn test_segment_file_with_another_name_stops_the_open() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("3.log"),
            encode_record(&put("a", b"one"), b"one"),
        )
        .await
        .unwrap();

        let Err(EngineError::Corrupt(message)) = Buffer::open(dir.path(), 1 << 20).await else {
            panic!("a misnamed segment opens");
        };

        assert!(message.contains("3.log"), "{message}");
    }

    #[tokio::test]
    async fn test_gap_in_segment_numbers_replays_every_segment() {
        let dir = tempfile::tempdir().unwrap();
        formatted(dir.path());
        for (seq, key) in [(0, "a"), (2, "b")] {
            let record = encode_record(&put(key, b"v"), b"v");
            tokio::fs::write(segment_path(dir.path(), seq), record)
                .await
                .unwrap();
        }

        let buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();

        assert!(buffer.object("b", "a").is_some());
        assert!(buffer.object("b", "b").is_some());
    }

    #[tokio::test]
    async fn test_open_of_2000_small_segments_takes_seconds_at_most() {
        let dir = tempfile::tempdir().unwrap();
        formatted(dir.path());
        for seq in 0..2000u64 {
            let key = format!("k{seq}");
            let record = encode_record(&put(&key, b"v"), b"v");
            tokio::fs::write(segment_path(dir.path(), seq), record)
                .await
                .unwrap();
        }

        let started = std::time::Instant::now();
        let buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
        let elapsed = started.elapsed();

        assert!(buffer.object("b", "k1999").is_some());
        assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
    }

    #[tokio::test]
    async fn test_corrupt_sealed_segment_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut buffer = Buffer::open(dir.path(), 1).await.unwrap();
            buffer.append(put("a", b"one"), b"one").await.unwrap();
            buffer.append(put("b", b"two"), b"two").await.unwrap();
        }
        let path = segment_path(dir.path(), 0);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes).unwrap();

        assert!(matches!(
            Buffer::open(dir.path(), 1).await,
            Err(EngineError::Corrupt(_))
        ));
    }

    #[tokio::test]
    async fn test_segment_rotates_at_target_size() {
        let dir = tempfile::tempdir().unwrap();
        let mut buffer = Buffer::open(dir.path(), 1).await.unwrap();
        buffer.append(put("a", b"one"), b"one").await.unwrap();
        buffer.append(put("b", b"two"), b"two").await.unwrap();

        assert_eq!(buffer.seal().await.unwrap(), [0, 1]);
    }

    #[tokio::test]
    async fn test_release_forgets_flushed_writes_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
        buffer.append(put("a", b"one"), b"one").await.unwrap();
        let sealed = buffer.seal().await.unwrap();
        buffer.append(put("b", b"two"), b"two").await.unwrap();

        buffer.release(&sealed).await.unwrap();

        assert!(buffer.object("b", "a").is_none());
        assert!(buffer.object("b", "b").is_some());
        assert!(!buffer.segment_path(sealed[0]).exists());
        assert_eq!(buffer.seal().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_rewrite_of_a_key_in_a_later_segment_survives_release() {
        let dir = tempfile::tempdir().unwrap();
        let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
        buffer.append(put("a", b"one"), b"one").await.unwrap();
        let sealed = buffer.seal().await.unwrap();
        buffer.append(put("a", b"two"), b"two").await.unwrap();

        buffer.release(&sealed).await.unwrap();

        let Some(BufferedObject::Put(a)) = buffer.object("b", "a") else {
            panic!("the rewrite is still buffered");
        };
        assert_eq!(
            read_put(dir.path(), a, 0..a.size).await.unwrap().unwrap(),
            b"two"
        );
    }

    #[tokio::test]
    async fn test_listing_stays_inside_bucket_and_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let mut buffer = Buffer::open(dir.path(), 1 << 20).await.unwrap();
        for key in ["x/1", "x/2", "y"] {
            buffer.append(put(key, b"d"), b"d").await.unwrap();
        }

        let first = |bucket, from| buffer.first_object_from(bucket, "x/", from).map(|(k, _)| k);

        assert_eq!(first("b", ""), Some("x/1"));
        assert_eq!(first("b", "x/1\0"), Some("x/2"));
        assert_eq!(first("b", "x/2\0"), None, "y is outside the prefix");
        assert_eq!(first("ba", ""), None, "another bucket");
    }
}
