//! Local write-back buffer: an append-only log on NVMe, cut into segments.
//!
//! A write is acknowledged once its record is fsynced. A flush seals the
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
use std::time::{SystemTime, UNIX_EPOCH};

use journal::Entry;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tracing::{debug, warn};

use crate::EngineError;

const PREFIX_LEN: usize = 4 + 8 + 32;

/// Larger heads are garbage: keys, bucket names and metadata are small.
const MAX_HEAD_LEN: u32 = 64 * 1024;

const SEGMENT_SUFFIX: &str = ".log";
const INTENT_FILE: &str = "intent";
const INTENT_TEMP: &str = ".intent.tmp";

pub(crate) fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// The fixed part of a record. The data of a put follows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Head {
    /// Unix nanoseconds at acknowledgement.
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

/// Encodes a record. Pure, so the format has a golden test.
pub(crate) fn encode_record(head: &Head, data: &[u8]) -> Vec<u8> {
    let head_bytes = postcard::to_allocvec(head).expect("a record head always serializes");
    let head_len = u32::try_from(head_bytes.len()).expect("a record head is smaller than 4 GiB");

    let mut out = Vec::with_capacity(PREFIX_LEN + head_bytes.len() + data.len());
    out.extend_from_slice(&head_len.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(blake3::hash(&head_bytes).as_bytes());
    out.extend_from_slice(&head_bytes);
    out.extend_from_slice(data);
    out
}

/// A record read back from a segment.
pub(crate) struct Record {
    pub head: Head,
    pub data: Vec<u8>,
    /// Position of `data` in the segment file.
    pub data_offset: u64,
}

enum Read {
    Record(Record),
    End,
    /// A torn or corrupt record starts at this offset.
    Invalid(u64),
}

/// Reads the records of one segment in order.
pub(crate) struct SegmentReader {
    file: BufReader<File>,
    offset: u64,
    len: u64,
}

impl SegmentReader {
    pub async fn open(path: &Path) -> Result<Self, EngineError> {
        let file = File::open(path).await?;
        let len = file.metadata().await?.len();

        Ok(Self {
            file: BufReader::new(file),
            offset: 0,
            len,
        })
    }

    /// Next record, or `None` at the end. A torn or corrupt record is an error.
    pub async fn next(&mut self, path: &Path) -> Result<Option<Record>, EngineError> {
        match self.read().await? {
            Read::Record(record) => Ok(Some(record)),
            Read::End => Ok(None),
            Read::Invalid(at) => Err(EngineError::Corrupt(format!(
                "{}: invalid record at offset {at}",
                path.display()
            ))),
        }
    }

    async fn read(&mut self) -> Result<Read, EngineError> {
        let start = self.offset;

        if start == self.len {
            return Ok(Read::End);
        }

        let mut prefix = [0u8; PREFIX_LEN];
        if !read_full(&mut self.file, &mut prefix).await? {
            return Ok(Read::Invalid(start));
        }

        let head_len = u32::from_le_bytes(prefix[..4].try_into().expect("4 bytes"));
        let data_len = u64::from_le_bytes(prefix[4..12].try_into().expect("8 bytes"));
        let head_hash = &prefix[12..];
        let remaining = self.len - start - PREFIX_LEN as u64;

        if head_len > MAX_HEAD_LEN || u64::from(head_len) + data_len > remaining {
            return Ok(Read::Invalid(start));
        }

        let mut head_bytes = vec![0u8; head_len as usize];
        let mut data = vec![0u8; data_len as usize];
        if !read_full(&mut self.file, &mut head_bytes).await?
            || !read_full(&mut self.file, &mut data).await?
        {
            return Ok(Read::Invalid(start));
        }

        let Some(head) = decode_head(head_hash, &head_bytes, &data) else {
            return Ok(Read::Invalid(start));
        };

        let data_offset = start + (PREFIX_LEN as u64) + u64::from(head_len);
        self.offset = data_offset + data_len;

        Ok(Read::Record(Record {
            head,
            data,
            data_offset,
        }))
    }
}

/// Checks the head hash and, for a put, the data hash.
fn decode_head(head_hash: &[u8], head_bytes: &[u8], data: &[u8]) -> Option<Head> {
    if blake3::hash(head_bytes).as_bytes()[..] != head_hash[..] {
        return None;
    }

    let head: Head = postcard::from_bytes(head_bytes).ok()?;
    let data_is_valid = match &head.op {
        Op::Put { content_hash, .. } => blake3::hash(data).as_bytes() == content_hash,
        _ => data.is_empty(),
    };

    data_is_valid.then_some(head)
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
}

/// What a flush must commit, and the segments to delete once it is in the remote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Intent {
    pub entry: Entry,
    pub segments: Vec<u64>,
    /// Unix nanoseconds when the flush started its plan. An old plan is never committed.
    pub planned_at: u64,
}

struct Active {
    seq: u64,
    file: File,
    len: u64,
}

pub(crate) struct Buffer {
    dir: PathBuf,
    segment_target: u64,
    active: Active,
    /// Sealed segments and their sizes.
    sealed: BTreeMap<u64, u64>,
    objects: BTreeMap<(String, String), BufferedObject>,
    buckets: BTreeMap<String, BufferedBucket>,
}

impl Buffer {
    /// Opens the buffer in `dir` and replays the segments a previous process left.
    /// A torn record at the end of the last segment is cut off: it was never acknowledged.
    pub async fn open(dir: impl Into<PathBuf>, segment_target: u64) -> Result<Self, EngineError> {
        let dir = dir.into();
        tokio::fs::create_dir_all(&dir).await?;

        let existing = list_segments(&dir).await?;
        let mut buffer = Self {
            active: create_segment(&dir, existing.last().map_or(0, |last| last + 1)).await?,
            dir,
            segment_target,
            sealed: BTreeMap::new(),
            objects: BTreeMap::new(),
            buckets: BTreeMap::new(),
        };

        for (i, &seq) in existing.iter().enumerate() {
            let is_last = i + 1 == existing.len();
            buffer.replay(seq, is_last).await?;
        }

        Ok(buffer)
    }

    async fn replay(&mut self, seq: u64, is_last: bool) -> Result<(), EngineError> {
        let path = self.segment_path(seq);
        let mut reader = SegmentReader::open(&path).await?;
        let mut records = 0;

        let end = loop {
            match reader.read().await? {
                Read::Record(record) => {
                    self.track(
                        seq,
                        &record.head,
                        record.data_offset,
                        record.data.len() as u64,
                    );
                    records += 1;
                }
                Read::End => break reader.len,
                Read::Invalid(at) if is_last => {
                    warn!(
                        segment = seq,
                        offset = at,
                        dropped = reader.len - at,
                        "cut a torn record"
                    );
                    let file = tokio::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .await?;
                    file.set_len(at).await?;
                    file.sync_all().await?;
                    break at;
                }
                Read::Invalid(at) => {
                    return Err(EngineError::Corrupt(format!(
                        "{}: invalid record at offset {at}",
                        path.display()
                    )));
                }
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

    /// Appends a record and fsyncs it. Once this returns, the write survives a crash.
    pub async fn append(&mut self, head: Head, data: &[u8]) -> Result<(), EngineError> {
        let record = encode_record(&head, data);
        let data_offset = self.active.len + (record.len() - data.len()) as u64;

        if let Err(e) = self.write_active(&record).await {
            // A partial record inside a segment would stop the replay of every record after it.
            self.active.file.set_len(self.active.len).await?;
            return Err(e);
        }

        self.active.len += record.len() as u64;
        self.track(self.active.seq, &head, data_offset, data.len() as u64);

        if self.active.len >= self.segment_target {
            self.rotate().await?;
        }

        Ok(())
    }

    async fn write_active(&mut self, record: &[u8]) -> Result<(), EngineError> {
        self.active.file.write_all(record).await?;
        self.active.file.sync_data().await?;
        Ok(())
    }

    fn track(&mut self, segment: u64, head: &Head, data_offset: u64, size: u64) {
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
                };
                self.buckets.insert(bucket.clone(), state);
            }
            Op::DeleteBucket { bucket } => {
                let state = BufferedBucket {
                    segment,
                    exists: false,
                    owner: None,
                };
                self.buckets.insert(bucket.clone(), state);
            }
        }
    }

    pub fn object(&self, bucket: &str, key: &str) -> Option<&BufferedObject> {
        self.objects.get(&(bucket.to_string(), key.to_string()))
    }

    /// Buffered writes to the keys of `bucket` under `prefix`, in key order.
    pub fn objects<'a>(
        &'a self,
        bucket: &'a str,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a str, &'a BufferedObject)> {
        self.objects
            .range((bucket.to_string(), prefix.to_string())..)
            .take_while(move |((b, k), _)| b == bucket && k.starts_with(prefix))
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
        let next = create_segment(&self.dir, self.active.seq + 1).await?;
        let sealed = std::mem::replace(&mut self.active, next);
        self.sealed.insert(sealed.seq, sealed.len);
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
pub(crate) async fn read_put(
    dir: &Path,
    put: &BufferedPut,
    range: Range<u64>,
) -> Result<Option<Vec<u8>>, EngineError> {
    let mut file = match File::open(segment_path(dir, put.segment)).await {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let mut data = vec![0u8; (range.end - range.start) as usize];
    file.seek(SeekFrom::Start(put.data_offset + range.start))
        .await?;
    file.read_exact(&mut data).await?;
    Ok(Some(data))
}

pub(crate) fn segment_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("{seq:020}{SEGMENT_SUFFIX}"))
}

async fn list_segments(dir: &Path) -> Result<Vec<u64>, EngineError> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    let mut seqs = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let seq = name
            .to_str()
            .and_then(|n| n.strip_suffix(SEGMENT_SUFFIX))
            .and_then(|n| n.parse::<u64>().ok());

        if let Some(seq) = seq {
            seqs.push(seq);
        }
    }

    seqs.sort_unstable();
    Ok(seqs)
}

async fn create_segment(dir: &Path, seq: u64) -> Result<Active, EngineError> {
    let file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(segment_path(dir, seq))
        .await?;
    sync_dir(dir).await?;
    Ok(Active { seq, file, len: 0 })
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

    async fn records(buffer: &Buffer, seq: u64) -> Vec<Record> {
        let path = buffer.segment_path(seq);
        let mut reader = SegmentReader::open(&path).await.unwrap();
        let mut out = Vec::new();
        while let Some(record) = reader.next(&path).await.unwrap() {
            out.push(record);
        }
        out
    }

    #[test]
    fn test_record_format_is_stable() {
        let bytes = encode_record(&put("k", b"data"), b"data");

        assert_eq!(
            blake3::hash(&bytes).to_string(),
            "16160308b47a1cbf772609dd37102a41263dad1f0d306352d659a7f905102949"
        );
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
        assert_eq!(read[1].data, b"two");
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

        let keys: Vec<_> = buffer.objects("b", "x/").map(|(k, _)| k).collect();

        assert_eq!(keys, ["x/1", "x/2"]);
        assert_eq!(buffer.objects("ba", "").count(), 0);
    }
}
