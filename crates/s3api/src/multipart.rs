//! Multipart uploads, with the parts on local disk until the complete.
//!
//! An upload lives on the proxy that started it. Its parts survive a restart:
//! `<dir>/<upload id>/meta`, and one file per part named `<number>-<etag>`.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::S3Error;
use crate::xml::PartInfo;

/// Makes upload ids and temporary names unique inside one process.
static COUNTER: AtomicU64 = AtomicU64::new(0);

const META: &str = "meta";
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

/// The parts of a complete, joined, and the metadata given at initiation.
pub(crate) struct Assembled {
    pub data: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
}

pub(crate) struct Uploads {
    dir: PathBuf,
}

impl Uploads {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory of an upload. Only 32 hex digits are an id, so no path can leave `dir`.
    fn upload_dir(&self, upload_id: &str) -> Result<PathBuf, S3Error> {
        let valid = upload_id.len() == 32 && upload_id.bytes().all(|b| b.is_ascii_hexdigit());
        if !valid {
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

    pub async fn initiate(
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

    /// Stores a part and returns its ETag. A part sent again replaces the old one.
    pub async fn put_part(
        &self,
        upload_id: &str,
        bucket: &str,
        key: &str,
        number: &str,
        data: &[u8],
    ) -> Result<String, S3Error> {
        let number: u16 = number
            .parse()
            .ok()
            .filter(|n| (1..=MAX_PART).contains(n))
            .ok_or_else(|| S3Error::invalid_argument("partNumber must be between 1 and 10000"))?;
        self.meta(upload_id, bucket, key).await?;

        let dir = self.upload_dir(upload_id)?;
        let etag = blake3::hash(data).to_hex().to_string();
        for ((old, old_etag), _) in part_files(&dir).await? {
            if old == number {
                remove_if_present(&dir.join(part_name(old, &old_etag))).await?;
            }
        }
        write_file(&dir, &part_name(number, &etag), data).await?;

        Ok(etag)
    }

    pub async fn parts(
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
    pub async fn abort(&self, upload_id: &str, bucket: &str, key: &str) -> Result<(), S3Error> {
        match self.meta(upload_id, bucket, key).await {
            Ok(_) => {}
            Err(e) if e.code == "NoSuchUpload" => return Ok(()),
            Err(e) => return Err(e),
        }

        remove_dir(&self.upload_dir(upload_id)?).await
    }

    /// Joins the requested parts, in ascending order, each with the ETag it was given.
    pub async fn assemble(
        &self,
        upload_id: &str,
        bucket: &str,
        key: &str,
        requested: &[(u16, String)],
    ) -> Result<Assembled, S3Error> {
        let meta = self.meta(upload_id, bucket, key).await?;

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

        let dir = self.upload_dir(upload_id)?;
        let stored: BTreeMap<u16, String> = part_files(&dir)
            .await?
            .into_iter()
            .map(|((number, etag), _)| (number, etag))
            .collect();
        let mut data = Vec::new();

        for (number, etag) in requested {
            if stored.get(number) != Some(etag) {
                return Err(S3Error::new(
                    "InvalidPart",
                    StatusCode::BAD_REQUEST,
                    format!("part {number} is missing or has another ETag"),
                ));
            }
            let part = tokio::fs::read(dir.join(part_name(*number, etag)))
                .await
                .map_err(io)?;
            data.extend_from_slice(&part);
        }

        Ok(Assembled {
            data,
            metadata: meta.metadata,
        })
    }

    /// Removes a completed upload.
    pub async fn finish(&self, upload_id: &str) -> Result<(), S3Error> {
        remove_dir(&self.upload_dir(upload_id)?).await
    }

    /// Uploads in progress for `bucket`: key, id, initiation time.
    pub async fn list(&self, bucket: &str) -> Result<Vec<(String, String, u64)>, S3Error> {
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
    let tmp = dir.join(format!(".tmp.{}.{seq}", std::process::id()));
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
        let uploads = Uploads::new(dir.path());
        (dir, uploads)
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

        let assembled = uploads
            .assemble(&id, "b", "k", &[(1, first), (2, second)])
            .await
            .unwrap();

        assert_eq!(assembled.data, b"hello world");
        assert_eq!(uploads.parts(&id, "b", "k").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_part_sent_again_replaces_the_old_one() {
        let (_dir, uploads) = uploads().await;
        let id = uploads.initiate("b", "k", BTreeMap::new()).await.unwrap();
        let old = uploads.put_part(&id, "b", "k", "1", b"old").await.unwrap();
        let new = uploads.put_part(&id, "b", "k", "1", b"new").await.unwrap();

        let parts = uploads.parts(&id, "b", "k").await.unwrap();
        let stale = uploads.assemble(&id, "b", "k", &[(1, old)]).await;

        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].2, new);
        assert_eq!(stale.err().unwrap().code, "InvalidPart");
    }

    #[tokio::test]
    async fn test_bad_requests_are_rejected() {
        let (_dir, uploads) = uploads().await;
        let id = uploads.initiate("b", "k", BTreeMap::new()).await.unwrap();
        let etag = uploads.put_part(&id, "b", "k", "1", b"x").await.unwrap();
        let code = |r: Result<Assembled, S3Error>| r.err().unwrap().code;

        assert_eq!(
            code(
                uploads
                    .assemble(&id, "b", "k", &[(2, etag.clone()), (1, etag.clone())])
                    .await
            ),
            "InvalidPartOrder"
        );
        assert_eq!(
            code(uploads.assemble(&id, "b", "other", &[(1, etag)]).await),
            "NoSuchUpload"
        );
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
}
