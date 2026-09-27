use std::io::{ErrorKind, SeekFrom};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::{Remote, RemoteError, check_key, check_prefix, check_range};

/// Makes temporary file names unique inside one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Remote in a local directory. Key `a/b` is the file `<root>/a/b`.
///
/// Unlike S3, keys `a` and `a/b` cannot both exist. `create` uses a hard link,
/// so the filesystem must support them.
pub struct DirRemote {
    root: PathBuf,
}

impl DirRemote {
    /// Opens a remote in `root`, and creates the directory if necessary.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, RemoteError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn key_of(&self, path: &Path) -> Option<String> {
        let relative = path.strip_prefix(&self.root).ok()?;
        let segments: Option<Vec<&str>> = relative.iter().map(|s| s.to_str()).collect();
        Some(segments?.join("/"))
    }
}

fn parent_of(path: &Path) -> &Path {
    path.parent().expect("a checked key has a parent in root")
}

/// Writes `data` to a fsynced temporary file next to `path`.
///
/// The dot prefix keeps a partial write out of `list`: keys never start with a dot.
async fn write_temp(path: &Path, data: &[u8]) -> Result<PathBuf, RemoteError> {
    let parent = parent_of(path);
    tokio::fs::create_dir_all(parent).await?;

    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".tmp.{}.{seq}", std::process::id()));

    let mut file = tokio::fs::File::create(&tmp).await?;
    file.write_all(data).await?;
    file.sync_all().await?;
    Ok(tmp)
}

/// Without this, a crash can lose the new directory entry.
async fn sync_parent(path: &Path) -> Result<(), RemoteError> {
    tokio::fs::File::open(parent_of(path))
        .await?
        .sync_all()
        .await?;
    Ok(())
}

async fn open_file(path: &Path) -> Result<Option<tokio::fs::File>, RemoteError> {
    match tokio::fs::File::open(path).await {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[async_trait::async_trait]
impl Remote for DirRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        check_key(key)?;
        let path = self.root.join(key);
        let tmp = write_temp(&path, &data).await?;

        tokio::fs::rename(&tmp, &path).await?;
        sync_parent(&path).await
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        check_key(key)?;
        let path = self.root.join(key);
        let tmp = write_temp(&path, &data).await?;

        // link() fails when the target exists, so two creates have one winner.
        let linked = tokio::fs::hard_link(&tmp, &path).await;
        tokio::fs::remove_file(&tmp).await?;

        match linked {
            Ok(()) => sync_parent(&path).await,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                Err(RemoteError::AlreadyExists(key.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        check_key(key)?;

        match tokio::fs::read(self.root.join(key)).await {
            Ok(data) => Ok(Some(Bytes::from(data))),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        check_key(key)?;

        let Some(mut file) = open_file(&self.root.join(key)).await? else {
            return Ok(None);
        };

        check_range(key, &range, file.metadata().await?.len())?;

        let mut data = vec![0; (range.end - range.start) as usize];
        file.seek(SeekFrom::Start(range.start)).await?;
        file.read_exact(&mut data).await?;
        Ok(Some(Bytes::from(data)))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        check_prefix(prefix)?;

        // Walk only the directory that the prefix names, not the whole remote.
        let base = match prefix.rfind('/') {
            Some(end) => self.root.join(&prefix[..end]),
            None => self.root.clone(),
        };

        let mut keys = Vec::new();
        let mut dirs = vec![base];

        while let Some(dir) = dirs.pop() {
            let mut entries = match tokio::fs::read_dir(&dir).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };

            while let Some(entry) = entries.next_entry().await? {
                if entry.file_name().to_string_lossy().starts_with('.') {
                    continue;
                }

                let path = entry.path();

                if entry.file_type().await?.is_dir() {
                    dirs.push(path);
                    continue;
                }

                if let Some(key) = self.key_of(&path)
                    && key.starts_with(prefix)
                {
                    keys.push(key);
                }
            }
        }

        keys.sort();
        Ok(keys)
    }
}
