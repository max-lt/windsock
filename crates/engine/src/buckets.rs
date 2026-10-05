//! Bucket operations.

use super::*;

impl<R: Remote + 'static> Engine<R> {
    pub async fn create_bucket(&self, name: &str, owner: Option<String>) -> Result<()> {
        check_bucket_name(name)?;
        let mut buffer = self.buffer.lock().await;

        if self.bucket_in(&buffer, name)?.is_some() {
            return Err(EngineError::BucketAlreadyExists(name.to_string()));
        }

        let op = Op::CreateBucket {
            bucket: name.to_string(),
            owner,
        };
        self.append(&mut buffer, op, &[]).await
    }

    /// Deletes an empty bucket. Emptiness is checked against what this proxy knows.
    pub async fn delete_bucket(&self, name: &str) -> Result<()> {
        self.retry_after_sync(|| self.delete_bucket_once(name))
            .await
    }

    pub(crate) async fn delete_bucket_once(&self, name: &str) -> Result<()> {
        let mut buffer = self.buffer.lock().await;
        self.require_bucket(&buffer, name)?;

        let has_objects = self
            .keys_in(&buffer, name, "")?
            .into_iter()
            .any(|(_, current)| current.exists());

        if has_objects {
            return Err(EngineError::BucketNotEmpty(name.to_string()));
        }

        let op = Op::DeleteBucket {
            bucket: name.to_string(),
        };
        self.append(&mut buffer, op, &[]).await
    }

    pub async fn bucket(&self, name: &str) -> Result<BucketInfo> {
        self.retry_after_sync(|| async move {
            let buffer = self.buffer.lock().await;
            self.require_bucket(&buffer, name)
        })
        .await
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketInfo>> {
        let buffer = self.buffer.lock().await;
        let mut buckets: BTreeMap<String, (Option<String>, u64)> = self
            .index()
            .buckets()?
            .into_iter()
            .map(|(name, state)| (name, (state.owner, state.hlc)))
            .collect();

        for (name, state) in buffer.buckets() {
            if state.exists {
                buckets.insert(name.to_string(), (state.owner.clone(), state.time));
            } else {
                buckets.remove(name);
            }
        }

        Ok(buckets
            .into_iter()
            .map(|(name, (owner, created))| BucketInfo {
                name,
                owner,
                created,
            })
            .collect())
    }

    pub(crate) fn bucket_in(&self, buffer: &Buffer, name: &str) -> Result<Option<BucketInfo>> {
        if let Some(state) = buffer.bucket(name) {
            return Ok(state.exists.then(|| BucketInfo {
                name: name.to_string(),
                owner: state.owner.clone(),
                created: state.time,
            }));
        }

        Ok(self
            .index()
            .bucket(name)?
            .filter(|state| state.exists)
            .map(|state| BucketInfo {
                name: name.to_string(),
                owner: state.owner,
                created: state.hlc,
            }))
    }

    pub(crate) fn require_bucket(&self, buffer: &Buffer, name: &str) -> Result<BucketInfo> {
        self.bucket_in(buffer, name)?
            .ok_or_else(|| EngineError::NoSuchBucket(name.to_string()))
    }
}

/// S3 rules: 3 to 63 bytes of lowercase letters, digits, dots and hyphens,
/// starting and ending with a letter or a digit.
pub(crate) fn check_bucket_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let valid = (3..=63).contains(&bytes.len())
        && bytes.iter().all(|b| edge(b) || *b == b'.' || *b == b'-')
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge);

    if !valid {
        return Err(EngineError::InvalidBucketName(name.to_string()));
    }

    Ok(())
}
