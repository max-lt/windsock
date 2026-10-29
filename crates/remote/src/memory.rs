use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::RwLock;

use bytes::Bytes;

use crate::{Remote, RemoteError, Sweep, check_key, check_prefix, check_range};

/// In-memory remote, for tests.
#[derive(Default)]
pub struct MemoryRemote {
    objects: RwLock<BTreeMap<String, Bytes>>,
}

#[async_trait::async_trait]
impl Remote for MemoryRemote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        check_key(key)?;
        self.objects
            .write()
            .expect("no panic while the lock is held")
            .insert(key.to_string(), data);
        Ok(())
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        check_key(key)?;
        let mut objects = self
            .objects
            .write()
            .expect("no panic while the lock is held");

        if objects.contains_key(key) {
            return Err(RemoteError::AlreadyExists(key.to_string()));
        }

        objects.insert(key.to_string(), data);
        Ok(())
    }

    async fn get(&self, key: &str, max_len: u64) -> Result<Option<Bytes>, RemoteError> {
        check_key(key)?;
        let objects = self
            .objects
            .read()
            .expect("no panic while the lock is held");
        match objects.get(key) {
            Some(data) if data.len() as u64 > max_len => Err(RemoteError::TooLarge {
                key: key.to_string(),
                len: data.len() as u64,
                max: max_len,
            }),
            data => Ok(data.cloned()),
        }
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        let Some(data) = self.get(key, u64::MAX).await? else {
            return Ok(None);
        };

        check_range(key, &range, data.len() as u64)?;
        Ok(Some(data.slice(range.start as usize..range.end as usize)))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        check_prefix(prefix)?;
        let objects = self
            .objects
            .read()
            .expect("no panic while the lock is held");

        Ok(objects
            .range(prefix.to_string()..)
            .map(|(key, _)| key)
            .take_while(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }

    async fn list_after(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, RemoteError> {
        check_prefix(prefix)?;
        let objects = self
            .objects
            .read()
            .expect("no panic while the lock is held");
        let start = match after < prefix {
            true => std::ops::Bound::Included(prefix.to_string()),
            false => std::ops::Bound::Excluded(after.to_string()),
        };

        Ok(objects
            .range((start, std::ops::Bound::Unbounded))
            .map(|(key, _)| key)
            .take_while(|key| key.starts_with(prefix))
            .take(limit)
            .cloned()
            .collect())
    }
}

#[async_trait::async_trait]
impl Sweep for MemoryRemote {
    async fn delete(&self, key: &str) -> Result<(), RemoteError> {
        check_key(key)?;
        self.objects
            .write()
            .expect("no panic while the lock is held")
            .remove(key);
        Ok(())
    }
}
