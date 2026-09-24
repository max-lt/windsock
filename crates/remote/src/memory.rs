use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::RwLock;

use bytes::Bytes;

use crate::{Remote, RemoteError, check_key, check_prefix, check_range};

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

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        check_key(key)?;
        let objects = self
            .objects
            .read()
            .expect("no panic while the lock is held");
        Ok(objects.get(key).cloned())
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        let Some(data) = self.get(key).await? else {
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
}
