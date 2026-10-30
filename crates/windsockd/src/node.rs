//! A handle on a running node for the process that embeds windsockd. It reads the node state and
//! sets the cache limit. It writes no object, bucket or configuration.

use std::sync::Arc;

use engine::{
    BucketInfo, CacheState, Engine, EngineError, ListAfter, ListEntry, ListQuery, ObjectInfo,
};
use model::NodeId;
use remote::Sweep;

/// The state of a node, cheap to read at any time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub node: NodeId,
    /// Bytes in the buffer that are not in the remote yet.
    pub buffered_bytes: u64,
    pub buffer_limit: u64,
    pub cache: CacheState,
    /// Bytes of open multipart uploads.
    pub parts_bytes: u64,
    pub parts_limit: u64,
    pub quarantined: bool,
    pub index_poisoned: bool,
    pub draining: bool,
    pub gc_enabled: bool,
    /// Another node that ran the GC in the last horizon.
    pub other_gc_node: Option<NodeId>,
}

/// The most objects in one page of [`Node::list`], as for S3 ListObjects: a larger `max` gets this.
pub const MAX_PAGE: usize = 1000;

/// One page of a listing. The ETag of an object is the hex of its `content_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub objects: Vec<ObjectInfo>,
    /// The `after` key of the next page, when more objects follow.
    pub next: Option<String>,
}

#[async_trait::async_trait]
trait NodeOps: Send + Sync {
    async fn status(&self) -> NodeStatus;
    async fn buckets(&self) -> Result<Vec<BucketInfo>, EngineError>;
    async fn list(
        &self,
        bucket: &str,
        prefix: &str,
        after: Option<&str>,
        max: usize,
    ) -> Result<Page, EngineError>;
    async fn set_cache_limit(&self, bytes: u64) -> Result<CacheState, EngineError>;
}

/// A running node. Clone it freely: every clone reaches the same engine.
#[derive(Clone)]
pub struct Node(Arc<dyn NodeOps>);

impl Node {
    pub(crate) fn new<R: Sweep + 'static>(
        engine: Arc<Engine<R>>,
        uploads: Arc<s3api::Uploads>,
        limits: Limits,
    ) -> Self {
        Self(Arc::new(EngineNode {
            engine,
            uploads,
            limits,
        }))
    }

    pub async fn status(&self) -> NodeStatus {
        self.0.status().await
    }

    pub async fn buckets(&self) -> Result<Vec<BucketInfo>, EngineError> {
        self.0.buckets().await
    }

    /// At most `max` objects of `bucket` under `prefix`, in key order, after the key `after`. A
    /// `max` over [`MAX_PAGE`] gets [`MAX_PAGE`].
    pub async fn list(
        &self,
        bucket: &str,
        prefix: &str,
        after: Option<&str>,
        max: usize,
    ) -> Result<Page, EngineError> {
        self.0.list(bucket, prefix, after, max).await
    }

    /// Sets the bound of the chunk cache, at most `cache_bytes`. 0 empties the cache.
    pub async fn set_cache_limit(&self, bytes: u64) -> Result<CacheState, EngineError> {
        self.0.set_cache_limit(bytes).await
    }
}

/// The limits of the configuration that the status shows.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub buffer: u64,
    pub parts: u64,
    pub gc_enabled: bool,
}

struct EngineNode<R> {
    engine: Arc<Engine<R>>,
    uploads: Arc<s3api::Uploads>,
    limits: Limits,
}

#[async_trait::async_trait]
impl<R: Sweep + 'static> NodeOps for EngineNode<R> {
    async fn status(&self) -> NodeStatus {
        NodeStatus {
            node: self.engine.node(),
            buffered_bytes: self.engine.buffered_bytes().await,
            buffer_limit: self.limits.buffer,
            cache: self.engine.cache_state(),
            parts_bytes: self.uploads.held(),
            parts_limit: self.limits.parts,
            quarantined: self.engine.is_quarantined(),
            index_poisoned: self.engine.index_is_poisoned(),
            draining: self.engine.is_draining(),
            gc_enabled: self.limits.gc_enabled,
            other_gc_node: self.engine.other_gc_node(),
        }
    }

    async fn buckets(&self) -> Result<Vec<BucketInfo>, EngineError> {
        self.engine.list_buckets().await
    }

    async fn list(
        &self,
        bucket: &str,
        prefix: &str,
        after: Option<&str>,
        max: usize,
    ) -> Result<Page, EngineError> {
        let query = ListQuery {
            prefix,
            delimiter: None,
            after: after.map(|key| ListAfter::Key(key.to_string())),
            max_keys: max.min(MAX_PAGE),
        };
        let page = self.engine.list_page(bucket, &query).await?;
        let objects: Vec<ObjectInfo> = page
            .entries
            .into_iter()
            .filter_map(|entry| match entry {
                ListEntry::Object(info) => Some(info),
                ListEntry::CommonPrefix(_) => None,
            })
            .collect();
        let next = match page.truncated {
            true => objects.last().map(|object| object.key.clone()),
            false => None,
        };
        Ok(Page { objects, next })
    }

    async fn set_cache_limit(&self, bytes: u64) -> Result<CacheState, EngineError> {
        self.engine.set_cache_limit(bytes).await
    }
}
