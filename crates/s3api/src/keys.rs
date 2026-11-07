//! The secret key and the grants of each access key. The router asks a [`KeyStore`] on every
//! request and keeps no copy, so a change in the store applies at the next request.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use axum::http::StatusCode;
use tracing::warn;
use zeroize::Zeroizing;

use crate::S3Error;

/// The secret key of an access key. Its `Debug` form hides it, and its memory is wiped on drop.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// What a key can do on a bucket. ReadWrite covers Read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Access {
    /// GET and HEAD of objects and buckets, and the listings.
    Read,
    /// Also the writes and deletes of objects, the multipart steps and DeleteBucket.
    ReadWrite,
}

/// The rights of one access key. The access on a bucket is the greatest that a field gives.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grants {
    pub all_buckets: Option<Access>,
    pub buckets: BTreeMap<String, Access>,
    /// CreateBucket, and ReadWrite on each bucket that the engine names this key as the owner of.
    pub create_bucket: bool,
}

impl Grants {
    /// Every operation on every bucket, as for the keys of the configuration.
    pub fn full() -> Self {
        Self {
            all_buckets: Some(Access::ReadWrite),
            buckets: BTreeMap::new(),
            create_bucket: true,
        }
    }

    /// The access on `bucket`. `Owner::Key` when the engine names this key as its owner.
    pub fn access(&self, bucket: &str, owner: Owner) -> Option<Access> {
        let owned = (owner == Owner::Key && self.create_bucket).then_some(Access::ReadWrite);
        [self.all_buckets, self.buckets.get(bucket).copied(), owned]
            .into_iter()
            .flatten()
            .max()
    }
}

/// Whether the engine names the key of a request as the owner of a bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Key,
    Other,
}

/// An access key as the store knows it.
#[derive(Debug)]
pub struct Key {
    pub secret: Secret,
    pub grants: Grants,
}

/// The store failed: the request gets 503 and is never let through.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct KeyStoreError(String);

impl KeyStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// The source of the secret keys and their grants.
///
/// - s3api keeps no cache: each request costs one lookup, also for an unknown key. The store
///   caches its answers, the negative ones too, to protect itself.
/// - SigV4 needs the secret in clear, so the store holds secrets that it can read back. The
///   process that embeds windsockd protects them at rest.
/// - A key or a grant revoked during a streamed PUT does not stop that PUT. The next request fails.
/// - The secret is wiped from memory at the end of the request.
/// - A lookup longer than [`KEY_STORE_DEADLINE`] gets 503.
/// - `key` must not block its thread: the deadline is a timer on the same runtime, and a
///   blocked thread also stops every other request on it. A store over a synchronous database
///   runs its lookup with `spawn_blocking`:
///
/// ```ignore
/// async fn key(&self, access_key: &str) -> Result<Option<Key>, KeyStoreError> {
///     let (db, access_key) = (self.db.clone(), access_key.to_string());
///     tokio::task::spawn_blocking(move || db.key_of(&access_key))
///         .await
///         .map_err(|e| KeyStoreError::new(e.to_string()))?
/// }
/// ```
#[async_trait::async_trait]
pub trait KeyStore: Send + Sync {
    /// The secret and the grants of `access_key`. `None` when the key is unknown or revoked.
    async fn key(&self, access_key: &str) -> Result<Option<Key>, KeyStoreError>;
}

/// Keys fixed at start, from the configuration, each with [`Grants::full`].
pub struct StaticKeys(HashMap<String, Zeroizing<String>>);

impl StaticKeys {
    pub fn new(keys: HashMap<String, String>) -> Self {
        Self(
            keys.into_iter()
                .map(|(access, secret)| (access, Zeroizing::new(secret)))
                .collect(),
        )
    }
}

#[async_trait::async_trait]
impl KeyStore for StaticKeys {
    async fn key(&self, access_key: &str) -> Result<Option<Key>, KeyStoreError> {
        Ok(self.0.get(access_key).map(|secret| Key {
            secret: Secret::new(secret.to_string()),
            grants: Grants::full(),
        }))
    }
}

/// The longest wait for one lookup: a store that hangs must not hold the connection.
pub const KEY_STORE_DEADLINE: Duration = Duration::from_secs(2);

fn unknown_key() -> S3Error {
    S3Error::new(
        "InvalidAccessKeyId",
        StatusCode::FORBIDDEN,
        "the access key does not exist",
    )
}

fn unavailable() -> S3Error {
    S3Error::new(
        "ServiceUnavailable",
        StatusCode::SERVICE_UNAVAILABLE,
        "the key store is not available",
    )
}

/// The key of `access_key`, or the S3 error that denies the request.
pub(crate) async fn key_of(store: &dyn KeyStore, access_key: &str) -> Result<Key, S3Error> {
    let Ok(answer) = tokio::time::timeout(KEY_STORE_DEADLINE, store.key(access_key)).await else {
        warn!(
            deadline_ms = KEY_STORE_DEADLINE.as_millis() as u64,
            "key store did not answer in time: the request is denied"
        );
        return Err(unavailable());
    };
    match answer {
        // Anyone can sign with an empty secret: it is no key.
        Ok(Some(key)) if key.secret.expose().is_empty() => {
            warn!(
                access_key,
                "key store gave an empty secret: the request is denied"
            );
            Err(unknown_key())
        }
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(unknown_key()),
        Err(e) => {
            // The client sees no text of the store: it can name files or hosts.
            warn!(%e, "key store failed: the request is denied");
            Err(unavailable())
        }
    }
}
