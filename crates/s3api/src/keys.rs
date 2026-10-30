//! The secret keys that SigV4 needs, by access key. The router asks a [`KeyStore`] on every
//! request and keeps no copy, so a change in the store applies at the next request.

use std::collections::HashMap;

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

/// The store failed: the request gets 503 and is never let through.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct KeyStoreError(String);

impl KeyStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// The source of the secret keys.
#[async_trait::async_trait]
pub trait KeyStore: Send + Sync {
    /// The secret of `access_key`. `None` when the key is unknown or revoked.
    async fn secret(&self, access_key: &str) -> Result<Option<Secret>, KeyStoreError>;
}

/// Keys fixed at start, from the configuration.
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
    async fn secret(&self, access_key: &str) -> Result<Option<Secret>, KeyStoreError> {
        Ok(self
            .0
            .get(access_key)
            .map(|secret| Secret::new(secret.to_string())))
    }
}

/// The secret of `access_key`, or the S3 error that denies the request.
pub(crate) async fn secret_of(store: &dyn KeyStore, access_key: &str) -> Result<Secret, S3Error> {
    match store.secret(access_key).await {
        Ok(Some(secret)) => Ok(secret),
        Ok(None) => Err(S3Error::new(
            "InvalidAccessKeyId",
            StatusCode::FORBIDDEN,
            "the access key does not exist",
        )),
        Err(e) => {
            // The client sees no text of the store: it can name files or hosts.
            warn!(%e, "key store failed: the request is denied");
            Err(S3Error::new(
                "ServiceUnavailable",
                StatusCode::SERVICE_UNAVAILABLE,
                "the key store is not available",
            ))
        }
    }
}
