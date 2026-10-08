//! The remote object `key-id` names the repository key of the remote.
//!
//! The first proxy writes it with a create-only write. A proxy with another
//! key must not start: its chunks, packs and entries would be unreadable to
//! the other proxies, and its chunk IDs would never dedup with theirs.

use bytes::Bytes;
use keys::RepoKey;
use remote::{Remote, RemoteError};
use tracing::info;

use crate::{EngineError, Result};

/// Remote key of the key ID of the repository key.
pub const KEY_ID_KEY: &str = "key-id";

/// Writes the key ID when the remote has none, then checks that it is the ID of `key`.
pub(crate) async fn check_key<R: Remote>(remote: &R, key: &RepoKey) -> Result<()> {
    let id = key.id();

    match remote
        .create(KEY_ID_KEY, Bytes::copy_from_slice(id.as_bytes()))
        .await
    {
        Ok(()) => {
            info!(key_id = %id, "wrote the key ID to the remote");
            return Ok(());
        }
        Err(RemoteError::AlreadyExists(_)) => {}
        Err(e) => return Err(e.into()),
    }

    let Some(stored) = remote.get(KEY_ID_KEY).await? else {
        return Err(EngineError::Corrupt(format!(
            "{KEY_ID_KEY} exists for a create, not for a read"
        )));
    };

    if stored.as_ref() != id.as_bytes() {
        return Err(EngineError::WrongKey(id));
    }

    Ok(())
}
