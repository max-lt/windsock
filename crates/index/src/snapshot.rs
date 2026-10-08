//! Snapshot format: the index state at its applied frontiers, for bootstrap.
//!
//! Layout: `VERSION | sealed postcard(Snapshot)`. A reader checks the bytes against the
//! blake3 hash in the snapshot key.

use journal::Frontiers;
use keys::{Nonce, RepoKey};
use model::ObjectId;
use serde::{Deserialize, Serialize};

use crate::{BucketState, IndexError, ObjectState};

const VERSION: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub frontiers: Frontiers,
    /// Index object keys, as `object_key` builds them, and their states.
    pub objects: Vec<(Vec<u8>, ObjectState)>,
    pub buckets: Vec<(String, BucketState)>,
    /// Index condemn keys and the lowest condemn HLC.
    pub condemned: Vec<(Vec<u8>, u64)>,
    /// Manifests that the versions name, when this index holds them. Inline
    /// manifests exist nowhere else once their entries are redacted.
    pub manifests: Vec<(ObjectId, Vec<u8>)>,
}

impl Snapshot {
    /// Seals the snapshot with `nonce`, which must never repeat.
    pub fn encode(&self, key: &RepoKey, nonce: &Nonce) -> Vec<u8> {
        let plain = postcard::to_allocvec(self).expect("a snapshot always serializes");
        let mut bytes = vec![VERSION];
        bytes.extend(key.seal(nonce, &plain));
        bytes
    }

    /// Checks `bytes` against their blake3 `hash`, opens and decodes them.
    pub fn decode(key: &RepoKey, hash: &[u8; 32], bytes: &[u8]) -> Result<Self, IndexError> {
        let bad = || IndexError::Corrupt(postcard::Error::DeserializeBadEncoding);

        if blake3::hash(bytes).as_bytes() != hash {
            return Err(bad());
        }

        let Some((&VERSION, body)) = bytes.split_first() else {
            return Err(bad());
        };
        let plain = key.open(body).map_err(|_| bad())?;

        Ok(postcard::from_bytes(&plain)?)
    }
}
