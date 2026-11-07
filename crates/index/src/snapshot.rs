//! Snapshot format: the index state at its applied frontiers, for bootstrap.
//!
//! Layout: `VERSION | postcard(Snapshot)`. A reader checks the bytes against the
//! blake3 hash in the snapshot key.

use journal::Frontiers;
use model::ObjectId;
use serde::{Deserialize, Serialize};

use crate::{BucketState, IndexError, ObjectState, RetireMark};

/// Format 3 adds the retired chains.
const VERSION: u8 = 3;

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
    /// Each valid Retire action: a writer that reached it knew the retired entries.
    pub retired: Vec<RetireMark>,
}

impl Snapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![VERSION];
        bytes.extend(postcard::to_allocvec(self).expect("a snapshot always serializes"));
        bytes
    }

    /// Decodes `bytes`. The seal of the snapshot already proved them whole.
    pub fn decode(bytes: &[u8]) -> Result<Self, IndexError> {
        let bad = || IndexError::Corrupt(postcard::Error::DeserializeBadEncoding);

        let Some((&version, body)) = bytes.split_first() else {
            return Err(bad());
        };
        if version != VERSION {
            return Err(IndexError::Format {
                what: "snapshot",
                found: u32::from(version),
                expected: u32::from(VERSION),
            });
        }

        Ok(postcard::from_bytes(body)?)
    }
}
