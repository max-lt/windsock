//! Identifiers shared by all Windsock crates.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A string is not the hex form of a 32-byte identifier.
#[derive(Debug, thiserror::Error)]
#[error("invalid identifier: {0:?}")]
pub struct ParseIdError(String);

macro_rules! id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut bytes = [0u8; 32];
                hex::decode_to_slice(s, &mut bytes).map_err(|_| ParseIdError(s.to_string()))?;
                Ok(Self(bytes))
            }
        }
    };
}

id! {
    /// Content hash of a raw chunk.
    ChunkId
}

id! {
    /// Content hash of a pack object.
    PackId
}

id! {
    /// Content hash of a serialized manifest.
    ObjectId
}

id! {
    /// Public ed25519 key of a proxy.
    NodeId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let id = ChunkId::from_bytes([0xab; 32]);
        let text = id.to_string();

        assert_eq!(text, "ab".repeat(32));
        assert_eq!(text.parse::<ChunkId>().unwrap(), id);
    }

    #[test]
    fn test_parse_rejects_wrong_length() {
        assert!("abcd".parse::<PackId>().is_err());
        assert!("ab".repeat(33).parse::<PackId>().is_err());
    }

    #[test]
    fn test_parse_rejects_non_hex() {
        assert!("zz".repeat(32).parse::<ObjectId>().is_err());
    }
}
