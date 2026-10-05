//! Engine settings and per-prefix storage policies.

use std::time::Duration;

use chunking::Compression;

/// How an object is cut into chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chunking {
    /// FastCDC boundaries: shifted data still dedups.
    ContentDefined,
    /// Fixed chunks of `chunking::MAX_SIZE` bytes, for data that never dedups (sealed or encrypted).
    Fixed,
}

/// How the engine stores the objects of one prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub chunking: Chunking,
    /// `Compression::Zstd` stores a chunk compressed when zstd makes it smaller.
    pub compression: Compression,
    /// Every put acts as `If-None-Match: *`.
    pub create_only: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            chunking: Chunking::ContentDefined,
            compression: Compression::Zstd,
            create_only: false,
        }
    }
}

/// A policy for the keys of `bucket` that start with `prefix`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixPolicy {
    pub bucket: String,
    pub prefix: String,
    pub policy: Policy,
}

#[derive(Clone, Debug)]
pub struct Config {
    /// A shared pack closes once it reaches this size.
    pub pack_target: usize,
    /// An object of at least this size gets packs of its own.
    pub own_pack_threshold: usize,
    /// The flusher uploads buffered writes at least this often.
    pub flush_delay: Duration,
    /// Puts fail once the local buffer holds this many bytes.
    pub buffer_limit: u64,
    /// The longest matching prefix wins. Keys that match none get `default_policy`.
    pub policies: Vec<PrefixPolicy>,
    pub default_policy: Policy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pack_target: 64 * 1024 * 1024,
            own_pack_threshold: 8 * 1024 * 1024,
            flush_delay: Duration::from_secs(1),
            buffer_limit: 8 * 1024 * 1024 * 1024,
            policies: Vec::new(),
            default_policy: Policy::default(),
        }
    }
}

impl Config {
    pub fn policy(&self, bucket: &str, key: &str) -> Policy {
        self.policies
            .iter()
            .filter(|rule| rule.bucket == bucket && key.starts_with(&rule.prefix))
            .max_by_key(|rule| rule.prefix.len())
            .map_or(self.default_policy, |rule| rule.policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(bucket: &str, prefix: &str, create_only: bool) -> PrefixPolicy {
        PrefixPolicy {
            bucket: bucket.into(),
            prefix: prefix.into(),
            policy: Policy {
                create_only,
                ..Policy::default()
            },
        }
    }

    #[test]
    fn test_longest_matching_prefix_wins() {
        let config = Config {
            policies: vec![
                rule("wal", "", true),
                rule("wal", "tmp/", false),
                rule("other", "tmp/", true),
            ],
            ..Config::default()
        };

        assert!(config.policy("wal", "seg/1").create_only);
        assert!(!config.policy("wal", "tmp/1").create_only);
        assert!(!config.policy("data", "tmp/1").create_only);
    }
}
