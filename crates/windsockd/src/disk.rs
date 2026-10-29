//! The startup check that the cache and the buffer limits fit on the disk.

use std::path::Path;

use engine::LocalUsage;
use rustix::fs::statvfs;
use tracing::{info, warn};

/// The limits of the local data that can grow.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub cache: u64,
    pub buffer: u64,
}

/// The bytes that the cache and the buffer can still take.
pub fn growth(usage: LocalUsage, limits: Limits) -> u64 {
    let cache = limits.cache.saturating_sub(usage.cache);
    let buffer = limits.buffer.saturating_sub(usage.buffer + usage.reserved);
    cache + buffer
}

/// Warns when the cache and the buffer cannot reach their limits on the disk of `dir`.
pub fn check(dir: &Path, usage: LocalUsage, limits: Limits) {
    let stat = match statvfs(dir) {
        Ok(stat) => stat,
        Err(e) => {
            warn!(%e, dir = %dir.display(), "cannot read the free disk space");
            return;
        }
    };
    let available = stat.f_bavail * stat.f_frsize;
    let growth = growth(usage, limits);

    if growth > available {
        warn!(
            available,
            growth,
            index = usage.index,
            cache = usage.cache,
            buffer = usage.buffer + usage.reserved,
            cache_bytes = limits.cache,
            buffer_limit_bytes = limits.buffer,
            "the cache and the buffer limits do not fit on the disk: lower engine.cache_bytes"
        );
        return;
    }
    info!(
        available,
        growth,
        index = usage.index,
        cache = usage.cache,
        buffer = usage.buffer + usage.reserved,
        "local disk"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits {
        cache: 16,
        buffer: 8,
    };

    #[test]
    fn test_growth_is_the_room_left_under_each_limit() {
        let usage = LocalUsage {
            index: 100,
            cache: 6,
            buffer: 2,
            reserved: 1,
        };

        assert_eq!(growth(usage, LIMITS), 10 + 5);
    }

    #[test]
    fn test_growth_is_zero_above_the_limits() {
        let usage = LocalUsage {
            index: 0,
            cache: 20,
            buffer: 9,
            reserved: 3,
        };

        assert_eq!(growth(usage, LIMITS), 0);
    }
}
