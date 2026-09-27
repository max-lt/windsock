//! Hybrid logical clock: wall-clock nanoseconds, kept strictly monotonic.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn wall_clock_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

#[derive(Debug)]
pub struct HybridClock {
    last: AtomicU64,
}

impl Default for HybridClock {
    fn default() -> Self {
        Self {
            last: AtomicU64::new(wall_clock_nanos()),
        }
    }
}

impl HybridClock {
    /// Returns `max(wall clock, last) + 1`: unique and rising, even under clock skew.
    pub fn tick(&self) -> u64 {
        loop {
            let prev = self.last.load(Ordering::SeqCst);
            let next = prev.max(wall_clock_nanos()) + 1;

            if self
                .last
                .compare_exchange(prev, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return next;
            }
        }
    }

    /// Moves the clock past a timestamp seen from another node.
    pub fn witness(&self, remote_hlc: u64) {
        self.last.fetch_max(remote_hlc, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticks_rise() {
        let clock = HybridClock::default();
        let ticks: Vec<_> = (0..1000).map(|_| clock.tick()).collect();

        assert!(ticks.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn test_witness_moves_the_clock_forward() {
        let clock = HybridClock::default();
        let far_future = u64::MAX / 2;
        clock.witness(far_future);

        assert!(clock.tick() > far_future);
    }
}
