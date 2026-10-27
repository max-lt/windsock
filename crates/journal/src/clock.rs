//! Hybrid logical clock: wall-clock nanoseconds, kept strictly monotonic.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "sim")]
thread_local! {
    /// A wall clock that a test sets on its thread. Zero: the system clock.
    static MANUAL_WALL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// The highest manual wall clock so far: a monotonic clock that never steps back.
    static MANUAL_MONOTONIC: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Nanoseconds on a clock that never steps back, from an arbitrary start: for elapsed times.
pub fn monotonic_nanos() -> u64 {
    #[cfg(feature = "sim")]
    if MANUAL_WALL.with(std::cell::Cell::get) != 0 {
        return MANUAL_MONOTONIC.with(std::cell::Cell::get);
    }
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos() as u64
}

fn system_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// The wall clock in unix nanoseconds.
#[cfg(not(feature = "sim"))]
pub fn wall_clock_nanos() -> u64 {
    system_nanos()
}

/// The wall clock in unix nanoseconds: the system clock, or the value of [`set_manual_wall`].
#[cfg(feature = "sim")]
pub fn wall_clock_nanos() -> u64 {
    match MANUAL_WALL.with(std::cell::Cell::get) {
        0 => system_nanos(),
        manual => manual,
    }
}

/// Replaces the wall clock of this thread with `nanos`, or gives back the system clock for
/// `None`. Only with the feature `sim`, for deterministic tests.
#[cfg(feature = "sim")]
pub fn set_manual_wall(nanos: Option<u64>) {
    MANUAL_WALL.with(|wall| wall.set(nanos.unwrap_or(0)));
    let nanos = nanos.unwrap_or(0);
    MANUAL_MONOTONIC.with(|mono| mono.set(mono.get().max(nanos)));
}

/// The highest HLC that a reader takes now, `ahead` past its wall clock.
pub fn limit(ahead: u64) -> u64 {
    wall_clock_nanos().saturating_add(ahead)
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
    /// Returns `max(wall clock, last) + 1`: unique and rising, even under clock skew. `None` at
    /// the end of the u64 range: a wrap to 0 would rank a new write under every old one.
    pub fn tick(&self) -> Option<u64> {
        loop {
            let prev = self.last.load(Ordering::SeqCst);
            let next = prev.max(wall_clock_nanos()).checked_add(1)?;

            if self
                .last
                .compare_exchange(prev, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(next);
            }
        }
    }

    /// The last HLC that this clock issued or saw.
    pub fn last(&self) -> u64 {
        self.last.load(Ordering::SeqCst)
    }

    /// Moves the clock past a timestamp seen from another node.
    pub fn witness(&self, remote_hlc: u64) {
        self.last.fetch_max(remote_hlc, Ordering::SeqCst);
    }

    /// Like [`HybridClock::witness`], but never past `ahead` from the wall clock: a bad clock
    /// or a forged value must not move every later ack far into the future.
    pub fn witness_at_most(&self, remote_hlc: u64, ahead: u64) {
        self.witness(remote_hlc.min(limit(ahead)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticks_rise() {
        let clock = HybridClock::default();
        let ticks: Vec<_> = (0..1000).map(|_| clock.tick().unwrap()).collect();

        assert!(ticks.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn test_tick_at_the_end_of_the_range_fails_and_does_not_wrap() {
        let clock = HybridClock::default();
        clock.witness(u64::MAX);

        assert_eq!(clock.tick(), None);
        assert_eq!(clock.tick(), None);
    }

    #[test]
    fn test_witness_moves_the_clock_forward() {
        let clock = HybridClock::default();
        let far_future = u64::MAX / 2;
        clock.witness(far_future);

        assert!(clock.tick().unwrap() > far_future);
    }
}
