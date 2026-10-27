//! Crash points for the simulation test. With the feature `sim` off, each point does nothing.

use crate::Result;

/// A local step of the flush and the commit, after which the simulation can crash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Point {
    SegmentRead,
    Plan,
    PackUpload,
    Intent,
    Commit,
    Apply,
    Release,
}

#[cfg(feature = "sim")]
thread_local! {
    static ARMED: std::cell::Cell<Option<Point>> = const { std::cell::Cell::new(None) };
}

/// Makes the next pass at `point` on this thread fail with [`crate::EngineError::SimCrash`].
#[cfg(feature = "sim")]
pub fn arm_crash(point: Option<Point>) {
    ARMED.with(|armed| armed.set(point));
}

/// Fails once at the armed point. The caller drops the engine, as a kill would.
#[cfg(feature = "sim")]
pub(crate) fn crash_point(point: Point) -> Result<()> {
    match ARMED.with(|armed| armed.get()) {
        Some(armed) if armed == point => {
            ARMED.with(|armed| armed.set(None));
            Err(crate::EngineError::SimCrash(point))
        }
        _ => Ok(()),
    }
}

#[cfg(not(feature = "sim"))]
#[inline(always)]
pub(crate) fn crash_point(_point: Point) -> Result<()> {
    Ok(())
}
