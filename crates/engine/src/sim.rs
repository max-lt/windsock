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
    /// A streamed put: its data is fsynced in the spool file.
    SpoolData,
    /// Its head is written and fsynced after the data.
    SpoolHead,
    /// The next active segment exists and is durable. The rename of the spool file comes next.
    SpoolNext,
    /// The spool file has its segment name. The directory fsync comes next.
    SpoolDirSync,
    /// The spool file is renamed to a segment, and the directory is fsynced.
    SpoolRename,
    /// The put is durable, and its ack is not given yet.
    SpoolAck,
    /// A put is in the active segment with no fsync and no ack.
    Appended,
    /// A record with bad data is in a durable quarantine file, and still in its segment.
    QuarantineCopy,
    /// The segment of that record is written again without it.
    QuarantineRewrite,
    /// The flush read a put and checked its data. Its chunk pass reads the data again next.
    FlushVerified,
    /// A multipart complete wrote part of the object to its spool.
    CompleteAssembly,
    /// The complete wrote the hash of the object in its claimed upload; the commit comes next.
    CompleteMarked,
    /// The object is committed; the parts are still on disk.
    CompleteCommitted,
}

#[cfg(feature = "sim")]
thread_local! {
    static ARMED: std::cell::Cell<Option<Point>> = const { std::cell::Cell::new(None) };
    static DEDUP_HITS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The chunks that a flush on this thread found stored and did not upload again.
#[cfg(feature = "sim")]
pub fn dedup_hits() -> u64 {
    DEDUP_HITS.with(std::cell::Cell::get)
}

#[cfg(feature = "sim")]
pub(crate) fn count_dedup() {
    DEDUP_HITS.with(|hits| hits.set(hits.get() + 1));
}

#[cfg(not(feature = "sim"))]
#[inline(always)]
pub(crate) fn count_dedup() {}

/// Makes the next pass at `point` on this thread fail with [`crate::EngineError::SimCrash`].
#[cfg(feature = "sim")]
pub fn arm_crash(point: Option<Point>) {
    ARMED.with(|armed| armed.set(point));
}

/// Fails once at the armed point. The caller drops the engine, as a kill would.
#[cfg(feature = "sim")]
pub fn crash_point(point: Point) -> Result<()> {
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
pub fn crash_point(_point: Point) -> Result<()> {
    Ok(())
}

/// A test action and the point where it runs.
#[cfg(feature = "sim")]
type Action = Option<(Point, Box<dyn FnOnce()>)>;

#[cfg(feature = "sim")]
thread_local! {
    static ACTION: std::cell::RefCell<Action> = const { std::cell::RefCell::new(None) };
}

/// Runs `action` at the next pass at `point` on this thread, and goes on: a test changes a file
/// there.
#[cfg(feature = "sim")]
pub fn arm_action(point: Point, action: impl FnOnce() + 'static) {
    ACTION.with(|armed| *armed.borrow_mut() = Some((point, Box::new(action))));
}

#[cfg(feature = "sim")]
pub(crate) fn action_point(point: Point) {
    let action = ACTION.with(|armed| {
        let mut armed = armed.borrow_mut();
        match armed.as_ref() {
            Some((at, _)) if *at == point => armed.take().map(|(_, action)| action),
            _ => None,
        }
    });
    if let Some(action) = action {
        action();
    }
}

#[cfg(not(feature = "sim"))]
#[inline(always)]
pub(crate) fn action_point(_point: Point) {}
