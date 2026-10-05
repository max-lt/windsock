//! Retries with exponential backoff, a time limit per attempt, and one for the whole call.

use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hyper::StatusCode;
use remote::RemoteError;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct Retry {
    /// Attempts, the first included.
    pub attempts: u32,
    pub first_delay: Duration,
    pub max_delay: Duration,
    /// An attempt that takes longer fails and counts as transient.
    pub attempt_timeout: Duration,
    /// No new attempt starts after this, from the start of the call.
    pub total: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            attempts: 6,
            first_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            attempt_timeout: Duration::from_secs(60),
            total: Duration::from_secs(120),
        }
    }
}

/// Statuses that a later attempt can fix: overload, server faults, timeouts, and a
/// conditional write that ran into another one.
pub(crate) fn is_transient(status: StatusCode, code: &str) -> bool {
    matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504)
        || (status == StatusCode::CONFLICT && code == "ConditionalRequestConflict")
}

impl Retry {
    /// The pause before attempt `n + 1`: doubling from `first_delay` up to `max_delay`,
    /// then a random point in its upper half, so many clients do not retry in step.
    fn delay(&self, n: u32) -> Duration {
        let full = self
            .first_delay
            .saturating_mul(1 << n.min(16))
            .min(self.max_delay);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let half = full / 2;
        half + Duration::from_nanos(u64::from(nanos) % (half.as_nanos() as u64).max(1))
    }

    /// Runs `attempt` until it succeeds. Every error of `attempt` counts as transient.
    pub(crate) async fn run<T, F, Fut>(&self, attempt: F) -> Result<T, RemoteError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, RemoteError>>,
    {
        let start = Instant::now();
        let mut n = 0;

        loop {
            let error = match tokio::time::timeout(self.attempt_timeout, attempt()).await {
                Ok(Ok(value)) => return Ok(value),
                Ok(Err(e)) => e,
                Err(_) => RemoteError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the remote did not answer in time",
                )),
            };

            n += 1;
            let delay = self.delay(n - 1);
            if n >= self.attempts || start.elapsed() + delay >= self.total {
                return Err(error);
            }

            warn!(attempt = n, %error, ?delay, "remote call failed: retrying");
            tokio::time::sleep(delay).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn quick() -> Retry {
        Retry {
            attempts: 4,
            first_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
            attempt_timeout: Duration::from_millis(200),
            total: Duration::from_secs(5),
        }
    }

    fn transient() -> RemoteError {
        RemoteError::Io(std::io::Error::other("down"))
    }

    #[test]
    fn test_delay_doubles_up_to_the_maximum() {
        let policy = Retry {
            first_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            ..quick()
        };

        for (n, full) in [(0, 100), (1, 200), (2, 400), (5, 1000), (30, 1000)] {
            let delay = policy.delay(n).as_millis();
            assert!(
                (full / 2..=full).contains(&delay),
                "attempt {n}: {delay} ms"
            );
        }
    }

    #[tokio::test]
    async fn test_transient_failure_is_retried() {
        let calls = AtomicU32::new(0);

        let result = quick()
            .run(|| async {
                match calls.fetch_add(1, Ordering::SeqCst) {
                    0 | 1 => Err(transient()),
                    _ => Ok(7),
                }
            })
            .await;

        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_attempts_are_bounded() {
        let calls = AtomicU32::new(0);

        let result: Result<(), _> = quick()
            .run(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(transient())
            })
            .await;

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_slow_attempt_times_out_and_the_call_stops_at_its_limit() {
        let policy = Retry {
            attempt_timeout: Duration::from_millis(50),
            total: Duration::from_millis(120),
            attempts: 100,
            ..quick()
        };
        let start = Instant::now();

        let result: Result<(), _> = policy
            .run(|| async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(RemoteError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut)
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_transient_statuses() {
        assert!(is_transient(StatusCode::SERVICE_UNAVAILABLE, "SlowDown"));
        assert!(is_transient(
            StatusCode::CONFLICT,
            "ConditionalRequestConflict"
        ));
        assert!(!is_transient(StatusCode::CONFLICT, "BucketNotEmpty"));
        assert!(!is_transient(StatusCode::FORBIDDEN, "AccessDenied"));
        assert!(!is_transient(
            StatusCode::PRECONDITION_FAILED,
            "PreconditionFailed"
        ));
    }
}
