//! A TCP listener that keeps at most a fixed number of connections open.
//!
//! Above the limit it stops accepting. New clients wait in the kernel backlog. They use no fd of
//! this process. Thus the engine keeps the fds that it needs for a flush.
//! A connection with no request in progress closes after an idle timeout. Thus idle clients
//! cannot keep the slots.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::{IncomingStream, Listener};
use rustix::process::{Resource, getrlimit};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};
use tracing::debug;

/// Descriptors kept for the engine: buffer segments, index files, cache files, remote calls.
pub const FD_RESERVE: u64 = 256;

/// The connection limit for a soft descriptor limit `soft` (`None`: no limit).
pub fn connection_limit(soft: Option<u64>) -> usize {
    let limit = match soft {
        None => u64::MAX,
        Some(soft) if soft >= 2 * FD_RESERVE => soft - FD_RESERVE,
        Some(soft) => soft / 2,
    };
    usize::try_from(limit).map_or(Semaphore::MAX_PERMITS, |l| l.min(Semaphore::MAX_PERMITS))
}

pub fn soft_fd_limit() -> Option<u64> {
    getrlimit(Resource::Nofile).current
}

pub struct LimitedListener {
    inner: TcpListener,
    permits: Arc<Semaphore>,
    idle_timeout: Duration,
}

impl LimitedListener {
    pub fn new(inner: TcpListener, max_connections: usize, idle_timeout: Duration) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(max_connections.min(Semaphore::MAX_PERMITS))),
            idle_timeout,
        }
    }
}

/// The requests in progress on one connection, and its last activity.
#[derive(Debug)]
pub struct Activity {
    requests: AtomicUsize,
    last: Mutex<Instant>,
}

impl Activity {
    fn touch(&self) {
        *self.last.lock().expect("no panic while the lock is held") = Instant::now();
    }

    fn last(&self) -> Instant {
        *self.last.lock().expect("no panic while the lock is held")
    }

    fn idle(&self) -> bool {
        self.requests.load(Ordering::SeqCst) == 0
    }
}

/// The activity of the connection that carries a request.
#[derive(Clone, Debug)]
pub struct ConnectionActivity(Arc<Activity>);

impl Connected<IncomingStream<'_, LimitedListener>> for ConnectionActivity {
    fn connect_info(stream: IncomingStream<'_, LimitedListener>) -> Self {
        Self(Arc::clone(&stream.io().activity))
    }
}

/// A request in progress. The connection is idle again when the last one drops.
struct InProgress(Arc<Activity>);

impl Drop for InProgress {
    fn drop(&mut self) {
        self.0.touch();
        self.0.requests.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Counts a request from its head to the end of its handler. The body upload is part of it.
pub async fn track_requests(
    ConnectInfo(ConnectionActivity(activity)): ConnectInfo<ConnectionActivity>,
    request: Request,
    next: Next,
) -> Response {
    activity.requests.fetch_add(1, Ordering::SeqCst);
    let _in_progress = InProgress(activity);
    next.run(request).await
}

impl Listener for LimitedListener {
    type Io = Connection;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        let (stream, address) = Listener::accept(&mut self.inner).await;
        let activity = Arc::new(Activity {
            requests: AtomicUsize::new(0),
            last: Mutex::new(Instant::now()),
        });
        let connection = Connection {
            stream,
            _permit: permit,
            idle: Box::pin(tokio::time::sleep(self.idle_timeout)),
            idle_timeout: self.idle_timeout,
            activity,
        };
        (connection, address)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// An accepted connection. Its slot is free again when it closes.
pub struct Connection {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    idle: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    activity: Arc<Activity>,
}

impl Connection {
    /// True when the idle timeout passed with no request in progress. If not, arms the timer again.
    fn idle_expired(&mut self, cx: &mut Context<'_>) -> bool {
        loop {
            if self.idle.as_mut().poll(cx).is_pending() {
                return false;
            }
            let deadline = self.activity.last() + self.idle_timeout;
            let next = match self.activity.idle() {
                true if Instant::now() >= deadline => return true,
                true => deadline,
                // A request in progress keeps the connection. Check again one timeout later.
                false => Instant::now() + self.idle_timeout,
            };
            self.idle.as_mut().reset(next);
        }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();

        match Pin::new(&mut this.stream).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() > before => {
                this.activity.touch();
                Poll::Ready(Ok(()))
            }
            Poll::Pending if this.idle_expired(cx) => {
                // An end of stream makes the HTTP server close the connection.
                debug!("closing an idle connection");
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.stream).poll_write(cx, buf);
        if matches!(written, Poll::Ready(Ok(n)) if n > 0) {
            this.activity.touch();
        }
        written
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.stream).poll_write_vectored(cx, bufs);
        if matches!(written, Poll::Ready(Ok(n)) if n > 0) {
            this.activity.touch();
        }
        written
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_connection_limit_keeps_a_reserve_for_the_engine() {
        assert_eq!(connection_limit(Some(1024)), 768);
        assert_eq!(connection_limit(Some(128)), 64);
        assert_eq!(connection_limit(None), Semaphore::MAX_PERMITS);
    }

    #[tokio::test]
    async fn test_listener_stops_accepting_at_the_limit() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let mut listener = LimitedListener::new(tcp, 1, Duration::from_secs(60));
        let _a = TcpStream::connect(address).await.unwrap();
        let _b = TcpStream::connect(address).await.unwrap();

        let (first, _) = listener.accept().await;
        let second = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(second.is_err(), "no second accept while the first is open");

        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;
        assert!(third.is_ok(), "a closed connection frees its slot");
    }
}
