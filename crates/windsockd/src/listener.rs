//! A TCP listener that keeps at most a fixed number of connections open.
//!
//! Above the limit it stops accepting: new clients wait in the kernel backlog and use no
//! descriptor of this process, so the engine keeps the descriptors it needs to flush.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::serve::Listener;
use rustix::process::{Resource, getrlimit};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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
}

impl LimitedListener {
    pub fn new(inner: TcpListener, max_connections: usize) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(max_connections.min(Semaphore::MAX_PERMITS))),
        }
    }
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
        (
            Connection {
                stream,
                _permit: permit,
            },
            address,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// An accepted connection. Its slot is free again when it closes.
pub struct Connection {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
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
        let mut listener = LimitedListener::new(tcp, 1);
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
