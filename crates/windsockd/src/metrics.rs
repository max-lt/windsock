//! Live counters of the S3 port: connections, clients and the request table, from the start.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

pub use s3api::{CLIENT_CLOSED, MAX_ROWS, OVERFLOW_BUCKET, RequestOp, RequestRow};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Metrics {
    pub connections: Connections,
    /// The clients with an open connection, by IP.
    pub clients: Vec<Client>,
    /// Requests from their head to the end of their response body.
    pub in_flight: u64,
    pub requests: Vec<RequestRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Connections {
    pub open: u64,
    pub accepted: u64,
    /// `max_connections`, or its default.
    pub limit: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Client {
    pub ip: IpAddr,
    pub connections: u32,
}

/// The open connections of the S3 port by client IP.
#[derive(Debug, Default)]
pub(crate) struct ConnectionCounts {
    accepted: AtomicU64,
    clients: Mutex<HashMap<IpAddr, u32>>,
}

impl ConnectionCounts {
    pub(crate) fn open(self: &Arc<Self>, ip: IpAddr) -> OpenConnection {
        let ip = ip.to_canonical();
        self.accepted.fetch_add(1, Ordering::SeqCst);
        let mut clients = self
            .clients
            .lock()
            .expect("no panic while the lock is held");
        *clients.entry(ip).or_default() += 1;
        OpenConnection {
            counts: Arc::clone(self),
            ip,
        }
    }

    /// The connections and the clients, by IP order.
    pub(crate) fn read(&self, limit: usize) -> (Connections, Vec<Client>) {
        let clients = self
            .clients
            .lock()
            .expect("no panic while the lock is held");
        let mut clients: Vec<Client> = clients
            .iter()
            .map(|(ip, connections)| Client {
                ip: *ip,
                connections: *connections,
            })
            .collect();
        clients.sort_by_key(|client| client.ip);
        let connections = Connections {
            open: clients
                .iter()
                .map(|client| u64::from(client.connections))
                .sum(),
            accepted: self.accepted.load(Ordering::SeqCst),
            limit: limit as u64,
        };
        (connections, clients)
    }
}

/// One accepted connection. Its client count goes down at the drop.
#[derive(Debug)]
pub(crate) struct OpenConnection {
    counts: Arc<ConnectionCounts>,
    ip: IpAddr,
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        let mut clients = self
            .counts
            .clients
            .lock()
            .expect("no panic while the lock is held");
        if let Some(count) = clients.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                clients.remove(&self.ip);
            }
        }
    }
}

/// What [`crate::Node::metrics`] reads.
#[derive(Clone)]
pub(crate) struct Meters {
    pub connections: Arc<ConnectionCounts>,
    pub requests: Arc<s3api::RequestStats>,
    pub limit: usize,
}

impl Meters {
    pub(crate) fn read(&self) -> Metrics {
        let (connections, clients) = self.connections.read(self.limit);
        Metrics {
            connections,
            clients,
            in_flight: self.requests.in_flight(),
            requests: self.requests.rows(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clients_count_open_connections_by_canonical_ip() {
        let counts = Arc::new(ConnectionCounts::default());
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();

        let a = counts.open(v4);
        let b = counts.open(mapped);
        let c = counts.open(other);
        drop(c);
        let (open, clients) = counts.read(8);
        drop((a, b));
        let (closed, after) = counts.read(8);

        assert_eq!(
            (open.open, open.accepted, open.limit),
            (2, 3, 8),
            "{clients:?}"
        );
        assert_eq!(
            clients,
            [Client {
                ip: v4,
                connections: 2
            }]
        );
        assert_eq!((closed.open, closed.accepted), (0, 3));
        assert!(after.is_empty());
    }
}
