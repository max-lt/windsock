//! Request totals by access key, bucket, op and status, counted at the end of the response body.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;

use axum::body::{Body, HttpBody};
use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use http_body::{Frame, SizeHint};
use serde::Serialize;
use tracing::warn;

/// The most rows. Past it, a new row goes to the [`OVERFLOW_BUCKET`] row of its op and status.
pub const MAX_ROWS: usize = 4096;

/// The bucket of the overflow rows.
pub const OVERFLOW_BUCKET: &str = "<overflow>";

/// The status of a request whose client went away before the response.
pub const CLIENT_CLOSED: u16 = 499;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum RequestOp {
    /// GET or HEAD of an object, HEAD of a bucket.
    Read,
    /// PUT and POST, copies and multipart steps included, and the abort of an upload.
    Write,
    /// DELETE of an object or a bucket.
    Delete,
    /// ListBuckets, ListObjects, ListParts and ListMultipartUploads.
    List,
    Other,
}

/// The totals of the requests with the same access key, bucket, op and status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequestRow {
    /// None when the request did not pass the auth.
    pub access_key: Option<String>,
    /// None when the request did not pass the auth or names no bucket.
    pub bucket: Option<String>,
    pub op: RequestOp,
    /// The response status, or [`CLIENT_CLOSED`].
    pub status: u16,
    pub count: u64,
    /// Body bytes read from the client, aws-chunked framing included.
    pub bytes_in: u64,
    /// Body bytes sent, up to the end of the stream or the drop of the response.
    pub bytes_out: u64,
    /// The sum over the requests, from the request head to the end of the response body.
    pub duration_us: u64,
}

/// The request table of one router, from its start.
#[derive(Debug, Default)]
pub struct RequestStats {
    in_flight: AtomicU64,
    rows: Mutex<HashMap<RowKey, Totals>>,
    overflowed: AtomicBool,
}

type RowKey = (Option<String>, Option<String>, RequestOp, u16);

#[derive(Clone, Copy, Debug, Default)]
struct Totals {
    count: u64,
    bytes_in: u64,
    bytes_out: u64,
    duration_us: u64,
}

impl RequestStats {
    /// Requests from their head to the end of their response body.
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Every row, in key order.
    pub fn rows(&self) -> Vec<RequestRow> {
        let rows = self.rows.lock().expect("no panic while the lock is held");
        let mut rows: Vec<RequestRow> = rows
            .iter()
            .map(|((access_key, bucket, op, status), totals)| RequestRow {
                access_key: access_key.clone(),
                bucket: bucket.clone(),
                op: *op,
                status: *status,
                count: totals.count,
                bytes_in: totals.bytes_in,
                bytes_out: totals.bytes_out,
                duration_us: totals.duration_us,
            })
            .collect();
        rows.sort_by(|a, b| {
            (&a.access_key, &a.bucket, a.op, a.status).cmp(&(
                &b.access_key,
                &b.bucket,
                b.op,
                b.status,
            ))
        });
        rows
    }

    fn record(&self, key: RowKey, add: Totals) {
        let mut rows = self.rows.lock().expect("no panic while the lock is held");
        let key = match rows.len() >= MAX_ROWS && !rows.contains_key(&key) {
            true => {
                if !self.overflowed.swap(true, Ordering::SeqCst) {
                    warn!(
                        max = MAX_ROWS,
                        "the request table is full: new rows go to the overflow rows"
                    );
                }
                (None, Some(OVERFLOW_BUCKET.to_string()), key.2, key.3)
            }
            false => key,
        };
        let totals = rows.entry(key).or_default();
        totals.count = totals.count.saturating_add(add.count);
        totals.bytes_in = totals.bytes_in.saturating_add(add.bytes_in);
        totals.bytes_out = totals.bytes_out.saturating_add(add.bytes_out);
        totals.duration_us = totals.duration_us.saturating_add(add.duration_us);
    }
}

/// The access key that the auth accepted, set once per request.
#[derive(Clone, Debug, Default)]
pub(crate) struct CallerSlot(Arc<OnceLock<String>>);

impl CallerSlot {
    pub(crate) fn set(&self, access_key: &str) {
        let _ = self.0.set(access_key.to_string());
    }
}

/// Middleware outside the auth: it sees every request, also a refused one.
pub(crate) async fn count(
    State(stats): State<Arc<RequestStats>>,
    mut request: Request,
    next: Next,
) -> Response {
    let (op, bucket) = classify(
        request.method(),
        request.uri().path(),
        request.uri().query(),
    );
    let caller = CallerSlot::default();
    request.extensions_mut().insert(caller.clone());
    stats.in_flight.fetch_add(1, Ordering::SeqCst);
    let mut tally = Tally {
        stats,
        op,
        bucket,
        caller,
        status: CLIENT_CLOSED,
        started: Instant::now(),
        bytes_in: Arc::new(AtomicU64::new(0)),
        bytes_out: 0,
    };
    let bytes = Arc::clone(&tally.bytes_in);
    let request = request.map(|inner| Body::new(CountIn { inner, bytes }));

    let response = next.run(request).await;
    tally.status = response.status().as_u16();
    response.map(|inner| {
        Body::new(CountOut {
            inner,
            tally: Some(tally),
        })
    })
}

/// The op and the bucket named by the path. A query parameter picks the op where S3 does.
fn classify(method: &Method, path: &str, query: Option<&str>) -> (RequestOp, Option<String>) {
    let has = |name: &str| {
        form_urlencoded::parse(query.unwrap_or("").as_bytes()).any(|(key, _)| key == name)
    };
    let path = path.trim_start_matches('/');
    let (bucket, key) = path.split_once('/').unwrap_or((path, ""));
    let op = match (method, bucket.is_empty(), key.is_empty()) {
        (&Method::GET, true, _) => RequestOp::List,
        (_, true, _) => RequestOp::Other,
        (&Method::GET, false, true) if has("versioning") || has("location") => RequestOp::Other,
        (&Method::GET, false, true) => RequestOp::List,
        (&Method::GET, false, false) if has("uploadId") => RequestOp::List,
        (&Method::GET | &Method::HEAD, false, _) => RequestOp::Read,
        (&Method::PUT | &Method::POST, false, _) => RequestOp::Write,
        (&Method::DELETE, false, false) if has("uploadId") => RequestOp::Write,
        (&Method::DELETE, false, _) => RequestOp::Delete,
        _ => RequestOp::Other,
    };
    let bucket = (!bucket.is_empty()).then(|| bucket.to_string());
    (op, bucket)
}

/// One request. Its row gets it at the drop.
struct Tally {
    stats: Arc<RequestStats>,
    op: RequestOp,
    bucket: Option<String>,
    caller: CallerSlot,
    status: u16,
    started: Instant,
    bytes_in: Arc<AtomicU64>,
    bytes_out: u64,
}

impl Drop for Tally {
    fn drop(&mut self) {
        let access_key = self.caller.0.get().cloned();
        let bucket = access_key.as_ref().and(self.bucket.take());
        let elapsed = self.started.elapsed().as_micros();
        let add = Totals {
            count: 1,
            bytes_in: self.bytes_in.load(Ordering::SeqCst),
            bytes_out: self.bytes_out,
            duration_us: u64::try_from(elapsed).unwrap_or(u64::MAX),
        };
        self.stats
            .record((access_key, bucket, self.op, self.status), add);
        self.stats.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

struct CountIn {
    inner: Body,
    bytes: Arc<AtomicU64>,
}

impl HttpBody for CountIn {
    type Data = <Body as HttpBody>::Data;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let frame = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &frame
            && let Some(data) = frame.data_ref()
        {
            this.bytes.fetch_add(data.len() as u64, Ordering::SeqCst);
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct CountOut {
    inner: Body,
    tally: Option<Tally>,
}

impl HttpBody for CountOut {
    type Data = <Body as HttpBody>::Data;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let frame = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &frame
            && let Some(data) = frame.data_ref()
            && let Some(tally) = &mut this.tally
        {
            tally.bytes_out += data.len() as u64;
        }
        if matches!(frame, Poll::Ready(None | Some(Err(_)))) || this.inner.is_end_stream() {
            this.tally = None;
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(method: Method, uri: &str) -> RequestOp {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        classify(&method, path, Some(query)).0
    }

    #[test]
    fn test_classify_follows_the_s3_operation() {
        use RequestOp::*;
        let cases = [
            (Method::GET, "/", List),
            (Method::GET, "/b", List),
            (Method::GET, "/b/?list-type=2", List),
            (Method::GET, "/b?uploads", List),
            (Method::GET, "/b?versioning", Other),
            (Method::GET, "/b?location", Other),
            (Method::HEAD, "/b", Read),
            (Method::PUT, "/b", Write),
            (Method::DELETE, "/b", Delete),
            (Method::POST, "/b?delete", Write),
            (Method::GET, "/b/k", Read),
            (Method::HEAD, "/b/k", Read),
            (Method::GET, "/b/k?uploadId=u", List),
            (Method::PUT, "/b/k", Write),
            (Method::PUT, "/b/k?partNumber=1&uploadId=u", Write),
            (Method::POST, "/b/k?uploads", Write),
            (Method::DELETE, "/b/k", Delete),
            (Method::DELETE, "/b/k?uploadId=u", Write),
            (Method::PATCH, "/b/k", Other),
            (Method::PUT, "/", Other),
        ];
        for (method, uri, expected) in cases {
            assert_eq!(op(method.clone(), uri), expected, "{method} {uri}");
        }
    }

    #[test]
    fn test_table_past_its_cap_counts_new_rows_in_the_overflow_row() {
        let stats = RequestStats::default();
        let add = Totals {
            count: 1,
            ..Totals::default()
        };
        for n in 0..MAX_ROWS {
            stats.record(
                (
                    Some("k".into()),
                    Some(format!("b{n}")),
                    RequestOp::Read,
                    404,
                ),
                add,
            );
        }
        stats.record(
            (Some("k".into()), Some("b0".into()), RequestOp::Read, 404),
            add,
        );
        stats.record(
            (Some("k".into()), Some("new".into()), RequestOp::Read, 404),
            add,
        );
        stats.record(
            (Some("k".into()), Some("new2".into()), RequestOp::Read, 404),
            add,
        );

        let rows = stats.rows();
        assert_eq!(rows.len(), MAX_ROWS + 1);
        let b0 = rows.iter().find(|r| r.bucket.as_deref() == Some("b0"));
        assert_eq!(b0.unwrap().count, 2);
        let overflow = rows
            .iter()
            .find(|r| r.bucket.as_deref() == Some(OVERFLOW_BUCKET))
            .unwrap();
        assert_eq!(
            (
                &overflow.access_key,
                overflow.op,
                overflow.status,
                overflow.count
            ),
            (&None, RequestOp::Read, 404, 2)
        );
    }
}
