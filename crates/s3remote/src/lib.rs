//! A remote in an S3 bucket, over HTTP or HTTPS, with SigV4.
//!
//! HTTPS needs the feature `tls`: rustls with the ring provider, which compiles
//! C. Without the feature, an `https` endpoint is refused.
//!
//! Objects are immutable, so reads need no conditions. `create` is
//! `If-None-Match: *`: after an ambiguous failure, a retry can report
//! `AlreadyExists` for its own first attempt, which the journal resolves by hash.

mod retry;
mod xml;

use std::ops::Range;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderMap;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use remote::{Remote, RemoteError, Sweep, check_key, check_prefix};
use s3proto::sigv4::{self, Slash};
use tracing::debug;

pub use retry::Retry;

#[derive(Clone)]
pub struct S3Config {
    /// `http://host:port`, or `https://host[:port]` with the feature `tls`.
    pub endpoint: String,
    pub bucket: String,
    /// Prepended to every key, so one bucket can hold several remotes. Empty or ending with `/`.
    pub prefix: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub retry: Retry,
    /// PEM certificates to trust next to the public roots, for a store with a private CA.
    pub ca_pem: Option<Vec<u8>>,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("retry", &self.retry)
            .field("ca_pem", &self.ca_pem.as_ref().map(Vec::len))
            .finish()
    }
}

/// A response with its whole body.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    /// Method and URL, so an error names the host and the key.
    target: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The error of a status that is not a success, with the S3 code from the body.
    fn error(&self) -> RemoteError {
        let (code, message) = xml::error(&self.body);
        RemoteError::Service {
            status: self.status.as_u16(),
            code,
            message: format!("{message} ({})", self.target),
        }
    }
}

/// What one request differs in.
struct Call<'a> {
    method: Method,
    /// The object key in the remote, before the prefix. `None` addresses the bucket.
    key: Option<&'a str>,
    /// Name and value pairs, not encoded.
    query: Vec<(&'a str, String)>,
    headers: Vec<(&'static str, String)>,
    body: Bytes,
    /// The longest reply body that this call reads. The remote is not trusted.
    max_reply: usize,
}

/// The reply limit of a call with no known size: an object, a snapshot or a listing page.
pub const MAX_REPLY: usize = 1 << 30;

/// Room for an XML error body after a ranged read.
const ERROR_ROOM: usize = 64 * 1024;

impl<'a> Call<'a> {
    fn new(method: Method, key: Option<&'a str>) -> Self {
        Self {
            method,
            key,
            query: Vec::new(),
            headers: Vec::new(),
            body: Bytes::new(),
            max_reply: MAX_REPLY,
        }
    }
}

#[cfg(feature = "tls")]
type Connector = hyper_rustls::HttpsConnector<HttpConnector>;
#[cfg(not(feature = "tls"))]
type Connector = HttpConnector;

/// The error and every cause under it: hyper shows "client error (Connect)" and hides the TLS reason.
fn with_causes(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        text = format!("{text}: {next}");
        cause = next.source();
    }
    text
}

/// Calls to the remote at one time, and idle connections kept for reuse.
pub const MAX_IN_FLIGHT: usize = 64;

fn invalid(message: &str) -> RemoteError {
    RemoteError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.to_string(),
    ))
}

/// HTTP and HTTPS, with the public roots and the extra CA certificates.
#[cfg(feature = "tls")]
fn connector(ca_pem: Option<&[u8]>) -> Result<Connector, RemoteError> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = ca_pem {
        let mut added = 0;
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert =
                cert.map_err(|e| invalid(&format!("the CA certificates do not parse: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| invalid(&format!("a CA certificate is not valid: {e}")))?;
            added += 1;
        }
        // A CA file with no certificate is a configuration error, not a reason to trust less.
        if added == 0 {
            return Err(invalid("the CA certificates hold no PEM certificate"));
        }
    }

    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| invalid(&format!("TLS setup: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build())
}

#[cfg(not(feature = "tls"))]
fn connector(ca_pem: Option<&[u8]>) -> Result<Connector, RemoteError> {
    if ca_pem.is_some() {
        return Err(invalid(
            "CA certificates need Windsock built with the feature tls",
        ));
    }
    Ok(HttpConnector::new())
}

pub struct S3Remote {
    client: Client<Connector, Full<Bytes>>,
    /// Caps the open connections: a burst of reads waits here, not in the socket table.
    in_flight: Semaphore,
    /// `http` or `https`.
    scheme: &'static str,
    /// `host[:port]`, for the `host` header.
    authority: String,
    config: S3Config,
}

impl S3Remote {
    pub fn new(config: S3Config) -> Result<Self, RemoteError> {
        let (scheme, authority) = match config.endpoint.split_once("://") {
            Some(("http", rest)) => ("http", rest),
            Some(("https", rest)) if cfg!(feature = "tls") => ("https", rest),
            Some(("https", _)) => {
                return Err(invalid("https needs Windsock built with the feature tls"));
            }
            _ => {
                return Err(invalid(
                    "the endpoint must be http:// or https://, then host[:port]",
                ));
            }
        };
        let authority = authority.trim_end_matches('/').to_string();
        if authority.is_empty() || authority.contains('/') {
            return Err(invalid(
                "the endpoint must be scheme://host[:port], with no path",
            ));
        }
        if !config.prefix.is_empty() && !config.prefix.ends_with('/') {
            return Err(invalid("the key prefix must be empty or end with '/'"));
        }
        if config.access_key.trim().is_empty() || config.secret_key.trim().is_empty() {
            return Err(invalid(
                "the access key and the secret key of the remote must not be empty",
            ));
        }

        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(MAX_IN_FLIGHT)
            .build(connector(config.ca_pem.as_deref())?);
        Ok(Self {
            in_flight: Semaphore::new(MAX_IN_FLIGHT),
            client,
            scheme,
            authority,
            config,
        })
    }

    fn path(&self, key: Option<&str>) -> String {
        let bucket = sigv4::uri_encode(self.config.bucket.as_bytes(), Slash::Encode);
        match key {
            Some(key) => {
                let full = format!("{}{key}", self.config.prefix);
                format!(
                    "/{bucket}/{}",
                    sigv4::uri_encode(full.as_bytes(), Slash::Keep)
                )
            }
            None => format!("/{bucket}"),
        }
    }

    fn signed(&self, call: &Call<'_>) -> Request<Full<Bytes>> {
        let path = self.path(call.key);
        let query = call
            .query
            .iter()
            .map(|(name, value)| {
                format!(
                    "{name}={}",
                    sigv4::uri_encode(value.as_bytes(), Slash::Encode)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let timestamp = sigv4::timestamp(now);
        let payload_hash = sigv4::sha256_hex(&call.body);

        let mut headers = vec![
            ("host".to_string(), self.authority.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), timestamp.clone()),
        ];
        headers.extend(call.headers.iter().map(|(n, v)| (n.to_string(), v.clone())));

        let (authorization, _) = sigv4::sign(
            &sigv4::Request {
                method: call.method.as_str(),
                path: &path,
                query: &query,
                headers: &headers,
                payload_hash: &payload_hash,
            },
            &self.config.access_key,
            &self.config.secret_key,
            &timestamp,
            &self.config.region,
        );

        let uri = match query.is_empty() {
            true => format!("{}://{}{path}", self.scheme, self.authority),
            false => format!("{}://{}{path}?{query}", self.scheme, self.authority),
        };
        let mut request = Request::builder().method(call.method.clone()).uri(uri);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        // hyper sends no length for an empty body, and R2 refuses such a PUT with 411.
        request
            .header("authorization", authorization)
            .header("content-length", call.body.len())
            .body(Full::new(call.body.clone()))
            .expect("a signed request is valid")
    }

    /// Sends a call, signed again for every attempt, under the retry policy.
    /// A reply with a status that a retry does not fix comes back as `Ok`.
    async fn send(&self, call: Call<'_>) -> Result<Reply, RemoteError> {
        let policy = &self.config.retry;
        let target = format!(
            "{} {}://{}{}",
            call.method,
            self.scheme,
            self.authority,
            self.path(call.key)
        );

        // Outside the attempt timeout: a wait for a slot is not a slow remote.
        let _slot = self
            .in_flight
            .acquire()
            .await
            .expect("the semaphore is never closed");
        policy
            .run(|| async {
                let response = self
                    .client
                    .request(self.signed(&call))
                    .await
                    .map_err(|e| RemoteError::Io(std::io::Error::other(with_causes(&e))))?;
                let status = response.status();
                let headers = response.headers().clone();
                let body = http_body_util::Limited::new(response.into_body(), call.max_reply)
                    .collect()
                    .await
                    .map_err(|e| {
                        if e.is::<http_body_util::LengthLimitError>() {
                            let key = call.key.unwrap_or("the bucket");
                            let limit = call.max_reply;
                            return RemoteError::Io(std::io::Error::other(format!(
                                "the reply for {key} is larger than the limit of {limit} bytes"
                            )));
                        }
                        RemoteError::Io(std::io::Error::other(e))
                    })?
                    .to_bytes();
                let reply = Reply {
                    status,
                    headers,
                    body,
                    target: target.clone(),
                };

                if retry::is_transient(status, &xml::error(&reply.body).0) {
                    debug!(%status, method = %call.method, "transient error");
                    return Err(reply.error());
                }
                Ok(reply)
            })
            .await
            .map_err(|e| match e {
                RemoteError::Io(io) => {
                    RemoteError::Io(std::io::Error::new(io.kind(), format!("{target}: {io}")))
                }
                other => other,
            })
    }

    /// The size of an object, or `None` if it does not exist.
    async fn size(&self, key: &str) -> Result<Option<u64>, RemoteError> {
        let reply = self.send(Call::new(Method::HEAD, Some(key))).await?;

        match reply.status {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => reply
                .header("content-length")
                .and_then(|v| v.parse().ok())
                .map(Some)
                .ok_or_else(|| reply.error()),
            _ => Err(reply.error()),
        }
    }

    async fn invalid_range(
        &self,
        key: &str,
        range: &Range<u64>,
    ) -> Result<Option<Bytes>, RemoteError> {
        let Some(len) = self.size(key).await? else {
            return Ok(None);
        };

        Err(RemoteError::InvalidRange {
            key: key.to_string(),
            start: range.start,
            end: range.end,
            len,
        })
    }
}

/// The total size in a `Content-Range: bytes a-b/total` header.
fn total_size(content_range: Option<&str>) -> Option<u64> {
    content_range?.rsplit_once('/')?.1.parse().ok()
}

#[async_trait::async_trait]
impl Remote for S3Remote {
    async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        check_key(key)?;
        let mut call = Call::new(Method::PUT, Some(key));
        call.body = data;

        let reply = self.send(call).await?;
        match reply.status.is_success() {
            true => Ok(()),
            false => Err(reply.error()),
        }
    }

    async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
        check_key(key)?;
        let mut call = Call::new(Method::PUT, Some(key));
        call.headers.push(("if-none-match", "*".to_string()));
        call.body = data;

        let reply = self.send(call).await?;
        match reply.status {
            status if status.is_success() => Ok(()),
            StatusCode::PRECONDITION_FAILED => Err(RemoteError::AlreadyExists(key.to_string())),
            _ => Err(reply.error()),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
        check_key(key)?;
        let reply = self.send(Call::new(Method::GET, Some(key))).await?;

        match reply.status {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => Ok(Some(reply.body)),
            _ => Err(reply.error()),
        }
    }

    async fn get_range(&self, key: &str, range: Range<u64>) -> Result<Option<Bytes>, RemoteError> {
        check_key(key)?;

        // HTTP has no empty or reversed range: the size decides.
        if range.start >= range.end {
            let Some(len) = self.size(key).await? else {
                return Ok(None);
            };
            if range.start == range.end && range.end <= len {
                return Ok(Some(Bytes::new()));
            }
            return self.invalid_range(key, &range).await;
        }

        let mut call = Call::new(Method::GET, Some(key));
        call.headers
            .push(("range", format!("bytes={}-{}", range.start, range.end - 1)));
        let wanted = usize::try_from(range.end - range.start)
            .map_err(|_| invalid("the range does not fit in memory"))?;
        call.max_reply = wanted.saturating_add(ERROR_ROOM);
        let reply = self.send(call).await?;

        match reply.status {
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::RANGE_NOT_SATISFIABLE => self.invalid_range(key, &range).await,
            StatusCode::PARTIAL_CONTENT if reply.body.len() == wanted => Ok(Some(reply.body)),
            // S3 cuts a range that ends past the object: the object is shorter than the range.
            StatusCode::PARTIAL_CONTENT => match total_size(reply.header("content-range")) {
                Some(len) => Err(RemoteError::InvalidRange {
                    key: key.to_string(),
                    start: range.start,
                    end: range.end,
                    len,
                }),
                None => self.invalid_range(key, &range).await,
            },
            // A server that ignores Range sends the whole object.
            StatusCode::OK if range.end <= reply.body.len() as u64 => Ok(Some(
                reply.body.slice(range.start as usize..range.end as usize),
            )),
            StatusCode::OK => Err(RemoteError::InvalidRange {
                key: key.to_string(),
                start: range.start,
                end: range.end,
                len: reply.body.len() as u64,
            }),
            _ => Err(reply.error()),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
        check_prefix(prefix)?;
        let full_prefix = format!("{}{prefix}", self.config.prefix);
        let mut keys = Vec::new();
        let mut token: Option<String> = None;

        loop {
            let mut call = Call::new(Method::GET, None);
            if let Some(token) = &token {
                call.query.push(("continuation-token", token.clone()));
            }
            call.query.push(("list-type", "2".to_string()));
            call.query.push(("prefix", full_prefix.clone()));

            let reply = self.send(call).await?;
            if !reply.status.is_success() {
                return Err(reply.error());
            }

            let page = xml::list_page(&reply.body).ok_or_else(|| RemoteError::Service {
                status: reply.status.as_u16(),
                code: "MalformedResponse".to_string(),
                message: "the list response does not parse".to_string(),
            })?;
            keys.extend(
                page.keys
                    .iter()
                    .filter_map(|k| k.strip_prefix(&self.config.prefix).map(str::to_string)),
            );

            match page.next_token {
                Some(next) if page.truncated => token = Some(next),
                _ => return Ok(keys),
            }
        }
    }
}

#[async_trait::async_trait]
impl Sweep for S3Remote {
    async fn delete(&self, key: &str) -> Result<(), RemoteError> {
        check_key(key)?;
        let reply = self.send(Call::new(Method::DELETE, Some(key))).await?;

        match reply.status {
            status if status.is_success() => Ok(()),
            StatusCode::NOT_FOUND => Ok(()),
            _ => Err(reply.error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_debug_hides_the_secret_key() {
        let mut config = config("http://127.0.0.1:1", "");
        config.secret_key = "very-secret-value".into();

        let text = format!("{config:?}");

        assert!(!text.contains("very-secret-value"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }

    fn config(endpoint: &str, prefix: &str) -> S3Config {
        S3Config {
            endpoint: endpoint.into(),
            bucket: "bkt".into(),
            prefix: prefix.into(),
            region: "us-east-1".into(),
            access_key: "AK".into(),
            secret_key: "SK".into(),
            retry: Retry::default(),
            ca_pem: None,
        }
    }

    #[tokio::test]
    async fn test_endpoint_rules() {
        assert!(S3Remote::new(config("http://127.0.0.1:9000", "")).is_ok());
        assert_eq!(
            S3Remote::new(config("https://s3.example.com", "")).is_ok(),
            cfg!(feature = "tls"),
            "https works with the feature tls only"
        );
        assert!(S3Remote::new(config("ftp://host", "")).is_err());
        assert!(S3Remote::new(config("http://host/path", "")).is_err());
        assert!(S3Remote::new(config("http://host", "no-slash")).is_err());
    }

    #[tokio::test]
    async fn test_object_paths_are_encoded_under_the_prefix() {
        let remote = S3Remote::new(config("http://h:1", "a b/")).unwrap();

        assert_eq!(remote.path(Some("log/x")), "/bkt/a%20b/log/x");
        assert_eq!(remote.path(None), "/bkt");
    }

    #[test]
    fn test_total_size() {
        assert_eq!(total_size(Some("bytes 2-3/4")), Some(4));
        assert_eq!(total_size(Some("bytes */4")), Some(4));
        assert_eq!(total_size(None), None);
    }
}
