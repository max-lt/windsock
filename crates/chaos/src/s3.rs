//! A small S3 client: SigV4 with the body hash, path-style, over plain HTTP.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Request};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use s3proto::sigv4;

/// How a write ended, as a client sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 2xx: the proxy acked the write.
    Acked,
    /// 4xx or 503: the proxy refused it before any effect.
    Refused,
    /// Any other error or no answer: the write can have an effect or not.
    Unknown,
}

pub struct Reply {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Reply {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn outcome(&self) -> Outcome {
        match self.status {
            200..=299 => Outcome::Acked,
            400..=499 | 503 => Outcome::Refused,
            _ => Outcome::Unknown,
        }
    }
}

#[derive(Clone)]
pub struct S3 {
    client: Client<HttpConnector, Full<Bytes>>,
    address: String,
    access: String,
    secret: String,
}

/// An error before a status: no connection, a timeout, a cut answer.
pub type Failure = String;

impl S3 {
    pub fn new(address: &str, access: &str, secret: &str) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(3)));
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            address: address.to_string(),
            access: access.to_string(),
            secret: secret.to_string(),
        }
    }

    /// Sends one signed request. `query` is canonical: sorted, already encoded.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        query: &str,
        extra: &[(&str, String)],
        body: Bytes,
    ) -> Result<Reply, Failure> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let timestamp = sigv4::timestamp(now);
        let payload_hash = sigv4::sha256_hex(&body);
        let mut headers = vec![
            ("host".to_string(), self.address.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), timestamp.clone()),
        ];
        headers.extend(extra.iter().map(|(n, v)| (n.to_string(), v.clone())));
        let (authorization, _) = sigv4::sign(
            &sigv4::Request {
                method,
                path,
                query,
                headers: &headers,
                payload_hash: &payload_hash,
            },
            &self.access,
            &self.secret,
            &timestamp,
            "us-east-1",
        );

        let uri = match query {
            "" => format!("http://{}{path}", self.address),
            query => format!("http://{}{path}?{query}", self.address),
        };
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let request = request
            .header("authorization", authorization)
            .body(Full::new(body))
            .map_err(|e| e.to_string())?;

        let call = async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            Ok(Reply {
                status,
                headers,
                body,
            })
        };
        tokio::time::timeout(Duration::from_secs(30), call)
            .await
            .map_err(|_| "no answer in 30 s".to_string())?
    }

    pub async fn put(&self, path: &str, body: Bytes) -> Outcome {
        self.send("PUT", path, "", &[], body)
            .await
            .map_or(Outcome::Unknown, |r| r.outcome())
    }

    pub async fn delete(&self, path: &str) -> Outcome {
        self.send("DELETE", path, "", &[], Bytes::new())
            .await
            .map_or(Outcome::Unknown, |r| r.outcome())
    }

    pub async fn get(&self, path: &str) -> Result<Reply, Failure> {
        self.send("GET", path, "", &[], Bytes::new()).await
    }

    pub async fn get_range(&self, path: &str, range: &str) -> Result<Reply, Failure> {
        let extra = [("range", range.to_string())];
        self.send("GET", path, "", &extra, Bytes::new()).await
    }

    pub async fn list(&self, bucket: &str, prefix: &str) -> Result<Reply, Failure> {
        let query = format!("list-type=2&max-keys=7&prefix={}", encode(prefix));
        self.send("GET", &format!("/{bucket}"), &query, &[], Bytes::new())
            .await
    }

    /// A multipart upload of `parts`. `None` when a step before the complete fails: the object
    /// does not change then.
    pub async fn multipart(&self, path: &str, parts: &[Bytes]) -> Option<Outcome> {
        let created = self
            .send("POST", path, "uploads=", &[], Bytes::new())
            .await
            .ok()?;
        if !created.ok() {
            return None;
        }
        let upload = tag(&created.body, "UploadId")?;
        let mut done = String::from("<CompleteMultipartUpload>");
        for (n, part) in parts.iter().enumerate() {
            let number = n + 1;
            let query = format!("partNumber={number}&uploadId={}", encode(&upload));
            let reply = self
                .send("PUT", path, &query, &[], part.clone())
                .await
                .ok()?;
            let etag = reply.headers.get("etag")?.to_str().ok()?.to_string();
            if !reply.ok() {
                return None;
            }
            done.push_str(&format!(
                "<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
            ));
        }
        done.push_str("</CompleteMultipartUpload>");
        let query = format!("uploadId={}", encode(&upload));
        let completed = self
            .send("POST", path, &query, &[], Bytes::from(done))
            .await;
        Some(completed.map_or(Outcome::Unknown, |r| r.outcome()))
    }
}

/// The text of the first `<name>` element.
fn tag(body: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let start = text.find(&format!("<{name}>"))? + name.len() + 2;
    let end = start + text[start..].find(&format!("</{name}>"))?;
    Some(text[start..end].to_string())
}

fn encode(value: &str) -> String {
    sigv4::uri_encode(value.as_bytes(), sigv4::Slash::Encode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_reads_the_first_element() {
        let body = b"<A><UploadId>abc</UploadId><UploadId>x</UploadId></A>";

        assert_eq!(tag(body, "UploadId").as_deref(), Some("abc"));
        assert_eq!(tag(body, "Key"), None);
    }

    #[test]
    fn test_status_gives_the_outcome() {
        let reply = |status| Reply {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };

        assert_eq!(reply(200).outcome(), Outcome::Acked);
        assert_eq!(reply(503).outcome(), Outcome::Refused);
        assert_eq!(reply(404).outcome(), Outcome::Refused);
        assert_eq!(reply(500).outcome(), Outcome::Unknown);
    }
}
