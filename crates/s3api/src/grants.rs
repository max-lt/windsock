//! The grant check of a request whose signature matched, before its handler runs.

use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use engine::{Engine, EngineError};
use remote::Remote;

use crate::S3Error;
use crate::keys::{Access, Grants, Owner};

/// What a request needs from the grants of its key.
#[derive(Debug, PartialEq, Eq)]
enum Need {
    /// ListBuckets: its handler shows only the buckets that the key can reach.
    Nothing,
    CreateBucket,
    /// An access on each bucket.
    On(Vec<(String, Access)>),
}

/// 403 when the grants do not cover the request, whether its bucket exists or not.
pub(crate) async fn check<R: Remote + 'static>(
    engine: &Engine<R>,
    parts: &Parts,
    access_key: &str,
    grants: &Grants,
) -> Result<(), S3Error> {
    match need(parts) {
        Need::Nothing => Ok(()),
        Need::CreateBucket if grants.create_bucket => Ok(()),
        Need::CreateBucket => Err(denied()),
        Need::On(buckets) => {
            for (bucket, needed) in buckets {
                if access_on(engine, &bucket, access_key, grants).await? < Some(needed) {
                    return Err(denied());
                }
            }
            Ok(())
        }
    }
}

/// The access of `access_key` on `bucket`. The owner lookup runs only when it can add access.
pub(crate) async fn access_on<R: Remote + 'static>(
    engine: &Engine<R>,
    bucket: &str,
    access_key: &str,
    grants: &Grants,
) -> Result<Option<Access>, S3Error> {
    let granted = grants.access(bucket, Owner::Other);
    if granted == Some(Access::ReadWrite) || !grants.create_bucket {
        return Ok(granted);
    }
    let owner = match engine.bucket(bucket).await {
        Ok(info) if info.owner.as_deref() == Some(access_key) => Owner::Key,
        Ok(_) | Err(EngineError::NoSuchBucket(_) | EngineError::InvalidBucketName(_)) => {
            Owner::Other
        }
        Err(e) => return Err(e.into()),
    };
    Ok(grants.access(bucket, owner))
}

fn denied() -> S3Error {
    S3Error::new(
        "AccessDenied",
        StatusCode::FORBIDDEN,
        "the access key has no grant for this request",
    )
}

/// A grant name never holds a `%`: a bucket sent percent-encoded matches no grant by name.
fn need(parts: &Parts) -> Need {
    let path = parts.uri.path().trim_start_matches('/');
    let (bucket, key) = path.split_once('/').unwrap_or((path, ""));
    if bucket.is_empty() {
        return Need::Nothing;
    }
    let on = |access| (bucket.to_string(), access);
    match (&parts.method, key.is_empty()) {
        (&Method::GET | &Method::HEAD, _) => Need::On(vec![on(Access::Read)]),
        // Every bucket PUT that succeeds creates the bucket.
        (&Method::PUT, true) => Need::CreateBucket,
        (&Method::PUT, false) => {
            let mut needs = vec![on(Access::ReadWrite)];
            if let Some(source) = copy_source_bucket(parts) {
                needs.push((source, Access::Read));
            }
            Need::On(needs)
        }
        _ => Need::On(vec![on(Access::ReadWrite)]),
    }
}

/// None when the header does not parse: the handler then refuses the copy before any read.
fn copy_source_bucket(parts: &Parts) -> Option<String> {
    let source = parts.headers.get("x-amz-copy-source")?.to_str().ok()?;
    let (bucket, _) = crate::handlers::copy_source_path(source)?;
    Some(bucket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn need_of(method: Method, uri: &str, copy: Option<&str>) -> Need {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(source) = copy {
            request = request.header("x-amz-copy-source", source);
        }
        need(&request.body(()).unwrap().into_parts().0)
    }

    fn on(list: &[(&str, Access)]) -> Need {
        Need::On(list.iter().map(|(b, a)| (b.to_string(), *a)).collect())
    }

    #[test]
    fn test_need_follows_the_s3_operation() {
        use Access::*;
        let cases = [
            (Method::GET, "/", None, Need::Nothing),
            (Method::GET, "/b", None, on(&[("b", Read)])),
            (Method::HEAD, "/b/", None, on(&[("b", Read)])),
            (Method::GET, "/b?uploads", None, on(&[("b", Read)])),
            (Method::GET, "/b/k?uploadId=u", None, on(&[("b", Read)])),
            (Method::PUT, "/b", None, Need::CreateBucket),
            (Method::PUT, "/b?versioning", None, Need::CreateBucket),
            (Method::DELETE, "/b", None, on(&[("b", ReadWrite)])),
            (Method::POST, "/b?delete", None, on(&[("b", ReadWrite)])),
            (Method::PUT, "/b/k", None, on(&[("b", ReadWrite)])),
            (Method::POST, "/b/k?uploads", None, on(&[("b", ReadWrite)])),
            (
                Method::DELETE,
                "/b/k?uploadId=u",
                None,
                on(&[("b", ReadWrite)]),
            ),
            (Method::PATCH, "/b/k", None, on(&[("b", ReadWrite)])),
            (
                Method::PUT,
                "/b/k",
                Some("/src/a%2Fb"),
                on(&[("b", ReadWrite), ("src", Read)]),
            ),
            (
                Method::PUT,
                "/b/k?partNumber=1&uploadId=u",
                Some("src/a"),
                on(&[("b", ReadWrite), ("src", Read)]),
            ),
            (Method::PUT, "/b/k", Some("nokey"), on(&[("b", ReadWrite)])),
        ];
        for (method, uri, copy, expected) in cases {
            assert_eq!(
                need_of(method.clone(), uri, copy),
                expected,
                "{method} {uri}"
            );
        }
    }

    #[test]
    fn test_access_is_the_greatest_that_a_grant_gives() {
        use Access::*;
        let grants = Grants {
            all_buckets: Some(Read),
            buckets: [("rw".to_string(), ReadWrite)].into(),
            create_bucket: true,
        };
        let none = Grants::default();

        assert_eq!(grants.access("any", Owner::Other), Some(Read));
        assert_eq!(grants.access("rw", Owner::Other), Some(ReadWrite));
        assert_eq!(grants.access("mine", Owner::Key), Some(ReadWrite));
        assert_eq!(none.access("mine", Owner::Key), None);
        assert_eq!(Grants::full().access("any", Owner::Other), Some(ReadWrite));
    }
}
