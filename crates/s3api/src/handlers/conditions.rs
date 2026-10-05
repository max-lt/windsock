//! Conditional requests (RFC 7232, section 6) and byte ranges (RFC 7233).

use s3proto::time::parse_http_date;

use super::*;

/// What the precondition headers allow.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Precondition {
    Proceed,
    NotModified,
    Failed,
}

/// `If-Match` and `If-None-Match` hold a list of ETags, or `*`.
pub(super) fn etag_matches(list: &str, etag: &str) -> bool {
    list.split(',').map(str::trim).any(|candidate| {
        let candidate = candidate.strip_prefix("W/").unwrap_or(candidate);
        candidate == "*" || candidate.trim_matches('"') == etag
    })
}

pub(super) fn precondition(headers: &HeaderMap, info: &ObjectInfo) -> Precondition {
    let etag = etag(info);
    let modified = info.last_modified / 1_000_000_000;
    let date = |name| header(headers, name).and_then(parse_http_date);

    match header(headers, "if-match") {
        Some(list) if !etag_matches(list, &etag) => return Precondition::Failed,
        Some(_) => {}
        None if date("if-unmodified-since").is_some_and(|since| modified > since) => {
            return Precondition::Failed;
        }
        None => {}
    }

    match header(headers, "if-none-match") {
        Some(list) if etag_matches(list, &etag) => Precondition::NotModified,
        Some(_) => Precondition::Proceed,
        None if date("if-modified-since").is_some_and(|since| modified <= since) => {
            Precondition::NotModified
        }
        None => Precondition::Proceed,
    }
}

pub(super) fn not_modified(info: &ObjectInfo) -> Reply {
    Ok(reply(StatusCode::NOT_MODIFIED)
        .header("etag", xml::quoted(&etag(info)))
        .header("last-modified", http_date(info.last_modified))
        .body(Body::empty())
        .expect("formatted headers are valid"))
}

/// The byte range of a `Range` header. `None` serves the whole object: a header
/// that does not parse, or that asks for several ranges, is ignored, as RFC 7233 allows.
pub(super) fn byte_range(headers: &HeaderMap, size: u64) -> Result<Option<Range<u64>>, S3Error> {
    let Some(spec) = header(headers, "range").and_then(|r| r.trim().strip_prefix("bytes=")) else {
        return Ok(None);
    };
    if spec.contains(',') {
        return Ok(None);
    }
    let Some((start, end)) = spec.split_once('-') else {
        return Ok(None);
    };
    let unsatisfiable = || S3Error::invalid_range(format!("bytes={spec} is outside {size} bytes"));

    let range = match (
        start.trim().parse::<u64>().ok(),
        end.trim().parse::<u64>().ok(),
    ) {
        (None, Some(_)) if !start.trim().is_empty() => return Ok(None),
        (None, Some(0)) => return Err(unsatisfiable()),
        (None, Some(suffix)) => size.saturating_sub(suffix)..size,
        (Some(first), None) if end.trim().is_empty() => first..size,
        (Some(first), Some(last)) if first <= last => first..size.min(last + 1),
        _ => return Ok(None),
    };

    if range.start >= size {
        return Err(unsatisfiable());
    }

    Ok(Some(range))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().unwrap());
        }
        map
    }

    fn info() -> ObjectInfo {
        ObjectInfo {
            key: "k".into(),
            size: 100,
            content_hash: [0xab; 32],
            metadata: BTreeMap::new(),
            // Mon, 05 Oct 2026 12:00:00 GMT
            last_modified: 1_791_201_600_000_000_000,
            conflicted: false,
        }
    }

    #[test]
    fn test_ranges() {
        let range = |spec: &str| byte_range(&headers(&[("range", spec)]), 100);

        assert_eq!(range("bytes=0-9").unwrap(), Some(0..10));
        assert_eq!(range("bytes=90-").unwrap(), Some(90..100));
        assert_eq!(range("bytes=-10").unwrap(), Some(90..100));
        assert_eq!(range("bytes=95-200").unwrap(), Some(95..100));
        assert_eq!(range("bytes=-500").unwrap(), Some(0..100));
        assert!(range("bytes=100-").is_err());
        assert!(range("bytes=-0").is_err());
        assert_eq!(range("bytes=0-1,5-6").unwrap(), None);
        assert_eq!(range("bytes=9-1").unwrap(), None);
        assert_eq!(range("items=0-1").unwrap(), None);
        assert_eq!(byte_range(&HeaderMap::new(), 100).unwrap(), None);
    }

    #[test]
    fn test_preconditions() {
        let tag = format!("\"{}\"", "ab".repeat(32));
        let check = |pairs: &[(&'static str, &str)]| precondition(&headers(pairs), &info());

        assert_eq!(check(&[]), Precondition::Proceed);
        assert_eq!(check(&[("if-match", &tag)]), Precondition::Proceed);
        assert_eq!(check(&[("if-match", "\"other\"")]), Precondition::Failed);
        assert_eq!(check(&[("if-none-match", &tag)]), Precondition::NotModified);
        assert_eq!(check(&[("if-none-match", "*")]), Precondition::NotModified);
        assert_eq!(
            check(&[("if-none-match", "\"other\", W/\"x\"")]),
            Precondition::Proceed
        );
        assert_eq!(
            check(&[("if-modified-since", "Mon, 05 Oct 2026 12:00:00 GMT")]),
            Precondition::NotModified
        );
        assert_eq!(
            check(&[("if-modified-since", "Sun, 04 Oct 2026 12:00:00 GMT")]),
            Precondition::Proceed
        );
        assert_eq!(
            check(&[("if-unmodified-since", "Sun, 04 Oct 2026 12:00:00 GMT")]),
            Precondition::Failed
        );
        assert_eq!(
            check(&[
                ("if-match", &tag),
                ("if-unmodified-since", "Sun, 04 Oct 2026 12:00:00 GMT")
            ]),
            Precondition::Proceed,
            "If-Match takes over If-Unmodified-Since"
        );
        assert_eq!(
            check(&[
                ("if-none-match", "\"other\""),
                ("if-modified-since", "Mon, 05 Oct 2026 12:00:00 GMT")
            ]),
            Precondition::Proceed,
            "If-None-Match takes over If-Modified-Since"
        );
    }
}
