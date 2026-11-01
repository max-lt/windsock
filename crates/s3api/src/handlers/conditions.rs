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

/// Refuses a conditional header that is not visible ASCII. Read as absent, it would drop the
/// condition and write or read with none.
pub(super) fn check_conditions(headers: &HeaderMap) -> Result<(), S3Error> {
    const NAMES: [&str; 4] = [
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
    ];
    for name in NAMES {
        if headers
            .get(name)
            .is_some_and(|value| value.to_str().is_err())
        {
            return Err(S3Error::invalid_argument(format!(
                "{name} must be visible ASCII"
            )));
        }
    }
    Ok(())
}

/// The check that the conditional write headers ask of the current object.
pub(super) fn write_mode(headers: &HeaderMap) -> Result<WriteMode, S3Error> {
    check_conditions(headers)?;
    match (
        header(headers, "if-match"),
        header(headers, "if-none-match"),
    ) {
        (None, None) => Ok(WriteMode::Overwrite),
        (None, Some("*")) => Ok(WriteMode::CreateOnly),
        (None, Some(_)) => Err(S3Error::not_implemented(
            "If-None-Match on a write takes only '*'",
        )),
        (Some(list), None) => Ok(if_match(list)),
        (Some(_), Some(_)) => Err(S3Error::not_implemented(
            "If-Match with If-None-Match on a write is not supported",
        )),
    }
}

/// An ETag is the hex content hash, so a tag that is not 64 hex digits matches no object.
fn if_match(list: &str) -> WriteMode {
    let mut hashes = Vec::new();
    for candidate in list.split(',').map(str::trim) {
        if candidate == "*" {
            return WriteMode::IfExists;
        }
        let mut hash = [0u8; 32];
        if hex::decode_to_slice(candidate.trim_matches('"'), &mut hash).is_ok() {
            hashes.push(hash);
        }
    }
    WriteMode::IfMatch(hashes)
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
        // The last byte is at most size - 1: no sum, so no overflow at u64::MAX.
        (Some(first), Some(last)) if first <= last => first..size.min(last.saturating_add(1)),
        _ => return Ok(None),
    };

    if range.start >= size {
        return Err(unsatisfiable());
    }

    Ok(Some(range))
}

/// The `x-amz-copy-source-range` of a part copy: `bytes=first-last`, both bytes in the source.
/// `None` when the header is absent: the part takes the whole source.
pub(super) fn copy_source_range(
    headers: &HeaderMap,
    size: u64,
) -> Result<Option<Range<u64>>, S3Error> {
    let Some(value) = header(headers, "x-amz-copy-source-range") else {
        return Ok(None);
    };
    let invalid = || {
        S3Error::invalid_argument(format!(
            "x-amz-copy-source-range must be bytes=first-last inside the {size} bytes of the \
             source: {value}"
        ))
    };
    let (first, last) = value
        .strip_prefix("bytes=")
        .and_then(|spec| spec.split_once('-'))
        .ok_or_else(invalid)?;
    let (Ok(first), Ok(last)) = (first.parse::<u64>(), last.parse::<u64>()) else {
        return Err(invalid());
    };
    if first > last || last >= size {
        return Err(invalid());
    }
    Ok(Some(first..last + 1))
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

    /// The largest numbers clamp to the object, never wrap: a debug build would panic, and a
    /// release build would give an empty range.
    #[test]
    fn test_ranges_at_the_largest_number() {
        let range = |spec: &str| byte_range(&headers(&[("range", spec)]), 100);
        let max = u64::MAX;

        assert_eq!(range(&format!("bytes=0-{max}")).unwrap(), Some(0..100));
        assert_eq!(range(&format!("bytes=90-{max}")).unwrap(), Some(90..100));
        assert_eq!(range(&format!("bytes=-{max}")).unwrap(), Some(0..100));
        assert!(range(&format!("bytes={max}-")).is_err());
        assert!(range(&format!("bytes={max}-{max}")).is_err());
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
