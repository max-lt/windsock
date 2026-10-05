//! The S3 responses the client reads: list pages and errors.

use serde::Deserialize;

#[derive(Deserialize)]
struct ListResult {
    #[serde(rename = "IsTruncated", default)]
    is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    next_continuation_token: Option<String>,
    #[serde(rename = "Contents", default)]
    contents: Vec<Contents>,
}

#[derive(Deserialize)]
struct Contents {
    #[serde(rename = "Key")]
    key: String,
}

pub(crate) struct ListPage {
    pub keys: Vec<String>,
    pub truncated: bool,
    pub next_token: Option<String>,
}

pub(crate) fn list_page(body: &[u8]) -> Option<ListPage> {
    let result: ListResult = quick_xml::de::from_str(std::str::from_utf8(body).ok()?).ok()?;

    Some(ListPage {
        keys: result.contents.into_iter().map(|c| c.key).collect(),
        truncated: result.is_truncated,
        next_token: result.next_continuation_token,
    })
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(rename = "Code", default)]
    code: String,
    #[serde(rename = "Message", default)]
    message: String,
}

/// The code and message of an S3 error body. Empty when there is none, as for HEAD.
pub(crate) fn error(body: &[u8]) -> (String, String) {
    std::str::from_utf8(body)
        .ok()
        .and_then(|text| quick_xml::de::from_str::<ErrorBody>(text).ok())
        .map_or_else(Default::default, |e| (e.code, e.message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_page() {
        let body = br#"<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Name>b</Name><Prefix/><KeyCount>2</KeyCount><IsTruncated>true</IsTruncated>
            <NextContinuationToken>tok</NextContinuationToken>
            <Contents><Key>a</Key><Size>1</Size></Contents><Contents><Key>b/c</Key></Contents>
        </ListBucketResult>"#;

        let page = list_page(body).unwrap();

        assert_eq!(page.keys, ["a", "b/c"]);
        assert!(page.truncated);
        assert_eq!(page.next_token.as_deref(), Some("tok"));
    }

    #[test]
    fn test_empty_list_page() {
        let body =
            b"<ListBucketResult><Name>b</Name><IsTruncated>false</IsTruncated></ListBucketResult>";

        let page = list_page(body).unwrap();

        assert!(page.keys.is_empty() && !page.truncated);
    }

    #[test]
    fn test_error_body() {
        let body = b"<Error><Code>SlowDown</Code><Message>wait</Message></Error>";

        assert_eq!(error(body), ("SlowDown".to_string(), "wait".to_string()));
        assert_eq!(error(b""), (String::new(), String::new()));
    }
}
