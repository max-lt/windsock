//! Paged listings. A page seeks from its start key in the buffer and in the index, so its cost
//! does not grow with the number of keys under the prefix.

use super::*;
use crate::read::stored;

/// Where a page starts: after a key, or after every key under a common prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListAfter {
    Key(String),
    Prefix(String),
}

/// One listing request.
#[derive(Clone, Debug)]
pub struct ListQuery<'a> {
    pub prefix: &'a str,
    /// A key with the delimiter after the prefix rolls up into one common prefix.
    pub delimiter: Option<&'a str>,
    pub after: Option<ListAfter>,
    /// Objects and common prefixes in the page, together.
    pub max_keys: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListEntry {
    Object(ObjectInfo),
    CommonPrefix(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListPage {
    pub entries: Vec<ListEntry>,
    /// More entries follow the last one.
    pub truncated: bool,
}

/// A page entry before its object info is read.
pub(crate) enum Found {
    Object(String, Current),
    CommonPrefix(String),
}

impl<R: Remote + 'static> Engine<R> {
    /// One page of the objects of `bucket`, in key order.
    pub async fn list_page(&self, bucket: &str, query: &ListQuery<'_>) -> Result<ListPage> {
        self.retry_after_sync(|| async move {
            let (found, truncated) = self
                .read_settled(|buffer| {
                    self.require_bucket(buffer, bucket)?;
                    self.scan_page(buffer, bucket, query)
                })
                .await?;

            let mut entries = Vec::with_capacity(found.len());
            for item in found {
                entries.push(match item {
                    Found::Object(key, current) => {
                        ListEntry::Object(self.info(bucket, &key, current).await?)
                    }
                    Found::CommonPrefix(prefix) => ListEntry::CommonPrefix(prefix),
                });
            }
            Ok(ListPage { entries, truncated })
        })
        .await
    }

    pub(crate) fn scan_page(
        &self,
        buffer: &Buffer,
        bucket: &str,
        query: &ListQuery<'_>,
    ) -> Result<(Vec<Found>, bool)> {
        let prefix = query.prefix;
        let delimiter = query.delimiter.filter(|d| !d.is_empty());
        let start = match &query.after {
            None => Some(prefix.to_string()),
            Some(ListAfter::Key(key)) => Some(format!("{key}\0")),
            Some(ListAfter::Prefix(group)) => past_group(group),
        };
        let mut found = Vec::new();
        let Some(mut from) = start else {
            return Ok((found, false));
        };

        while let Some((key, current)) = self.first_from(buffer, bucket, prefix, &from)? {
            if !current.exists() {
                from = format!("{key}\0");
                continue;
            }

            let group = delimiter.and_then(|d| {
                let at = key[prefix.len()..].find(d)?;
                Some(key[..prefix.len() + at + d.len()].to_string())
            });
            if found.len() == query.max_keys {
                return Ok((found, true));
            }

            match group {
                Some(group) => {
                    let next = past_group(&group);
                    found.push(Found::CommonPrefix(group));
                    let Some(next) = next else {
                        return Ok((found, false));
                    };
                    from = next;
                }
                None => {
                    from = format!("{key}\0");
                    found.push(Found::Object(key, current));
                }
            }
        }

        Ok((found, false))
    }

    /// The first key at `from` or after it, from the buffer or the index. The buffer wins a tie.
    fn first_from(
        &self,
        buffer: &Buffer,
        bucket: &str,
        prefix: &str,
        from: &str,
    ) -> Result<Option<(String, Current)>> {
        let buffered = buffer.first_object_from(bucket, prefix, from);
        let indexed = self.index().first_from(bucket, prefix, from)?;

        let use_buffer = match (&buffered, &indexed) {
            (None, None) => return Ok(None),
            (Some((b, _)), Some((i, _))) => *b <= i.as_str(),
            (Some(_), None) => true,
            (None, Some(_)) => false,
        };

        if !use_buffer {
            let (key, state) = indexed.expect("the index has the smaller key");
            return Ok(Some((key, stored(&state))));
        }

        let (key, object) = buffered.expect("the buffer has the smaller key");
        let current = match object {
            BufferedObject::Put(put) => Current::Buffered(put.clone()),
            BufferedObject::Delete { .. } => Current::Absent,
        };
        Ok(Some((key.to_string(), current)))
    }
}

/// The smallest string after every string that starts with `group`. `None` when none exists.
fn past_group(group: &str) -> Option<String> {
    let mut out = group.to_string();
    while let Some(last) = out.pop() {
        if let Some(next) = (u32::from(last) + 1..=u32::from(char::MAX)).find_map(char::from_u32) {
            out.push(next);
            return Some(out);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_past_group_skips_surrogates_and_the_last_char() {
        assert_eq!(past_group("a/").as_deref(), Some("a0"));
        assert_eq!(past_group("a\u{7f}").as_deref(), Some("a\u{80}"));
        assert_eq!(past_group("a\u{d7ff}").as_deref(), Some("a\u{e000}"));
        assert_eq!(past_group("a\u{10ffff}").as_deref(), Some("b"));
        assert_eq!(past_group("\u{10ffff}\u{10ffff}"), None);
    }
}
