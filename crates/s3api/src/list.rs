//! Listing pages: delimiter roll-up, max-keys, and resume points. No I/O.

use crate::S3Error;

/// Where a page starts: after a key, or after every key under a common prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum After {
    Key(String),
    Prefix(String),
}

impl After {
    /// An opaque continuation token. The kind is in it, so a prefix resumes after its whole group.
    pub fn token(&self) -> String {
        match self {
            Self::Key(key) => format!("k{}", hex::encode(key)),
            Self::Prefix(prefix) => format!("p{}", hex::encode(prefix)),
        }
    }

    pub fn from_token(token: &str) -> Result<Self, S3Error> {
        let bad = || S3Error::invalid_argument("the continuation token is not valid");
        let (kind, hex) = token.split_at_checked(1).ok_or_else(bad)?;
        let text = String::from_utf8(hex::decode(hex).map_err(|_| bad())?).map_err(|_| bad())?;

        match kind {
            "k" => Ok(Self::Key(text)),
            "p" => Ok(Self::Prefix(text)),
            _ => Err(bad()),
        }
    }

    fn skips(&self, key: &str) -> bool {
        match self {
            Self::Key(after) => key <= after.as_str(),
            Self::Prefix(prefix) => key <= prefix.as_str() || key.starts_with(prefix.as_str()),
        }
    }
}

/// One entry of a page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Item {
    /// Index into the keys given to [`page`].
    Object(usize),
    CommonPrefix(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Page {
    pub items: Vec<Item>,
    pub truncated: bool,
}

impl Page {
    /// Where the next page starts.
    pub fn next(&self, keys: &[String]) -> Option<After> {
        if !self.truncated {
            return None;
        }

        match self.items.last()? {
            Item::Object(i) => Some(After::Key(keys[*i].clone())),
            Item::CommonPrefix(prefix) => Some(After::Prefix(prefix.clone())),
        }
    }
}

/// Cuts a page from `keys`, sorted and all under `prefix`. A key with `delimiter`
/// after the prefix rolls up into one common prefix; each counts as one item.
pub(crate) fn page(
    keys: &[String],
    prefix: &str,
    delimiter: Option<&str>,
    max_keys: usize,
    after: Option<&After>,
) -> Page {
    let delimiter = delimiter.filter(|d| !d.is_empty());
    let mut items = Vec::new();
    let mut last_prefix: Option<String> = None;

    for (i, key) in keys.iter().enumerate() {
        if after.is_some_and(|a| a.skips(key)) {
            continue;
        }

        let rolled = delimiter.and_then(|d| {
            let pos = key[prefix.len()..].find(d)?;
            Some(key[..prefix.len() + pos + d.len()].to_string())
        });

        let item = match rolled {
            Some(common) if last_prefix.as_ref() == Some(&common) => continue,
            Some(common) => Item::CommonPrefix(common),
            None => Item::Object(i),
        };

        if items.len() == max_keys {
            return Page {
                items,
                truncated: true,
            };
        }

        if let Item::CommonPrefix(common) = &item {
            last_prefix = Some(common.clone());
        }
        items.push(item);
    }

    Page {
        items,
        truncated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn names(keys: &[String], page: &Page) -> Vec<String> {
        page.items
            .iter()
            .map(|item| match item {
                Item::Object(i) => keys[*i].clone(),
                Item::CommonPrefix(p) => format!("{p}*"),
            })
            .collect()
    }

    /// Every page, until the last one.
    fn walk(
        keys: &[String],
        prefix: &str,
        delimiter: Option<&str>,
        max_keys: usize,
    ) -> Vec<Vec<String>> {
        let mut pages = Vec::new();
        let mut after = None;

        loop {
            let page = page(keys, prefix, delimiter, max_keys, after.as_ref());
            pages.push(names(keys, &page));
            match page.next(keys) {
                Some(next) => after = Some(After::from_token(&next.token()).unwrap()),
                None => return pages,
            }
        }
    }

    #[test]
    fn test_delimiter_rolls_keys_up() {
        let keys = keys(&["a/1", "a/2", "b", "c/d/e", "c/f"]);

        assert_eq!(walk(&keys, "", Some("/"), 1000), [["a/*", "b", "c/*"]]);
        assert_eq!(
            walk(&keys, "", None, 1000),
            [["a/1", "a/2", "b", "c/d/e", "c/f"]]
        );
    }

    #[test]
    fn test_pages_resume_after_a_common_prefix() {
        let keys = keys(&["a/1", "a/2", "b", "c/1", "c/2", "d"]);

        assert_eq!(
            walk(&keys, "", Some("/"), 2),
            [vec!["a/*", "b"], vec!["c/*", "d"]]
        );
        assert_eq!(
            walk(&keys, "", Some("/"), 1),
            [["a/*"], ["b"], ["c/*"], ["d"]]
        );
    }

    #[test]
    fn test_pages_without_delimiter_cover_every_key_once() {
        let keys = keys(&["a", "b", "c", "d", "e"]);

        assert_eq!(
            walk(&keys, "", None, 2),
            [vec!["a", "b"], vec!["c", "d"], vec!["e"]]
        );
    }

    #[test]
    fn test_exact_fit_is_not_truncated() {
        let keys = keys(&["a", "b"]);

        assert!(!page(&keys, "", None, 2, None).truncated);
        assert!(page(&keys, "", None, 1, None).truncated);
    }

    #[test]
    fn test_prefix_and_delimiter_roll_up_below_the_prefix() {
        let keys = keys(&["p/a/1", "p/a/2", "p/b"]);

        assert_eq!(walk(&keys, "p/", Some("/"), 1000), [["p/a/*", "p/b"]]);
    }

    #[test]
    fn test_start_after_a_key() {
        let keys = keys(&["a", "b", "c"]);
        let page = page(&keys, "", None, 1000, Some(&After::Key("a".into())));

        assert_eq!(names(&keys, &page), ["b", "c"]);
    }

    #[test]
    fn test_bad_token_is_rejected() {
        assert!(After::from_token("x00").is_err());
        assert!(After::from_token("kzz").is_err());
        assert!(After::from_token("").is_err());
    }
}
