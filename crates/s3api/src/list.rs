//! Resume points of a listing, and the in-memory page model that the engine listing must match.

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

    pub fn into_engine(self) -> engine::ListAfter {
        match self {
            Self::Key(key) => engine::ListAfter::Key(key),
            Self::Prefix(prefix) => engine::ListAfter::Prefix(prefix),
        }
    }

    #[cfg(test)]
    fn skips(&self, key: &str) -> bool {
        match self {
            Self::Key(after) => key <= after.as_str(),
            Self::Prefix(prefix) => key <= prefix.as_str() || key.starts_with(prefix.as_str()),
        }
    }
}

#[cfg(test)]
/// One entry of a page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Item {
    /// Index into the keys given to [`page`].
    Object(usize),
    CommonPrefix(String),
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Page {
    pub items: Vec<Item>,
    pub truncated: bool,
}

#[cfg(test)]
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

#[cfg(test)]
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

    /// A small xorshift: the same keys and queries on every run.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }

        fn key(&mut self) -> String {
            const PARTS: [&str; 6] = ["a", "b", "/", "c", "\u{e9}", "b/"];
            (0..1 + self.below(6))
                .map(|_| PARTS[self.below(PARTS.len())])
                .collect()
        }
    }

    /// The engine page, in the shape of the model page.
    fn engine_names(page: &engine::ListPage) -> Vec<String> {
        page.entries
            .iter()
            .map(|entry| match entry {
                engine::ListEntry::Object(info) => info.key.clone(),
                engine::ListEntry::CommonPrefix(p) => format!("{p}*"),
            })
            .collect()
    }

    /// The engine listing matches the in-memory model on random keys, in the buffer and in the
    /// index, with deletes, prefixes, delimiters, start points and page sizes.
    #[tokio::test]
    async fn test_engine_pages_match_the_model() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine::Engine::open(
            dir.path(),
            std::sync::Arc::new(remote::MemoryRemote::default()),
            ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
            engine::RepoKey::from_hex(&"07".repeat(32)).unwrap().keys(),
            engine::Config::default(),
        )
        .await
        .unwrap();
        engine.create_bucket("bkt", None).await.unwrap();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut live = std::collections::BTreeSet::new();

        for round in 0..3 {
            for _ in 0..150 {
                let key = rng.key();
                let put = engine.put(
                    "bkt",
                    &key,
                    bytes::Bytes::from(key.clone()),
                    Default::default(),
                    engine::WriteMode::Overwrite,
                );
                put.await.unwrap();
                live.insert(key);
            }
            for _ in 0..40 {
                let key = rng.key();
                if live.remove(&key) {
                    engine.delete("bkt", &key).await.unwrap();
                }
            }
            if round < 2 {
                engine.flush().await.unwrap();
            }
        }
        let keys: Vec<String> = live.into_iter().collect();

        for _ in 0..400 {
            let prefix = match rng.below(3) {
                0 => String::new(),
                _ => {
                    let key = &keys[rng.below(keys.len())];
                    let cut = key
                        .char_indices()
                        .map(|(i, _)| i)
                        .nth(rng.below(3))
                        .unwrap_or(0);
                    key[..cut].to_string()
                }
            };
            let delimiter = [None, Some("/"), Some("b"), Some("b/")][rng.below(4)];
            let max_keys = [1, 2, 3, 7, 50, 1000][rng.below(6)];
            let after = match rng.below(4) {
                0 => Some(After::Key(rng.key())),
                1 => Some(After::Prefix(rng.key())),
                _ => None,
            };
            let under: Vec<String> = keys
                .iter()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            let mut want_after = after.clone();
            let mut got_after = after;

            loop {
                let want = page(&under, &prefix, delimiter, max_keys, want_after.as_ref());
                let query = engine::ListQuery {
                    prefix: &prefix,
                    delimiter,
                    after: got_after.clone().map(After::into_engine),
                    max_keys,
                };
                let got = engine.list_page("bkt", &query).await.unwrap();
                let context = format!("{prefix:?} {delimiter:?} {max_keys} {got_after:?}");

                assert_eq!(engine_names(&got), names(&under, &want), "{context}");
                assert_eq!(got.truncated, want.truncated, "{context}");
                let Some(next) = want.next(&under) else {
                    break;
                };
                got_after = Some(After::from_token(&next.token()).unwrap());
                want_after = Some(next);
            }
        }
    }
}
