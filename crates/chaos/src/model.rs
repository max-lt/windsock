//! What a client may read back for each key, and a seeded random source.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use crate::s3::Outcome;

/// The blake3 of an object, or `None` for no object.
pub type Value = Option<[u8; 16]>;

pub fn digest(data: &[u8]) -> Value {
    let hash = blake3::hash(data);
    Some(
        hash.as_bytes()[..16]
            .try_into()
            .expect("a hash has 32 bytes"),
    )
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Counts {
    pub ops: u64,
    pub acked: u64,
    pub refused: u64,
    pub unknown: u64,
}

/// For each key, the values that a read may return: an acked write gives one, an unknown
/// outcome adds one to the earlier ones.
#[derive(Default)]
pub struct Model {
    inner: Mutex<(BTreeMap<String, BTreeSet<Value>>, Counts)>,
    /// Each value that a key ever had or may have had: a copy can read any of them on a proxy that
    /// is behind.
    history: Mutex<BTreeMap<String, BTreeSet<Value>>>,
    /// Reads that returned a value that their key never had, and the reads checked.
    reads: Mutex<(Vec<String>, u64)>,
}

impl Model {
    pub fn record(&self, key: &str, value: Value, outcome: Outcome) {
        if outcome != Outcome::Refused {
            let mut history = self
                .history
                .lock()
                .expect("no panic while the lock is held");
            history.entry(key.to_string()).or_default().insert(value);
        }
        let mut inner = self.inner.lock().expect("no panic while the lock is held");
        let (allowed, counts) = &mut *inner;
        counts.ops += 1;
        let earlier = allowed
            .get(key)
            .cloned()
            .unwrap_or_else(|| BTreeSet::from([None]));
        match outcome {
            Outcome::Acked => {
                counts.acked += 1;
                allowed.insert(key.to_string(), BTreeSet::from([value]));
            }
            Outcome::Unknown => {
                counts.unknown += 1;
                let mut both = earlier;
                both.insert(value);
                allowed.insert(key.to_string(), both);
            }
            Outcome::Refused => counts.refused += 1,
        }
    }

    /// A copy of `source` to `key`. An acked copy gives the value that its ETag names. A copy that
    /// may have had an effect adds each value that `source` ever had.
    pub fn record_copy(&self, key: &str, source: &str, value: Value, outcome: Outcome) {
        if let (Outcome::Acked, Some(copied)) = (outcome, value) {
            let had = self
                .history
                .lock()
                .expect("no panic while the lock is held")
                .get(source)
                .is_some_and(|values| values.contains(&Some(copied)));
            if !had {
                let mut reads = self.reads.lock().expect("no panic while the lock is held");
                reads.0.push(format!(
                    "a copy of {source} to {key} gave {copied:?}, a value that the source never had"
                ));
            }
        }
        if let (Outcome::Acked, Some(_)) | (Outcome::Refused, _) = (outcome, value) {
            return self.record(key, value, outcome);
        }
        let sources = {
            let history = self
                .history
                .lock()
                .expect("no panic while the lock is held");
            let all = history.get(source).cloned().unwrap_or_default();
            // A copy of no object fails: it never removes the target.
            all.into_iter()
                .filter(Option::is_some)
                .collect::<BTreeSet<_>>()
        };
        let mut inner = self.inner.lock().expect("no panic while the lock is held");
        let (allowed, counts) = &mut *inner;
        counts.ops += 1;
        counts.unknown += 1;
        let allowed = allowed
            .entry(key.to_string())
            .or_insert_with(|| BTreeSet::from([None]));
        allowed.extend(sources.iter().copied());
        let mut history = self
            .history
            .lock()
            .expect("no panic while the lock is held");
        history.entry(key.to_string()).or_default().extend(sources);
    }

    pub fn allowed(&self) -> BTreeMap<String, BTreeSet<Value>> {
        self.inner
            .lock()
            .expect("no panic while the lock is held")
            .0
            .clone()
    }

    /// Checks a whole GET of `key` that returned `value`. One worker writes each key, one operation
    /// at a time, so every value that a proxy can give, also one that is behind, is in the history.
    pub fn check_read(&self, key: &str, value: Value) {
        let known = self
            .history
            .lock()
            .expect("no panic while the lock is held")
            .get(key)
            .is_some_and(|values| values.contains(&value));
        let mut reads = self.reads.lock().expect("no panic while the lock is held");
        reads.1 += 1;
        if !known {
            reads.0.push(format!(
                "GET {key} gave {value:?}, a value that it never had"
            ));
        }
    }

    /// The reads that broke the model, and the count of reads checked.
    pub fn read_faults(&self) -> (Vec<String>, u64) {
        self.reads
            .lock()
            .expect("no panic while the lock is held")
            .clone()
    }

    pub fn counts(&self) -> Counts {
        self.inner
            .lock()
            .expect("no panic while the lock is held")
            .1
    }
}

/// xorshift64*: the same run for the same seed, no dependency.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number in `0..n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }

    /// An index into `weights`, with the chance of each weight.
    pub fn weighted(&mut self, weights: &[u64]) -> usize {
        let mut roll = self.below(weights.iter().sum());
        for (n, weight) in weights.iter().enumerate() {
            if roll < *weight {
                return n;
            }
            roll -= weight;
        }
        weights.len() - 1
    }

    /// A duration in `low..high` seconds, in milliseconds.
    pub fn secs(&mut self, low: u64, high: u64) -> std::time::Duration {
        std::time::Duration::from_millis(low * 1000 + self.below((high - low) * 1000))
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_outcome_keeps_the_earlier_values() {
        let model = Model::default();
        model.record("k", digest(b"a"), Outcome::Acked);
        model.record("k", digest(b"b"), Outcome::Unknown);
        model.record("k", digest(b"c"), Outcome::Refused);

        let allowed = model.allowed();

        assert_eq!(allowed["k"], BTreeSet::from([digest(b"a"), digest(b"b")]));
        assert_eq!(model.counts().ops, 3);
    }

    #[test]
    fn test_acked_delete_allows_no_object_only() {
        let model = Model::default();
        model.record("k", digest(b"a"), Outcome::Unknown);
        model.record("k", None, Outcome::Acked);

        assert_eq!(model.allowed()["k"], BTreeSet::from([None]));
    }

    #[test]
    fn test_copy_with_no_answer_allows_each_value_of_the_source() {
        let model = Model::default();
        model.record("src", digest(b"a"), Outcome::Acked);
        model.record("src", digest(b"b"), Outcome::Acked);
        model.record("dst", digest(b"c"), Outcome::Acked);

        model.record_copy("dst", "src", None, Outcome::Unknown);
        model.record_copy("other", "src", digest(b"b"), Outcome::Acked);

        let want = BTreeSet::from([digest(b"a"), digest(b"b"), digest(b"c")]);
        assert_eq!(model.allowed()["dst"], want);
        assert_eq!(model.allowed()["other"], BTreeSet::from([digest(b"b")]));
    }

    #[test]
    fn test_read_of_a_value_that_the_key_never_had_is_a_fault() {
        let model = Model::default();
        model.record("k", digest(b"a"), Outcome::Acked);
        model.record("k", digest(b"b"), Outcome::Acked);
        model.record("k", digest(b"c"), Outcome::Refused);

        model.check_read("k", digest(b"a"));
        model.check_read("k", digest(b"c"));
        model.check_read("other", digest(b"a"));

        let (faults, reads) = model.read_faults();
        assert_eq!(reads, 3);
        assert_eq!(faults.len(), 2, "{faults:?}");
    }

    #[test]
    fn test_acked_copy_of_a_value_that_the_source_never_had_is_a_fault() {
        let model = Model::default();
        model.record("src", digest(b"a"), Outcome::Acked);

        model.record_copy("dst", "src", digest(b"a"), Outcome::Acked);
        model.record_copy("dst", "src", digest(b"x"), Outcome::Acked);

        let (faults, _) = model.read_faults();
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(faults[0].contains("never had"), "{faults:?}");
    }

    #[test]
    fn test_rng_repeats_for_one_seed() {
        let (mut a, mut b) = (Rng::new(7), Rng::new(7));

        assert_eq!(a.bytes(33), b.bytes(33));
        assert!((0..1000).all(|_| a.below(5) < 5));
        assert!((0..1000).all(|_| a.weighted(&[1, 0, 3]) != 1));
    }
}
