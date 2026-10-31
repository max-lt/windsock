//! Reads one entry from the remote: the header and the MAC first, the sealed actions last.

use std::ops::Range;

use bytes::Bytes;
use remote::{Remote, RemoteError};
use seal::Sealer;

use model::NodeId;

use crate::{ChainError, Entry, EntryHead, MAX_ENTRY, MAX_HEADER, TAIL_LEN, WireError};

/// Reads of one entry. A prune replaces an entry once, so a second change means a fault.
const ATTEMPTS: u32 = 3;

/// Why a reader refuses the object at an entry key.
pub(crate) enum Refused {
    Wire(WireError),
    TooLarge {
        len: u64,
    },
    /// The header names another node than the key.
    WrongNode {
        actual: NodeId,
    },
    /// The header names another seq than the key.
    WrongSeq {
        actual: u64,
    },
}

impl Refused {
    pub(crate) fn at(self, node: NodeId, seq: u64) -> ChainError {
        match self {
            Refused::WrongNode { actual } => ChainError::WrongNode {
                seq,
                expected: node,
                actual,
            },
            Refused::WrongSeq { actual } => ChainError::WrongSeq {
                expected: seq,
                actual,
            },
            Refused::Wire(WireError::Malformed) => ChainError::Malformed { seq },
            Refused::Wire(WireError::ActionsMismatch) => ChainError::ActionsMismatch { seq },
            Refused::Wire(WireError::Sealed) => ChainError::Sealed { seq },
            Refused::Wire(WireError::BadMac) => ChainError::BadMac { seq },
            Refused::TooLarge { len } => ChainError::TooLarge { seq, len },
        }
    }
}

/// The entry at a key, or `None` when no object is there.
pub(crate) type Read = Option<Result<Entry, Refused>>;

fn done(read: Result<Entry, WireError>) -> Option<Read> {
    Some(Some(read.map_err(Refused::Wire)))
}

fn refused(refused: Refused) -> Option<Read> {
    Some(Some(Err(refused)))
}

/// Reads entry `seq` of `node`. An entry of at most MAX_HEADER bytes costs one request. A larger
/// one costs four, and a reader takes its tail only for the node and seq of the key, and its
/// actions only after its MAC passes.
pub(crate) async fn read_entry<R: Remote>(
    remote: &R,
    (node, seq): (NodeId, u64),
    sealer: &Sealer,
) -> Result<Read, RemoteError> {
    let key = crate::entry_key(node, seq);
    for _ in 0..ATTEMPTS {
        if let Some(read) = attempt(remote, (&key, node, seq), sealer).await? {
            return Ok(read);
        }
    }
    Ok(Some(Err(Refused::Wire(WireError::Malformed))))
}

/// One read of the entry at `key`, or `None` when its parts do not fit together: the object changed
/// between two reads.
async fn attempt<R: Remote>(
    remote: &R,
    (key, node, seq): (&str, NodeId, u64),
    sealer: &Sealer,
) -> Result<Option<Read>, RemoteError> {
    let len = match remote.get(key, MAX_HEADER).await {
        Ok(None) => return Ok(Some(None)),
        Ok(Some(bytes)) => return Ok(done(Entry::from_wire(&bytes, sealer))),
        // A body with no length gives MAX_HEADER + 1: the header says the true length.
        Err(RemoteError::TooLarge { len, .. }) => len,
        Err(e) => return Err(e),
    };
    if len > MAX_ENTRY {
        return Ok(refused(Refused::TooLarge { len }));
    }
    let Some(prefix) = part(remote, key, 0..MAX_HEADER).await? else {
        return Ok(None);
    };
    let head = match EntryHead::parse(&prefix) {
        Ok(head) => head,
        Err(e) => return Ok(done(Err(e))),
    };
    // A copy of a real header under another key: refused before its tail and its actions.
    if head.node() != node {
        return Ok(refused(Refused::WrongNode {
            actual: head.node(),
        }));
    }
    if head.seq() != seq {
        return Ok(refused(Refused::WrongSeq { actual: head.seq() }));
    }
    let end = match head.wire_len() {
        Some(end) if end <= MAX_ENTRY => end,
        end => {
            let len = end.unwrap_or(u64::MAX);
            return Ok(refused(Refused::TooLarge { len }));
        }
    };
    let tail_start = end - TAIL_LEN;
    let tail = match end <= MAX_HEADER {
        true => prefix.slice(tail_start as usize..end as usize),
        false => match part(remote, key, tail_start..end).await? {
            Some(tail) => tail,
            None => return Ok(None),
        },
    };
    if let Err(e) = head.check_tail(&tail, sealer) {
        return Ok(done(Err(e)));
    }
    let sealed = match head.sealed_len() {
        None => None,
        Some(len) => {
            let mut sealed = Vec::with_capacity(len as usize);
            sealed.extend_from_slice(
                &prefix[head.header_len() as usize..tail_start.min(MAX_HEADER) as usize],
            );
            if tail_start > MAX_HEADER {
                let Some(rest) = part(remote, key, MAX_HEADER..tail_start).await? else {
                    return Ok(None);
                };
                sealed.extend_from_slice(&rest);
            }
            Some(sealed)
        }
    };
    Ok(done(Entry::from_parts(head, sealed, &tail, sealer)))
}

/// Reads `range` of `key`, or `None` when the object does not give exactly that range.
async fn part<R: Remote>(
    remote: &R,
    key: &str,
    range: Range<u64>,
) -> Result<Option<Bytes>, RemoteError> {
    let want = range.end - range.start;
    match remote.get_range(key, range).await {
        Ok(Some(bytes)) if bytes.len() as u64 == want => Ok(Some(bytes)),
        Ok(_) | Err(RemoteError::InvalidRange { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use model::{NodeId, ObjectId};
    use remote::MemoryRemote;

    use super::*;
    use crate::entry::{header_with_replayed_len, header_with_sealed_len, test_sealer};
    use crate::{Action, Frontiers, Journal, JournalError, LOG_PREFIX, Link, Seen, entry_key};

    /// A remote that logs the bytes of each answer for an entry key. It serves objects of any
    /// length from their start, and can give another version of an object at each read.
    #[derive(Default)]
    struct Served {
        inner: MemoryRemote,
        /// The start of an object and its length: zeros after the start.
        huge: Mutex<BTreeMap<String, (Vec<u8>, u64)>>,
        swaps: Mutex<BTreeMap<String, Swap>>,
        reads: Mutex<Vec<(String, u64)>>,
        /// Each ranged answer has one byte less than asked, as a store that cuts a body.
        short: std::sync::atomic::AtomicBool,
    }

    /// The versions of an object, the version that each read gets, and the reads so far.
    struct Swap {
        versions: Vec<Bytes>,
        order: Vec<usize>,
        done: usize,
    }

    impl Served {
        fn log(&self, key: &str, len: u64) {
            if key.starts_with(LOG_PREFIX) {
                let mut reads = self.reads.lock().unwrap();
                reads.push((key.to_string(), len));
            }
        }

        fn reads_of(&self, key: &str) -> Vec<u64> {
            let reads = self.reads.lock().unwrap();
            reads
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, len)| *len)
                .collect()
        }

        async fn object(&self, key: &str) -> Result<Option<Bytes>, RemoteError> {
            if let Some(swap) = self.swaps.lock().unwrap().get_mut(key) {
                let version = swap.order[swap.done % swap.order.len()];
                swap.done += 1;
                return Ok(Some(swap.versions[version].clone()));
            }
            self.inner.get(key, u64::MAX).await
        }
    }

    #[async_trait::async_trait]
    impl Remote for Served {
        async fn put(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
            self.inner.put(key, data).await
        }

        async fn create(&self, key: &str, data: Bytes) -> Result<(), RemoteError> {
            self.inner.create(key, data).await
        }

        async fn get(&self, key: &str, max: u64) -> Result<Option<Bytes>, RemoteError> {
            let huge = self.huge.lock().unwrap().get(key).cloned();
            let len = match huge {
                Some((start, len)) if len <= max => {
                    let mut data = vec![0; len as usize];
                    data[..start.len()].copy_from_slice(&start);
                    self.log(key, len);
                    return Ok(Some(Bytes::from(data)));
                }
                Some((_, len)) => len,
                None => match self.object(key).await? {
                    Some(data) if data.len() as u64 <= max => {
                        self.log(key, data.len() as u64);
                        return Ok(Some(data));
                    }
                    Some(data) => data.len() as u64,
                    None => return Ok(None),
                },
            };
            self.log(key, 0);
            Err(RemoteError::TooLarge {
                key: key.to_string(),
                len,
                max,
            })
        }

        async fn get_range(
            &self,
            key: &str,
            range: Range<u64>,
        ) -> Result<Option<Bytes>, RemoteError> {
            let huge = self.huge.lock().unwrap().get(key).cloned();
            let data = match huge {
                Some((start, len)) if range.end <= len => {
                    let mut bytes = vec![0; (range.end - range.start) as usize];
                    let from = (range.start as usize).min(start.len());
                    let to = (range.end as usize).min(start.len());
                    bytes[..to - from].copy_from_slice(&start[from..to]);
                    Bytes::from(bytes)
                }
                Some((_, len)) => return Err(invalid(key, &range, len)),
                None => match self.object(key).await? {
                    Some(data) if range.end <= data.len() as u64 => {
                        data.slice(range.start as usize..range.end as usize)
                    }
                    Some(data) => return Err(invalid(key, &range, data.len() as u64)),
                    None => return Ok(None),
                },
            };
            let data = match self.short.load(std::sync::atomic::Ordering::SeqCst) {
                true => data.slice(..data.len().saturating_sub(1)),
                false => data,
            };
            self.log(key, data.len() as u64);
            Ok(Some(data))
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, RemoteError> {
            self.inner.list(prefix).await
        }
    }

    fn invalid(key: &str, range: &Range<u64>, len: u64) -> RemoteError {
        RemoteError::InvalidRange {
            key: key.to_string(),
            start: range.start,
            end: range.end,
            len,
        }
    }

    fn writer() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn node() -> NodeId {
        NodeId::from_bytes(writer().verifying_key().to_bytes())
    }

    fn put(key: String) -> Action {
        Action::Put {
            bucket: "b".into(),
            key,
            manifest_id: ObjectId::from_bytes([1; 32]),
            inline_manifest: None,
            hlc: 1,
        }
    }

    /// The first entry of the writer chain, with actions of about `size` bytes.
    fn first(size: usize, hlc: u64, sealer: &Sealer) -> Entry {
        let actions = (0..size.div_ceil(1000))
            .map(|i| put(format!("{i:04}{}", "k".repeat(996))))
            .collect();
        Entry::sign(&writer(), 0, [0; 32], hlc, Seen::new(), actions, sealer)
    }

    fn reader(remote: &Arc<Served>) -> Journal<Served> {
        Journal::new(
            remote.clone(),
            SigningKey::from_bytes(&[9; 32]),
            test_sealer(),
            Frontiers::new(),
        )
    }

    async fn marker(remote: &Served) {
        remote
            .inner
            .put(&crate::node_key(node()), Bytes::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_small_entry_costs_one_request() {
        let remote = Arc::new(Served::default());
        let entry = first(1000, 2, &test_sealer());
        let wire = entry.to_wire();
        assert!(wire.len() as u64 <= MAX_HEADER);
        let key = entry_key(node(), 0);
        remote
            .inner
            .put(&key, Bytes::from(wire.clone()))
            .await
            .unwrap();

        let read = reader(&remote).sync_node(node()).await.unwrap();

        assert_eq!(read, vec![entry]);
        assert_eq!(remote.reads_of(&key), vec![wire.len() as u64]);
    }

    #[tokio::test]
    async fn test_large_entry_reads_its_actions_once() {
        let remote = Arc::new(Served::default());
        let entry = first(200_000, 2, &test_sealer());
        let wire = entry.to_wire();
        let key = entry_key(node(), 0);
        remote
            .inner
            .put(&key, Bytes::from(wire.clone()))
            .await
            .unwrap();

        let read = reader(&remote).sync_node(node()).await.unwrap();

        assert_eq!(read, vec![entry]);
        let reads = remote.reads_of(&key);
        let rest = wire.len() as u64 - MAX_HEADER - TAIL_LEN;
        assert_eq!(reads, vec![0, MAX_HEADER, TAIL_LEN, rest]);
        assert_eq!(reads.iter().sum::<u64>(), wire.len() as u64);
    }

    /// A writer with no repository key makes each audit read its first entry: one header and
    /// one tail, whatever length the entry claims.
    #[tokio::test]
    async fn test_fake_first_entry_of_one_gib_reads_one_header_and_one_tail() {
        let remote = Arc::new(Served::default());
        marker(&remote).await;
        let other = seal::RepoKey::from_hex(&"05".repeat(32)).unwrap().keys();
        let fake = first(10, 2, other.sealer());
        let header = header_with_sealed_len(&fake, MAX_ENTRY);
        let sealed = MAX_ENTRY - header.len() as u64 - TAIL_LEN;
        let header = header_with_sealed_len(&fake, sealed);
        let key = entry_key(node(), 0);
        remote
            .huge
            .lock()
            .unwrap()
            .insert(key.clone(), (header, MAX_ENTRY));
        let mut reader = reader(&remote);

        reader.sync_all().await.unwrap();

        assert_eq!(
            reader.broken().get(&node()),
            Some(&ChainError::BadMac { seq: 0 })
        );
        let read: u64 = remote.reads_of(&key).iter().sum();
        assert!(read <= MAX_HEADER + TAIL_LEN, "{read} bytes read");
    }

    /// A header that claims more bytes than the object has reads again, a bounded number of times.
    #[tokio::test]
    async fn test_fake_header_longer_than_its_object_reads_a_bounded_amount() {
        let remote = Arc::new(Served::default());
        marker(&remote).await;
        let fake = first(10, 2, &test_sealer());
        let key = entry_key(node(), 0);
        let header = header_with_sealed_len(&fake, MAX_ENTRY / 2);
        let len = 2 * MAX_HEADER;
        remote
            .huge
            .lock()
            .unwrap()
            .insert(key.clone(), (header, len));
        let mut reader = reader(&remote);

        reader.sync_all().await.unwrap();

        assert_eq!(
            reader.broken().get(&node()),
            Some(&ChainError::Malformed { seq: 0 })
        );
        let read: u64 = remote.reads_of(&key).iter().sum();
        assert!(
            read <= ATTEMPTS as u64 * (MAX_HEADER + TAIL_LEN),
            "{read} bytes read"
        );
    }

    /// Two normal syncs of a chain whose first object is `start` then zeros up to `len`: the
    /// error of the chain, the bytes that the first sync read, and the bytes of the second.
    async fn fake_first(start: Vec<u8>, len: u64) -> (Option<ChainError>, u64, u64) {
        let remote = Arc::new(Served::default());
        marker(&remote).await;
        let key = entry_key(node(), 0);
        remote
            .huge
            .lock()
            .unwrap()
            .insert(key.clone(), (start, len));
        let mut reader = reader(&remote);

        reader.sync_all().await.unwrap();
        let first: u64 = remote.reads_of(&key).iter().sum();
        reader.sync_all().await.unwrap();
        let second = remote.reads_of(&key).iter().sum::<u64>() - first;

        (reader.broken().get(&node()).cloned(), first, second)
    }

    /// A real header and tail with a larger length and junk between them: the signed length
    /// refuses it before the tail, and normal syncs do not read it again.
    #[tokio::test]
    async fn test_replayed_header_with_another_length_reads_one_header() {
        let real = first(100_000, 2, &test_sealer());
        let mut start = header_with_replayed_len(&real, MAX_ENTRY / 2);
        start.resize(MAX_HEADER as usize, 0);

        let (broken, first, second) = fake_first(start, MAX_ENTRY / 2 + 1024).await;

        assert_eq!(broken, Some(ChainError::ActionsMismatch { seq: 0 }));
        assert!(first <= MAX_HEADER + TAIL_LEN, "{first} bytes read");
        assert_eq!(second, 0, "a normal sync read the fake chain again");
    }

    /// A whole real entry of another node under the first key of this node: the node in the
    /// header refuses it before the tail, and normal syncs do not read it again.
    #[tokio::test]
    async fn test_real_entry_of_another_node_reads_one_header() {
        let other = SigningKey::from_bytes(&[5; 32]);
        let actions = (0..100)
            .map(|i| put(format!("{i:04}{}", "k".repeat(996))))
            .collect();
        let real = Entry::sign(&other, 0, [0; 32], 2, Seen::new(), actions, &test_sealer());
        let wire = real.to_wire();
        assert!(wire.len() as u64 > MAX_HEADER);
        let len = wire.len() as u64;

        let (broken, first, second) = fake_first(wire, len).await;

        assert!(
            matches!(broken, Some(ChainError::WrongNode { seq: 0, .. })),
            "{broken:?}"
        );
        assert!(first <= MAX_HEADER + TAIL_LEN, "{first} bytes read");
        assert_eq!(second, 0, "a normal sync read the fake chain again");
    }

    #[tokio::test]
    async fn test_entry_over_the_limit_reads_no_byte() {
        let remote = Arc::new(Served::default());
        marker(&remote).await;
        let fake = first(10, 2, &test_sealer());
        let key = entry_key(node(), 0);
        let header = header_with_sealed_len(&fake, MAX_ENTRY);
        remote
            .huge
            .lock()
            .unwrap()
            .insert(key.clone(), (header, 2 * MAX_ENTRY));
        let mut reader = reader(&remote);

        reader.sync_all().await.unwrap();

        assert_eq!(
            reader.broken().get(&node()),
            Some(&ChainError::TooLarge {
                seq: 0,
                len: 2 * MAX_ENTRY
            })
        );
        assert_eq!(remote.reads_of(&key).iter().sum::<u64>(), 0);
    }

    /// A header that claims more than the limit stops before the tail.
    #[tokio::test]
    async fn test_header_that_claims_over_the_limit_reads_no_tail() {
        let remote = Arc::new(Served::default());
        marker(&remote).await;
        let fake = first(10, 2, &test_sealer());
        let key = entry_key(node(), 0);
        let header = header_with_sealed_len(&fake, MAX_ENTRY);
        remote
            .huge
            .lock()
            .unwrap()
            .insert(key.clone(), (header, MAX_ENTRY));
        let mut reader = reader(&remote);

        reader.sync_all().await.unwrap();

        assert!(matches!(
            reader.broken().get(&node()),
            Some(&ChainError::TooLarge { seq: 0, .. })
        ));
        assert_eq!(remote.reads_of(&key), vec![0, MAX_HEADER]);
    }

    /// A store that gives parts of two objects to one read: the entry never applies, the chain
    /// is broken and named, and the reads stop after a bound.
    #[tokio::test]
    async fn test_object_that_changes_between_reads_is_never_taken() {
        let a = first(200_000, 2, &test_sealer()).to_wire();
        let b = first(200_000, 3, &test_sealer()).to_wire();
        let longer = first(300_000, 3, &test_sealer()).to_wire();
        assert_eq!(a.len(), b.len());
        let cases = [
            (b.clone(), vec![0, 1]),
            (b.clone(), vec![0, 0, 1, 1]),
            (b.clone(), vec![0, 0, 0, 1]),
            (longer.clone(), vec![0, 1]),
            (longer, vec![1, 0]),
        ];
        for (other, order) in cases {
            let remote = Arc::new(Served::default());
            marker(&remote).await;
            let key = entry_key(node(), 0);
            let versions = vec![Bytes::from(a.clone()), Bytes::from(other)];
            remote.swaps.lock().unwrap().insert(
                key.clone(),
                Swap {
                    versions,
                    order: order.clone(),
                    done: 0,
                },
            );
            let mut reader = reader(&remote);

            let read = reader.sync_all().await.unwrap();

            assert!(read.is_empty(), "{order:?}: an entry applied");
            assert!(reader.broken().contains_key(&node()), "{order:?}");
            let reads = remote.reads_of(&key).len();
            assert!(reads <= 4 * ATTEMPTS as usize, "{order:?}: {reads} reads");
        }
    }

    /// A prune replaces a large entry with its redacted form between two reads: the reader
    /// reads again and takes the redacted entry.
    #[tokio::test]
    async fn test_entry_redacted_between_two_reads_reads_again() {
        let remote = Arc::new(Served::default());
        let entry = first(200_000, 2, &test_sealer());
        let redacted = Bytes::from(entry.redacted().to_wire());
        let key = entry_key(node(), 0);
        let order = [vec![0; 3], vec![1; 20]].concat();
        let versions = vec![Bytes::from(entry.to_wire()), redacted];
        remote.swaps.lock().unwrap().insert(
            key.clone(),
            Swap {
                versions,
                order,
                done: 0,
            },
        );

        let read = reader(&remote).sync_node(node()).await.unwrap();

        assert_eq!(read.len(), 1);
        assert_eq!(read[0].hash(), entry.hash());
        assert_eq!(read[0].actions, None);
    }

    /// A store that gives fewer bytes than a range asks: the read stops after a bound, and the
    /// chain is broken and named.
    #[tokio::test]
    async fn test_short_ranged_answers_are_malformed() {
        let remote = Arc::new(Served::default());
        marker(&remote).await;
        let wire = first(200_000, 2, &test_sealer()).to_wire();
        let key = entry_key(node(), 0);
        remote.inner.put(&key, Bytes::from(wire)).await.unwrap();
        remote
            .short
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut reader = reader(&remote);

        let read = reader.sync_all().await.unwrap();

        assert!(read.is_empty());
        assert_eq!(
            reader.broken().get(&node()),
            Some(&ChainError::Malformed { seq: 0 })
        );
        assert_eq!(remote.reads_of(&key).len(), 2 * ATTEMPTS as usize);
    }

    fn seen_of(nodes: u32) -> Seen {
        (0..nodes)
            .map(|i| {
                let mut id = [0; 32];
                id[..4].copy_from_slice(&i.to_le_bytes());
                let link = Link {
                    seq: u64::MAX,
                    hash: [7; 32],
                };
                (NodeId::from_bytes(id), link)
            })
            .collect()
    }

    /// A reader decodes a header from one read of MAX_HEADER bytes: a writer never signs a
    /// larger one.
    #[tokio::test]
    async fn test_writer_refuses_a_header_over_the_limit() {
        let remote = Arc::new(Served::default());
        let journal = Journal::new(remote.clone(), writer(), test_sealer(), Frontiers::new());
        let action = || vec![put("k".into())];

        let fits = journal.prepare(action(), seen_of(850)).unwrap();
        let refused = journal.prepare(action(), seen_of(900));

        assert!(fits.header_len() <= MAX_HEADER);
        assert!(matches!(
            refused,
            Err(JournalError::HeaderTooLarge { seq: 0, len, max: MAX_HEADER }) if len > MAX_HEADER
        ));
    }
}
