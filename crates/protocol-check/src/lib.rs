//! Model check of the journal write and sync protocol, with Stateright.
//!
//! Each node identity writes one chain of entries. Entry seq `s` of node `n`
//! lives at the remote key `log/<n>/<s>`. A writer creates that key with a
//! create-only write. A PUT writes its data, then its entry, and is
//! acknowledged when the entry create succeeds.
//!
//! A reader reads seq `f+1`, `f+2`, ... from its frontier `f` up to the first
//! missing seq. Heads are hints for the reader and are not modeled: the
//! protocol stays correct when a head is lost or stale.
//!
//! An entry id stands for its content hash: two writes never share an id.
//! Sets of entries are bitmasks over entry ids, to keep states small.

use stateright::{Model, Property};

/// A journal entry. `node` is an index into the node identities.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Entry {
    pub node: u8,
    pub seq: i8,
    /// Id of the previous entry, 0 for the first entry of a chain.
    pub prev: u8,
    pub hlc: u16,
    pub key: u8,
    pub obj: u8,
}

/// A set of entry ids. Bit `i` is entry id `i + 1`.
type Ids = u32;

fn bit(id: u8) -> Ids {
    1 << (id - 1)
}

/// Last integrated entry of one chain. Seq -1 and id 0: nothing integrated.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Position {
    pub seq: i8,
    pub id: u8,
    pub hlc: u16,
}

const GENESIS: Position = Position {
    seq: -1,
    id: 0,
    hlc: 0,
};

/// Step of the PUT in progress in a process.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Step {
    Idle,
    Data { key: u8, obj: u8 },
    Entry { key: u8, obj: u8 },
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Process {
    /// Position of each node chain that this process has integrated.
    pub frontier: Vec<Position>,
    pub known: Ids,
    /// HLC. It survives a crash, as a wall clock does.
    pub clock: u16,
    /// An entry create failed: the process must read its own chain again.
    pub stale: bool,
    /// The process found a broken chain, and stopped.
    pub detected: bool,
    pub step: Step,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct State {
    /// Every entry ever written. Entry id `i` is `entries[i - 1]`.
    pub entries: Vec<Entry>,
    /// Entries in the remote.
    pub log: Ids,
    /// Object contents in the remote, as a bitmask over objects.
    pub data: u8,
    pub procs: Vec<Process>,
    pub crashes: u8,
    /// History: entries of acknowledged PUTs.
    pub acked: Ids,
    /// History: a sync succeeded but skipped an acknowledged entry.
    pub silent_miss: bool,
}

impl State {
    /// Entries of `set`, with their ids.
    fn iter(&self, set: Ids) -> impl Iterator<Item = (u8, &Entry)> {
        (1..=self.entries.len() as u8)
            .filter(move |&id| set & bit(id) != 0)
            .map(|id| (id, &self.entries[usize::from(id) - 1]))
    }

    fn at(&self, node: u8, seq: i8) -> impl Iterator<Item = (u8, &Entry)> {
        self.iter(self.log)
            .filter(move |(_, e)| e.node == node && e.seq == seq)
    }

    /// Reads the chain of `node` after position `f`: every seq up to the first missing one.
    /// Returns `None` when a seq has two entries, or when a link or the HLC order is broken.
    fn read_chain(&self, node: u8, f: Position) -> Option<(Ids, Position)> {
        let mut read = 0;
        let mut last = f;

        loop {
            let mut candidates = self.at(node, last.seq + 1);

            let Some((id, entry)) = candidates.next() else {
                return Some((read, last));
            };

            if candidates.next().is_some() || entry.prev != last.id || entry.hlc <= last.hlc {
                return None;
            }

            read |= bit(id);
            last = Position {
                seq: entry.seq,
                id,
                hlc: entry.hlc,
            };
        }
    }

    /// Last writer wins, ordered by (hlc, node, entry hash).
    fn index(&self, known: Ids, keys: u8) -> Vec<Option<u8>> {
        (0..keys)
            .map(|key| {
                self.iter(known)
                    .filter(|(_, e)| e.key == key)
                    .max_by_key(|(id, e)| (e.hlc, e.node, *id))
                    .map(|(_, e)| e.obj)
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Action {
    StartPut { proc: usize, key: u8, obj: u8 },
    WriteData { proc: usize },
    WriteEntry { proc: usize },
    AbortPut { proc: usize },
    Sync { proc: usize, node: u8 },
    Crash { proc: usize },
}

/// How an entry write treats an existing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryWrite {
    /// The write fails when the key exists (If-None-Match: *).
    CreateOnly,
    /// The write replaces the existing object.
    Overwrite,
}

/// Bounds and options of one model check run.
#[derive(Clone, Debug)]
pub struct JournalModel {
    /// Node identity of each process. Two processes on one identity: a zombie.
    pub identities: Vec<u8>,
    pub keys: u8,
    pub objs: u8,
    pub max_seq: i8,
    pub max_crashes: u8,
    pub entry_write: EntryWrite,
}

impl JournalModel {
    fn node_count(&self) -> usize {
        usize::from(*self.identities.iter().max().expect("at least one process")) + 1
    }

    fn write_entry(&self, s: &mut State, proc: usize) -> bool {
        let node = self.identities[proc];
        let p = &s.procs[proc];
        let f = p.frontier[usize::from(node)];
        let Step::Entry { key, obj } = p.step else {
            return false;
        };

        if p.stale || p.detected || f.seq >= self.max_seq {
            return false;
        }

        let taken: Ids = s.at(node, f.seq + 1).fold(0, |set, (id, _)| set | bit(id));

        if taken != 0 && self.entry_write == EntryWrite::CreateOnly {
            s.procs[proc].stale = true;
            return true;
        }

        let entry = Entry {
            node,
            seq: f.seq + 1,
            prev: f.id,
            hlc: p.clock + 1,
            key,
            obj,
        };
        s.entries.push(entry);
        let id = s.entries.len() as u8;

        s.log = (s.log & !taken) | bit(id);
        s.acked |= bit(id);

        let p = &mut s.procs[proc];
        p.clock = entry.hlc;
        p.frontier[usize::from(node)] = Position {
            seq: entry.seq,
            id,
            hlc: entry.hlc,
        };
        p.known |= bit(id);
        p.step = Step::Idle;
        true
    }

    fn sync(&self, s: &mut State, proc: usize, node: u8) {
        let f = s.procs[proc].frontier[usize::from(node)];

        let Some((read, top)) = s.read_chain(node, f) else {
            s.procs[proc].detected = true;
            return;
        };

        let p = &mut s.procs[proc];
        p.known |= read;
        p.frontier[usize::from(node)] = top;
        p.clock = p.clock.max(top.hlc);

        if node == self.identities[proc] {
            p.stale = false;
        }

        let known = p.known;
        let missed = s
            .iter(s.acked)
            .any(|(id, e)| e.node == node && e.seq <= top.seq && known & bit(id) == 0);
        s.silent_miss |= missed;
    }
}

impl Model for JournalModel {
    type State = State;
    type Action = Action;

    fn init_states(&self) -> Vec<State> {
        let process = Process {
            frontier: vec![GENESIS; self.node_count()],
            known: 0,
            clock: 0,
            stale: false,
            detected: false,
            step: Step::Idle,
        };

        vec![State {
            entries: Vec::new(),
            log: 0,
            data: 0,
            procs: vec![process; self.identities.len()],
            crashes: 0,
            acked: 0,
            silent_miss: false,
        }]
    }

    fn actions(&self, state: &State, actions: &mut Vec<Action>) {
        for (proc, p) in state.procs.iter().enumerate() {
            match p.step {
                Step::Idle if !p.detected => {
                    for key in 0..self.keys {
                        for obj in 0..self.objs {
                            actions.push(Action::StartPut { proc, key, obj });
                        }
                    }
                }
                Step::Idle => {}
                Step::Data { .. } => {
                    actions.push(Action::WriteData { proc });
                    actions.push(Action::AbortPut { proc });
                }
                Step::Entry { .. } => {
                    actions.push(Action::WriteEntry { proc });
                    actions.push(Action::AbortPut { proc });
                }
            }

            if !p.detected {
                for node in 0..self.node_count() as u8 {
                    actions.push(Action::Sync { proc, node });
                }
            }

            if state.crashes < self.max_crashes {
                actions.push(Action::Crash { proc });
            }
        }
    }

    fn next_state(&self, last: &State, action: Action) -> Option<State> {
        let mut s = last.clone();

        match action {
            Action::StartPut { proc, key, obj } => {
                s.procs[proc].step = Step::Data { key, obj };
            }
            Action::WriteData { proc } => {
                let Step::Data { key, obj } = s.procs[proc].step else {
                    return None;
                };
                s.data |= 1 << obj;
                s.procs[proc].step = Step::Entry { key, obj };
            }
            Action::WriteEntry { proc } => {
                if !self.write_entry(&mut s, proc) {
                    return None;
                }
            }
            Action::AbortPut { proc } => {
                s.procs[proc].step = Step::Idle;
            }
            Action::Sync { proc, node } => self.sync(&mut s, proc, node),
            Action::Crash { proc } => {
                s.crashes += 1;
                let p = &mut s.procs[proc];
                p.frontier = vec![GENESIS; self.node_count()];
                p.known = 0;
                p.stale = false;
                p.detected = false;
                p.step = Step::Idle;
            }
        }

        Some(s)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        let mut properties = vec![
            Property::always(DURABLE, |_: &Self, s: &State| {
                s.acked & !s.log == 0 && s.iter(s.acked).all(|(_, e)| s.data & (1 << e.obj) != 0)
            }),
            Property::always("no sync skips an acked entry", |_: &Self, s: &State| {
                !s.silent_miss
            }),
            Property::always("same frontier gives same index", |m: &Self, s: &State| {
                let healthy: Vec<_> = s.procs.iter().filter(|p| !p.detected).collect();
                healthy.iter().all(|p| {
                    healthy.iter().all(|q| {
                        p.frontier != q.frontier
                            || s.index(p.known, m.keys) == s.index(q.known, m.keys)
                    })
                })
            }),
            Property::always("hlc rises along each chain", |_: &Self, s: &State| {
                s.iter(s.log)
                    .all(|(_, e)| e.prev == 0 || e.hlc > s.entries[usize::from(e.prev) - 1].hlc)
            }),
            Property::always("no process finds a broken chain", |_: &Self, s: &State| {
                s.procs.iter().all(|p| !p.detected)
            }),
            Property::sometimes("a put is acked", |_: &Self, s: &State| s.acked != 0),
            Property::sometimes(
                "an entry create finds its key taken",
                |_: &Self, s: &State| s.procs.iter().any(|p| p.stale),
            ),
        ];

        // A model with one identity has no other node to learn from.
        if self.node_count() > 1 {
            properties.push(Property::sometimes(
                "a process learns another node",
                |m: &Self, s: &State| {
                    s.procs
                        .iter()
                        .enumerate()
                        .any(|(i, p)| s.iter(p.known).any(|(_, e)| e.node != m.identities[i]))
                },
            ));
        }

        properties
    }
}

/// Name of the property that an overwrite of the log breaks.
pub const DURABLE: &str = "acked entries stay in the remote";

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use stateright::{Checker, HasDiscoveries};

    use super::*;

    fn model(identities: &[u8], max_seq: i8, entry_write: EntryWrite) -> JournalModel {
        JournalModel {
            identities: identities.to_vec(),
            keys: 1,
            objs: 2,
            max_seq,
            max_crashes: 1,
            entry_write,
        }
    }

    /// Explores every state, unless `finish` is met first.
    fn check(model: JournalModel, finish: HasDiscoveries) -> impl Checker<JournalModel> {
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        model
            .checker()
            .threads(threads)
            .finish_when(finish)
            .spawn_dfs()
            .join()
    }

    fn check_safe(model: JournalModel) {
        check(model, HasDiscoveries::AnyFailures).assert_properties();
    }

    #[test]
    #[ignore = "model check: run on a build machine"]
    fn test_one_process_per_node_is_safe() {
        check_safe(model(&[0, 1], 2, EntryWrite::CreateOnly));
    }

    #[test]
    #[ignore = "model check: run on a build machine"]
    fn test_zombie_is_safe_with_create_only_writes() {
        check_safe(model(&[0, 1, 0], 1, EntryWrite::CreateOnly));
    }

    #[test]
    fn test_zombie_loses_acked_put_with_overwrite() {
        let first_loss = HasDiscoveries::AnyOf(BTreeSet::from([DURABLE]));
        check(model(&[0, 1, 0], 1, EntryWrite::Overwrite), first_loss)
            .assert_any_discovery(DURABLE);
    }

    /// Two processes on one identity, three entries per chain. The full model
    /// with a second node does not fit in 16 GB, and the second node adds
    /// nothing to this scenario.
    #[test]
    fn test_zombie_alone_is_safe_with_three_entries() {
        check_safe(model(&[0, 0], 2, EntryWrite::CreateOnly));
    }
}
