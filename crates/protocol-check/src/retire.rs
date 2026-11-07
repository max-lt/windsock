//! Model check of chain retirement: a GC runner retires a quiet chain, and writers leave it out
//! of `seen`.
//!
//! Node 0 is the GC runner. It writes puts and Retire entries, and a Retire entry lists only the
//! chain that it retires: a repository whose header guard trips can still write it. Nodes 1
//! and 2 write puts to one key; either can go quiet, be retired, and write again. Each node
//! applies entries to its own index, and two more readers apply them in any order, one of them
//! from a copy of the other (a snapshot).
//!
//! An entry keeps two seen maps: `full`, every chain that its writer had applied, and `listed`,
//! the links that it writes. A writer leaves out a chain that it saw retired at its frontier. A
//! reader decides that one put knew another from `listed` and the Retire entries that the GC
//! link of the put reaches. The properties compare that with `full`.
//!
//! Not in the model: a second GC runner (a handover, a Retire in a retired chain) and the skip
//! of a retired chain in the stable HLC. Unit tests of the index cover them.

use stateright::{Model, Property};

pub const NODES: usize = 3;
const GC: usize = 0;
/// Node indexes and the two readers that apply in any order.
const READERS: usize = NODES + 2;
const OBSERVER: usize = NODES;
const SNAPSHOT: usize = NODES + 1;

/// A put: its node and its seq.
type Put = (usize, usize);
/// The head of the key and the puts that it did not know.
type View = (Put, Vec<Put>);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Put,
    /// The entries of `node` below `upto` are retired.
    Retire {
        node: u8,
        upto: u8,
    },
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub kind: Kind,
    pub hlc: u8,
    /// Entries of each chain that the writer had applied.
    pub full: [u8; NODES],
    /// The seen links that the entry writes.
    pub listed: [Option<u8>; NODES],
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct State {
    pub chains: [Vec<Entry>; NODES],
    /// Entries of each chain that each reader applied, in chain order.
    pub applied: [[u8; NODES]; READERS],
}

/// Rules of the protocol. A check with one rule off shows that the rule is needed.
#[derive(Clone, Copy, Debug)]
pub struct Rules {
    /// A put knows a retired entry only through a GC link at or after the Retire entry.
    pub knew_needs_gc_link: bool,
    /// A writer leaves a chain out only while its frontier is the retired point.
    pub drop_at_frontier_only: bool,
    /// The GC retires only entries that it applied.
    pub retire_applied_only: bool,
    /// A put knows the retired entries at all: without this rule a writer only drops links.
    pub knew_retired: bool,
    /// A put of the GC runner knows what the Retire entries before it in its chain retired.
    pub knew_own_retires: bool,
}

pub const SAFE: Rules = Rules {
    knew_needs_gc_link: true,
    drop_at_frontier_only: true,
    retire_applied_only: true,
    knew_retired: true,
    knew_own_retires: true,
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Action {
    Put {
        node: usize,
    },
    Retire {
        node: usize,
    },
    Apply {
        reader: usize,
        node: usize,
    },
    /// The snapshot reader starts from a copy of the observer.
    Bootstrap,
}

#[derive(Clone, Debug)]
pub struct RetireModel {
    pub max_entries: usize,
    pub max_retires: usize,
    pub rules: Rules,
}

/// Name of the property that a missing rule breaks.
pub const SAME_KNEW: &str = "knew with retired chains equals knew with the full seen";
pub const CAUSAL: &str = "a reader applies a put after all that its writer applied";

/// The writers 1 and 2 swap places: no rule names a writer.
fn swap_writers(s: &State) -> State {
    let node = |n: usize| match n {
        1 => 2,
        2 => 1,
        n => n,
    };
    let entry = |e: &Entry| Entry {
        kind: match e.kind {
            Kind::Retire { node: n, upto } => Kind::Retire {
                node: node(usize::from(n)) as u8,
                upto,
            },
            Kind::Put => Kind::Put,
        },
        hlc: e.hlc,
        full: std::array::from_fn(|m| e.full[node(m)]),
        listed: std::array::from_fn(|m| e.listed[node(m)]),
    };
    State {
        chains: std::array::from_fn(|n| s.chains[node(n)].iter().map(entry).collect()),
        applied: std::array::from_fn(|r| {
            let row = s.applied[if r < NODES { node(r) } else { r }];
            std::array::from_fn(|m| row[node(m)])
        }),
    }
}

/// One state for a state and its swap of the writers.
pub fn representative(s: &State) -> State {
    let swapped = swap_writers(s);
    match swapped < *s {
        true => swapped,
        false => s.clone(),
    }
}

impl Entry {
    /// The entries of chain `m` that a reader applies first: a Retire waits for its link only.
    fn needs(&self, m: usize) -> u8 {
        match self.kind {
            Kind::Put => self.full[m],
            Kind::Retire { .. } => self.listed[m].unwrap_or(0),
        }
    }
}

impl State {
    fn entries(&self) -> usize {
        self.chains.iter().map(Vec::len).sum()
    }

    fn retires(&self) -> usize {
        self.chains[GC].len()
    }

    /// The highest retired point of `node` among the GC entries below `gc`.
    fn retired_upto(&self, node: usize, gc: u8) -> u8 {
        self.chains[GC][..usize::from(gc)]
            .iter()
            .filter_map(|e| match e.kind {
                Kind::Retire { node: n, upto } if usize::from(n) == node => Some(upto),
                _ => None,
            })
            .max()
            .unwrap_or(0)
    }

    /// The highest HLC that `reader` applied.
    fn top_hlc(&self, reader: usize) -> u8 {
        (0..NODES)
            .flat_map(|n| self.chains[n][..usize::from(self.applied[reader][n])].iter())
            .map(|e| e.hlc)
            .max()
            .unwrap_or(0)
    }

    fn ready(&self, reader: usize, node: usize) -> Option<&Entry> {
        let next = self.chains[node].get(usize::from(self.applied[reader][node]))?;
        (0..NODES)
            .all(|m| next.listed[m].is_none_or(|c| self.applied[reader][m] >= c))
            .then_some(next)
    }

    /// The applied puts of `reader`: (node, seq).
    fn puts(&self, reader: usize) -> Vec<Put> {
        (0..NODES)
            .flat_map(|n| (0..usize::from(self.applied[reader][n])).map(move |s| (n, s)))
            .filter(|&(n, s)| self.chains[n][s].kind == Kind::Put)
            .collect()
    }
}

impl RetireModel {
    /// The seen of a new entry of `node`: every chain that it applied, less the chains that it
    /// saw retired at its frontier.
    fn seen(&self, s: &State, node: usize) -> ([u8; NODES], [Option<u8>; NODES]) {
        let full = s.applied[node];
        let mut listed = [None; NODES];
        for m in (0..NODES).filter(|&m| m != node && full[m] > 0) {
            let upto = s.retired_upto(m, full[GC]);
            let dropped =
                m != GC && upto > 0 && (upto == full[m] || !self.rules.drop_at_frontier_only);
            if !dropped {
                listed[m] = Some(full[m]);
            }
        }
        (full, listed)
    }

    fn append(&self, s: &mut State, node: usize, kind: Kind, listed: [Option<u8>; NODES]) {
        let entry = Entry {
            kind,
            hlc: s.top_hlc(node) + 1,
            full: s.applied[node],
            listed,
        };
        s.chains[node].push(entry);
        s.applied[node][node] += 1;
    }

    /// Did the writer of put `a` know put `b`, as a reader decides it from `listed`?
    fn knew(&self, s: &State, a: Put, b: Put) -> bool {
        if a.0 == b.0 {
            return b.1 < a.1;
        }
        let entry = &s.chains[a.0][a.1];
        if entry.listed[b.0].is_some_and(|c| usize::from(c) > b.1) {
            return true;
        }
        if !self.rules.knew_retired {
            return false;
        }
        // The GC runner lists no link to its own chain: its earlier entries are its link.
        let gc = match self.rules.knew_needs_gc_link {
            true if a.0 == GC && self.rules.knew_own_retires => a.1 as u8,
            true => entry.listed[GC].unwrap_or(0),
            false => s.chains[GC].len() as u8,
        };
        b.1 < usize::from(s.retired_upto(b.0, gc))
    }

    fn knew_full(s: &State, a: Put, b: Put) -> bool {
        a.0 == b.0 && b.1 < a.1 || a.0 != b.0 && usize::from(s.chains[a.0][a.1].full[b.0]) > b.1
    }

    /// The head of the key in `reader`, and the puts that it did not know: the conflicts.
    fn view(&self, s: &State, reader: usize) -> Option<View> {
        let puts = s.puts(reader);
        let head = *puts.iter().max_by_key(|&&(n, i)| (s.chains[n][i].hlc, n))?;
        let conflicts = puts
            .into_iter()
            .filter(|&p| p != head && !self.knew(s, head, p))
            .collect();
        Some((head, conflicts))
    }
}

impl Model for RetireModel {
    type State = State;
    type Action = Action;

    fn init_states(&self) -> Vec<State> {
        vec![State {
            chains: Default::default(),
            applied: [[0; NODES]; READERS],
        }]
    }

    fn actions(&self, s: &State, actions: &mut Vec<Action>) {
        if s.entries() < self.max_entries {
            actions.push(Action::Put { node: GC });
            for node in 1..NODES {
                actions.push(Action::Put { node });
                if s.retires() < self.max_retires {
                    actions.push(Action::Retire { node });
                }
            }
        }
        for reader in 0..READERS {
            for node in 0..NODES {
                actions.push(Action::Apply { reader, node });
            }
        }
        actions.push(Action::Bootstrap);
    }

    fn next_state(&self, last: &State, action: Action) -> Option<State> {
        let mut s = last.clone();
        match action {
            Action::Put { node } => {
                let (_, listed) = self.seen(&s, node);
                self.append(&mut s, node, Kind::Put, listed);
            }
            Action::Retire { node } => {
                let applied = s.applied[GC][node];
                if applied == 0 || s.retired_upto(node, s.chains[GC].len() as u8) >= applied {
                    return None;
                }
                let upto = match self.rules.retire_applied_only {
                    true => applied,
                    false => applied + 1,
                };
                let mut listed = [None; NODES];
                listed[node] = Some(applied);
                let kind = Kind::Retire {
                    node: node as u8,
                    upto,
                };
                self.append(&mut s, GC, kind, listed);
            }
            Action::Apply { reader, node } => {
                // A node applies its own entries as it writes them.
                if reader == node || s.ready(reader, node).is_none() {
                    return None;
                }
                s.applied[reader][node] += 1;
            }
            Action::Bootstrap => {
                if s.applied[SNAPSHOT] != [0; NODES] || s.applied[OBSERVER] == [0; NODES] {
                    return None;
                }
                s.applied[SNAPSHOT] = s.applied[OBSERVER];
            }
        }
        Some(s)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always(SAME_KNEW, |m: &Self, s: &State| {
                (0..READERS).all(|r| {
                    let puts = s.puts(r);
                    puts.iter().all(|&a| {
                        puts.iter()
                            .all(|&b| a == b || m.knew(s, a, b) == Self::knew_full(s, a, b))
                    })
                })
            }),
            Property::always(CAUSAL, |_: &Self, s: &State| {
                (0..READERS).all(|r| {
                    (0..NODES).all(|n| {
                        s.chains[n][..usize::from(s.applied[r][n])]
                            .iter()
                            .all(|e| (0..NODES).all(|m| m == n || s.applied[r][m] >= e.needs(m)))
                    })
                })
            }),
            Property::always("readers with the same entries show the same key", {
                |m: &Self, s: &State| {
                    s.applied[OBSERVER] != s.applied[SNAPSHOT]
                        || m.view(s, OBSERVER) == m.view(s, SNAPSHOT)
                }
            }),
            Property::eventually("every reader applies every entry", |_: &Self, s: &State| {
                let all: [u8; NODES] = std::array::from_fn(|n| s.chains[n].len() as u8);
                s.applied.iter().all(|a| *a == all)
            }),
            Property::sometimes(
                "a writer leaves a retired chain out",
                |_: &Self, s: &State| {
                    (1..NODES).any(|n| {
                        s.chains[n].iter().any(|e| {
                            (1..NODES).any(|m| m != n && e.full[m] > 0 && e.listed[m].is_none())
                        })
                    })
                },
            ),
            Property::sometimes("a retired chain writes again", |_: &Self, s: &State| {
                s.chains[GC].iter().any(|e| match e.kind {
                    Kind::Retire { node, upto } => {
                        s.chains[usize::from(node)].len() > usize::from(upto)
                    }
                    Kind::Put => false,
                })
            }),
            Property::sometimes("two retires of one chain", |_: &Self, s: &State| {
                (1..NODES).any(|n| {
                    s.chains[GC]
                        .iter()
                        .filter(|e| matches!(e.kind, Kind::Retire { node, .. } if usize::from(node) == n))
                        .count()
                        > 1
                })
            }),
            Property::sometimes("a reader starts from a snapshot", |_: &Self, s: &State| {
                s.applied[SNAPSHOT] != [0; NODES]
            }),
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use stateright::{Checker, Expectation, HasDiscoveries};

    use super::*;

    fn model(rules: Rules) -> RetireModel {
        RetireModel {
            max_entries: 5,
            max_retires: 2,
            rules,
        }
    }

    fn threads() -> usize {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    }

    /// Breadth first: the shortest break is a few steps deep. Depth first with the writer
    /// symmetry: the reduction must keep the break.
    fn assert_breaks(rules: Rules, property: &'static str) {
        let found = || HasDiscoveries::AnyOf(BTreeSet::from([property]));
        model(rules)
            .checker()
            .threads(threads())
            .finish_when(found())
            .spawn_bfs()
            .join()
            .assert_any_discovery(property);
        model(rules)
            .checker()
            .threads(threads())
            .symmetry_fn(representative)
            .finish_when(found())
            .spawn_dfs()
            .join()
            .assert_any_discovery(property);
    }

    /// The swap of the writers is a symmetry: at 3 entries the reduced space has about half the
    /// states of the full one, and the full one has every state of the reduced one.
    #[test]
    fn test_writer_symmetry_halves_the_states() {
        let small = RetireModel {
            max_entries: 3,
            ..model(SAFE)
        };
        let full = small
            .clone()
            .checker()
            .spawn_dfs()
            .join()
            .unique_state_count();
        let reduced = small
            .checker()
            .symmetry_fn(representative)
            .spawn_dfs()
            .join()
            .unique_state_count();

        eprintln!("states at 3 entries: {full} full, {reduced} with the writer symmetry");
        assert!(
            reduced * 2 >= full && reduced * 10 <= full * 6,
            "{full} {reduced}"
        );
    }

    #[test]
    fn test_retire_rules_hold_at_3_entries() {
        let small = RetireModel {
            max_entries: 3,
            ..model(SAFE)
        };
        let checked = small.clone().checker().spawn_bfs().join();

        // The sometimes properties need more entries than 3.
        let always = small
            .properties()
            .into_iter()
            .filter(|p| p.expectation == Expectation::Always);
        for property in always {
            checked.assert_no_discovery(property.name);
        }
    }

    #[test]
    #[ignore = "model check: run on a build machine"]
    fn test_retire_rules_keep_knew_causal_and_order_free() {
        model(SAFE)
            .checker()
            .threads(threads())
            .symmetry_fn(representative)
            .finish_when(HasDiscoveries::AnyFailures)
            .spawn_dfs()
            .join()
            .assert_properties();
    }

    #[test]
    fn test_knew_through_any_retire_breaks_knew() {
        assert_breaks(
            Rules {
                knew_needs_gc_link: false,
                ..SAFE
            },
            SAME_KNEW,
        );
    }

    #[test]
    fn test_drop_past_the_retired_point_breaks_knew() {
        assert_breaks(
            Rules {
                drop_at_frontier_only: false,
                ..SAFE
            },
            SAME_KNEW,
        );
    }

    #[test]
    fn test_retire_of_an_entry_that_the_gc_did_not_apply_breaks_causal_order() {
        assert_breaks(
            Rules {
                retire_applied_only: false,
                ..SAFE
            },
            CAUSAL,
        );
    }

    #[test]
    fn test_gc_put_with_no_knew_of_its_own_retires_breaks_knew() {
        assert_breaks(
            Rules {
                knew_own_retires: false,
                ..SAFE
            },
            SAME_KNEW,
        );
    }

    #[test]
    fn test_drop_with_no_retired_knew_breaks_knew() {
        assert_breaks(
            Rules {
                knew_retired: false,
                ..SAFE
            },
            SAME_KNEW,
        );
    }
}
