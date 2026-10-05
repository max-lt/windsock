//! Model check of the pack sweep: a condemn in the journal, a delete after a horizon.
//!
//! Writers put objects. A put either dedups against a pack its index knows, or
//! uploads a fresh pack: a fresh upload always gets a new pack id. The GC
//! appends a condemn for a pack that no current object uses, and deletes the
//! pack later. A writer that applies a condemn forgets the pack, and a later
//! put that names the pack revives it.
//!
//! The journal is one log in creation order: the journal model checks the
//! chains, and a sync reads every entry written before it. Each rule compares
//! two times of one clock, so only clock rates matter, not offsets.

use stateright::{Model, Property};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Kind {
    Put { key: u8, pack: u8 },
    Delete { key: u8 },
    Condemn { pack: u8 },
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Entry {
    pub time: u8,
    pub kind: Kind,
}

/// A put between its plan and its entry. It survives a crash, as the intent file does.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Plan {
    pub key: u8,
    pub pack: u8,
    pub at: u8,
}

/// A journal reader: the first `applied` entries of the log, read at `synced_at`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Reader {
    pub applied: u8,
    pub synced_at: Option<u8>,
}

const FRESH: Reader = Reader {
    applied: 0,
    synced_at: None,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Writer {
    pub reader: Reader,
    pub plan: Option<Plan>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct State {
    pub time: u8,
    pub log: Vec<Entry>,
    /// Packs in the remote, as a bitmask over pack ids.
    pub packs: u8,
    /// Pack ids issued so far. The next fresh upload gets this id.
    pub issued: u8,
    pub writers: Vec<Writer>,
    pub gc: Reader,
    pub crashes: u8,
}

fn bit(pack: u8) -> u8 {
    1 << pack
}

impl State {
    fn view(&self, reader: Reader) -> &[Entry] {
        &self.log[..usize::from(reader.applied)]
    }
}

/// The last put or delete of `key`.
fn head(view: &[Entry], key: u8) -> Option<Kind> {
    view.iter().rev().map(|e| e.kind).find(|kind| match kind {
        Kind::Put { key: k, .. } | Kind::Delete { key: k } => *k == key,
        Kind::Condemn { .. } => false,
    })
}

/// A current object uses `pack`.
fn is_live(view: &[Entry], keys: u8, pack: u8) -> bool {
    (0..keys).any(|key| head(view, key) == Some(Kind::Put { key, pack }))
}

/// The condemn of `pack` that no later put revived.
fn standing_condemn(view: &[Entry], pack: u8) -> Option<Entry> {
    view.iter().rev().copied().find_map(|e| match e.kind {
        Kind::Put { pack: p, .. } if p == pack => Some(None),
        Kind::Condemn { pack: p } if p == pack => Some(Some(e)),
        _ => None,
    })?
}

/// A pack that a writer index holds: a put named it, and no condemn came after.
fn is_known(view: &[Entry], pack: u8) -> bool {
    let named = view
        .iter()
        .any(|e| matches!(e.kind, Kind::Put { pack: p, .. } if p == pack));
    named && standing_condemn(view, pack).is_none()
}

/// Rules of the protocol. A check with one rule off shows that the rule is needed.
#[derive(Clone, Copy, Debug)]
pub struct Rules {
    /// A writer dedups only when its last sync is younger than half the horizon.
    pub fresh_sync: bool,
    /// A writer commits only a plan younger than half the horizon.
    pub fresh_plan: bool,
    /// The GC deletes only after a sync that starts a horizon after the condemn.
    pub sweep_after_horizon: bool,
}

pub const SAFE: Rules = Rules {
    fresh_sync: true,
    fresh_plan: true,
    sweep_after_horizon: true,
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Action {
    Tick,
    Sync { writer: usize },
    PlanDedup { writer: usize, key: u8, pack: u8 },
    PlanFresh { writer: usize, key: u8 },
    Commit { writer: usize },
    Abort { writer: usize },
    Delete { key: u8 },
    Crash { writer: usize },
    GcSync,
    Condemn { pack: u8 },
    Sweep { pack: u8 },
}

#[derive(Clone, Debug)]
pub struct GcModel {
    pub writers: usize,
    pub keys: u8,
    pub horizon: u8,
    pub max_time: u8,
    pub max_entries: usize,
    pub max_packs: u8,
    pub max_crashes: u8,
    pub rules: Rules,
}

/// Name of the property that a missing rule breaks.
pub const READABLE: &str = "every current object is readable";

impl GcModel {
    fn half(&self) -> u8 {
        self.horizon / 2
    }

    fn younger_than_half(&self, now: u8, then: Option<u8>) -> bool {
        then.is_some_and(|t| now < t + self.half())
    }

    fn plan_dedup(&self, s: &mut State, writer: usize, key: u8, pack: u8) -> bool {
        let w = &s.writers[writer];

        if w.plan.is_some() || !is_known(s.view(w.reader), pack) {
            return false;
        }

        if self.rules.fresh_sync && !self.younger_than_half(s.time, w.reader.synced_at) {
            return false;
        }

        s.writers[writer].plan = Some(Plan {
            key,
            pack,
            at: s.time,
        });
        true
    }

    fn plan_fresh(&self, s: &mut State, writer: usize, key: u8) -> bool {
        if s.writers[writer].plan.is_some() || s.issued >= self.max_packs {
            return false;
        }

        let pack = s.issued;
        s.issued += 1;
        s.packs |= bit(pack);
        s.writers[writer].plan = Some(Plan {
            key,
            pack,
            at: s.time,
        });
        true
    }

    fn commit(&self, s: &mut State, writer: usize) -> bool {
        let w = &s.writers[writer];
        let Some(plan) = w.plan else {
            return false;
        };

        if s.log.len() >= self.max_entries {
            return false;
        }

        if self.rules.fresh_plan && !self.younger_than_half(s.time, Some(plan.at)) {
            return false;
        }

        let entry = Entry {
            time: s.time,
            kind: Kind::Put {
                key: plan.key,
                pack: plan.pack,
            },
        };
        s.log.push(entry);
        s.writers[writer].plan = None;
        true
    }

    fn condemn(&self, s: &mut State, pack: u8) -> bool {
        let view = s.view(s.gc);
        let in_remote = s.packs & bit(pack) != 0;

        if !in_remote
            || is_live(view, self.keys, pack)
            || standing_condemn(view, pack).is_some()
            || s.log.len() >= self.max_entries
        {
            return false;
        }

        s.log.push(Entry {
            time: s.time,
            kind: Kind::Condemn { pack },
        });
        true
    }

    fn sweep(&self, s: &mut State, pack: u8) -> bool {
        let view = s.view(s.gc);
        let Some(condemn) = standing_condemn(view, pack) else {
            return false;
        };

        let waited =
            s.gc.synced_at
                .is_some_and(|synced| synced >= condemn.time + self.horizon);

        if s.packs & bit(pack) == 0 || is_live(view, self.keys, pack) {
            return false;
        }

        if self.rules.sweep_after_horizon && !waited {
            return false;
        }

        s.packs &= !bit(pack);
        true
    }

    fn sync(s: &State) -> Reader {
        Reader {
            applied: s.log.len() as u8,
            synced_at: Some(s.time),
        }
    }
}

impl Model for GcModel {
    type State = State;
    type Action = Action;

    fn init_states(&self) -> Vec<State> {
        let writer = Writer {
            reader: FRESH,
            plan: None,
        };

        vec![State {
            time: 0,
            log: Vec::new(),
            packs: 0,
            issued: 0,
            writers: vec![writer; self.writers],
            gc: FRESH,
            crashes: 0,
        }]
    }

    fn actions(&self, state: &State, actions: &mut Vec<Action>) {
        if state.time < self.max_time {
            actions.push(Action::Tick);
        }

        for writer in 0..self.writers {
            actions.push(Action::Sync { writer });
            actions.push(Action::Commit { writer });
            actions.push(Action::Abort { writer });

            for key in 0..self.keys {
                actions.push(Action::PlanFresh { writer, key });
                for pack in 0..state.issued {
                    actions.push(Action::PlanDedup { writer, key, pack });
                }
            }

            if state.crashes < self.max_crashes {
                actions.push(Action::Crash { writer });
            }
        }

        if state.log.len() < self.max_entries {
            for key in 0..self.keys {
                actions.push(Action::Delete { key });
            }
        }

        actions.push(Action::GcSync);

        for pack in 0..state.issued {
            actions.push(Action::Condemn { pack });
            actions.push(Action::Sweep { pack });
        }
    }

    fn next_state(&self, last: &State, action: Action) -> Option<State> {
        let mut s = last.clone();

        let changed = match action {
            Action::Tick => {
                s.time += 1;
                true
            }
            Action::Sync { writer } => {
                s.writers[writer].reader = Self::sync(&s);
                true
            }
            Action::PlanDedup { writer, key, pack } => self.plan_dedup(&mut s, writer, key, pack),
            Action::PlanFresh { writer, key } => self.plan_fresh(&mut s, writer, key),
            Action::Commit { writer } => self.commit(&mut s, writer),
            Action::Abort { writer } => s.writers[writer].plan.take().is_some(),
            Action::Delete { key } => {
                s.log.push(Entry {
                    time: s.time,
                    kind: Kind::Delete { key },
                });
                true
            }
            Action::Crash { writer } => {
                s.crashes += 1;
                s.writers[writer].reader = FRESH;
                true
            }
            Action::GcSync => {
                s.gc = Self::sync(&s);
                true
            }
            Action::Condemn { pack } => self.condemn(&mut s, pack),
            Action::Sweep { pack } => self.sweep(&mut s, pack),
        };

        (changed && s != *last).then_some(s)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always(READABLE, |m: &Self, s: &State| {
                (0..m.keys).all(|key| match head(&s.log, key) {
                    Some(Kind::Put { pack, .. }) => s.packs & bit(pack) != 0,
                    _ => true,
                })
            }),
            Property::sometimes("a pack is swept", |_: &Self, s: &State| {
                (0..s.issued).any(|pack| s.packs & bit(pack) == 0)
            }),
            Property::sometimes("a put dedups against another put", |_: &Self, s: &State| {
                s.log.iter().enumerate().any(|(i, e)| match e.kind {
                    Kind::Put { pack, .. } => s.log[..i]
                        .iter()
                        .any(|f| matches!(f.kind, Kind::Put { pack: p, .. } if p == pack)),
                    _ => false,
                })
            }),
            Property::sometimes("a put revives a condemned pack", |_: &Self, s: &State| {
                s.log.iter().enumerate().any(|(i, e)| match e.kind {
                    Kind::Put { pack, .. } => {
                        s.log[..i].iter().any(|f| f.kind == Kind::Condemn { pack })
                    }
                    _ => false,
                })
            }),
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use stateright::{Checker, HasDiscoveries};

    use super::*;

    fn model(rules: Rules) -> GcModel {
        GcModel {
            writers: 1,
            keys: 1,
            horizon: 2,
            max_time: 4,
            max_entries: 4,
            max_packs: 2,
            max_crashes: 1,
            rules,
        }
    }

    fn check(model: GcModel, finish: HasDiscoveries) -> impl Checker<GcModel> {
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        model
            .checker()
            .threads(threads)
            .finish_when(finish)
            .spawn_dfs()
            .join()
    }

    /// Breadth first: the shortest loss is a few steps deep.
    fn assert_loses_data(rules: Rules) {
        let first_loss = HasDiscoveries::AnyOf(BTreeSet::from([READABLE]));
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        model(rules)
            .checker()
            .threads(threads)
            .finish_when(first_loss)
            .spawn_bfs()
            .join()
            .assert_any_discovery(READABLE);
    }

    fn check_safe(model: GcModel) {
        check(model, HasDiscoveries::AnyFailures).assert_properties();
    }

    #[test]
    #[ignore = "model check: run on a build machine"]
    fn test_sweep_rules_keep_every_object_readable() {
        check_safe(model(SAFE));
    }

    #[test]
    #[ignore = "model check: run on a build machine"]
    fn test_sweep_rules_are_safe_with_a_longer_horizon() {
        check_safe(GcModel {
            horizon: 4,
            max_time: 7,
            max_entries: 5,
            ..model(SAFE)
        });
    }

    #[test]
    #[ignore = "model check: run on a build machine"]
    fn test_sweep_rules_are_safe_with_two_writers() {
        check_safe(GcModel {
            writers: 2,
            ..model(SAFE)
        });
    }

    #[test]
    fn test_sweep_without_horizon_loses_data() {
        assert_loses_data(Rules {
            sweep_after_horizon: false,
            ..SAFE
        });
    }

    #[test]
    fn test_dedup_after_an_old_sync_loses_data() {
        assert_loses_data(Rules {
            fresh_sync: false,
            ..SAFE
        });
    }

    #[test]
    fn test_commit_of_an_old_plan_loses_data() {
        assert_loses_data(Rules {
            fresh_plan: false,
            ..SAFE
        });
    }
}
