# Windsock

S3-compatible proxy and cache. The remote object store (Backblaze B2 or any
S3-compatible store) holds the only durable copy of the data.

Design, decisions and milestones: `../windsock-todo.md`.

## Build and test

```bash
cargo build                    # build everything
cargo test                     # all tests
cargo test -p model            # one crate
cargo clippy -- -D warnings    # lint, zero warnings
cargo fmt --check              # format check
```

A milestone is complete only when `cargo clippy -- -D warnings` and `cargo fmt --check` pass.

## Layout

All crates live in `crates/<name>`. Crate names have no project prefix.
The daemon crate is `windsockd`.

- `model`: shared identifiers (ChunkId, PackId, ObjectId, NodeId).
- `chunking`: FastCDC chunk boundaries, chunk IDs, per-chunk zstd compression.
- `pack`: pack format v2 (header with a nonce, chunks, postcard footer, trailer), builder, parser,
  one-chunk read.
- `remote`: `Remote` trait (put, create, get, get_range, list, no delete), `Sweep` trait (delete,
  GC only), memory and local directory backends.
- `journal`: one signed chain per node (`log/<node>/<seq>`, create-only), `seen` links to other
  chains (causal DAG, no merge entries), redactable actions, chain validation, HLC.
- `index`: Fjall view of the journal. Causal apply (an entry waits for its `seen`), per-key versions
  (LWW by (hlc, node), conflicts computed from `seen`), buckets, chunk locations, applied frontiers,
  condemned packs and manifests, live manifests, stable HLC, version prune, snapshot export and load.
- `engine`: object operations. NVMe write-back buffer (segments, replay, intent file), per-prefix
  policy, pack planning, inline manifests, group commit, reads from buffer then remote, sync on miss,
  GC (`gc.rs`: condemn, delete after H, version prune), snapshots and journal prune (`snapshot.rs`).
- `protocol-check`: Stateright models of the journal write and sync protocol (`lib.rs`) and of the
  pack sweep (`gc.rs`). The slow checks are `#[ignore]`: run them in release on a build machine,
  never on the laptop.

## Invariants

- The remote is the source of truth. Local state is a cache. A proxy can rebuild it from the remote.
- Every remote object is immutable. `nodes/<node_id>` is an empty marker, written once. One
  exception: the journal prune replaces a log entry once with its redacted form (same hash, same
  signature), so the key stays taken and the chain stays valid.
- Only the GC deletes remote objects. The write path never deletes.
- The GC deletes a pack or a manifest only when no current object uses it, after a condemn entry
  in the journal and a GC sync that starts a horizon H (24 h) later. A writer dedups only after a
  sync younger than H/2, and commits only a plan younger than H/2. `protocol-check/src/gc.rs`
  checks these rules; each one is needed.
- A fresh upload gets a new remote key (a nonce in packs and manifests). A deleted key is never
  written again.
- A proxy that applied a condemn of a pack never learns that pack again.
- A broken chain fails alone: a sync reads the other chains and names the broken one. The GC
  refuses to run while a chain is broken. GC rule 1 counts only a sync with no broken chain: without
  one, a flush writes every chunk and dedups nothing.
- An index never applies a redacted entry. A proxy with no state, or one that meets a redacted
  entry, loads the latest snapshot and reads the chains from its frontiers.
- Clock assumption: no proxy clock is more than R (version retention, 24 h) away from the others.
  The version prune drops versions below (stable HLC - R), and refuses to run when the stable HLC
  is more than R ahead of the GC clock.
- A journal entry is written create-only at `log/<node_id>/<seq>`. One entry per seq: no fork.
- An entry signs `blake3(action)`, not the action: a purge can drop the action and keep the chain.
- An entry lists in `seen` the last entry of every other chain its writer had applied (not read).
  The index applies an entry only after everything in its `seen`.
- Index state is a function of the set of applied entries, never of their order. A conflict is
  computed (the head did not know another version), not stored.
- Write order: pack and manifest, then log entry. Each step is durable before the next step.
- A write is acknowledged once fsynced in the local buffer. The buffer drops it only after its
  log entry is in the remote and applied to the index.
- A signed entry goes to the intent file before its create. A restart retries that entry before it signs a new one.
- Proxies do not coordinate. The index merge is LWW: HLC first, then NodeId.
- The journal core (`chain.rs`) does no I/O. Keep decision code out of the async shell.

## Code style

- `thiserror` in library crates. `anyhow` only in `windsockd`.
- `tracing` with structured fields. No `println!`.
- `postcard` + `serde` for the wire format and for persistence.
- Identifiers are `[u8; 32]` newtypes from `model`. Use `blake3` for hashes.
- `tokio` runtime.
- Small functions. Early returns instead of deep nesting.
- Comments: one line, the reason only. No history, no ticket text, ASCII only.
- Public types get a one-line doc comment. Skip it when the name says everything.

## Dependencies

No C dependencies. Read the `build.rs` of a crate before you add it.
Check after each new dependency. The build must pass with no C compiler:

```bash
cargo clean && CC=/usr/bin/false CXX=/usr/bin/false cargo build
```

The TLS provider for B2 is an open point. See `../windsock-todo.md`.

| Purpose | Crate |
|---|---|
| Hashing | `blake3` with feature `pure` (the default build compiles C and asm) |
| Chunking | `fastcdc` v5, `v2020` module |
| Compression | `ruzstd`, level `Fastest` (standard zstd frames) |
| Async | `tokio`, `async-trait` |
| Buffers | `bytes` |
| Hex encoding | `hex` |
| Serialization | `serde`, `postcard` |
| Errors | `thiserror` |
| Signatures | `ed25519-dalek` v2 |
| Logging | `tracing` |
| Local index | `fjall` v3 |
| Tests | `tempfile` |
| Model checking | `stateright` |

Add a crate to this table when a milestone adds it.

## Workflow

1. Implement only the milestone you get.
2. Run the tests of the affected crates.
3. Run `cargo clippy -- -D warnings`.
4. Run `cargo fmt`.
5. Stop. Start the next milestone only on request.

## Tests

- Unit tests: in the same file, under `#[cfg(test)] mod tests`.
- Integration tests: in `tests/`.
- Use `tempfile` for filesystem tests. Use `tokio::test` for async tests.
- Name tests by behavior: `test_hex_roundtrip`, `test_parse_rejects_non_hex`.
- Test public behavior. Do not copy the implementation logic into the test.
- A golden test pins each storage format. It must not depend on the zstd encoder output.

## Bug fixes

1. Write a test that fails and shows the bug.
2. Fix the bug.
3. Run the test, then the full test suite.

## Do not

- No `unwrap()` in library code. Use `expect("reason")` only for an invariant that cannot fail.
- No `unsafe`.
- No erasure coding, no replication between proxies, no consensus, no refcount.
