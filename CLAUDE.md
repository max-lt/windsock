# Windsock

S3-compatible proxy and cache. The remote object store (Backblaze B2 or any
S3-compatible store) holds the only durable copy of the data.

Design, decisions and milestones: `../windsock-todo.md`. State: milestones 0 to 14 are done. The
section "Hand-over" of that file lists the open decisions and the known limits: read it first.

## Build and test

```bash
cargo build                                  # build everything
cargo test                                   # all tests (about 280; windsockd cluster tests ~85 s)
cargo test -p model                          # one crate
cargo clippy --all-targets -- -D warnings    # lint, zero warnings, tests included
cargo fmt --check                            # format check
scripts/bench.sh                             # bench, release build, a few minutes
```

A milestone is complete only when `cargo clippy --all-targets -- -D warnings` and
`cargo fmt --check` pass. `README.md` shows how to run the daemon locally.

## Layout

All crates live in `crates/<name>`. Crate names have no project prefix.
The daemon crate is `windsockd`.

- `model`: shared identifiers (ChunkId, PackId, ObjectId, NodeId).
- `chunking`: FastCDC chunk boundaries, chunk IDs, per-chunk zstd compression.
- `pack`: pack format v2 (header with a nonce, chunks, postcard footer, trailer), builder, parser,
  one-chunk read.
- `remote`: `Remote` trait (put, create, get, get_range, list, no delete), `Sweep` trait (delete,
  GC only), memory and local directory backends, the contract checks (`contract`, feature `contract`)
  that every backend passes.
- `s3proto`: SigV4 (header signing, aws-chunked) and S3 date formats, for the server and the client.
- `s3remote`: `Remote` and `Sweep` in an S3 bucket: SigV4 with the body hash, create via
  `If-None-Match: *`, retries with backoff and time limits. HTTPS only with the feature `tls`
  (rustls + ring, public roots plus an optional PEM CA file).
- `journal`: one signed chain per node (`log/<node>/<seq>`, create-only), `seen` links to other
  chains (causal DAG, no merge entries), redactable actions, chain validation, HLC.
- `index`: Fjall view of the journal. Causal apply (an entry waits for its `seen`), per-key versions
  (LWW by (hlc, node), conflicts computed from `seen`), buckets, chunk locations, applied frontiers,
  condemned packs and manifests, live manifests, stable HLC, version prune, snapshot export and load.
- `cache`: disk cache of raw chunks by ChunkId: LRU by size, blake3 check on every read, one fetch
  per missing chunk (singleflight).
- `engine`: object operations. `lib.rs`: types, errors, `open`. One module per kind of operation:
  `buckets.rs`, `write.rs` (puts fsynced in the buffer), `read.rs` (buffer, then index, cache and
  remote), `sync.rs` (other chains, manifests, chunk locations, sync on miss), `flush.rs` (plan,
  upload, intent, commit, group commit). Also `buffer.rs` (NVMe write-back log: segments, replay,
  intent file, group fsync), `plan.rs` (packs and range reads, no I/O), `manifest.rs`, `config.rs` (per-prefix
  policy: chunking, compression, create-only, cache), `gc.rs` (condemn, delete after H, version
  prune) and `snapshot.rs` (snapshots, bootstrap, journal prune).
- `s3api`: S3 over HTTP (axum) on the engine. `auth.rs`: SigV4 in the header (payload hash checked,
  aws-chunked decoded, 15 min clock skew), keys from configuration. `handlers/`: `bucket.rs`,
  `object.rs`, `conditions.rs` (RFC 7232 preconditions, RFC 7233 ranges). `list.rs`: ListObjects
  v1 and v2 paging (no I/O). `multipart.rs`: parts on local disk. `xml.rs`. ETag = blake3 hex of
  the data.
- `windsockd`: the daemon. `init <dir>` writes a TOML configuration with a new key pair; `run <config>`
  serves S3, syncs, runs the GC when `gc.enabled`, and flushes the buffer on SIGINT or SIGTERM.
  `README.md` has the steps to run it locally.
- `bench`: `windsock-bench`, the bench through the S3 API on a counting DirRemote. Rerun with
  `scripts/bench.sh`; the numbers are in `../windsock-todo.md`, milestone 14.
- `protocol-check`: Stateright models of the journal write and sync protocol (`lib.rs`) and of the
  pack sweep (`gc.rs`). The slow checks are `#[ignore]`: run them in release on a build machine,
  never on the laptop.

## Invariants

- The remote is the source of truth. Local state is a cache. A proxy can rebuild it from the remote.
- Every remote object is immutable. `nodes/<node_id>` is an empty marker, written once. One
  exception: the journal prune replaces a log entry once with its redacted form (same hash, same
  signature), so the key stays taken and the chain stays valid.
- Only the GC deletes remote objects, plus the storage probe, which deletes its own objects under
  `probe/`. The write path never deletes.
- The store must keep the storage contract in `docs/storage.md`: conditional create,
  read-after-write, list-after-write, ranged reads. `remote::check_before_serving` runs the
  probe before `windsockd` serves. A violation stops it. After 3 ambiguous errors it starts with
  a warning. `windsockd diagnose <config>` runs the probe once.
- The GC deletes a pack or a manifest only when no current object uses it, after a condemn entry
  in the journal and a GC sync that starts a horizon H (24 h) later. A writer dedups only after a
  sync younger than H/2, and commits only a plan younger than H/2. `protocol-check/src/gc.rs`
  checks these rules; each one is needed.
- A flush batch must plan and upload in less than H/2, or rule 2 refuses its commit (StalePlan)
  every time and the writes never reach the journal. H stays far above one batch: 24 h by default,
  and `windsockd` warns under one hour.
- A fresh upload gets a new remote key (a nonce in packs and manifests). A deleted key is never
  written again.
- A proxy that applied a condemn of a pack never learns that pack again.
- A broken chain fails alone: a sync reads the other chains and names the broken one. The GC
  refuses to run while a chain is broken. GC rule 1 counts only a sync with no broken chain: without
  one, a flush writes every chunk and dedups nothing.
- The chunk cache is local and keyed by ChunkId. A chunk never changes for its ChunkId, so the cache
  never goes stale and the GC never touches it. A cache read that fails its hash check is a miss.
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
- Group fsync. A write appends its record under the buffer lock. It waits for the fsync outside
  the lock. One fsync runs at a time. It covers all records that exist when it starts. A group has
  no minimum size and no timer.
- A rotation fsyncs the segment that it seals. Thus only the last segment can end with a torn
  record, and a flush uploads only fsynced records.
- A read returns only when all buffered writes that it saw are fsynced.
- If an fsync fails, the buffer cuts the active segment to its last fsynced size. Then it reads
  the buffer from disk again. Each write that the fsync covered fails with `WriteLost`.
- If this repair fails, the buffer refuses all writes until a restart (`BufferBroken`).
- A signed entry goes to the intent file before its create. A restart retries that entry before it signs a new one.
- Proxies do not coordinate. The index merge is LWW: HLC first, then NodeId.
- The journal core (`chain.rs`) does no I/O. Keep decision code out of the async shell.
- `windsockd` accepts at most `max_connections` connections (default: soft fd limit - 256), so a
  flush always has descriptors.

## Code style

- `thiserror` in library crates. `anyhow` only in `windsockd`.
- `tracing` with structured fields. No `println!`.
- `postcard` + `serde` for the wire format and for persistence.
- Identifiers are `[u8; 32]` newtypes from `model`. Use `blake3` for hashes.
- `tokio` runtime.
- Small functions. Early returns instead of deep nesting.
- Comments: one line, the reason only. No history, no ticket text, ASCII only.
- No comment separators between sections: one module per concern.
- A parameter whose meaning a bare `true` or `false` does not show at the call is a two-value enum.
- Public types get a one-line doc comment. Skip it when the name says everything.
- Commit subjects: imperative, capitalized (`Add ...`, `Fix ...`, `Split ...`), 72 characters at
  most. The body says why, in ASD-STE100. Commits stay local until Maxime says otherwise.

## Dependencies

No C dependencies. Read the `build.rs` of a crate before you add it.
Check after each new dependency. The build must pass with no C compiler:

```bash
cargo clean && CC=/usr/bin/false CXX=/usr/bin/false cargo build
```

One exception, decided by Maxime: the feature `tls` (`s3remote/tls`, `windsockd/tls`) compiles
`ring`, the TLS crypto provider. Only that feature may compile C. Lint it too:
`cargo clippy --all-targets --features windsockd/tls,s3remote/tls -- -D warnings`, and
`cargo test -p s3remote -p windsockd --features tls`.

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
| HTTP server | `axum` 0.8 |
| HTTP client | `hyper` 1, `hyper-util` (`client-legacy`) |
| Daemon errors | `anyhow` (only in `windsockd`) |
| Configuration | `toml` 0.8 |
| Log output | `tracing-subscriber` with `env-filter` |
| XML | `quick-xml` with `serialize` |
| SigV4 | `hmac`, `sha2`, `subtle` |
| URL form encoding | `form_urlencoded` |
| fd limit | `rustix` (`process`) |
| HTTP body type (`windsockd`) | `http-body` 1 |
| TLS (feature `tls` only) | `rustls` 0.23 with `ring`, `hyper-rustls` 0.27, `tokio-rustls` 0.26, `webpki-roots` 1 |
| HTTP tests | `tower` (`util`), `http-body-util` |

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
- Every backend runs `remote::contract::check` (feature `contract`).
- `windsockd/tests` run the binary as a process through `tests/common`; a failing test prints the
  daemon log. The cluster tests run one at a time.

## Bug fixes

1. Write a test that fails and shows the bug.
2. Fix the bug.
3. Run the test, then the full test suite.

## Do not

- No `unwrap()` in library code. Use `expect("reason")` only for an invariant that cannot fail.
  `remote::contract` is test support code: it panics on purpose.
- No `unsafe`.
- No erasure coding, no replication between proxies, no consensus, no refcount.
