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
- `pack`: pack format (header, chunks, postcard footer, trailer), builder, parser, one-chunk read.
- `remote`: `Remote` trait (put, get, get_range, list, no delete), memory and local directory backends.

## Invariants

- The remote is the source of truth. Local state is a cache. A proxy can rebuild it from the remote.
- Remote objects are immutable, except `heads/<node_id>`. One proxy writes each head.
- Windsock never deletes a remote object.
- Write order: pack and manifest, then log entry, then head. Each step is durable before the next step.
- Proxies do not coordinate. The index merge is LWW: HLC first, then NodeId.

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
| Tests | `tempfile` |

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
- No erasure coding, no replication between proxies, no consensus, no GC, no refcount.
