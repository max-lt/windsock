#!/bin/sh
# Reruns the Windsock bench and writes the report to bench.md (or to $1).
# Close other heavy programs first: the report notes the load, it does not remove it.
set -eu
cd "$(dirname "$0")/.."
cargo build --release -p bench
./target/release/windsock-bench --runs "${RUNS:-5}" --seconds "${SECONDS_PER_RUN:-15}" \
    --rate "${RATE:-500}" --out "${1:-bench.md}"
