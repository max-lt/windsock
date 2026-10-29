# Bench, release build: close other heavy programs first, the report notes the load.
bench out="bench.md" runs="5" seconds="15" rate="500":
    cargo build --release -p bench
    ./target/release/windsock-bench --runs {{runs}} --seconds {{seconds}} --rate {{rate}} --out {{out}}

# Format check, then clippy on the default build, on the tls feature and on fuzz/.
check:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo clippy --all-targets --features windsockd/tls,s3remote/tls -- -D warnings
    cd fuzz && cargo fmt --check && cargo clippy --all-targets -- -D warnings

test:
    cargo test --no-fail-fast

# Each fuzz target for `seconds`, or only `target`. Needs nightly and cargo-fuzz.
fuzz seconds="60" target="":
    #!/bin/sh
    set -eu
    cd fuzz
    targets="{{target}}"
    for t in ${targets:-$(cargo +nightly fuzz list)}; do
        cargo +nightly fuzz run "$t" -- -max_total_time={{seconds}}
    done
