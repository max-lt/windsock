# Bench, release build: close other heavy programs first, the report notes the load.
bench out="bench.md" runs="5" seconds="15" rate="500":
    cargo build --release -p bench
    ./target/release/windsock-bench --runs {{runs}} --seconds {{seconds}} --rate {{rate}} --out {{out}}

# Format check, then clippy on the default build and on the tls feature.
check:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo clippy --all-targets --features windsockd/tls,s3remote/tls -- -D warnings

test:
    cargo test --no-fail-fast
