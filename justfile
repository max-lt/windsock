# Bench, release build: close other heavy programs first, the report notes the load.
bench out="bench.md" runs="5" seconds="15" rate="500":
    cargo build --release -p bench
    ./target/release/windsock-bench --runs {{runs}} --seconds {{seconds}} --rate {{rate}} --out {{out}}
