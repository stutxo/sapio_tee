#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

# No services, AWS, clock, RNG, network fetches, or unpinned dependency updates.
# Run inside the existing Nix dev shell if the pinned tools are not on PATH.
if [[ "$(rustc --version)" != "rustc 1.98.1 "* ]]; then
    echo "Use Rust 1.98.1 and wasm32-unknown-unknown (see flake.nix)." >&2
    exit 1
fi
mkdir -p target
rustc examples/cohort_exit/predicate.rs \
    --crate-name sapio_cohort_exit_predicate --crate-type cdylib --edition 2021 \
    --target wasm32-unknown-unknown -C opt-level=z -C lto -C codegen-units=1 \
    -C panic=abort -C strip=symbols -C link-arg=-zstack-size=65536 \
    -C link-arg=--initial-memory=4194304 -C link-arg=--max-memory=4194304 \
    -o target/cohort-exit.wasm
cmp target/cohort-exit.wasm examples/cohort_exit/cohort_exit.wasm
cargo run --offline --locked --release --example cohort_exit
