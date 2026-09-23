#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "$root"
if [[ $# -ne 0 ]]; then
    echo "usage: bash experiments/op_checkzkp/build-generic.sh" >&2
    exit 2
fi
if [[ "${CHECKZKP_GENERIC_SHELL:-}" != 1 ]]; then
    exec nix develop --offline --no-update-lock-file --command \
        env CHECKZKP_GENERIC_SHELL=1 bash "$root/experiments/op_checkzkp/build-generic.sh"
fi
if [[ "$(rustc --version)" != "rustc 1.98.1 "* ]]; then
    echo "Expected the repository's pinned rustc 1.98.1" >&2
    exit 1
fi
export CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 RAYON_NUM_THREADS=1
export LC_ALL=C TZ=UTC
unset CARGO_ENCODED_RUSTFLAGS
manifest="$root/experiments/op_checkzkp/Cargo.toml"
target="$root/experiments/op_checkzkp/target"
output="$target/generic-comparison"
mkdir -p "$output"

CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
RUSTFLAGS="-C link-arg=-zstack-size=1048576 -C link-arg=--initial-memory=8388608 -C link-arg=--max-memory=67108864" \
    cargo build --offline --locked --manifest-path "$manifest" \
    -p checkzkp-generic-guest --release --target wasm32-unknown-unknown --target-dir "$target"
bash "$root/experiments/op_checkzkp/optimize.sh" \
    "$target/wasm32-unknown-unknown/release/checkzkp_generic_guest.wasm" "$output/groth16.wasm"
RUSTFLAGS="" CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
    cargo build --offline --locked --manifest-path "$manifest" \
    -p checkzkp-generic-probe --release --target-dir "$target"
printf 'Generic proof core: %s\nProbe: %s\n' "$output/groth16.wasm" "$target/release/checkzkp-generic-probe"
printf 'This core has no Sapio signing entrypoint; application authorization remains separate.\n'
