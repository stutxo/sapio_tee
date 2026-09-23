#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "$root"
if [[ $# -ne 0 ]]; then
    echo "usage: bash experiments/op_checkzkp/compare-arkworks.sh" >&2
    exit 2
fi
if [[ "${CHECKZKP_COMPARISON_SHELL:-}" != 1 ]]; then
    exec nix develop --offline --no-update-lock-file --command \
        env CHECKZKP_COMPARISON_SHELL=1 bash "$root/experiments/op_checkzkp/compare-arkworks.sh"
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
output="$target/arkworks-comparison"
corpus="$root/experiments/op_checkzkp/fixtures/corpus.json"
mkdir -p "$output"

build_guest() {
    local package="$1" artifact="$2" destination="$3"
    shift 3
    CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
    RUSTFLAGS="-C link-arg=-zstack-size=1048576 -C link-arg=--initial-memory=8388608 -C link-arg=--max-memory=67108864" \
        cargo build --offline --locked --manifest-path "$manifest" \
        -p "$package" --release --target wasm32-unknown-unknown --target-dir "$target" "$@"
    bash "$root/experiments/op_checkzkp/optimize.sh" \
        "$target/wasm32-unknown-unknown/release/$artifact.wasm" "$output/$destination.wasm"
}

# Same compiler, optimization, stack and memory configuration for every variant.
# Separate outputs preserve the retained production-gated artifact and old logs.
build_guest checkzkp-guest checkzkp_guest retained
build_guest checkzkp-ark-guest checkzkp_ark_guest arkworks
build_guest checkzkp-ark-guest checkzkp_ark_guest arkworks-msm --features msm
RUSTFLAGS="" CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
    cargo build --offline --locked --manifest-path "$manifest" \
    -p checkzkp-probe --release --target-dir "$target"

# These are frozen-corpus diagnostic measurements, never signing/deployment gates.
# Explicit legacy admission permits measuring an oversized arkworks artifact;
# it does not make that artifact admissible to the unchanged production oracle.
"$target/release/checkzkp-probe" --benchmark "$output/retained.wasm" "$corpus" \
    | tee "$output/retained.log"
for variant in arkworks arkworks-msm; do
    "$target/release/checkzkp-probe" --benchmark "$output/$variant.wasm" "$corpus" \
        --backend arkworks --legacy-diagnostic | tee "$output/$variant.log"
done
printf '\nComparison artifacts and logs: %s\n' "$output"
printf 'Run the fresh production gate separately; diagnostic success does not imply deployability.\n'
