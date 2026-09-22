#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$root"
if [[ $# -ne 0 ]]; then
    echo "usage: bash autoresearch.sh" >&2
    exit 2
fi

# Only cached, pinned Nix inputs are admitted during measurement. Dependency
# acquisition and OS-random PUBLIC fixture generation belong to harness setup,
# never to this deterministic workload.
if [[ "${CHECKZKP_AUTORESEARCH_SHELL:-}" != 1 ]]; then
    exec nix develop --offline --no-update-lock-file --command \
        env CHECKZKP_AUTORESEARCH_SHELL=1 bash "$root/autoresearch.sh"
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
corpus="$root/experiments/op_checkzkp/fixtures/corpus.json"
if [[ ! -s "$corpus" ]]; then
    echo "Missing fixed public corpus: generate it once during harness setup" >&2
    exit 1
fi

# Score the UNINSTRUMENTED guest with the original release settings. The raised
# measurement allowance is diagnostic only; production remains at 100M fuel.
CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
RUSTFLAGS="-C link-arg=-zstack-size=1048576 -C link-arg=--initial-memory=8388608 -C link-arg=--max-memory=67108864" \
    cargo build --offline --locked --manifest-path "$manifest" \
    -p checkzkp-guest --release --target wasm32-unknown-unknown --target-dir "$target"
RUSTFLAGS="" CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
    cargo build --offline --locked --manifest-path "$manifest" \
    -p checkzkp-probe --release --target-dir "$target"

# The profile builder works on ignored source copies only. Its stage results
# include instrumentation overhead and never contribute to the primary score.
python3 "$root/experiments/op_checkzkp/profile/build.py"
bash "$root/experiments/op_checkzkp/optimize.sh" \
    "$target/wasm32-unknown-unknown/release/checkzkp_guest.wasm" "$target/checkzkp_guest.scored.wasm"
bash "$root/experiments/op_checkzkp/optimize.sh" \
    "$target/checkzkp_guest.profile.wasm" "$target/checkzkp_guest.profile.optimized.wasm"
exec "$target/release/checkzkp-probe" --benchmark \
    "$target/checkzkp_guest.scored.wasm" "$corpus" \
    --profile-module "$target/checkzkp_guest.profile.optimized.wasm"
