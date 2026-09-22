#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

# Run through the repository's pinned Nix shell. Each invocation creates a new
# secret and a fresh experimental trusted setup. Never fund these synthetic keys.
compiler_version="$(rustc --version)"
if [[ "$compiler_version" != "rustc 1.98.1 "* ]]; then
    echo "Expected rustc 1.98.1; use nix develop --no-update-lock-file -c bash $0" >&2
    exit 1
fi
opt_level="${CHECKZKP_OPT_LEVEL:-s}"
case "$opt_level" in
    s|z|3) ;;
    *) echo "CHECKZKP_OPT_LEVEL must be s, z, or 3" >&2; exit 2 ;;
esac
manifest=experiments/op_checkzkp/Cargo.toml
target=experiments/op_checkzkp/target
CARGO_PROFILE_RELEASE_OPT_LEVEL="$opt_level" \
RUSTFLAGS="-C link-arg=-zstack-size=1048576 -C link-arg=--initial-memory=8388608 -C link-arg=--max-memory=67108864" \
    cargo build --locked --manifest-path "$manifest" -p checkzkp-guest \
    --release --target wasm32-unknown-unknown --target-dir "$target"

# Default path enforces the actual ProgramOracle limits and validates signatures.
# The measured BN254 verifier currently exhausts that 100M fuel budget; default
# failure is the experiment's result, not a successful opcode deployment.
# The default opt-level=s build measured ~486-488M fuel per proof, so these
# fixtures need about 500M. Use --diagnostic-fuel 1000000000 for headroom.
# These measurements are not a worst-case bound for every proof/transaction.
# --diagnostic-fuel N explicitly bypasses module admission/changes fuel and NEVER
# signs: diagnostic success must not be mistaken for a deployable predicate.
exec cargo run --locked --manifest-path "$manifest" -p checkzkp-probe --release \
    --target-dir "$target" -- "$target/wasm32-unknown-unknown/release/checkzkp_guest.wasm" "$@"
