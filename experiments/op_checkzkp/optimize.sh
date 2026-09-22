#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ $# -ne 2 || "$1" == "$2" ]]; then
    echo "usage: bash optimize.sh INPUT.wasm DISTINCT_OUTPUT.wasm" >&2
    exit 2
fi
# Always consume Cargo's original artifact, never an earlier optimized output.
# bulk-memory-opt admits the memory.copy/fill already emitted by pinned rustc;
# this does not change the evaluator's instruction/import admission policy.
export BINARYEN_CORES=1
optimizer=(nix shell --offline --inputs-from "$root" nixpkgs#binaryen --command wasm-opt)
if [[ "$("${optimizer[@]}" --version)" != "wasm-opt version 132" ]]; then
    echo "Expected pinned Binaryen 132" >&2
    exit 1
fi
"${optimizer[@]}" -O2 --enable-bulk-memory-opt "$1" -o "$2"
