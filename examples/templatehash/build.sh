#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

mode="${1:---check}"
if [[ $# -gt 1 || ( "$mode" != --check && "$mode" != --write ) ]]; then
    echo "usage: $0 [--check|--write]" >&2
    exit 2
fi

# Use the repository's Nix-pinned compiler from PATH, not a rustup override.
if ! compiler_version="$(rustc --version 2>/dev/null)"; then
    echo "rustc 1.98.1 with wasm32-unknown-unknown is required on PATH." >&2
    exit 1
fi
if [[ "$compiler_version" != "rustc 1.98.1 "* ]]; then
    echo "Expected rustc 1.98.1; found: $compiler_version" >&2
    exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT
built="$temporary/templatehash.wasm"

# Same artifact identity flags as the vault example; see its PROVENANCE.txt.
rustc predicate.rs \
    --crate-name sapio_templatehash_predicate \
    --crate-type cdylib \
    --edition 2021 \
    --target wasm32-unknown-unknown \
    -C opt-level=z \
    -C lto \
    -C codegen-units=1 \
    -C panic=abort \
    -C strip=symbols \
    -C link-arg=-zstack-size=65536 \
    -C link-arg=--initial-memory=4194304 \
    -C link-arg=--max-memory=4194304 \
    -o "$built"

if [[ $(wc -c < "$built") -gt 65536 ]]; then
    echo "Template-hash predicate exceeds the 64 KiB inline program limit" >&2
    exit 1
fi
if [[ "$mode" == --write ]]; then
    install -m 644 "$built" templatehash.wasm
else
    # A missing or different artifact fails without updating the checked-in file.
    cmp "$built" templatehash.wasm
fi
