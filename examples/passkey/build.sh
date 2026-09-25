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
    echo "From the repository root: nix develop --command bash examples/passkey/build.sh $mode" >&2
    exit 1
fi
if [[ "$compiler_version" != "rustc 1.98.1 "* ]]; then
    echo "Expected rustc 1.98.1; found: $compiler_version" >&2
    echo "From the repository root: nix develop --command bash examples/passkey/build.sh $mode" >&2
    exit 1
fi

if [[ ! -f guest/Cargo.lock || ! -f recovery/Cargo.lock || ! -f client/Cargo.lock ]]; then
    echo "Missing standalone Cargo.lock; all three WASM dependency graphs must be locked." >&2
    exit 1
fi

if [[ "$(clang --version)" != *"clang version 21.1.8"* ]]; then
    echo "Clang 21.1.8 from the pinned Nix environment is required for browser MuSig2." >&2
    exit 1
fi
if ! command -v llvm-ar >/dev/null; then
    echo "llvm-ar from the pinned Nix environment is required." >&2
    exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT
built="$temporary/target/wasm32-unknown-unknown/release/sapio_passkey_predicate.wasm"
recovery_built="$temporary/recovery/wasm32-unknown-unknown/release/passkey_recovery.wasm"
client_built="$temporary/client/wasm32-unknown-unknown/release/passkey_client.wasm"

# The standalone crate pins its dependency graph through Cargo.lock. Release
# size/LTO/strip settings and these fixed-memory flags define artifact identity.
# The predicate uses no WASI, network fetch, native host dependency or optimizer.
unset CARGO_ENCODED_RUSTFLAGS
CARGO_INCREMENTAL=0 \
RUSTC="$(command -v rustc)" \
RUSTFLAGS="-C link-arg=-zstack-size=65536 -C link-arg=--initial-memory=4194304 -C link-arg=--max-memory=4194304" \
cargo build \
    --manifest-path guest/Cargo.toml \
    --locked \
    --offline \
    --release \
    --target wasm32-unknown-unknown \
    --target-dir "$temporary/target"

if [[ $(wc -c < "$built") -gt 65536 ]]; then
    echo "Passkey predicate exceeds the 64 KiB inline program limit" >&2
    exit 1
fi

# This larger browser-only module is never uploaded to the enclave. Its vetted
# libsecp256k1 MuSig2 implementation needs a WASM-capable C compiler and archiver.
# libsecp256k1's Rust wrappers retain caller locations even without debug info.
# Normalize the cache prefix, and preserve paths containing spaces as one flag.
cargo_home="$(cd -- "${CARGO_HOME:-"$HOME/.cargo"}" && pwd)"
recovery_flags=(
    "--remap-path-prefix=$cargo_home=/cargo"
    "-Clink-arg=-zstack-size=65536"
    "-Clink-arg=--initial-memory=4194304"
    "-Clink-arg=--max-memory=4194304"
)
CARGO_INCREMENTAL=0 \
RUSTC="$(command -v rustc)" \
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; printf '%s' "${recovery_flags[*]}")" \
CC_wasm32_unknown_unknown="$(command -v clang)" \
AR_wasm32_unknown_unknown="$(command -v llvm-ar)" \
CFLAGS_wasm32_unknown_unknown="-ffreestanding -nostdlibinc -resource-dir=$(clang -print-resource-dir)" \
cargo build \
    --manifest-path recovery/Cargo.toml \
    --locked \
    --offline \
    --release \
    --target wasm32-unknown-unknown \
    --target-dir "$temporary/recovery"

# The wallet client builds transactions and verifies/finalizes both paths locally.
# It never contains private keys or calls the Sapio guest's metered host imports.
client_flags=(
    "--remap-path-prefix=$cargo_home=/cargo"
    "--remap-path-prefix=$PWD=/passkey"
    "-Clink-arg=-zstack-size=262144"
    "-Clink-arg=--initial-memory=33554432"
    "-Clink-arg=--max-memory=33554432"
)
CARGO_INCREMENTAL=0 \
RUSTC="$(command -v rustc)" \
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; printf '%s' "${client_flags[*]}")" \
CC_wasm32_unknown_unknown="$(command -v clang)" \
AR_wasm32_unknown_unknown="$(command -v llvm-ar)" \
CFLAGS_wasm32_unknown_unknown="-ffreestanding -nostdlibinc -resource-dir=$(clang -print-resource-dir)" \
cargo build \
    --manifest-path client/Cargo.toml \
    --locked \
    --offline \
    --release \
    --target wasm32-unknown-unknown \
    --target-dir "$temporary/client"

if [[ "$mode" == --write ]]; then
    install -m 644 "$built" passkey.wasm
    install -m 644 "$recovery_built" recovery.wasm
    install -m 644 "$client_built" wallet.wasm
else
    # A missing or different artifact fails without updating the checked-in file.
    cmp "$built" passkey.wasm
    cmp "$recovery_built" recovery.wasm
    cmp "$client_built" wallet.wasm
fi
