#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/../.." && pwd)
if [[ -z ${IN_NIX_SHELL:-} ]]; then
    exec nix develop --offline "$root" --command bash "$0" "$@"
fi
[[ $(rustc --version) == 'rustc 1.98.1 '* ]] || { echo 'Guest requires pinned rustc 1.98.1' >&2; exit 1; }
export CHECKSTWO_ROOT="$root"
native_rustc=${CHECKSTWO_NATIVE_RUSTC:-}
if [[ -z "$native_rustc" ]]; then
    native_toolchain=$(nix build --offline --impure --no-link --print-out-paths --expr '
        let flake = builtins.getFlake ("git+file://" + builtins.getEnv "CHECKSTWO_ROOT");
            pkgs = import flake.inputs.nixpkgs {
                system = builtins.currentSystem;
                overlays = [ flake.inputs.rust-overlay.overlays.default ];
            };
        in pkgs.rust-bin.nightly."2026-08-12".default')
    native_rustc="$native_toolchain/bin/rustc"
fi
[[ $("$native_rustc" --version) == 'rustc 1.99.0-nightly (3d6c19bb9 2026-08-11)' ]] || { echo 'Native compiler must match pinned nightly 2026-08-12' >&2; exit 1; }
guest_rustc=$(command -v rustc)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
mkdir -p "$here/target"

# Target code gets no network, host environment, home, keys, or writable sources.
# The only host-writable tree is this experiment's ignored target directory.
# Limits are installed inside the namespace so namespace creation itself does
# not inherit an artificially small host-wide process allowance.
sandbox() {
    local compiler=$1
    shift
    local -a args=(
        --unshare-all --die-with-parent --new-session --clearenv --cap-drop ALL
        --ro-bind /nix/store /nix/store
        --ro-bind /run/current-system/sw /run/current-system/sw
        --proc /proc --dev /dev
        --size 1073741824 --tmpfs /work --dir /work/home --dir /work/tmp --dir /work/cargo
        --ro-bind "$cargo_home/registry" /work/cargo/registry
        --ro-bind "$cargo_home/git" /work/cargo/git
        --ro-bind "$here" "$here" --bind "$here/target" "$here/target"
        --ro-bind "$root/examples/vault/guest.rs" "$root/examples/vault/guest.rs"
        --ro-bind "$root/experiments/op_checkzkp/probe/src/runtime.rs" "$root/experiments/op_checkzkp/probe/src/runtime.rs"
        --setenv HOME /work/home --setenv TMPDIR /work/tmp --setenv CARGO_HOME /work/cargo
        --setenv CARGO_NET_OFFLINE true --setenv CARGO_INCREMENTAL 0 --setenv CARGO_BUILD_JOBS 4
        --setenv CARGO_TARGET_DIR "$here/target" --setenv RUSTC "$compiler"
        --setenv RAYON_NUM_THREADS 1 --setenv LC_ALL C --setenv TZ UTC --setenv PATH "$PATH"
        --chdir "$here"
    )
    local name
    for name in LIBCLANG_PATH CC CXX AR LD PKG_CONFIG_PATH NIX_CFLAGS_COMPILE NIX_LDFLAGS NIX_CC NIX_BINTOOLS RUSTFLAGS CARGO_PROFILE_RELEASE_OPT_LEVEL; do
        if [[ -n ${!name:-} ]]; then args+=(--setenv "$name" "${!name}"); fi
    done
    timeout 1800 bwrap "${args[@]}" /run/current-system/sw/bin/prlimit \
        --cpu=1200 --as=12884901888 --nproc=512 --nofile=1024 --fsize=1073741824 -- "$@"
}

native_build() {
    CARGO_PROFILE_RELEASE_OPT_LEVEL=3 sandbox "$native_rustc" cargo build --locked --offline --release -p checkstwo-probe
}
generate() {
    sandbox "$native_rustc" "$here/target/release/checkstwo-probe" generate "$here/target/fixtures" "$here/target/preprocessed-root.bin"
}
guest_build() {
    [[ $(wc -c < "$here/target/preprocessed-root.bin") == 32 ]] || { echo 'Generate the fixed selector root first' >&2; exit 1; }
    RUSTFLAGS='-C link-arg=-zstack-size=1048576 -C link-arg=--initial-memory=8388608 -C link-arg=--max-memory=67108864' \
        sandbox "$guest_rustc" cargo build --locked --offline --release --target wasm32-unknown-unknown -p checkstwo-guest
    bash "$root/experiments/op_checkzkp/optimize.sh" \
        "$here/target/wasm32-unknown-unknown/release/checkstwo_guest.wasm" "$here/target/checkstwo_guest.wasm"
}
measure() {
    sandbox "$native_rustc" "$here/target/release/checkstwo-probe" measure "$here/target/checkstwo_guest.wasm" "$here/target/fixtures" "$@"
}

case ${1:-all} in
    fetch) cargo fetch --locked --manifest-path "$here/Cargo.toml" ;;
    native-build) native_build ;;
    generate) generate ;;
    guest-build) guest_build ;;
    measure) measure ;;
    diagnostic) measure --diagnostic ;;
    test) sandbox "$native_rustc" cargo test --locked --offline --release -p checkstwo-prover --lib ;;
    all) native_build; generate; guest_build; measure ;;
    *) echo 'usage: run.sh [fetch|native-build|generate|guest-build|measure|diagnostic|test|all]' >&2; exit 2 ;;
esac
