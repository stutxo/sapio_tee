#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "$root"

usage() {
    echo "usage: bash experiments/op_checkzkp/build-mcl.sh [fetch | build [Oz|Os] [cpp|llvm]]" >&2
    exit 2
}
fail() {
    echo "build-mcl: $*" >&2
    exit 1
}
mode="${1:-build}"
opt="${2:-Oz}"
backend="${3:-cpp}"
case "$mode" in
    fetch) [[ $# -eq 1 ]] || usage ;;
    build)
        [[ $# -le 3 && ( "$opt" == Oz || "$opt" == Os ) \
            && ( "$backend" == cpp || "$backend" == llvm ) ]] || usage ;;
    *) usage ;;
esac
command -v nix >/dev/null || fail "Nix is required; use the repository's pinned development shell."
if [[ "${CHECKZKP_MCL_SHELL:-}" != 1 ]]; then
    # Resolving the toolchain is always offline; only the explicit fetch below
    # accesses the network. Never update the repository's flake lock.
    exec nix develop --offline --no-update-lock-file --command \
        env CHECKZKP_MCL_SHELL=1 bash "$root/experiments/op_checkzkp/build-mcl.sh" "$@"
fi
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0
umask 022
for tool in sha256sum tar mktemp mkdir cp mv rm readlink; do
    command -v "$tool" >/dev/null || fail "Missing prerequisite in pinned Nix shell: $tool"
done

revision=cbb18eb08b86129cf936a6436b5e6c68a2ce8ddf
sha256=1eaa35a4eb6028d5818d7c41f67eb3d69b3083a298e474a6b47fbd955f21e983
experiment="$root/experiments/op_checkzkp"
cache="$experiment/target/mcl-source"
archive="$cache/mcl-$revision.tar.gz"
output="$experiment/target/mcl-comparison"
adapter="$experiment/mcl-guest"
scratch=
cleanup() {
    if [[ -n "$scratch" ]]; then rm -rf -- "$scratch"; fi
}
trap cleanup EXIT
verify_archive() {
    printf '%s  %s\n' "$sha256" "$1" | sha256sum --check --status \
        || fail "MCL archive SHA256 mismatch; expected $sha256. No compilation performed."
}
mkdir -p -- "$cache"
if [[ "$mode" == fetch ]]; then
    command -v curl >/dev/null || fail "Missing curl in the pinned Nix shell."
    scratch="$(mktemp -d "$cache/fetch.XXXXXXXX")"
    curl --fail --location --proto '=https' --proto-redir '=https' \
        "https://codeload.github.com/herumi/mcl/tar.gz/$revision" \
        --output "$scratch/mcl.tar.gz"
    verify_archive "$scratch/mcl.tar.gz"
    mv -- "$scratch/mcl.tar.gz" "$archive"
    printf 'Verified MCL v4.10 source archive: %s\n' "$archive"
    printf 'Build offline: bash experiments/op_checkzkp/build-mcl.sh build\n'
    exit 0
fi
[[ -f "$archive" ]] || fail "Missing cached MCL archive. First run: bash experiments/op_checkzkp/build-mcl.sh fetch"
verify_archive "$archive"
for tool in clang clang++ rustc; do
    command -v "$tool" >/dev/null || fail "Missing prerequisite in pinned Nix shell: $tool"
done
[[ "$(rustc --version)" == "rustc 1.98.1 "* ]] \
    || fail "Expected the repository's pinned rustc 1.98.1."
for compiler in clang clang++; do
    [[ "$("$compiler" --version)" == "clang version 21.1.8"$'\n'* ]] \
        || fail "Expected pinned $compiler 21.1.8."
done
# The Nix host wrapper injects x86-only hardening flags. Use its pinned,
# unwrapped compiler for freestanding WASM, not a second compiler/toolchain.
clang_wrapper="$(dirname "$(dirname "$(readlink -f "$(command -v clang)")")")"
[[ -f "$clang_wrapper/nix-support/orig-cc" ]] \
    || fail "Missing Nix clang provenance: $clang_wrapper/nix-support/orig-cc"
read -r clang_root < "$clang_wrapper/nix-support/orig-cc"
wasm_cc="$clang_root/bin/clang"
wasm_cxx="$clang_root/bin/clang++"
[[ -x "$wasm_cc" && -x "$wasm_cxx" ]] || fail "Missing unwrapped pinned clang."
# rust-lld is shipped with pinned rustc; no separate LLD download/bootstrap.
linker="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
[[ -x "$linker" ]] || fail "Missing bundled rust-lld: $linker"
[[ "$("$linker" -flavor wasm --version)" == "LLD 22.1.8 "* ]] \
    || fail "Expected rustc 1.98.1's bundled LLD 22.1.8."
for file in codec.hpp guest.cpp prepare.cpp; do
    [[ -f "$adapter/$file" ]] || fail "Missing MCL adapter: $adapter/$file"
done
[[ -f "$experiment/optimize.sh" ]] || fail "Missing pinned Binaryen optimization script."
# Fail before compiling if the pinned optimizer is not available offline.
[[ "$(nix shell --offline --inputs-from "$root" nixpkgs#binaryen --command wasm-opt --version)" == "wasm-opt version 132" ]] \
    || fail "Expected cached pinned Binaryen 132 (used by optimize.sh)."

# Always extract the verified archive afresh. An edited, previously extracted
# checkout must never become build input. All objects live outside this tree.
scratch="$(mktemp -d "$cache/build.XXXXXXXX")"
tar --extract --gzip --file "$archive" --directory "$scratch" --no-same-owner
source="$scratch/mcl-$revision"
wasm_runtime="$source/src/wasm"
mkdir -p -- "$output/native" "$output/wasm"
common=(
    "-$opt" -DNDEBUG -fvisibility=hidden -ffunction-sections -fdata-sections
    -DMCL_FP_BIT=256 -DMCL_FR_BIT=256 -DMCL_DONT_EXPORT -DMCL_STANDALONE
    -DMCL_BINT_ASM=0 -DMCL_MSM=0
    -DCYBOZU_MINIMUM_EXCEPTION
    -I "$source/include" -I "$source/src"
    "-ffile-prefix-map=$source=mcl-$revision"
    "-ffile-prefix-map=$root=."
)
# Match upstream Makefile.wasm: C++03 avoids freestanding <functional> dependencies.
cxx=(-std=c++03 -fno-exceptions -fno-rtti -fno-threadsafe-statics)
# MCL_MSM=0 disables only the optional native AVX512 implementation; ordinary
# public G1 MSM remains available. Native preparation uses portable C++.
clang++ "${common[@]}" "${cxx[@]}" -DMCL_DONT_USE_XBYAK -c "$source/src/fp.cpp" -o "$output/native/fp.o"
clang++ "${common[@]}" "${cxx[@]}" -DMCL_DONT_USE_XBYAK -c "$adapter/prepare.cpp" -o "$output/native/prepare.o"
clang++ "${common[@]}" "${cxx[@]}" -Wl,--gc-sections \
    "$output/native/fp.o" "$output/native/prepare.o" -o "$output/native/prepare"

wasm=(
    --target=wasm32-unknown-unknown -flto -ffreestanding -fno-builtin
    -fno-stack-protector -DMCL_SIZEOF_UNIT=4 -I "$wasm_runtime"
)
# This is the unchanged optional backend from upstream Makefile.wasm, not
# generated or edited arithmetic. MCL_BINT_ASM remains 0 as upstream requires.
llvm_objects=()
if [[ "$backend" == llvm ]]; then
    wasm+=(-DMCL_USE_LLVM=1)
    for unit in base32 bint32; do
        "$wasm_cc" --target=wasm32-unknown-unknown "-$opt" -flto -Wno-override-module \
            -c "$source/src/$unit.ll" -o "$output/wasm/$unit.o"
        llvm_objects+=("$output/wasm/$unit.o")
    done
fi
"$wasm_cxx" "${common[@]}" "${wasm[@]}" "${cxx[@]}" -nostdinc++ \
    -c "$source/src/fp.cpp" -o "$output/wasm/fp.o"
"$wasm_cxx" "${common[@]}" "${wasm[@]}" "${cxx[@]}" -nostdinc++ \
    -c "$adapter/guest.cpp" -o "$output/wasm/guest.o"
# Stock standalone runtime, with upstream Makefile.wasm's allocator options.
# No JS glue, stack helpers, exported allocator, or imported memory is needed.
dlmalloc=(
    -DLACKS_SYS_TYPES_H -DLACKS_FCNTL_H -DLACKS_UNISTD_H -DLACKS_SYS_MMAN_H
    -DLACKS_STRINGS_H -DLACKS_SYS_PARAM_H -DLACKS_SCHED_H -DLACKS_TIME_H
    -DHAVE_MORECORE=1 -DHAVE_MMAP=0 -DNO_MALLOC_STATS=1 -DMORECORE_CONTIGUOUS=0
    '-Dsize_t=unsigned long' -Dptrdiff_t=long -DMALLOC_ALIGNMENT=16 -DUSE_LOCKS=0
)
"$wasm_cc" "${common[@]}" "${wasm[@]}" "${dlmalloc[@]}" \
    -c "$wasm_runtime/dlmalloc.c" -o "$output/wasm/dlmalloc.o"
"$wasm_cc" "${common[@]}" "${wasm[@]}" \
    -c "$wasm_runtime/libc.c" -o "$output/wasm/libc.o"
# The adapter declares its sole SHA256 import explicitly. Undefined symbols
# are otherwise link errors; never use --allow-undefined or --import-memory.
# Constructors are explicitly called once inside the metered guest entrypoint.
"$linker" -flavor wasm --no-entry --gc-sections --strip-all --lto-O3 \
    --export-memory --export=sapio_alloc_v1 --export=sapio_evaluate_v1 \
    --initial-memory=8388608 --max-memory=67108864 -z stack-size=1048576 \
    "$output/wasm/fp.o" "$output/wasm/guest.o" \
    "$output/wasm/dlmalloc.o" "$output/wasm/libc.o" \
    "${llvm_objects[@]}" \
    -o "$output/mcl.raw.wasm"
bash "$experiment/optimize.sh" "$output/mcl.raw.wasm" "$output/mcl.optimized.wasm"
# Keep upstream's required redistribution notice beside the binary artifacts.
cp -- "$source/COPYRIGHT" "$output/MCL-COPYRIGHT"
# Publish only after both native and WASM builds have succeeded.
mv -- "$output/native/prepare" "$output/prepare"
mv -- "$output/mcl.optimized.wasm" "$output/mcl.wasm"
printf 'MCL v4.10 %s, clang 21.1.8, rust-lld 22.1.8, Binaryen 132, -%s, %s backend\n' "$revision" "$opt" "$backend"
printf 'Native preparer: %s\nGuest: %s\n' "$output/prepare" "$output/mcl.wasm"
