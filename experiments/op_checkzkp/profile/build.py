#!/usr/bin/env python3
"""Build an instrumented source copy, never the scored verifier or Cargo cache.

Instrumentation ONLY: marker calls and compiler scheduling around them add fuel
and can perturb optimization. Phase totals are approximate diagnostics, not the
uninstrumented verification_fuel score. Requires Python 3.11+ and the pinned Nix
Rust toolchain; all Cargo operations are offline.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
if sys.version_info < (3, 11):
    sys.exit("Profiling build requires Python 3.11 or newer")

import tomllib


EXPERIMENT = Path(__file__).resolve().parents[1]
REPOSITORY = EXPERIMENT.parents[1]
TARGET = EXPERIMENT / "target"
WORKSPACE = TARGET / "profile-workspace"
BUILD_TARGET = TARGET / "profile-build"
ARTIFACT = TARGET / "checkzkp_guest.profile.wasm"
WASM_TARGET = "wasm32-unknown-unknown"
RUST_VERSION = "1.98.1"
RUSTFLAGS = (
    "-C link-arg=-zstack-size=1048576 "
    "-C link-arg=--initial-memory=8388608 "
    "-C link-arg=--max-memory=67108864"
)
BN_CHECKSUM = "72b5bbfa79abbae15dd642ea8176a21a635ff3c00059961d1ea27ad04e5b441c"
RELEASE_PROFILE = {
    "opt-level": 3,
    "lto": True,
    "codegen-units": 1,
    "panic": "abort",
    "strip": "symbols",
}

# Identical import in the two copied crates; no new cryptographic host import.
MARKER = '''// Diagnostic instrumentation ONLY; never use this module for scoring.
// Host markers add overhead, so phase fuel is approximate.
#[link(wasm_import_module = "checkzkp_profile")]
extern "C" {
    #[link_name = "mark"]
    fn checkzkp_profile_mark(phase: i32);
}

#[inline(always)]
fn profile_phase(phase: i32) {
    // The diagnostic host only records remaining fuel; it must not reenter WASM.
    unsafe { checkzkp_profile_mark(phase) }
}

'''

PAIRING_BATCH = '''pub fn pairing_batch(ps: &[G1], qs: &[G2]) -> Fq12 {
    let mut p_affines: Vec<AffineG<G1Params>> = Vec::new();
    let mut q_precomputes: Vec<G2Precomp> = Vec::new();
    for (p, q) in ps.into_iter().zip(qs.into_iter()) {

        let p_affine = p.to_affine();
        let q_affine = q.to_affine();
        let exists = match(p_affine, q_affine)
        {
            (None, _) | (_, None) => false,
            (Some(_p_affine), Some(_q_affine)) => true,
        };

        if exists {
            p_affines.push(p.to_affine().unwrap());
            q_precomputes.push(q.to_affine().unwrap().precompute());
        }
    }
    if q_precomputes.len() == 0 {
        return Fq12::one();
    }
    miller_loop_batch(&q_precomputes, &p_affines).final_exponentiation().expect("miller loop cannot produce zero")
}
'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unique(text, anchor, label):
    count = text.count(anchor)
    require(count == 1, f"Source drift at {label}: expected one exact anchor, found {count}")


def replace_once(text, anchor, replacement, label):
    unique(text, anchor, label)
    return text.replace(anchor, replacement, 1)


def instrument_guest(source):
    source = replace_once(
        source,
        '#[path = "../../../../examples/vault/guest.rs"]\nmod guest;\n',
        '#[path = "abi.rs"]\nmod guest;\n\n' + MARKER,
        "guest shared ABI module",
    )
    source = replace_once(
        source,
        ') -> i32 {\n    guest::evaluate(\n',
        ') -> i32 {\n    profile_phase(0);\n    let result = guest::evaluate(\n',
        "guest ABI entry",
    )
    source = replace_once(
        source,
        '        evaluate,\n    )\n}\n',
        '        evaluate,\n    );\n    profile_phase(8);\n    result\n}\n',
        "guest ABI return (including rejected and malformed paths)",
    )
    for anchor, phase, label in [
        ('    let mut proof = Reader::new(&witness[..PROOF_BYTES]);\n', 1, "proof decoding"),
        ('    let mut transcript = [0u8; DOMAIN.len() + 32];\n', 2, "transaction digest"),
        ('    let mut vk = Reader::new(&parameters[..VK_BYTES]);\n', 3, "VK decoding"),
        ('    // Six public Fr values: the big-endian 128-bit halves of C, T, A.\n', 4, "public input scalars"),
        ('    if !vk.is_finished() {\n', 3, "VK trailing bytes check"),
        ('    // A computed IC accumulator may be zero; encoded points may never be infinity.\n', 5, "pairing preparation"),
    ]:
        source = replace_once(source, anchor, f"    profile_phase({phase});\n" + anchor, label)
    # Keep scalar construction BEFORE point decoding, exactly as in the original.
    # Only separate the existing read from its multiplication; no checks change.
    return replace_once(
        source,
        '            ic = ic + read_g1(&mut vk)? * public;\n',
        '            profile_phase(3);\n'
        '            let point = read_g1(&mut vk)?;\n'
        '            profile_phase(4);\n'
        '            ic = ic + point * public;\n',
        "IC decoding versus multiplication",
    )


def instrument_groups(source):
    body = replace_once(
        PAIRING_BATCH,
        '        return Fq12::one();\n',
        '        profile_phase(8);\n        return Fq12::one();\n',
        "pairing empty batch return",
    )
    body = replace_once(
        body,
        '    miller_loop_batch(&q_precomputes, &p_affines).final_exponentiation().expect("miller loop cannot produce zero")\n',
        '    profile_phase(6);\n'
        '    let miller = miller_loop_batch(&q_precomputes, &p_affines);\n'
        '    profile_phase(7);\n'
        '    let result = miller.final_exponentiation().expect("miller loop cannot produce zero");\n'
        '    profile_phase(8);\n'
        '    result\n',
        "Miller loop and final exponentiation",
    )
    # Match the entire original batch implementation, including infinity handling
    # and repeated affine conversion. Deliberately do not optimize any of it.
    return replace_once(source, PAIRING_BATCH, MARKER + body, "substrate-bn groups::pairing_batch")


def run(arguments, environment, capture=False):
    result = subprocess.run(
        arguments,
        cwd=REPOSITORY,
        env=environment,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        check=True,
    )
    return result.stdout


def metadata(manifest, environment, locked=True):
    arguments = [
        "cargo", "metadata", "--offline", "--format-version", "1",
        "--filter-platform", WASM_TARGET, "--manifest-path", str(manifest),
    ]
    if locked:
        arguments.append("--locked")
    return json.loads(run(arguments, environment, capture=True))


def package_key(package):
    return package["name"], package["version"], package.get("source")


def one_package(packages, name, version):
    matches = [p for p in packages if p["name"] == name and p["version"] == version]
    require(len(matches) == 1, f"Expected exactly one {name} {version}, found {len(matches)}")
    return matches[0]


def validate_resolution(original, generated, original_lock, generated_lock, guest, bn):
    """Allow pruning and the local BN substitution, never a dependency update.

    Package identity alone is insufficient when the baseline locks two versions
    of a dependency. Compare resolved dependency edges too, to prevent switching
    to another already-locked version. A standalone guest may omit features and
    edges activated only by the native workspace members, but must add none.
    """
    original_keys = {package_key(p): p["id"] for p in original["packages"]}
    local = {
        (WORKSPACE / "guest/Cargo.toml").resolve(): guest,
        (WORKSPACE / "substrate-bn/Cargo.toml").resolve(): bn,
    }
    mapped = {}
    for package in generated["packages"]:
        key = package_key(package)
        if package.get("source") is None:
            expected = local.get(Path(package["manifest_path"]).resolve())
            require(expected is not None, f"Unexpected generated path dependency: {package['manifest_path']}")
            require(key[:2] == package_key(expected)[:2], f"Path package version drift: {key}")
            key = package_key(expected)
        require(key in original_keys, f"Dependency resolution drift: {key}")
        mapped[package["id"]] = original_keys[key]

    copied_bn = one_package(generated["packages"], "substrate-bn", "0.6.0")
    require(
        Path(copied_bn["manifest_path"]).resolve() == (WORKSPACE / "substrate-bn/Cargo.toml").resolve(),
        "Generated guest did not resolve the instrumented substrate-bn copy",
    )
    original_nodes = {n["id"]: n for n in original["resolve"]["nodes"]}
    for node in generated["resolve"]["nodes"]:
        expected = original_nodes[mapped[node["id"]]]
        require(
            set(node["features"]) <= set(expected["features"]),
            f"New dependency features in {node['id']}",
        )
        expected_edges = {
            (dep["name"], dep["pkg"]): {(kind["kind"], kind["target"]) for kind in dep["dep_kinds"]}
            for dep in expected["deps"]
        }
        for dep in node["deps"]:
            edge = (dep["name"], mapped[dep["pkg"]])
            kinds = {(kind["kind"], kind["target"]) for kind in dep["dep_kinds"]}
            require(
                edge in expected_edges and kinds <= expected_edges[edge],
                f"Dependency edge drift: {node['id']} -> {dep['name']}",
            )

    locked = {package_key(p): p for p in original_lock["package"]}
    for package in generated_lock["package"]:
        key = package_key(package)
        if key == ("substrate-bn", "0.6.0", None):
            require("checksum" not in package, "Unexpected checksum on path substrate-bn")
            continue
        require(key in locked, f"Generated lock contains an unpinned dependency: {key}")
        require(
            package.get("checksum") == locked[key].get("checksum"),
            f"Dependency checksum drift: {key}",
        )


def main():
    manifest_path = EXPERIMENT / "Cargo.toml"
    lock_path = EXPERIMENT / "Cargo.lock"
    guest_manifest = EXPERIMENT / "guest/Cargo.toml"
    guest_source_path = EXPERIMENT / "guest/src/lib.rs"
    helper_path = REPOSITORY / "examples/vault/guest.rs"
    # Snapshot these inputs before generating anything. The build must not silently
    # mix revisions if another process edits the experiment while it is running.
    inputs = {
        path: path.read_bytes()
        for path in [manifest_path, lock_path, guest_manifest, guest_source_path, helper_path, EXPERIMENT / "run.sh"]
    }
    workspace_manifest = tomllib.loads(inputs[manifest_path].decode())
    require(workspace_manifest["profile"]["release"] == RELEASE_PROFILE, "Baseline release profile drift")
    run_script = inputs[EXPERIMENT / "run.sh"].decode()
    unique(run_script, 'opt_level="${CHECKZKP_OPT_LEVEL:-s}"\n', "run.sh default optimization")
    unique(run_script, f'RUSTFLAGS="{RUSTFLAGS}" \\\n', "run.sh linker flags")
    unique(run_script, f'if [[ "$compiler_version" != "rustc {RUST_VERSION} "* ]]; then\n', "run.sh Rust toolchain")
    require('/target/' in (EXPERIMENT / ".gitignore").read_text().splitlines(), "Generated target directory must be ignored")

    environment = os.environ.copy()
    # CARGO_ENCODED_RUSTFLAGS takes precedence over RUSTFLAGS. Do not let the
    # caller accidentally instrument/build with a different codegen configuration.
    environment.pop("CARGO_ENCODED_RUSTFLAGS", None)
    environment.update({
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(BUILD_TARGET),
        "CARGO_PROFILE_RELEASE_OPT_LEVEL": "s",
        "CARGO_PROFILE_RELEASE_LTO": "true",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
        "CARGO_PROFILE_RELEASE_PANIC": "abort",
        "CARGO_PROFILE_RELEASE_STRIP": "symbols",
        "RUSTFLAGS": RUSTFLAGS,
    })
    compiler = run(["rustc", "--version"], environment, capture=True).strip()
    require(compiler.startswith(f"rustc {RUST_VERSION} "), f"Expected rustc {RUST_VERSION}; use the pinned nix develop shell (found {compiler})")

    original_lock = tomllib.loads(inputs[lock_path].decode())
    locked_bn = one_package(original_lock["package"], "substrate-bn", "0.6.0")
    require(locked_bn.get("source") is None, "Expected the tracked experimental substrate-bn fork")
    original = metadata(manifest_path, environment)
    bn = one_package(original["packages"], "substrate-bn", "0.6.0")
    guest = one_package(original["packages"], "checkzkp-guest", "0.1.0")
    require(package_key(bn) == package_key(locked_bn), "Metadata did not resolve the locked substrate-bn package")
    require(Path(guest["manifest_path"]).resolve() == guest_manifest, "Unexpected baseline guest package")
    bn_directory = Path(bn["manifest_path"]).resolve().parent
    require(bn_directory == EXPERIMENT / "vendor/substrate-bn", "Unexpected BN source directory")
    provenance = tomllib.loads((bn_directory / "Cargo.toml").read_text())
    require(provenance["package"]["metadata"]["upstream"]["registry-checksum"] == BN_CHECKSUM,
            "Vendored substrate-bn upstream provenance drift")
    groups = bn_directory / "src/groups/mod.rs"
    # Validate anchors before replacing any generated workspace from a prior run.
    generated_guest = instrument_guest(inputs[guest_source_path].decode())
    generated_groups = instrument_groups(groups.read_text())
    for license_name in ["LICENSE-APACHE", "LICENSE-MIT"]:
        require((bn_directory / license_name).is_file(), f"Missing substrate-bn license: {license_name}")

    require(not WORKSPACE.is_symlink(), "Refusing a symlinked profile workspace")
    if WORKSPACE.exists():
        shutil.rmtree(WORKSPACE)
    (WORKSPACE / "guest/src").mkdir(parents=True)
    shutil.copytree(bn_directory, WORKSPACE / "substrate-bn")
    (WORKSPACE / "substrate-bn/src/groups/mod.rs").write_text(generated_groups)
    (WORKSPACE / "guest/Cargo.toml").write_bytes(inputs[guest_manifest])
    (WORKSPACE / "guest/src/lib.rs").write_text(generated_guest)
    (WORKSPACE / "guest/src/abi.rs").write_bytes(inputs[helper_path])
    (WORKSPACE / "Cargo.toml").write_text('''# Generated diagnostic workspace; never used for verification_fuel scoring.
[workspace]
resolver = "2"
members = ["guest"]
exclude = ["substrate-bn"]

[patch.crates-io]
substrate-bn = { path = "substrate-bn" }

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = "symbols"
''')
    generated_manifest = WORKSPACE / "Cargo.toml"
    generated_lock_path = WORKSPACE / "Cargo.lock"
    generated_lock_path.write_bytes(inputs[lock_path])
    # Only this copied lock may change: Cargo prunes native workspace packages and
    # replaces the registry BN package with its same-version instrumented path.
    # Refuse any other version/source/checksum or active dependency-edge change.
    generated = metadata(generated_manifest, environment, locked=False)
    generated_lock = tomllib.loads(generated_lock_path.read_text())
    validate_resolution(original, generated, original_lock, generated_lock, guest, bn)
    run([
        "cargo", "build", "--offline", "--locked", "--manifest-path", str(generated_manifest),
        "-p", "checkzkp-guest", "--release", "--target", WASM_TARGET,
        "--target-dir", str(BUILD_TARGET),
    ], environment)
    for path, contents in inputs.items():
        require(path.read_bytes() == contents, f"Baseline input changed during profiling build: {path}")
    built = BUILD_TARGET / WASM_TARGET / "release/checkzkp_guest.wasm"
    require(built.is_file(), f"Cargo did not produce {built}")
    with built.open("rb") as module:
        require(module.read(8) == b"\x00asm\x01\x00\x00\x00", "Profiling artifact is not a WASM module")
    staged = WORKSPACE / ARTIFACT.name
    shutil.copyfile(built, staged)
    staged.replace(ARTIFACT)
    print(f"Diagnostic-only artifact: {ARTIFACT}")
    print("Marker overhead is included; phase fuel is approximate and must not replace verification_fuel.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Profiling build failed: {error}", file=sys.stderr)
        sys.exit(1)
