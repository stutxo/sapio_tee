#!/usr/bin/env python3
"""Build the locked deployment artifacts for Terraform's external data source."""

import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile


def run(command, repository):
    # Nix's progress/build diagnostics stay on stderr; only its structured result
    # is captured. Terraform must receive exactly one JSON object on stdout.
    return subprocess.run(
        command,
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout


def build(repository, roots, package):
    result = json.loads(run([
        "nix", "build",
        "--extra-experimental-features", "nix-command flakes",
        "--no-update-lock-file", "--no-write-lock-file",
        "--json", "--out-link", str(roots / package),
        f".#{package}",
    ], repository))
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise ValueError(f"#{package}: Nix did not return exactly one build result")
    outputs = result[0].get("outputs")
    if not isinstance(outputs, dict) or not isinstance(outputs.get("out"), str):
        raise ValueError(f"#{package}: Nix did not return an 'out' store path")
    output = Path(outputs["out"])
    if not output.is_absolute() or not output.is_dir():
        raise ValueError(f"#{package}: invalid output directory: {output}")
    return output.resolve(strict=True)


def artifact(output, relative):
    path = (output / relative).resolve(strict=True)
    if not path.is_relative_to(output) or not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"missing, empty, or out-of-output artifact: {output / relative}")
    return path


def measurements(path):
    with path.open("r", encoding="utf-8") as source:
        encoded = source.read(16385)
    if len(encoded) > 16384:
        raise ValueError(f"measurement file is unexpectedly large: {path}")
    values = json.loads(encoded)
    if not isinstance(values, dict):
        raise ValueError(f"measurements must be a flat JSON object: {path}")
    result = {}
    for name in ("PCR0", "PCR1", "PCR2"):
        value = values.get(name)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{96}", value):
            raise ValueError(f"{path}: {name} must be exactly 96 hexadecimal characters")
        if int(value, 16) == 0:
            raise ValueError(f"{path}: {name} is zero; debug-mode measurements are forbidden")
        result[name.lower()] = value.lower()
    return result


def check_runner(path):
    if not os.access(path, os.X_OK):
        raise ValueError(f"runner is not executable: {path}")
    with path.open("rb") as source:
        size = os.fstat(source.fileno()).st_size
        header = source.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError(f"runner must be an ELF64 little-endian executable: {path}")
        elf_type, machine = struct.unpack_from("<HH", header, 16)
        if machine != 183 or elf_type not in (2, 3):
            raise ValueError(f"runner must be an AArch64 executable: {path}")
        phoff = struct.unpack_from("<Q", header, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", header, 54)
        if phentsize != 56 or not 1 <= phnum <= 1024 or phoff < 64 or phoff + phnum * 56 > size:
            raise ValueError(f"runner has an invalid ELF program-header table: {path}")
        source.seek(phoff)
        for program_header in struct.iter_unpack("<IIQQQQQQ", source.read(phnum * 56)):
            if program_header[0] in (2, 3):  # PT_DYNAMIC / PT_INTERP
                raise ValueError(f"unexpected dynamic linking in the pinned static runner: {path}")


def main():
    try:
        query = json.load(sys.stdin)
        if not isinstance(query, dict) or not isinstance(query.get("repository_root"), str):
            raise ValueError("external query must contain a string repository_root")
        if not query["repository_root"]:
            raise ValueError("repository_root must not be empty")
        repository = Path(query["repository_root"]).resolve(strict=True)
        if not repository.is_dir():
            raise ValueError("repository_root must be a directory")
        for name in ("flake.nix", "flake.lock"):
            if not (repository / name).is_file():
                raise ValueError(f"repository_root must contain {name}")

        root_directory = repository / ".local" / "terraform"
        root_directory.mkdir(parents=True, exist_ok=True)
        # Retain independent GC roots: a later plan must not unpin the immutable
        # store paths already recorded by an earlier plan or in Terraform state.
        roots = Path(tempfile.mkdtemp(prefix="build-", dir=root_directory))
        eif_output = build(repository, roots, "eif")
        runner_output = build(repository, roots, "enclaver")
        eif = artifact(eif_output, "sapio_tee.eif")
        runner = artifact(runner_output, "bin/enclaver")
        pcrs = measurements(artifact(eif_output, "pcr.json"))
        check_runner(runner)
        references = run([
            "nix-store", "--query", "--references", str(runner_output),
        ], repository).splitlines()
        if references:
            raise ValueError(
                "runner output has Nix store references and cannot be copied standalone: "
                + ", ".join(references)
            )
        result = {"eif_path": str(eif), "runner_path": str(runner), **pcrs}
        sys.stdout.write(json.dumps(result) + "\n")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"build.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
