#!/usr/bin/env python3
"""Select and copy reviewed build inputs before any Nix path import.

Planning is local only. Candidate discovery is NOT a confidentiality check:
review every selected path and its contents before using create --reviewed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys


LAYOUT = {"tee": "sapio_tee"}
MANIFEST = "source-manifest.json"
# A positive list for discovery, not authorization to publish these files.
# Other required build inputs must be selected explicitly with --include.
CODE_SUFFIXES = {".rs", ".wasm", ".wat", ".py", ".sh"}
BUILD_NAMES = {"Cargo.toml", "Cargo.lock", "flake.nix", "flake.lock", "enclaver.yaml"}


def relative_path(value):
    if not isinstance(value, str) or not value:
        raise ValueError("source paths must be nonempty relative POSIX paths")
    path = PurePosixPath(value)
    if not path.parts or path.is_absolute() or str(path) != value or any(part in (".", "..") for part in path.parts):
        raise ValueError(f"invalid source path: {value!r}")
    if value == MANIFEST:
        raise ValueError(f"{MANIFEST} is reserved for snapshot provenance")
    return path


def file_content(root, relative):
    path = root
    parts = relative_path(relative).parts
    for index, part in enumerate(parts):
        path = path / part
        mode = path.lstat().st_mode
        if index < len(parts) - 1:
            if not stat.S_ISDIR(mode):
                raise ValueError(f"source parent is not a real directory: {path}")
        elif not stat.S_ISREG(mode):
            raise ValueError(f"source is not a regular file: {path}")
    # Hash and copy the same bytes. A changed source cannot silently replace
    # the contents whose digest the operator reviewed.
    with path.open("rb") as source:
        data = source.read()
        executable = bool(os.fstat(source.fileno()).st_mode & 0o111)
    return data, executable


def entry_for(root, relative):
    data, executable = file_content(root, relative)
    return {"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "executable": executable}


def entries_by_path(entries):
    if not isinstance(entries, list):
        raise ValueError("files must be an explicit array")
    result = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "executable"}:
            raise ValueError("invalid source inventory entry")
        name = str(relative_path(entry["path"]))
        if name in result or type(entry["executable"]) is not bool:
            raise ValueError("duplicate source path or invalid executable flag")
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("invalid source digest")
        result[name] = entry
    if "Cargo.toml" not in result:
        raise ValueError("each snapshot must include its Cargo.toml")
    return result


def write_json(path, value):
    # Neither plans nor snapshots overwrite previous provenance.
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def plan_sources(roots, includes):
    explicit = {name: set() for name in LAYOUT}
    for include in includes:
        name, separator, relative = include.partition(":")
        if not separator or name not in explicit:
            raise ValueError("--include must be tee:PATH")
        explicit[name].add(str(relative_path(relative)))
    repositories = {}
    for name, supplied_root in roots.items():
        root = Path(supplied_root).resolve(strict=True)
        # Only query Git; do not stage files or use a commit as source content.
        # Untracked, nonignored implementation files are included as candidates.
        listing = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            check=True, stdout=subprocess.PIPE,
        ).stdout
        candidates = set(explicit[name])
        for raw in listing.split(b"\0"):
            if not raw:
                continue
            relative = raw.decode("utf-8")
            path = relative_path(relative)
            if path.suffix in CODE_SUFFIXES or path.name in BUILD_NAMES:
                # A deleted tracked source is not part of the current worktree.
                if (root / relative).exists() or (root / relative).is_symlink():
                    candidates.add(relative)
        repositories[name] = {
            "root": str(root),
            "files": [entry_for(root, relative) for relative in sorted(candidates)],
        }
    return {"version": 1, "repositories": repositories}


def create_snapshots(plan, destination):
    if not isinstance(plan, dict) or set(plan) != {"version", "repositories"} or type(plan["version"]) is not int or plan["version"] != 1:
        raise ValueError("unsupported source plan")
    if not isinstance(plan["repositories"], dict) or set(plan["repositories"]) != set(LAYOUT):
        raise ValueError("source plan must select only tee; dependencies use public git pins")
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700)  # Must be a fresh, private directory.
    for name, layout in LAYOUT.items():
        repository = plan["repositories"][name]
        if not isinstance(repository, dict) or set(repository) != {"root", "files"}:
            raise ValueError("invalid repository inventory")
        root = Path(repository["root"]).resolve(strict=True)
        if destination.is_relative_to(root):
            raise ValueError("snapshots must be outside the source worktrees")
        entries = entries_by_path(repository["files"])
        snapshot = destination / layout
        snapshot.mkdir(parents=True, mode=0o700)
        for relative, expected in entries.items():
            data, executable = file_content(root, relative)
            if hashlib.sha256(data).hexdigest() != expected["sha256"] or executable != expected["executable"]:
                raise ValueError(f"source changed after review: {name}:{relative}; make and review a new plan")
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(data)
            target.chmod(0o555 if executable else 0o444)
        write_json(snapshot / MANIFEST, {"version": 1, "files": repository["files"]})
        (snapshot / MANIFEST).chmod(0o444)
        for directory in snapshot.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o555)
        snapshot.chmod(0o555)
    # A failure leaves only a private partial directory. Never import it into Nix.
    return destination


def verify_snapshot(snapshot):
    """Reject changed, extra, missing or linked files before importing a snapshot."""
    snapshot = Path(snapshot).resolve(strict=True)
    provenance = snapshot / MANIFEST
    if not stat.S_ISREG(provenance.lstat().st_mode):
        raise ValueError("snapshot provenance must be a regular file")
    with provenance.open(encoding="utf-8") as source:
        manifest = json.load(source)
    if not isinstance(manifest, dict) or set(manifest) != {"version", "files"} or type(manifest["version"]) is not int or manifest["version"] != 1:
        raise ValueError("unsupported snapshot provenance")
    entries = entries_by_path(manifest["files"])
    expected_dirs = {str(parent) for name in entries for parent in PurePosixPath(name).parents if str(parent) != "."}
    actual = set()
    for path in snapshot.rglob("*"):
        relative = path.relative_to(snapshot).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            if relative not in expected_dirs:
                raise ValueError(f"unreviewed snapshot directory: {path}")
        elif stat.S_ISREG(mode):
            actual.add(relative)
        else:
            raise ValueError(f"snapshot contains a link or special file: {path}")
    if actual != set(entries) | {MANIFEST}:
        raise ValueError(f"snapshot has missing or unreviewed files: {snapshot}")
    for relative, expected in entries.items():
        if entry_for(snapshot, relative) != expected:
            raise ValueError(f"snapshot differs from reviewed inventory: {snapshot / relative}")
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="write a local candidate inventory; does not invoke Nix")
    for name in LAYOUT:
        plan.add_argument(f"--{name}", required=True, type=Path)
    plan.add_argument("--include", action="append", default=[], help="explicit additional repo:relative/path")
    plan.add_argument("--output", required=True, type=Path)
    create = commands.add_parser("create", help="copy exactly the reviewed inventory, checking every digest")
    create.add_argument("--plan", required=True, type=Path)
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--reviewed", required=True, action="store_true", help="confirm review of every selected file and its contents for public disclosure")
    verify = commands.add_parser("verify", help="check snapshots before Nix imports them")
    verify.add_argument("snapshots", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            roots = {name: getattr(args, name) for name in LAYOUT}
            write_json(args.output, plan_sources(roots, args.include))
            print(f"Review all paths AND contents selected by {args.output}; remove any private/unneeded files.")
        elif args.command == "create":
            with args.plan.open(encoding="utf-8") as source:
                plan = json.load(source)
            print(create_snapshots(plan, args.output))
        else:
            for snapshot in args.snapshots:
                print(verify_snapshot(snapshot))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"source_snapshot.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
