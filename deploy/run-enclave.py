#!/usr/bin/env python3
"""Run an existing aarch64 EIF on a prepared Graviton Nitro parent; never create AWS resources."""

import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess


def positive_i32(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if not 0 < number <= 2**31 - 1:
        raise argparse.ArgumentTypeError("must be between 1 and 2147483647")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eif", required=True, type=Path)
    parser.add_argument("--runner", required=True, help="path to the pinned enclaver executable")
    parser.add_argument("--cpu-count", required=True, type=positive_i32)
    parser.add_argument("--memory-mib", required=True, type=positive_i32)
    args = parser.parse_args()
    manifest = Path(__file__).resolve().parent.parent / "enclaver.yaml"
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        parser.error("only aarch64 (Graviton) Linux Nitro parent instances are supported")
    if args.cpu_count % 2:
        parser.error("aarch64 Nitro enclaves require an even CPU count (whole physical cores)")
    if not args.eif.is_file() or not manifest.is_file():
        parser.error("EIF or repository enclaver.yaml is missing")
    runner = shutil.which(args.runner)
    if runner is None:
        parser.error("--runner must identify an executable pinned enclaver binary")
    for command in ("nitro-cli", "systemctl"):
        if shutil.which(command) is None:
            parser.error(f"{command} is required on the prepared parent instance")
    if not Path("/dev/nitro_enclaves").exists():
        parser.error("/dev/nitro_enclaves is absent; enable Nitro Enclaves and its driver")
    if not os.access("/dev/nitro_enclaves", os.R_OK | os.W_OK):
        parser.error("no read/write access to /dev/nitro_enclaves; configure ne group membership")
    try:
        subprocess.run(["nitro-cli", "--version"], check=True)
        subprocess.run(
            ["systemctl", "is-active", "--quiet", "nitro-enclaves-allocator.service"],
            check=True,
        )
        subprocess.run(["nitro-cli", "describe-enclaves"], check=True)
    except subprocess.CalledProcessError as error:
        parser.error(f"Nitro CLI/allocator preflight failed (exit {error.returncode})")
    print(
        "The allocator must reserve the requested CPUs and MiB. The runner exposes "
        "ports 8000/8367 on ALL parent interfaces: restrict firewall/security groups "
        "before launch. Debug mode is disabled.",
        flush=True,
    )
    # Upstream CLI has no 'run' subcommand; --memory-mb is in MiB per nitro-cli.
    os.execv(runner, [
        runner,
        "--eif-file", str(args.eif.resolve()),
        "--manifest-file", str(manifest),
        "--cpu-count", str(args.cpu_count),
        "--memory-mb", str(args.memory_mib),
    ])


if __name__ == "__main__":
    main()
