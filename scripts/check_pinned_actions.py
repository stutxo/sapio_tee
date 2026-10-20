"""Fail if any GitHub Actions `uses:` reference is not pinned to a commit SHA.

Mutable tags can be repointed; a 40-hex commit cannot. Pin with the tag in a
trailing comment, e.g. `uses: actions/checkout@<sha> # v5`. Local references
(`uses: ./...`) are exempt — but composite local action definition files
(action.yml/action.yaml anywhere in the tree, conventionally .github/actions/)
can themselves contain `uses:` references, so those files are scanned too.
Quoted keys and flow mappings (`- {"uses": ...}`, `- "uses": ...`, `uses :`)
are the same YAML property and are scanned too.
Exits 1 and lists every violation otherwise.
"""

import re
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
USES = re.compile(
    r"""^\s*-?\s*(?:\{\s*)?["']?uses["']?\s*:\s*["']?([^\s"'#},]+)"""
)
# Any other spelling of the `uses` key that the matcher above did not consume
# must fail closed rather than being silently skipped.
USES_SHAPE = re.compile(r"""(?i)(?:^|[\s{,])["']?uses["']?\s*:""")

def scan_files():
    workflows = Path(".github/workflows")
    if workflows.is_dir():
        yield from sorted(workflows.glob("*.y*ml"))
    # Composite action definitions can carry their own `uses:` steps.
    # rglob also reaches .github/workflows/action.yml; dedupe downstream.
    yield from sorted(Path(".").rglob("action.yml"))
    yield from sorted(Path(".").rglob("action.yaml"))

def main() -> int:
    failures = []
    for workflow in dict.fromkeys(scan_files()):
        for line_number, line in enumerate(workflow.read_text().splitlines(), 1):
            match = USES.match(line)
            if not match:
                # Fail closed on any uses: shape the regex cannot parse rather
                # than silently skipping it.
                if USES_SHAPE.search(line) and not line.lstrip().startswith("#"):
                    failures.append(f"{workflow}:{line_number}: unparsable uses: line {line.strip()!r}")
                continue
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            _, _, ref = reference.rpartition("@")
            if not SHA.match(ref):
                failures.append(f"{workflow}:{line_number}: unpinned action {reference!r}")
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print("pin every action to a full commit SHA (keep the tag as a # comment)", file=sys.stderr)
        return 1
    print("all action references are commit-SHA pinned")
    return 0

if __name__ == "__main__":
    sys.exit(main())
