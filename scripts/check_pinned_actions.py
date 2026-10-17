"""Fail if any GitHub Actions `uses:` reference is not pinned to a commit SHA.

Mutable tags can be repointed; a 40-hex commit cannot. Pin with the tag in a
trailing comment, e.g. `uses: actions/checkout@<sha> # v5`. Local actions
(`uses: ./...`) are exempt. Exits 1 and lists every violation otherwise.
"""

import re
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")

def main() -> int:
    workflows_dir = Path(".github/workflows")
    failures = []
    for workflow in sorted(workflows_dir.glob("*.y*ml")):
        for line_number, line in enumerate(workflow.read_text().splitlines(), 1):
            match = USES.match(line)
            if not match:
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
