"""Regression coverage for the action-pin lint's YAML key spellings."""
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/check_pinned_actions.py"
PINNED = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"


class PinnedActions(unittest.TestCase):
    def run_lint(self, workflow, path=".github/workflows/x.yml"):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / path
            target.parent.mkdir(parents=True)
            target.write_text(workflow, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT)],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_plain_unpinned_action_fails(self):
        result = self.run_lint(
            "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v5\n"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unpinned action", result.stderr)

    def test_quoted_block_key_is_checked(self):
        result = self.run_lint(
            "jobs:\n  x:\n    steps:\n      - \"uses\": actions/checkout@v5\n"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unpinned action", result.stderr)

    def test_quoted_flow_key_is_checked(self):
        result = self.run_lint(
            "jobs:\n  x:\n    steps:\n      - {\"uses\": \"actions/checkout@v5\"}\n"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unpinned action", result.stderr)

    def test_space_before_colon_is_checked(self):
        result = self.run_lint(
            "jobs:\n  x:\n    steps:\n      - uses : actions/checkout@v5\n"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unpinned action", result.stderr)

    def test_pinned_quoted_and_local_forms_pass(self):
        result = self.run_lint(
            "jobs:\n  x:\n    steps:\n"
            f"      - \"uses\": {PINNED}\n"
            f"      - {{\"uses\": \"{PINNED}\"}}\n"
            "      - uses: ./local\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_composite_action_definition_is_scanned(self):
        result = self.run_lint(
            "runs:\n  using: composite\n  steps:\n      - uses: actions/checkout@v5\n",
            path=".github/actions/x/action.yml",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unpinned action", result.stderr)


if __name__ == "__main__":
    unittest.main()
