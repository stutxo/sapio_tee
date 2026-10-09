"""Source selection tests only; these never invoke Nix or produce images."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("source_snapshot", ROOT / "scripts/source_snapshot.py")
SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOT)
BUILD_SPEC = importlib.util.spec_from_file_location("terraform_build", ROOT / "deploy/terraform/build.py")
BUILD = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_SPEC.loader.exec_module(BUILD)


class SourceSnapshot(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.roots = {}
        for name in SNAPSHOT.LAYOUT:
            root = self.directory / name
            root.mkdir()
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            (root / "Cargo.toml").write_text('[package]\nname = "source-fixture"\n', encoding="utf-8")
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text("pub fn newly_written() {}\n", encoding="utf-8")
            (root / ".gitignore").write_text(
                (ROOT / ".gitignore").read_text(encoding="utf-8") + "\nignored.rs\n.env\n",
                encoding="utf-8",
            )
            (root / "ignored.rs").write_text("private ignored source\n", encoding="utf-8")
            (root / ".env").write_text("PRIVATE_TEST_TOKEN=never-import\n", encoding="utf-8")
            (root / "terraform.tfstate").write_text('{"private":"never-import"}\n', encoding="utf-8")
            self.roots[name] = root
        self.destination = self.directory / "reviewed"

    def plan(self, includes=()):
        return SNAPSHOT.plan_sources(self.roots, includes)

    def create(self, plan=None):
        SNAPSHOT.create_snapshots(self.plan() if plan is None else plan, self.destination)
        return [self.destination / layout for layout in SNAPSHOT.LAYOUT.values()]

    def test_untracked_code_is_selected_without_staging_and_private_data_is_not(self):
        for repository in self.plan()["repositories"].values():
            self.assertEqual({entry["path"] for entry in repository["files"]},
                             {"Cargo.toml", "src/lib.rs"})
        for snapshot in self.create():
            self.assertEqual(SNAPSHOT.verify_snapshot(snapshot), snapshot)
            self.assertTrue((snapshot / "src/lib.rs").is_file())
            self.assertFalse((snapshot / ".git").exists())
            self.assertFalse((snapshot / ".env").exists())
            self.assertFalse((snapshot / "terraform.tfstate").exists())
            self.assertNotIn(str(self.directory), (snapshot / SNAPSHOT.MANIFEST).read_text())

    def test_nested_rust_targets_are_ignored_without_removing_experiment_sources(self):
        root = self.roots["tee"]
        experiment = root / "experiments" / "predicate"
        target = experiment / "target" / "debug" / "build"
        target.mkdir(parents=True)
        source = experiment / "lib.rs"
        source.write_text("pub fn experiment() {}\n", encoding="utf-8")
        generated = target / "generated.rs"
        generated.write_text("private build output\n", encoding="utf-8")
        files = {entry["path"] for entry in self.plan()["repositories"]["tee"]["files"]}
        self.assertIn("experiments/predicate/lib.rs", files)
        self.assertNotIn("experiments/predicate/target/debug/build/generated.rs", files)
        self.assertTrue(generated.is_file())
        self.assertTrue(source.is_file())

    def test_review_can_remove_source_looking_private_files(self):
        (self.roots["tee"] / "private.rs").write_text("private source-like contents\n", encoding="utf-8")
        plan = self.plan()
        files = plan["repositories"]["tee"]["files"]
        self.assertIn("private.rs", {entry["path"] for entry in files})
        plan["repositories"]["tee"]["files"] = [entry for entry in files if entry["path"] != "private.rs"]
        tee, = self.create(plan)
        self.assertFalse((tee / "private.rs").exists())
        SNAPSHOT.verify_snapshot(tee)

    def test_noncode_build_fixture_requires_explicit_selection(self):
        root = self.roots["tee"]
        (root / "vector.json").write_text('{"public_test_vector":1}\n', encoding="utf-8")
        self.assertNotIn("vector.json", {entry["path"] for entry in self.plan()["repositories"]["tee"]["files"]})
        plan = self.plan(["tee:vector.json"])
        tee, = self.create(plan)
        self.assertTrue((tee / "vector.json").is_file())
        SNAPSHOT.verify_snapshot(tee)

    def test_source_change_after_review_is_rejected(self):
        plan = self.plan()
        (self.roots["tee"] / "src/lib.rs").write_text("changed bytes\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source changed after review"):
            self.create(plan)

    def test_symlink_source_is_rejected(self):
        (self.roots["tee"] / "linked.rs").symlink_to(self.roots["tee"] / ".env")
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            self.plan()

    def test_symlink_parent_is_rejected(self):
        (self.roots["tee"] / "linked").symlink_to(self.roots["tee"] / "src", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "not a real directory"):
            self.plan(["tee:linked/lib.rs"])

    def test_snapshot_inside_a_worktree_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside the source worktrees"):
            SNAPSHOT.create_snapshots(self.plan(), self.roots["tee"] / "snapshot")

    def test_extra_snapshot_file_is_rejected_before_import(self):
        tee, = self.create()
        tee.chmod(0o755)
        (tee / ".env").write_text("private later addition\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing or unreviewed files"):
            SNAPSHOT.verify_snapshot(tee)

    def test_snapshot_modification_is_rejected(self):
        tee, = self.create()
        source = tee / "src/lib.rs"
        source.chmod(0o644)
        source.write_text("modified snapshot\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "differs from reviewed inventory"):
            SNAPSHOT.verify_snapshot(tee)

    def test_snapshot_link_is_rejected(self):
        tee, = self.create()
        tee.chmod(0o755)
        (tee / "extra").symlink_to(self.roots["tee"] / ".env")
        with self.assertRaisesRegex(ValueError, "link or special file"):
            SNAPSHOT.verify_snapshot(tee)

    def test_invalid_inventory_paths_are_rejected(self):
        for value in ("", ".", "..", "../private", "/private", "a/../private", "a//b", "a/./b"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                SNAPSHOT.relative_path(value)

    def test_terraform_rejects_a_raw_worktree_before_nix(self):
        with patch.object(BUILD, "run") as run, self.assertRaises(OSError):
            BUILD.build(self.roots["tee"], self.directory, "app", self.roots["tee"])
        run.assert_not_called()

    def test_create_requires_explicit_review_confirmation(self):
        with patch("sys.argv", ["source_snapshot.py", "create", "--plan", "plan.json",
                                "--output", str(self.destination)]):
            with patch.object(SNAPSHOT, "create_snapshots") as create, self.assertRaises(SystemExit) as error:
                SNAPSHOT.main()
        self.assertEqual(error.exception.code, 2)
        create.assert_not_called()

    def test_obsolete_sibling_inventory_is_rejected(self):
        plan = self.plan()
        plan["repositories"]["sapio"] = plan["repositories"]["tee"]
        with self.assertRaisesRegex(ValueError, "must select only tee"):
            self.create(plan)

    def test_terraform_rejects_changed_self_source_before_nix(self):
        tee, = self.create()
        source = tee / "src/lib.rs"
        source.chmod(0o644)
        source.write_text("unreviewed changes\n", encoding="utf-8")
        with patch.object(BUILD, "run") as run, self.assertRaisesRegex(ValueError, "differs from reviewed inventory"):
            BUILD.build(self.roots["tee"], self.directory, "app", tee)
        run.assert_not_called()



if __name__ == "__main__":
    unittest.main()
