"""Tests the main-branch guard against actual tracked Git entries."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECK = Path(__file__).resolve().parents[1] / "tools/check_orchestration_boundary.py"


class OrchestrationBoundaryTests(unittest.TestCase):
    def check_tree(self, paths):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            for relative in paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
                subprocess.run(["git", "-C", str(root), "add", "--", relative], check=True)
            return subprocess.run([sys.executable, str(CHECK), "--repo", str(root)],
                                  capture_output=True, text=True)

    def test_application_code_and_main_policy_are_allowed(self):
        result = self.check_tree(["src/fugu/config.py", "AGENTS.md", "docs/orchestration-boundary.md"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_framework_setup_path_is_rejected(self):
        for path in ["rig.yaml", "rig.yml", "rig/agents/lead/agent.yaml",
                     "openrig/config.yaml", ".openrig/settings.json", "BOTS.md",
                     "drover/config", ".drover/config", "drover.config",
                     "drover.yaml", "drover.yml", ".codex/config.toml",
                     "web/.codex/config.toml", "web/.agents/skills/team/SKILL.md", "web/.beans.yml",
                     ".agents/skills/fleet-peers/SKILL.md", ".beans.yml",
                     ".beans.yaml", "tests/test_rig_setup.py", "docs/DROVER.md"]:
            with self.subTest(path=path):
                result = self.check_tree([path])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(path, result.stdout)

    def test_task_records_and_historical_evidence_are_allowed(self):
        result = self.check_tree([".beans/fugu-ab12--task.md", "docs/rig-work/finished-task/evidence.md"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_paths_with_spaces_cannot_hide_setup(self):
        result = self.check_tree(["rig/role guidance.md"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("rig/role guidance.md", result.stdout)

    def test_board_accepts_only_direct_markdown_task_records(self):
        for path in [".beans/config.yaml", ".beans/startup.sh", ".beans/nested/config.md"]:
            with self.subTest(path=path):
                result = self.check_tree([path])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(path, result.stdout)

    def test_non_repository_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(CHECK), "--repo", directory],
                                    capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
