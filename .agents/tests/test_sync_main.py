"""Exercise the setup sync helper against real, isolated Git repositories."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[1] / "sync_main.py"


class SetupSyncTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.is_file(), "The protected setup-sync helper is missing")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="Sync Test",
                        GIT_AUTHOR_EMAIL="sync@example.invalid",
                        GIT_COMMITTER_NAME="Sync Test",
                        GIT_COMMITTER_EMAIL="sync@example.invalid")
        self.git("init", "-b", "main")
        self.write("app.txt", "base application\n")
        self.write("rig.yaml", "topology\n")
        self.write("rig/context/project.md", "context\n")
        self.write("BOTS.md", "team rules\n")
        self.write("tests/test_rig_setup.py", "setup checks\n")
        self.git("add", ".")
        self.git("commit", "-m", "base")

    def git(self, *args, check=True):
        return subprocess.run(["git", *args], cwd=self.repo, env=self.env,
                              capture_output=True, text=True, check=check)

    def write(self, name, value):
        target = self.repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)

    def prepare(self, branch="setup/openrig", conflict=False):
        self.git("checkout", "-b", branch)
        self.write("AGENTS.md", "branch instructions\n")
        self.write("rig/context/project.md", "newer branch context\n")
        self.write(".agents/skills/local/SKILL.md", "branch skill\n")
        self.write(".beans.yml", "beans config\n")
        self.write("docs/DROVER.md", "setup guide\n")
        shutil.copy2(HELPER, self.repo / ".agents/sync_main.py")
        if conflict:
            self.write("app.txt", "setup application change\n")
        self.git("add", ".")
        self.git("commit", "-m", "setup")
        before = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("checkout", "main")
        self.git("rm", "-r", "rig", "rig.yaml", "BOTS.md", "tests/test_rig_setup.py")
        self.write("AGENTS.md", "application restrictions\n")
        self.write("app.txt", "latest application\n")
        self.write(".beans/task.md", "new task record\n")
        self.git("add", ".")
        self.git("commit", "-m", "framework-free main")
        self.git("checkout", branch)
        return before

    def sync(self):
        return subprocess.run(["python3", str(HELPER), "--no-fetch"],
                              cwd=self.repo, env=self.env, capture_output=True, text=True)

    def assert_preserved(self):
        expected = {"rig.yaml": "topology\n", "BOTS.md": "team rules\n",
                    "rig/context/project.md": "newer branch context\n",
                    "AGENTS.md": "branch instructions\n",
                    ".agents/skills/local/SKILL.md": "branch skill\n",
                    ".beans.yml": "beans config\n",
                    "docs/DROVER.md": "setup guide\n",
                    "tests/test_rig_setup.py": "setup checks\n"}
        for name, value in expected.items():
            with self.subTest(path=name):
                self.assertEqual((self.repo / name).read_text(), value)
                self.assertEqual(self.git("show", ":" + name).stdout, value)
        self.assertEqual((self.repo / ".agents/sync_main.py").read_bytes(), HELPER.read_bytes())

    def assert_sync(self, branch):
        before = self.prepare(branch)
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_preserved()
        self.assertEqual((self.repo / "app.txt").read_text(), "latest application\n")
        self.assertEqual((self.repo / ".beans/task.md").read_text(), "new task record\n")
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), before)
        self.assertTrue(self.git("for-each-ref", "refs/setup-sync-backups").stdout)
        self.assertEqual(self.git("diff", "--name-only", "--diff-filter=U").stdout, "")
        self.git("commit", "-m", "sync main preserving setup")
        again = self.sync()
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertEqual(self.git("status", "--porcelain").stdout, "")

    def test_openrig_sync_preserves_setup_and_stages_latest_application(self):
        self.assert_sync("setup/openrig")

    def test_drover_sync_preserves_setup_and_stages_latest_application(self):
        self.assert_sync("setup/drover")

    def test_application_conflict_is_left_for_manual_resolution(self):
        before = self.prepare(conflict=True)
        result = self.sync()
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved()
        self.assertEqual(self.git("diff", "--name-only", "--diff-filter=U").stdout, "app.txt\n")
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), before)
        self.assertIn("application", result.stdout + result.stderr)

    def test_dirty_tracked_worktree_is_untouched(self):
        before = self.prepare()
        self.write("rig.yaml", "uncommitted owner change\n")
        result = self.sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.repo / "rig.yaml").read_text(), "uncommitted owner change\n")
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), before)
        self.assertFalse(self.git("for-each-ref", "refs/setup-sync-backups").stdout)

    def test_untracked_files_are_untouched(self):
        self.prepare()
        self.write("owner.txt", "owner work\n")
        result = self.sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.repo / "owner.txt").read_text(), "owner work\n")
        self.assertFalse(self.git("for-each-ref", "refs/setup-sync-backups").stdout)

    def test_executable_and_symlink_setup_files_survive(self):
        before = self.prepare()
        self.write("rig/run.sh", "#!/bin/sh\nexit 0\n")
        (self.repo / "rig/run.sh").chmod(0o755)
        (self.repo / "rig/link").symlink_to("run.sh")
        self.git("add", "rig/run.sh", "rig/link")
        self.git("commit", "-m", "setup file modes")
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.repo / "rig/run.sh").stat().st_mode & 0o777, 0o755)
        self.assertTrue((self.repo / "rig/link").is_symlink())
        self.assertEqual(os.readlink(self.repo / "rig/link"), "run.sh")
        self.assertEqual(self.git("ls-files", "--stage", "rig/run.sh").stdout.split()[0], "100755")

    def test_second_main_update_keeps_setup_and_imports_new_application(self):
        self.prepare()
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.git("commit", "-m", "first preserved sync")
        self.git("checkout", "main")
        self.write("app.txt", "second application update\n")
        self.write("AGENTS.md", "new application restrictions\n")
        self.git("add", "app.txt", "AGENTS.md")
        self.git("commit", "-m", "second main update")
        self.git("checkout", "setup/openrig")
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_preserved()
        self.assertEqual((self.repo / "app.txt").read_text(), "second application update\n")

    def test_main_is_refused(self):
        before = self.git("rev-parse", "HEAD").stdout.strip()
        result = self.sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("setup/openrig", result.stdout + result.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), before)
        self.assertEqual(self.git("status", "--porcelain").stdout, "")

    def test_ignored_local_file_cannot_be_overwritten_by_main(self):
        self.prepare()
        self.git("checkout", "main")
        self.write("runtime.txt", "incoming tracked file\n")
        self.git("add", "runtime.txt")
        self.git("commit", "-m", "incoming file collision")
        self.git("checkout", "setup/openrig")
        self.write(".git/info/exclude", "runtime.txt\n")
        self.write("runtime.txt", "ignored owner state\n")
        before = self.git("rev-parse", "HEAD").stdout.strip()
        result = self.sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.repo / "runtime.txt").read_text(), "ignored owner state\n")
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), before)
        self.assertEqual((self.repo / "AGENTS.md").read_text(), "branch instructions\n")


if __name__ == "__main__":
    unittest.main()
