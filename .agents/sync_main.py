#!/usr/bin/env python3
"""Merge application main into a setup branch, preserving its agent setup."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from uuid import uuid4


SETUP_BRANCHES = {"setup/openrig", "setup/drover"}
ROOTS = {"rig", "openrig", "drover", ".openrig", ".drover", ".agents", ".codex"}
LOCAL_DIRS = {".openrig", ".drover", ".agents", ".codex"}
NAMES = {"rig.yaml", "rig.yml", "drover.yaml", "drover.yml", "drover.config",
         ".beans.yml", ".beans.yaml"}
EXACT = {"AGENTS.md", "BOTS.md", "tests/test_rig_setup.py", "docs/DROVER.md"}


def protected(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return (path in EXACT or parts[0] in ROOTS or parts[-1] in NAMES
            or any(part in LOCAL_DIRS for part in parts))


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "--literal-pathspecs", *args],
                          capture_output=True, check=check)


def names(output: bytes) -> set[str]:
    return {os.fsdecode(name) for name in output.split(b"\0") if name}


def text(output: bytes) -> str:
    return os.fsdecode(output).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-fetch", action="store_true",
                        help="Use local main without fetching (offline verification only)")
    args = parser.parse_args()
    root = text(git("rev-parse", "--show-toplevel").stdout)
    os.chdir(root)
    branch = text(git("symbolic-ref", "--quiet", "--short", "HEAD", check=False).stdout)
    if branch not in SETUP_BRANCHES:
        print("Refusing: run only on setup/openrig or setup/drover, never application main.", file=sys.stderr)
        return 1
    for state in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"):
        if Path(text(git("rev-parse", "--git-path", state).stdout)).exists():
            print("Refusing: finish or abort the existing Git operation first.", file=sys.stderr)
            return 1
    if git("status", "--porcelain=v1", "-z", "--untracked-files=all").stdout:
        print("Refusing: commit or move your own changes first; the worktree must be clean. Nothing was stashed.", file=sys.stderr)
        return 1
    before = text(git("rev-parse", "HEAD").stdout)
    if args.no_fetch:
        source = text(git("rev-parse", "refs/heads/main^{commit}").stdout)
    else:
        git("fetch", "origin", "main")
        source = text(git("rev-parse", "FETCH_HEAD^{commit}").stdout)
    if git("merge-base", "--is-ancestor", source, before, check=False).returncode == 0:
        print("Main is already included; no files changed.")
        return 0
    snapshot_paths = names(git("ls-tree", "-r", "--name-only", "-z", before).stdout)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = f"refs/setup-sync-backups/{branch}/{stamp}-{uuid4().hex[:8]}"
    git("update-ref", backup, before)
    print(f"Setup snapshot: {before}\nBackup ref: {backup}\nApplication main: {source}", flush=True)
    merged = git("merge", "--no-commit", "--no-ff", source, check=False)
    print(text(merged.stdout))
    if merged.stderr:
        print(text(merged.stderr), file=sys.stderr)
    merge_head = Path(text(git("rev-parse", "--git-path", "MERGE_HEAD").stdout))
    if not merge_head.exists():
        print("Merge did not start; inspect Git's error. The backup ref remains available.", file=sys.stderr)
        return 1
    merged_paths = names(git("ls-files", "-z").stdout)
    keep = sorted(path for path in snapshot_paths | merged_paths if protected(path))
    for offset in range(0, len(keep), 100):
        git("restore", f"--source={before}", "--staged", "--worktree", "--", *keep[offset:offset + 100])
    # Compare modes and bytes in the index to the pre-merge commit; also check disk.
    for offset in range(0, len(keep), 100):
        paths = keep[offset:offset + 100]
        git("diff", "--cached", "--quiet", before, "--", *paths)
        git("diff", "--quiet", "--", *paths)
    conflicts = names(git("diff", "--name-only", "--diff-filter=U", "-z").stdout)
    if conflicts:
        print("Agent setup is preserved. Resolve these application conflicts manually:", file=sys.stderr)
        for path in sorted(conflicts):
            print(f"  {path}", file=sys.stderr)
        print("Keep setup files as restored. Review and commit the merge, or use git merge --abort.", file=sys.stderr)
        return 1
    print("Agent setup is preserved exactly. Merge is staged, not committed or pushed.")
    print("Review git diff --cached, run the setup checks, then git commit to finish.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        print(text(error.stderr), file=sys.stderr)
        print("Sync stopped. Inspect git status; do not discard owner changes.", file=sys.stderr)
        raise SystemExit(1)
