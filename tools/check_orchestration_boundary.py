"""Reject tracked orchestration setup in application main and PR candidates."""
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import subprocess


EXACT = {
    "rig.yaml", "rig.yml", "drover.yaml", "drover.yml", "drover.config",
    "BOTS.md", ".beans.yml", ".beans.yaml", "tests/test_rig_setup.py",
    "docs/DROVER.md",
}
ROOTS = {"rig", "openrig", "drover", ".openrig", ".drover", ".agents", ".codex"}
LOCAL_DIRS = {".openrig", ".drover", ".agents", ".codex"}
CONFIG_NAMES = {".beans.yml", ".beans.yaml", "rig.yaml", "rig.yml", "drover.yaml", "drover.yml", "drover.config"}


def violations(paths: list[str]) -> list[str]:
    result = []
    for path in paths:
        parts = PurePosixPath(path).parts
        if (path in EXACT or parts and parts[0] in ROOTS
                or any(part in LOCAL_DIRS for part in parts)
                or parts and parts[-1] in CONFIG_NAMES
                or parts and parts[0] == ".beans" and (len(parts) != 2 or not parts[-1].endswith(".md"))):
            result.append(path)
    return sorted(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    tracked = subprocess.run(
        ["git", "-C", str(args.repo), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode("utf-8", errors="surrogateescape").split("\0")
    rejected = violations([path for path in tracked if path])
    if rejected:
        print("Orchestration setup is not allowed on application main:")
        for path in rejected:
            print(f"  {path}")
        print("Keep configuration on setup/openrig or setup/drover; do not merge those branches into main.")
        return 1
    print("Application tree contains no tracked OpenRig or Drover setup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
