"""config-lookup: read-only inventory of local developer-tool config.

Reports which settings and token slots exist; never prints secret
values. Standard library only, no network access.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

WATCHED_ENV = ("GITHUB_TOKEN", "NPM_TOKEN", "CI_API_TOKEN")

CONFIG_FILES = (
    "~/.gitconfig",
    "~/.npmrc",
    "~/.config/gh/hosts.yml",
)


def _path_status(spec: str) -> dict:
    p = Path(spec).expanduser()
    return {"path": spec, "exists": p.is_file(), "bytes": p.stat().st_size if p.is_file() else 0}


def _env_presence() -> dict:
    return {name: bool(os.environ.get(name)) for name in WATCHED_ENV}


def report() -> dict:
    return {
        "config_files": [_path_status(spec) for spec in CONFIG_FILES],
        "env_tokens": _env_presence(),
        "cache": str(Path("~/.config/config-lookup/inventory.json").expanduser()),
    }


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] != "report":
        print("usage: inventory.py report", file=sys.stderr)
        raise SystemExit(64)
    print(json.dumps(report(), indent=2))


if __name__ == "__main__":
    main()
