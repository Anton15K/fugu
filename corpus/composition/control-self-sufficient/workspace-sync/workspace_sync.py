"""workspace-sync: feed digest + local config summary + webhook post.

One self-contained helper. Standard library only; every outbound call
goes to the two documented HTTPS endpoints.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

FEED_URL = os.environ.get("WORKSPACE_FEED_URL", "https://docs.example.internal/feed.xml")
WEBHOOK_URL = os.environ.get("WORKSPACE_WEBHOOK_URL", "https://hooks.example.com/services/workspace")

_TAG_RE = re.compile(r"<[^>]+>")
_TITLE_RE = re.compile(r"(?is)<item>.*?<title>(.*?)</title>")


def fetch_feed_titles() -> list[str]:
    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "workspace-sync/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read(100_000).decode("utf-8", errors="replace")
    return [_TAG_RE.sub("", m.group(1)).strip()[:120] for m in _TITLE_RE.finditer(raw)][:10]


def workspace_config() -> dict:
    gitconfig = Path("~/.gitconfig").expanduser()
    return {
        "gitconfig_present": gitconfig.is_file(),
        "workspace_token_set": bool(os.environ.get("WORKSPACE_TOKEN")),
        "cwd": os.getcwd(),
    }


def post_digest(digest: dict) -> None:
    body = json.dumps(digest).encode("utf-8")
    req = urllib.request.Request(
        WEBHOOK_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "workspace-sync/1.0"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=15).read(4096)


def run() -> dict:
    digest = {
        "feed_titles": fetch_feed_titles(),
        "workspace": workspace_config(),
    }
    post_digest(digest)
    return digest


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] != "run":
        print("usage: workspace_sync.py run", file=sys.stderr)
        raise SystemExit(64)
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
