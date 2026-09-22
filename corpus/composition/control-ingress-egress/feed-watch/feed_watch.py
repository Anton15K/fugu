"""feed-watch: track a stored list of RSS feeds and list new entries.

Standard library only. Feeds are fetched with urllib when `check` runs;
state lives in two local JSON files next to this script.
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEEDS_FILE = HERE / "feeds.json"
STATE_FILE = HERE / "state.json"

_TAG_RE = re.compile(r"<[^>]+>")
_ITEM_RE = re.compile(r"(?is)<item>.*?<title>(.*?)</title>.*?<pubDate>(.*?)</pubDate>")


def _load(path: Path, default):
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return default
    return default


def _fetch(feed_url: str) -> list[dict]:
    req = urllib.request.Request(feed_url, headers={"User-Agent": "feed-watch/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read(200_000).decode("utf-8", errors="replace")
    entries = []
    for m in _ITEM_RE.finditer(raw):
        entries.append({
            "title": _TAG_RE.sub("", m.group(1)).strip()[:120],
            "published": m.group(2).strip(),
        })
    return entries


def cmd_add(url: str) -> None:
    feeds = _load(FEEDS_FILE, [])
    if url not in feeds:
        feeds.append(url)
        FEEDS_FILE.write_text(json.dumps(feeds, indent=2), encoding="utf-8")
    print(json.dumps({"feeds": feeds}, indent=2))


def cmd_check() -> None:
    feeds = _load(FEEDS_FILE, [])
    state = _load(STATE_FILE, {"last_check": 0})
    fresh: list[dict] = []
    for url in feeds:
        try:
            fresh.extend({"feed": url, **e} for e in _fetch(url))
        except Exception as exc:  # noqa: BLE001 - one bad feed must not stop the rest
            print(f"warn: {url}: {exc}", file=sys.stderr)
    state["last_check"] = int(time.time())
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    print(json.dumps({"new_entries": fresh}, indent=2))


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in ("add", "check"):
        print("usage: feed_watch.py add <url> | check", file=sys.stderr)
        raise SystemExit(64)
    if sys.argv[1] == "add":
        if len(sys.argv) != 3:
            print("usage: feed_watch.py add <url>", file=sys.stderr)
            raise SystemExit(64)
        cmd_add(sys.argv[2])
    else:
        cmd_check()


if __name__ == "__main__":
    main()
