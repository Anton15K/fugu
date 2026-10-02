"""web-digest: minimal MCP-style stdio server for page and feed digests.

Standard library only. Tools fetch remote content on request, honest
descriptions, nothing persisted between calls.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request

TOOLS = [
    {
        "name": "fetch_url",
        "description": "Fetch one public web page and return its readable text. Returns the page title and body trimmed to 4000 characters.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    },
    {
        "name": "read_rss",
        "description": "Pull the latest items from an RSS or Atom feed. Returns the ten most recent entry titles and links.",
        "inputSchema": {
            "type": "object",
            "properties": {"feed": {"type": "string"}},
            "required": ["feed"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    },
]

VERSION = "1.0.0"

_TAG_RE = re.compile(r"<[^>]+>")


def handle_fetch_url(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "web-digest/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read(200_000).decode("utf-8", errors="replace")
    title = ""
    m = re.search(r"(?is)<title>(.*?)</title>", raw)
    if m:
        title = _TAG_RE.sub("", m.group(1)).strip()[:120]
    body = _TAG_RE.sub(" ", raw)[:4000]
    return {"title": title, "body": body.strip(), "source": url}


def handle_read_rss(feed: str) -> dict:
    req = urllib.request.Request(feed, headers={"User-Agent": "web-digest/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read(200_000).decode("utf-8", errors="replace")
    entries = []
    for m in re.finditer(r"(?is)<item>.*?<title>(.*?)</title>.*?<link>(.*?)</link>", raw):
        entries.append({"title": _TAG_RE.sub("", m.group(1)).strip()[:120], "link": m.group(2).strip()})
    return {"entries": entries[:10]}


HANDLERS = {"fetch_url": handle_fetch_url, "read_rss": handle_read_rss}


def respond(id_, result) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": id_, "result": result})


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = req.get("method", "")
        if method == "initialize":
            out = {"protocolVersion": "2024-11-05", "serverInfo": {"name": "web-digest", "version": VERSION}, "capabilities": {"tools": {}}}
        elif method == "tools/list":
            out = {"tools": TOOLS}
        elif method == "tools/call":
            name = req["params"]["name"]
            args = req["params"].get("arguments", {})
            out = {"content": [{"type": "text", "text": json.dumps(HANDLERS[name](**args))}]}
        else:
            out = {}
        sys.stdout.write(respond(req.get("id"), out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
