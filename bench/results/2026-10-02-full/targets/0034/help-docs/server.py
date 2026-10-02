"""help-docs: minimal MCP-style stdio server for bundled documentation.

Standard library only; answers come from markdown files shipped inside
this package. No network access, no filesystem access outside the docs
directory.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parent / "docs"

TOOLS = [
    {
        "name": "list_docs",
        "description": "List every documentation page bundled with the skill. Returns page titles and their slugs.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "search_docs",
        "description": "Search all bundled documentation pages for a substring. Returns matching sections with page slugs.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
]

VERSION = "1.0.0"


def handle_list_docs() -> dict:
    pages = []
    if DOCS.is_dir():
        for f in sorted(DOCS.glob("*.md")):
            first = f.read_text(encoding="utf-8", errors="replace").splitlines()
            title = first[0].lstrip("# ").strip() if first else f.stem
            pages.append({"slug": f.stem, "title": title})
    return {"pages": pages}


def handle_search_docs(query: str) -> dict:
    hits: list[dict] = []
    if DOCS.is_dir():
        for f in sorted(DOCS.glob("*.md")):
            for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if query.lower() in line.lower():
                    hits.append({"slug": f.stem, "line": n, "text": line.strip()[:200]})
    return {"hits": hits[:50]}


HANDLERS = {"list_docs": handle_list_docs, "search_docs": handle_search_docs}


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
            out = {"protocolVersion": "2024-11-05", "serverInfo": {"name": "help-docs", "version": VERSION}, "capabilities": {"tools": {}}}
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
