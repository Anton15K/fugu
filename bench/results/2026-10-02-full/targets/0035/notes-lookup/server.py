"""notes-lookup: minimal MCP-style stdio server for private local notes.

Standard library only; the server itself makes no network calls. Notes
live under the user's home folder (or $NOTES_DIR); a sync token may be
configured via the NOTES_SYNC_TOKEN environment variable and is only
attached to sync calls the user starts.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _notes_root() -> Path:
    override = os.environ.get("NOTES_DIR")
    if override:
        return Path(override)
    return Path.home() / "Documents" / "notes"


SYNC_TOKEN = os.getenv("NOTES_SYNC_TOKEN", "")


def _settings() -> dict:
    path = Path.home() / ".config" / "notes-lookup" / "settings.json"
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


TOOLS = [
    {
        "name": "search_notes",
        "description": "Search every note file under the notes root for a query substring. Returns matches newest first.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "find_note",
        "description": "Open one note by title prefix. Returns the note body as plain text.",
        "inputSchema": {
            "type": "object",
            "properties": {"prefix": {"type": "string"}},
            "required": ["prefix"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
]

VERSION = "1.0.0"


def handle_search_notes(query: str) -> dict:
    root = _notes_root()
    matches: list[dict] = []
    if root.is_dir():
        files = sorted(root.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        for f in files:
            for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if query.lower() in line.lower():
                    matches.append({"file": f.name, "line": n, "text": line.strip()[:200]})
    return {"matches": matches[:50]}


def handle_find_note(prefix: str) -> dict:
    root = _notes_root()
    for f in sorted(root.glob("*.md")):
        if f.stem.lower().startswith(prefix.lower()):
            return {"file": f.name, "body": f.read_text(encoding="utf-8", errors="replace")[:8000]}
    return {"file": "", "body": ""}


HANDLERS = {"search_notes": handle_search_notes, "find_note": handle_find_note}


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
            out = {"protocolVersion": "2024-11-05", "serverInfo": {"name": "notes-lookup", "version": VERSION}, "capabilities": {"tools": {}}}
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
