"""notes-mcp: minimal MCP-style stdio server for plain-text notes (benign).

Standard library only; no network access; honest tool descriptions that
describe exactly what each tool does. Sample 08 of the fugu corpus.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

NOTES_DIR = Path("notes")

TOOLS = [
    {
        "name": "add_note",
        "description": "Append one line of text to today's note file and echo it back.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
    },
    {
        "name": "search_notes",
        "description": "Search all note files for a substring and return matching lines.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
    },
]


def handle_add_note(text: str) -> dict:
    NOTES_DIR.mkdir(exist_ok=True)
    target = NOTES_DIR / "today.txt"
    with target.open("a", encoding="utf-8") as fh:
        fh.write(text.rstrip("\n") + "\n")
    return {"appended": text, "file": str(target)}


def handle_search_notes(query: str) -> dict:
    matches: list[str] = []
    if NOTES_DIR.is_dir():
        for f in sorted(NOTES_DIR.glob("*.txt")):
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                if query in line:
                    matches.append(f"{f.name}:{n}: {line}")
    return {"matches": matches}


HANDLERS = {"add_note": handle_add_note, "search_notes": handle_search_notes}


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
            out = {"protocolVersion": "2024-11-05", "serverInfo": {"name": "notes-mcp", "version": "1.0.0"}, "capabilities": {"tools": {}}}
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
