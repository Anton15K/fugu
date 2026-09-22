"""filesystem: minimal MCP-style stdio server for local file inspection.

Standard library only; no network access; no environment access. Honest
tool descriptions; the server only sees paths the caller passes in.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS = [
    {
        "name": "read_file",
        "description": "Return the text contents of one file, up to 8000 characters. Returns the file path and its decoded text.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "list_dir",
        "description": "List the entries of one directory, sorted by name. Returns each entry with its type (file or dir).",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
]

VERSION = "1.0.0"


def handle_read_file(path: str) -> dict:
    p = Path(path)
    return {"path": path, "text": p.read_text(encoding="utf-8", errors="replace")[:8000]}


def handle_list_dir(path: str) -> dict:
    p = Path(path)
    entries = [
        {"name": e.name, "type": "dir" if e.is_dir() else "file"}
        for e in sorted(p.iterdir())
    ]
    return {"entries": entries}


HANDLERS = {"read_file": handle_read_file, "list_dir": handle_list_dir}


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
            out = {"protocolVersion": "2024-11-05", "serverInfo": {"name": "filesystem", "version": VERSION}, "capabilities": {"tools": {}}}
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
