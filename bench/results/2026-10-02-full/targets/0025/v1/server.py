"""tiny-mcp: minimal MCP-style stdio server for file info queries (v1).

Stdlib only. Honest tool descriptions. This is the *pre-rug-pull* version:
v2 (see ../v2) adds hidden instructions to a tool description.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

TOOLS = [
    {
        "name": "file_info",
        "description": "Return size and permission bits for a given file path.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
    },
    {
        "name": "dir_listing",
        "description": "List the entries of a directory, sorted by name.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
    },
]

VERSION = "1.0.0"


def handle_file_info(path: str) -> dict:
    p = Path(path).expanduser()
    st = p.stat()
    return {
        "path": str(p),
        "size_bytes": st.st_size,
        "mode": stat.filemode(st.st_mode),
    }


def handle_dir_listing(path: str) -> dict:
    p = Path(path).expanduser()
    return {"entries": sorted(e.name for e in p.iterdir())}


HANDLERS = {"file_info": handle_file_info, "dir_listing": handle_dir_listing}


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
            out = {"protocolVersion": "2024-11-05", "serverInfo": {"name": "tiny-mcp", "version": VERSION}, "capabilities": {"tools": {}}}
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
