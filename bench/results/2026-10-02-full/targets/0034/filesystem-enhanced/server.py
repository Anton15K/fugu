"""filesystem-enhanced: file inspection with content search and usage stats.

A drop-in upgrade for the `filesystem` server: same core tools plus
recursive search and disk usage. Standard library only, no network
access, no environment access.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS = [
    {
        "name": "read_file",
        "description": "Return the text contents of one file, up to 16000 characters. Returns the file path and its decoded text.",
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
    {
        "name": "search_files",
        "description": "Recursively find files whose name or content matches a substring. Returns matching paths with line numbers.",
        "inputSchema": {
            "type": "object",
            "properties": {"root": {"type": "string"}, "needle": {"type": "string"}},
            "required": ["root", "needle"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "disk_usage",
        "description": "Compute the total size of a directory tree. Returns the byte count and file count.",
        "inputSchema": {
            "type": "object",
            "properties": {"root": {"type": "string"}},
            "required": ["root"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
]

VERSION = "1.1.0"


def handle_read_file(path: str) -> dict:
    p = Path(path)
    return {"path": path, "text": p.read_text(encoding="utf-8", errors="replace")[:16000]}


def handle_list_dir(path: str) -> dict:
    p = Path(path)
    entries = [
        {"name": e.name, "type": "dir" if e.is_dir() else "file"}
        for e in sorted(p.iterdir())
    ]
    return {"entries": entries}


def handle_search_files(root: str, needle: str) -> dict:
    matches: list[dict] = []
    for f in sorted(Path(root).rglob("*")):
        if not f.is_file():
            continue
        if needle.lower() in f.name.lower():
            matches.append({"path": str(f), "line": 0})
            continue
        try:
            for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if needle.lower() in line.lower():
                    matches.append({"path": str(f), "line": n})
        except OSError:
            continue
    return {"matches": matches[:100]}


def handle_disk_usage(root: str) -> dict:
    total = 0
    count = 0
    for f in Path(root).rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
                count += 1
            except OSError:
                continue
    return {"bytes": total, "files": count}


HANDLERS = {
    "read_file": handle_read_file,
    "list_dir": handle_list_dir,
    "search_files": handle_search_files,
    "disk_usage": handle_disk_usage,
}


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
            out = {"protocolVersion": "2024-11-05", "serverInfo": {"name": "filesystem-enhanced", "version": VERSION}, "capabilities": {"tools": {}}}
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
