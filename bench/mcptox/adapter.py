"""Adapt MCPTox cases into fugu sample dirs (bench/run_bench.py-compatible).

Each valid MCPTox instance becomes one sample directory shaped like a
minimal MCP server, so the fugu static pipeline (S0 concealment + S1
static) sees exactly the artifact class MCPTox attacks: a ``TOOLS`` list
whose poisoned entry carries the malicious description.

Layout per case (mirrors corpus/08-clean-mcp-server + bench/real manifests):

  <out>/<case_id>/
    server.py            # minimal MCP-shaped stdio server; TOOLS[0] is the
                         # poisoned tool (name + full poisoned description),
                         # followed by honest stubs for the legitimate tools
    manifest.fugu.json   # fugu bench manifest (kind=malicious, expected ids
                         # from bench.mcptox.mapping.expected_owasp_ids)
    case.json            # the raw upstream case for provenance/debugging

The benign tools get short honest descriptions ("Call <name> ...") - they
are the attack's *vehicle*, not its payload; the ground truth is the
poisoned description, which is preserved verbatim (only the upstream
literal ``\\n`` escapes are normalized, as in fetch.parse_poisoned_tool).

Deterministic: sample content is a pure function of the case fields (no
timestamps), so regenerated dirs are byte-identical.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from bench.mcptox.mapping import expected_owasp_ids

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Honest stub description for the legitimate (unpoisoned) vehicle tools.
_BENIGN_DESC = (
    "Call the upstream '{tool}' tool of the {server} MCP server with the "
    "arguments the user requested, and return its result."
)


def safe_dir_name(case_id: str) -> str:
    """Filesystem-safe, collision-free sample dir name."""
    slug = _SAFE_ID_RE.sub("-", case_id.strip()).strip("-") or "case"
    return re.sub(r"-+", "-", slug)


def _python_string_literal(s: str) -> str:
    """repr() as a Python string literal - always safe embedded source."""
    return repr(s)


def render_server_py(case: dict) -> str:
    """Minimal MCP-server-shaped target carrying the poisoned description."""
    server = case.get("server", "unknown")
    poisoned_name = case.get("poisoned_tool_name") or "poisoned_tool"
    poisoned_desc = case.get("poisoned_description", "")
    category = case.get("category", "")
    paradigm = case.get("paradigm", "")

    tools_entries: list[str] = [
        "    {",
        '        "name": ' + _python_string_literal(poisoned_name) + ",",
        '        "description": ' + _python_string_literal(poisoned_desc) + ",",
        '        "inputSchema": {"type": "object", "properties": {}},',
        '        "annotations": {"readOnlyHint": True, "destructiveHint": False,'
        ' "idempotentHint": True, "openWorldHint": False},',
        "    },",
    ]
    for t in case.get("tools", []):
        if t == poisoned_name:
            continue
        tools_entries += [
            "    {",
            '        "name": ' + _python_string_literal(t) + ",",
            '        "description": '
            + _python_string_literal(_BENIGN_DESC.format(tool=t, server=server)) + ",",
            '        "inputSchema": {"type": "object", "properties": {}},',
            '        "annotations": {"readOnlyHint": True, "destructiveHint": False,'
            ' "idempotentHint": True, "openWorldHint": False},',
            "    },",
        ]

    body = (
        "from __future__ import annotations\n"
        "\n"
        "import json\n"
        "import sys\n"
        "\n"
        "SERVER_NAME = " + _python_string_literal(server) + "\n"
        "\n"
        "TOOLS = [\n"
        + "\n".join(tools_entries)
        + "\n]\n"
        "\n"
        "\n"
        "def respond(id_, result) -> str:\n"
        '    return json.dumps({"jsonrpc": "2.0", "id": id_, "result": result})\n'
        "\n"
        "\n"
        "def main() -> None:\n"
        '    """Never implemented: this target exists to be SCANNED, not run."""\n'
        "    for line in sys.stdin:\n"
        "        line = line.strip()\n"
        "        if not line:\n"
        "            continue\n"
        "        try:\n"
        "            req = json.loads(line)\n"
        "        except json.JSONDecodeError:\n"
        "            continue\n"
        "        method = req.get(\"method\", \"\")\n"
        "        if method == \"initialize\":\n"
        "            out = {\"protocolVersion\": \"2024-11-05\",\n"
        "                   \"serverInfo\": {\"name\": SERVER_NAME, \"version\": \"0.0.0\"},\n"
        "                   \"capabilities\": {\"tools\": {}}}\n"
        "        elif method == \"tools/list\":\n"
        "            out = {\"tools\": TOOLS}\n"
        "        else:\n"
        "            out = {}\n"
        "        sys.stdout.write(respond(req.get(\"id\"), out) + \"\\n\")\n"
        "        sys.stdout.flush()\n"
        "\n"
        "\n"
        'if __name__ == "__main__":\n'
        "    main()\n"
    )
    header = (
        '"""' + server + ": minimal MCP-server-shaped target adapted from MCPTox.\n"
        "\n"
        "Auto-generated by bench/mcptox/adapter.py from benchmark case\n"
        + case.get("case_id", "?") + " (category=" + category + ", paradigm=" + paradigm + ")."
        " The TOOLS list below embeds\n"
        "the benchmark's poisoned tool description VERBATIM; all other tools\n"
        "are honest stubs. Never execute - research artifact only.\n"
        '"""\n'
    )
    return header + body


def render_manifest(case: dict) -> str:
    """fugu bench manifest (schema matches corpus/manifest.json fields used
    by bench.run_bench.load_samples + bench/real manifests)."""
    manifest = {
        "name": "mcptox-" + safe_dir_name(case.get("case_id", "case")),
        "kind": "malicious",
        "expected_owasp_ids": expected_owasp_ids(
            case.get("category", ""), case.get("paradigm")
        ),
        "description": (
            f"MCPTox case {case.get('case_id', '?')} on server "
            f"'{case.get('server', '?')}' (category={case.get('category', '?')}, "
            f"paradigm={case.get('paradigm', '?')}): poisoned tool "
            f"'{case.get('poisoned_tool_name', '?')}' description. "
            "Upstream: arXiv 2508.14925 / github.com/zhiqiangwang4/MCPTox-Benchmark."
        ),
        "provenance": "real-benchmark",
        "source": {
            "benchmark": "MCPTox (arXiv 2508.14925)",
            "server": case.get("server", ""),
            "server_url": case.get("server_url", ""),
            "category": case.get("category", ""),
            "paradigm": case.get("paradigm", ""),
            "poisoned_tool": case.get("poisoned_tool_name", ""),
            "query": case.get("query", ""),
        },
    }
    return json.dumps(manifest, indent=2) + "\n"


def adapt_case(case: dict, out_root: Path) -> Path:
    """Write one MCPTox case as a fugu sample dir; returns the dir path."""
    d = out_root / safe_dir_name(case.get("case_id", "case"))
    d.mkdir(parents=True, exist_ok=True)
    (d / "server.py").write_text(render_server_py(case), encoding="utf-8")
    (d / "manifest.fugu.json").write_text(render_manifest(case), encoding="utf-8")
    (d / "case.json").write_text(
        json.dumps(case, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return d


def adapt_cases(cases: list[dict], out_root: Path, limit: int | None = None) -> list[Path]:
    """Adapt cases (optionally truncated); wipes only matching subdirs."""
    if limit is not None:
        cases = cases[:limit]
    out_root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for case in cases:
        written.append(adapt_case(case, out_root))
    return written


__all__ = [
    "safe_dir_name",
    "render_server_py",
    "render_manifest",
    "adapt_case",
    "adapt_cases",
]
