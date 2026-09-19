"""Download + cache the MCPTox benchmark (arXiv 2508.14925, AAAI-26).

Dataset discovery notes (2026-09-19):
  * There is NO official HuggingFace dataset - HF API search for "mcptox"
    returns []. The canonical release is the authors' GitHub repo
    ``zhiqiangwang4/MCPTox-Benchmark`` (linked from the AAAI camera-ready).
  * Canonical payload: ``response_all.json`` at a pinned commit - the same
    file+sha the third-party inspect-evals port (stefanoamorelli/
    inspect-evals-mcptox) pins, so our numbers are reproducible against a
    known-good snapshot.
  * Repo also ships ``pure_tool.json`` (485-case flat subset) and
    ``def_tool/*.py`` (486 per-server tool defs); we do not use them.

Schema of ``response_all.json`` (studied before writing the adapter):
  {
    "servers": {
      "<ServerName>": {
        "server_id": int, "category_id": int, "server_name": str,
        "server_url": str,                 # upstream project homepage
        "tool_names": [str, ...],          # legitimate tools on the server
        "clean_system_promot": str,        # [sic] unpoisoned system prompt
        "clean_querys": [...],             # [sic]
        "malicious_instance": [
          {
            "security_risk_description": str,   # Chinese-language note
            "wrong_data": 0 | 2,                # 2 = invalid, upstream-flagged
            "poisoned_tool": "Tool: <name>\\nDescription: <poisoned text>\\nArguments: ...",
            "metadata": {"paradigm": "Template-1|2|3",
                         "security risk": "<category>"},
            "datas": [ {"id": str, "query": str, "system": str,
                        "response": ..., "label": ..., "online_result": ...} ]
          }, ...
        ]
      }, ...
    }
  }
  1,348 instances total; 1,312 valid (wrong_data == 0); 45 servers;
  11 risk categories; 3 paradigms (T1=208, T2=519, T3=585).

Download is plain urllib (no huggingface_hub dependency). The file is
cached under bench/mcptox/data/ (gitignored).

Usage (from repo root; network required - this is the one live step):
  uv run --no-sync python -m bench.mcptox.fetch [--force]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

MCPTOX_DIR = Path(__file__).resolve().parent
DATA_DIR = MCPTOX_DIR / "data"
CACHE_PATH = DATA_DIR / "response_all.json"

# Pinned upstream snapshot (see stefanoamorelli/inspect-evals-mcptox dataset.py).
REPO = "zhiqiangwang4/MCPTox-Benchmark"
COMMIT = "f85189f9ad12504c197c7f920ab818a40657b1fa"
URL = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/response_all.json"
SHA256 = "79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(force: bool = False) -> Path:
    """Download+verify (or reuse) the cached MCPTox payload; returns its path."""
    if CACHE_PATH.is_file() and not force:
        digest = _sha256_file(CACHE_PATH)
        if digest == SHA256:
            return CACHE_PATH
        print(f"cache sha mismatch ({digest}); refetching", file=sys.stderr)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_PATH.with_suffix(".part")
    print(f"downloading {URL} ...")
    req = urllib.request.Request(URL, headers={"User-Agent": "fugu-bench/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, tmp.open("wb") as fh:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
    digest = _sha256_file(tmp)
    if digest != SHA256:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(
            f"sha256 mismatch for {URL}: got {digest}, want {SHA256}; refusing to cache"
        )
    tmp.replace(CACHE_PATH)
    print(f"cached {CACHE_PATH} ({CACHE_PATH.stat().st_size:,} bytes, sha256 ok)")
    return CACHE_PATH


def load_cases(path: Path | None = None) -> list[dict]:
    """Flatten the nested payload into one dict per VALID instance.

    Each returned case: {case_id, server, server_url, tools, poisoned_tool_name,
    poisoned_description, arguments_text, paradigm, category, query}.
    ``wrong_data`` instances (36/1348) are skipped, matching upstream +
    inspect-evals convention -> 1,312 cases.
    """
    path = path or fetch()
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    cases: list[dict] = []
    for server_name, server in doc["servers"].items():
        for i, inst in enumerate(server.get("malicious_instance", [])):
            if inst.get("wrong_data"):
                continue
            meta = inst.get("metadata", {}) or {}
            datas = inst.get("datas") or [{}]
            name, desc, args_text = parse_poisoned_tool(inst.get("poisoned_tool", ""))
            cases.append(
                {
                    "case_id": f"{server_name}-{i}",
                    "server": server.get("server_name", server_name),
                    "server_url": server.get("server_url", ""),
                    "tools": list(server.get("tool_names", [])),
                    "poisoned_tool_name": name,
                    "poisoned_description": desc,
                    "arguments_text": args_text,
                    "paradigm": meta.get("paradigm", ""),
                    "category": meta.get("security risk", ""),
                    "query": (datas[0] or {}).get("query", ""),
                }
            )
    return cases


def parse_poisoned_tool(block: str) -> tuple[str, str, str]:
    """Split a poisoned-tool block into (name, description, arguments text).

    Upstream blocks look like ``Tool: qubit\\nDescription: ...\\nArguments:``;
    ~half use LITERAL ``\\\\n`` escapes instead of real newlines (verified:
    635/1312), so both are normalized first. Mirrors the parsing contract of
    the inspect-evals port (name regex + description up to Arguments:/end).
    """
    text = block.replace("\\n", "\n").replace("\\t", "\t").strip()
    name = ""
    description = ""
    args_text = ""
    lines = text.split("\n")
    for j, line in enumerate(lines):
        if line.startswith("Tool:") and not name:
            name = line[len("Tool:"):].strip()
        elif line.startswith("Description:") and not description:
            description = line[len("Description:"):].strip()
            if "Arguments:" in description:  # same-line variant
                description, _, args_text = description.partition("Arguments:")
                description, args_text = description.strip(), args_text.strip()
            else:
                rest = "\n".join(lines[j + 1:])
                if "\nArguments:" in rest or rest.startswith("Arguments:"):
                    body, sep, args_text = rest.partition("Arguments:")
                    description = (description + "\n" + body).strip() if sep else description
                    args_text = args_text.strip()
                else:
                    description = (description + "\n" + rest).strip()
    return name, description, args_text


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--force", action="store_true", help="refetch even if cached")
    args = p.parse_args()
    path = fetch(force=args.force)
    cases = load_cases(path)
    from collections import Counter

    cats = Counter(c["category"] for c in cases)
    paradigms = Counter(c["paradigm"] for c in cases)
    print(f"valid cases: {len(cases)} across {len({c['server'] for c in cases})} servers")
    print("by category:", dict(sorted(cats.items(), key=lambda kv: -kv[1])))
    print("by paradigm:", dict(paradigms))
    missing_name = sum(1 for c in cases if not c["poisoned_tool_name"])
    empty_desc = sum(1 for c in cases if not c["poisoned_description"])
    print(f"parse check: missing name={missing_name}, empty description={empty_desc}")
    return 0 if (len(cases) == 1312 and not missing_name and not empty_desc) else 1


if __name__ == "__main__":
    sys.exit(main())
