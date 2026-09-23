"""Head-to-head benchmark on the EXACT file comparators publish against.

``pure_tool.json`` (485 flattened cases) is the MCPTox subset used by third-party
scanners' public numbers (e.g. fuzzd's bench README: 440/485 = 90.7% detection;
NYIT-Vancouver mcp-tools-detection: 367/491 = 74.7%). This module adapts that
file — NOT our response_all.json corpus — into fugu sample dirs so our numbers
are directly comparable, same data, same denominator.

Protocol notes for fairness:
  * The 485 entries are all MALICIOUS (poisoned tool descriptions) — pure_tool
    is the attack subset of MCPTox; benign-FP measurement stays in our
    bench/real corpus (n=76) which comparators also do separately (fuzzd: 20
    clean tools, 0% FP).
  * Detection convention matches our existing harness: a case counts as
    detected when fugu emits any finding >= medium severity.
  * Category comes from entry['security risk'] (upstream label, same field
    fuzzd reads); paradigm from entry['paradigm'].

Usage:
    uv run python -m bench.mcptox.run_puretool [--semantic] [--conc N]

Static mode is free/offline; --semantic additionally runs the S2 Nemotron
judge (Token Factory; ~650 prompt + ~270 completion tokens/case).
Writes bench/results/mcptox-puretool.json + .md
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

from bench.mcptox.adapter import safe_dir_name
from bench.mcptox.run_static import RESULTS, SAMPLES_ROOT, SEV_ORDER

PURE_TOOL_URL = (
    "https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/"
    "main/pure_tool.json"
)


def load_pure_tool(path: Path | None = None) -> list[dict]:
    """Fetch (cached) + flatten pure_tool.json into adapter-shaped cases."""
    import urllib.request

    cache = Path(__file__).parent / "data" / "pure_tool.json"
    if path is None:
        if not cache.exists():
            cache.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(PURE_TOOL_URL, cache)  # noqa: S310
        path = cache
    raw = json.loads(path.read_text())
    cases: list[dict] = []
    for server_group in raw:  # list of per-server dicts
        for case_id, e in server_group.items():
            cases.append(
                {
                    "case_id": case_id,
                    "server": e.get("server_name", ""),
                    "server_url": "",
                    "tools": [],
                    "poisoned_tool_name": e.get("tool_name", ""),
                    "poisoned_description": e.get("tool_content", ""),
                    "arguments_text": "",
                    "paradigm": e.get("paradigm", ""),
                    "category": e.get("security risk", ""),
                    "query": e.get("query", ""),
                }
            )
    return cases


def _run_one(sample_dir: Path, semantic: bool) -> list:
    from fugu.pipeline import run_audit

    return run_audit(
        sample_dir,
        include_semantic=semantic,
        include_harness=False,
        include_detonation=False,
        include_reputation=False,
    )


def _summarize(findings) -> dict:
    sev = Counter(f.severity for f in findings)
    ids = {oid for f in findings for oid in f.owasp_ids}
    rules = Counter(ev.meta.get("rule", "?") for f in findings for ev in f.evidence)
    sources = sorted(
        {
            ev.source.split(":")[1] if ev.source.startswith("file:") else ev.source
            for f in findings
            for ev in f.evidence
        }
    )
    return {
        "sev": dict(sev),
        "max_sev": max((SEV_ORDER.get(s, 0) for s in sev), default=0),
        "owasp_ids": sorted(ids),
        "rules": dict(rules),
        "n_findings": len(findings),
        "sources": sources,
        "titles": [f.title for f in findings][:8],
    }


async def main_async(semantic: bool, conc: int) -> int:
    from bench.mcptox.adapter import adapt_case

    cases = load_pure_tool()
    print(f"pure_tool.json: {len(cases)} cases, "
          f"{len({c['category'] for c in cases})} categories")

    mode = "static S0+S1" + (" + semantic S2" if semantic else "")
    print(f"mode: {mode} | concurrency: {conc}")

    rows: list[dict] = []
    t0 = time.perf_counter()
    sem = asyncio.Semaphore(conc)
    done = 0

    async def work(case: dict) -> None:
        nonlocal done
        d = adapt_case(case, SAMPLES_ROOT)
        async with sem:
            res = await asyncio.to_thread(_run_one, d, semantic)
        res = _summarize(res)
        res.update(
            {
                "case_id": case["case_id"],
                "category": case["category"],
                "paradigm": case["paradigm"],
                "detected_med": res["max_sev"] >= 2,
                "detected_any": bool(res["sev"]),
            },
        )
        rows.append(res)
        done += 1
        if done % 25 == 0:
            det = sum(r["detected_med"] for r in rows)
            print(f"  {done}/{len(cases)} | detected(med+): {det}/{done}")

    await asyncio.gather(*(work(c) for c in cases))
    dt = time.perf_counter() - t0

    n = len(rows)
    det_med = sum(r["detected_med"] for r in rows)
    det_any = sum(r["detected_any"] for r in rows)
    by_cat: dict[str, dict] = defaultdict(lambda: {"n": 0, "det": 0})
    for r in rows:
        by_cat[r["category"]]["n"] += 1
        by_cat[r["category"]]["det"] += int(r["detected_med"])
    by_par: dict[str, dict] = defaultdict(lambda: {"n": 0, "det": 0})
    for r in rows:
        by_par[r["paradigm"]]["n"] += 1
        by_par[r["paradigm"]]["det"] += int(r["detected_med"])

    out = {
        "n": n,
        "dataset": "MCPTox pure_tool.json (485-case flat subset)",
        "mode": mode,
        "detection_convention": "any finding >= medium severity",
        "detected_medplus": det_med,
        "detected_any": det_any,
        "by_category": {k: v for k, v in sorted(by_cat.items())},
        "by_paradigm": dict(by_par),
        "elapsed_s": round(dt, 1),
        "rows": rows,
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    tag = "puretool" + ("-semantic" if semantic else "-static")
    (RESULTS / f"mcptox-{tag}.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    md = [
        f"# MCPTox pure_tool.json head-to-head subset",
        "",
        f"n={n} (all malicious; the file fuzzd 90.7% / NYIT 74.7% publish against)"
        f" · mode: **{mode}** · {dt:.0f}s",
        "",
        f"**Detection (any finding >= medium): {det_med}/{n} "
        f"({100*det_med/n:.1f}%)** · any-severity: {det_any}/{n}",
        "",
        "| Category | n | detected |",
        "|---|---|---|",
    ]
    for cat, v in sorted(by_cat.items(), key=lambda kv: -kv[1]["n"]):
        md.append(f"| {cat} | {v['n']} | {v['det']} |")
    (RESULTS / f"mcptox-{tag}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"\nRESULT: {det_med}/{n} ({100*det_med/n:.1f}%) med+ "
          f"| {det_any}/{n} any | {dt:.0f}s")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--semantic", action="store_true", help="add S2 Nemotron judge")
    p.add_argument("--conc", type=int, default=6, help="semantic concurrency")
    args = p.parse_args()
    return asyncio.run(main_async(args.semantic, args.conc))


if __name__ == "__main__":
    raise SystemExit(main())
