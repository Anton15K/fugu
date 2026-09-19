"""Run SEMANTIC (S2) detection over the MCPTox stratified subset.

Same subset policy + detection convention as run_static (n=120 for API
budget). Uses run_audit(include_semantic=True, everything else off) - the
Nemotron judge sees the poisoned description exactly as S1 did.

Usage: (NEBIUS_API_KEY set) uv run --no-sync python -m bench.mcptox.run_semantic [--n 120]
Writes bench/results/mcptox-semantic.md + .json.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from bench.mcptox.run_static import RESULTS, SAMPLES_ROOT, SEV_ORDER, stratified_subset  # noqa: E402
from fugu.pipeline import run_audit  # noqa: E402


async def main_async(n: int, tag: str = "") -> int:
    from bench.mcptox.fetch import fetch, load_cases
    from bench.mcptox.adapter import adapt_cases
    from fugu.pipeline import build_stages, run_stages
    from fugu.types import AuditJob, JobStatus

    load_cases(fetch())
    cases = load_cases()
    subset = stratified_subset(cases, n)
    sample_dirs = adapt_cases(subset, SAMPLES_ROOT)

    stages = build_stages(
        include_detonation=False, include_harness=False, include_reputation=False
    )

    t0 = time.time()
    det_med = det_any = 0
    rows = []
    for i, (case, sample) in enumerate(zip(subset, sample_dirs)):
        job = AuditJob(id=f"mcptox-sem-{i}", source=str(sample), status=JobStatus.running)
        results = await run_stages(job, sample, stages)
        findings = [f for r in results for f in r.findings]
        sev = max((SEV_ORDER.get(f.severity, 0) for f in findings), default=0)
        det_med += sev >= 2
        det_any += bool(findings)
        rows.append(
            {
                "case_id": case.get("case_id"),
                "category": case.get("attack_scope") or case.get("category"),
                "severity_max": sev,
                "detected_med": sev >= 2,
                "findings": len(findings),
            }
        )
        if (i + 1) % 20 == 0:
            print(f"{i+1}/{len(subset)} med={det_med} any={det_any} {time.time()-t0:.0f}s", flush=True)

    by_cat = defaultdict(lambda: [0, 0])
    for r in rows:
        by_cat[r["category"]][1] += 1
        by_cat[r["category"]][0] += r["detected_med"]

    lines = [
        "# MCPTox - SEMANTIC (S2) detection run",
        "",
        f"n={len(rows)} (stratified, deterministic) · mode: S0+S1+S2 (Nemotron judge) · {time.strftime('%Y-%m-%d %H:%M')}",
        "",
        f"**Overall (medium+): {det_med}/{len(rows)} ({det_med/len(rows):.0%})** · any-finding: {det_any}/{len(rows)}",
        "",
        "| category | detected (med+) | n |", "|---|---|---|",
    ]
    for cat, (d, t) in sorted(by_cat.items(), key=lambda kv: -kv[1][1]):
        lines.append(f"| {cat} | {d}/{t} ({d/t:.0%}) | {t} |")
    text = "\n".join(lines)
    RESULTS.mkdir(exist_ok=True)
    suffix = f"-{tag}" if tag else ""
    (RESULTS / f"mcptox-semantic{suffix}.md").write_text(text + "\n")
    (RESULTS / f"mcptox-semantic{suffix}.json").write_text(
        json.dumps({"n": len(rows), "det_med": det_med, "rows": rows}, indent=1)
    )
    print(text)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=120)
    p.add_argument("--tag", default="", help="suffix for output files (e.g. 'confirm')")
    args = p.parse_args()
    return asyncio.run(main_async(args.n, args.tag))


if __name__ == "__main__":
    sys.exit(main())
