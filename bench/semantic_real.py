"""Semantic (S2) benign-FP run over the real-world skill set.

The "no crying wolf" counterpart to the MCPTox 99%: run ONLY the semantic
judge (+static, it is free) over every real third-party skill and count how
many get flagged medium+. A skill is FLAGGED if any finding >= medium.

Usage (NEBIUS_API_KEY set):
  uv run --no-sync python -m bench.semantic_real
Writes bench/results/semantic-real.md + .json.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bench.run_bench import REAL, load_samples  # noqa: E402
from fugu.pipeline import build_stages, run_stages  # noqa: E402
from fugu.types import AuditJob, JobStatus  # noqa: E402

RESULTS = ROOT / "bench" / "results"


async def main_async() -> int:
    samples: list[dict] = []
    for samples_dir in sorted(REAL.glob("*-samples")):
        samples += load_samples(samples_dir, manifest_name="manifest.fugu.json")
    if not samples:
        print("no real samples - run `python -m bench.fetch_real` first", file=sys.stderr)
        return 1

    stages = build_stages(include_detonation=False, include_harness=False, include_reputation=False)
    flagged: list[tuple[str, list]] = []
    rows: list[dict] = []
    t0 = time.time()
    for i, s in enumerate(samples):
        job = AuditJob(id=f"semreal-{i}", source=str(s["path"]), status=JobStatus.running)
        results = await run_stages(job, s["path"], stages)
        findings = [f for r in results for f in r.findings]
        med = [f for f in findings if f.severity in ("critical", "high", "medium")]
        rows.append(
            {
                "name": s["name"],
                "findings": len(findings),
                "med_plus": len(med),
                "med_titles": [f.title for f in med],
                "med_excerpts": [(f.title, (f.evidence[0].excerpt[:150] if f.evidence else "")) for f in med],
            }
        )
        if med:
            flagged.append((s["name"], med))
        if (i + 1) % 10 == 0:
            print(f"{i+1}/{len(samples)} flagged={len(flagged)} {time.time()-t0:.0f}s", flush=True)

    n = len(samples)
    lines = [
        "# Semantic (S2) benign-FP run - real-world skills",
        "",
        f"n={n} · mode: S0+S1+S2 (Nemotron judge) · {time.strftime('%Y-%m-%d %H:%M')}",
        "",
        f"**FLAGGED (medium+): {len(flagged)}/{n} ({len(flagged)/n:.0%})** - the no-crying-wolf number for the semantic tier",
        "",
    ]
    if flagged:
        lines += ["| skill | findings (med+) |", "|---|---|"]
        lines += [f"| {name} | {'; '.join(f.title for f in med[:3])} |" for name, med in flagged]
    text = "\n".join(lines)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "semantic-real.md").write_text(text + "\n")
    (RESULTS / "semantic-real.json").write_text(json.dumps(rows, indent=1))
    print(text)
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
