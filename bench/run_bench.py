"""Fugu benchmark: external validity + tiered detection (docs/benchmark.md).

Runs the pipeline over two provenance sets and reports them SEPARATELY
(CASCADE arXiv 2604.17125: detection is not provenance-invariant; pooled
numbers from crafted corpora inflate):

  crafted  - corpus/ (attacks we authored + benign twins)
  real     - bench/real/*-samples (public third-party skills, benign)

Modes:
  --static  offline deterministic pass (S0+S1)          [default, free]
  --live    adds S2 semantic (Nemotron judge) + S4 harness

Headline numbers (MCPZoo arXiv 2607.11086 frames the field's problem:
scanners flag 96.89% of servers; <50% of sampled alerts are true positives):
  - benign-FP rate on REAL skills      (crying-wolf metric)
  - attack detection rate on CRAFTED    (per confidence tier)
  - severity/OWASP histogram + split tables

Usage:
  uv run --no-sync python -m bench.run_bench [--live] [--markdown out.md]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fugu.pipeline import build_stages, run_stages  # noqa: E402
from fugu.types import AuditJob, JobStatus  # noqa: E402

CRAFTED = ROOT / "corpus"
REAL = ROOT / "bench" / "real"

# Field context rows (published numbers, for honest framing)
PAPER_CONTEXT = [
    ("MCPZoo '26 (2607.11086)", "share of servers flagged risky by existing scanners", "96.89%"),
    ("MCPZoo '26 (2607.11086)", "TRUE-positive rate of sampled scanner alerts (manual validation)", "<50%"),
    ("MCPTox AAAI-26 (2508.14925)", "max tool-poisoning attack success rate across 20 agents", "72.8%"),
    ("MCPTox AAAI-26 (2508.14925)", "best refusal rate against tool poisoning", "<3%"),
    ("Registry census '26 (2609.10962)", "tools omitting optional safety annotations", "58.8%"),
    ("SkillSecurer '26 (2609.14079)", "skills.sh skills with latent injection vulnerabilities", ">17%"),
]


def load_samples(base: Path, manifest_name: str = "manifest.json") -> list[dict]:
    samples = []
    for d in sorted(base.iterdir()):
        m = d / manifest_name
        if not d.is_dir() or not m.is_file():
            continue
        doc = json.loads(m.read_text())
        samples.append({"name": doc.get("name", d.name), "kind": doc.get("kind", "benign"),
                        "expected": set(doc.get("expected_owasp_ids", [])), "path": d})
    return samples


async def audit(sample: dict, live: bool) -> dict:
    job = AuditJob(id=f"bench-{sample['name']}", source=str(sample["path"]),
                   status=JobStatus.running, depth="standard")
    stages = build_stages(
        include_detonation=live,      # detonation is slow; live mode = semantic+harness focus
        include_semantic=live,
        include_harness=live,
        include_reputation=False,
    )
    if not live:
        stages = [s for s in stages if s.name in ("concealment", "static")]
    t0 = time.perf_counter()
    results = await run_stages(job, sample["path"], stages)
    findings = [f for r in results for f in r.findings]
    return {
        "findings": findings,
        "sev": Counter(f.severity for f in findings),
        "tiers": Counter(f.confidence for f in findings),
        "owasp": {f.owasp_ids[0] for f in findings} | {o for f in findings for o in f.owasp_ids},
        "stage_ok": {r.stage: r.ok for r in results},
        "secs": round(time.perf_counter() - t0, 1),
    }


def rates(samples: list[dict], runs: dict[str, dict]) -> dict:
    malicious = [s for s in samples if s["kind"] == "malicious"]
    benign = [s for s in samples if s["kind"] == "benign"]
    detected = sum(1 for s in malicious if runs[s["name"]]["sev"].get("medium", 0)
                   + runs[s["name"]]["sev"].get("high", 0)
                   + runs[s["name"]]["sev"].get("critical", 0) > 0)
    flagged = sum(1 for s in benign if runs[s["name"]]["sev"].get("medium", 0)
                  + runs[s["name"]]["sev"].get("high", 0)
                  + runs[s["name"]]["sev"].get("critical", 0) > 0)
    info_only = sum(1 for s in benign if runs[s["name"]]["sev"] and not (
        runs[s["name"]]["sev"].get("medium", 0) or runs[s["name"]]["sev"].get("high", 0)
        or runs[s["name"]]["sev"].get("critical", 0)))
    return {
        "n": len(samples), "n_malicious": len(malicious), "n_benign": len(benign),
        "detection": detected, "detection_rate": detected / len(malicious) if malicious else None,
        "fp": flagged, "fp_rate": flagged / len(benign) if benign else None,
        "benign_info_only": info_only,
        "avg_secs": round(sum(r["secs"] for r in runs.values()) / max(len(runs), 1), 1),
    }


def render_md(mode: str, sets: dict[str, tuple[list, dict]], out: Path) -> str:
    lines = [
        "# Fugu benchmark report",
        "",
        f"Mode: **{mode}** · Generated: {time.strftime('%Y-%m-%d %H:%M')} · Tool: `python -m bench.run_bench`",
        "",
        "Provenance-split results (CASCADE 2604.17125: pooled crafted+real numbers inflate; we never pool):",
        "",
        "| Provenance set | n (mal/ben) | Attack detection | Benign flag rate | Info-only on benign | avg s/audit |",
        "|---|---|---|---|---|---|",
    ]
    for label, (samples, runs) in sets.items():
        r = rates(samples, runs)
        det = f"{r['detection']}/{r['n_malicious']} ({r['detection_rate']:.0%})" if r["detection_rate"] is not None else "n/a"
        fp = f"{r['fp']}/{r['n_benign']} ({r['fp_rate']:.0%})" if r["fp_rate"] is not None else "n/a"
        lines.append(f"| {label} | {r['n']} ({r['n_malicious']}/{r['n_benign']}) | {det} | {fp} | {r['benign_info_only']} | {r['avg_secs']} |")
    lines += ["", "Field context (published, not our measurements):", "",
              "| Source | Finding | Number |", "|---|---|---|"]
    lines += [f"| {a} | {b} | {c} |" for a, b, c in PAPER_CONTEXT]
    text = "\n".join(lines)
    if out:
        out.write_text(text + "\n")
    return text


async def main_async(args) -> int:
    sets: dict[str, tuple[list, dict]] = {}
    crafted = load_samples(CRAFTED)
    runs = {s["name"]: await audit(s, args.live) for s in crafted}
    sets["crafted (corpus/)"] = (crafted, runs)

    real_all: list[dict] = []
    for samples_dir in sorted(REAL.glob("*-samples")):
        real_all += load_samples(samples_dir, manifest_name="manifest.fugu.json")
    if real_all:
        runs_real = {s["name"]: await audit(s, args.live) for s in real_all}
        sets[f"real (public skills, n={len(real_all)})"] = (real_all, runs_real)
    else:
        print("NOTE: no real samples found - run `python -m bench.fetch_real` first", file=sys.stderr)

    mode = "static S0+S1" if not args.live else "live S0+S1+S2(semantic)+S4(harness)"
    md = render_md(mode, sets, ROOT / "docs" / "benchmark.md")
    print(md)

    # per-tier detail for crafted attacks
    _, crafted_runs = sets["crafted (corpus/)"]
    tier_det = Counter()
    for s in crafted:
        if s["kind"] != "malicious":
            continue
        for tier in ("deterministic", "empirical", "advisory"):
            if any(tier in r["tiers"] for n, r in crafted_runs.items() if n == s["name"]):
                tier_det[tier] += 1
    print("\nAttack detection by tier (crafted):", dict(tier_det))
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--live", action="store_true", help="include semantic+harness stages (LLM calls)")
    p.add_argument("--markdown", default=None)
    args = p.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
