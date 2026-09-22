"""Composition set benchmark: detection/FP over corpus/composition sets.

Runs the REAL detector stack in-process, offline (children audited with
static-only stages — the deterministic path; LLM stages self-no-op in
benchmark mode exactly as in run_bench). For every set under
corpus/composition/ it builds MemberResults the same way the server's
run_composition_job does (findings from run_audit + tool names harvested
from the tree), runs CompositionStage, and emits a predictions file for
eval.run_eval --sets plus a markdown summary.

Usage:
  uv run python -m bench.composition_sets            # prints + writes results
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fugu.pipeline import run_audit  # noqa: E402
from fugu.pipeline.stages.composition import (  # noqa: E402
    CompositionStage,
    MemberResult,
)
from fugu.server.composition_jobs import harvest_tool_names  # noqa: E402
from eval.loader import load_set_specs  # noqa: E402
from eval.metrics import set_metrics, sets_to_markdown  # noqa: E402

SETS_ROOT = ROOT / "corpus" / "composition"
RESULTS = ROOT / "bench" / "results" / "composition-sets.json"


def member_result(dir_: Path, label: str) -> MemberResult:
    findings = run_audit(
        dir_,
        include_detonation=False,
        include_semantic=False,
        include_harness=False,
        include_reputation=False,
    )
    return MemberResult(
        label=label,
        slug=dir_.name,
        findings=findings,
        tool_names=harvest_tool_names(dir_),
        target_dir=dir_,
    )


def run_set(spec) -> dict:
    stage = CompositionStage()
    stage._member_results = [
        member_result(SETS_ROOT / spec.name / m.dir, m.label or m.dir)
        for m in spec.members
    ]
    result = asyncio.run(stage.run(job=None, target=None))  # type: ignore[arg-type]
    trifecta = any("trifecta" in f.title.lower() for f in result.findings)
    shadowing = any("shadowing" in f.title.lower() for f in result.findings)
    return {
        "set": spec.name,
        "trifecta": trifecta,
        "shadowing": shadowing,
        "findings": [
            {"severity": f.severity, "confidence": f.confidence, "title": f.title}
            for f in result.findings
        ],
    }


def main_async() -> int:
    specs = load_set_specs(SETS_ROOT)
    runs = []
    for spec in specs:
        r = run_set(spec)
        kind = next(s.kind for s in specs if s.name == r["set"])
        exp = next(s.expected for s in specs if s.name == r["set"])
        ok = r["trifecta"] == exp["trifecta"]
        print(f"  {r['set']:28s} [{kind:7s}] trifecta={r['trifecta']!s:5s} "
              f"shadowing={r['shadowing']!s:5s} expected_trifecta={exp['trifecta']!s:5s} "
              f"{'OK' if ok else 'MISS'}")
        runs.append(r)

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({"sets": runs}, indent=2) + "\n")

    report = set_metrics(
        [{"set": r["set"], "trifecta": r["trifecta"], "shadowing": r["shadowing"]} for r in runs],
        specs,
    )
    print()
    print(sets_to_markdown(report))
    print(f"\npredictions written to {RESULTS}")
    return 0


def main() -> int:
    return main_async()


if __name__ == "__main__":
    sys.exit(main())
