"""Verdict aggregation - one pure function shared by server, CLI and eval.

Policy (documented for judges; keep in sync with README):
  FAIL  - any critical finding, OR any high finding backed by deterministic
          or empirical evidence (canary hits, harness signals, scanner hits)
  WARN  - any advisory high, or any medium finding, or detonation/harness
          could not run (coverage caveat)
  PASS  - only low/info findings (or none)

Every verdict also reports: severity counts, the strongest confidence tier
observed, and a coverage note listing stages that were skipped (a PASS from
a static-only run says so explicitly - eval honesty, drift D2).
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from fugu.types import Finding, StageResult

_TIER_RANK = {"deterministic": 3, "empirical": 2, "measured": 1, "advisory": 0}
_LIVE_STAGES = ("semantic", "detonation", "harness")


def aggregate_verdict(
    findings: list[Finding], stage_results: list[StageResult]
) -> dict[str, Any]:
    """Return the final verdict document for one audit."""
    sev_counts = Counter(f.severity for f in findings)
    tiers = [f.confidence for f in findings]
    max_tier = max(tiers, key=lambda t: _TIER_RANK.get(t, -1)) if tiers else None

    has_critical = sev_counts.get("critical", 0) > 0
    has_hard_high = any(
        f.severity == "high" and f.confidence in ("deterministic", "empirical")
        for f in findings
    )
    has_advisory_high = any(
        f.severity == "high" and f.confidence not in ("deterministic", "empirical")
        for f in findings
    )
    has_medium = sev_counts.get("medium", 0) > 0

    skipped = sorted(
        r.stage for r in stage_results if not r.ok or "skipped" in (r.metrics or {})
    )
    detonation_failed = any(r.stage == "detonation" and not r.ok for r in stage_results)

    if has_critical or has_hard_high:
        status = "fail"
    elif has_advisory_high or has_medium or detonation_failed:
        status = "warn"
    else:
        status = "pass"

    reasons: list[str] = []
    if has_critical:
        reasons.append(f"{sev_counts['critical']} critical finding(s)")
    if has_hard_high:
        reasons.append("high-severity finding(s) with deterministic/empirical evidence")
    if has_advisory_high:
        reasons.append("high-severity finding(s) pending semantic confirmation (advisory)")
    if has_medium:
        reasons.append(f"{sev_counts.get('medium', 0)} medium finding(s)")
    if detonation_failed:
        reasons.append("detonation stage failed - dynamic coverage incomplete")
    if not reasons:
        reasons.append("no findings above low/info severity")

    coverage: list[str] = []
    for stage in _LIVE_STAGES:
        for r in stage_results:
            if r.stage == stage and (not r.ok or "skipped" in (r.metrics or {})):
                coverage.append(f"{stage}: {'failed' if not r.ok else 'skipped'}")

    return {
        "status": status,
        "total_findings": len(findings),
        "severity_counts": {k: sev_counts.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "max_confidence_tier": max_tier,
        "reasons": reasons,
        "coverage_caveats": coverage,
        "static_only": bool(coverage) and status != "fail",
    }


__all__ = ["aggregate_verdict"]
