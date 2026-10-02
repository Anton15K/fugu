"""Verdict aggregation - one pure function shared by server, CLI and eval.

Policy (documented for judges; keep in sync with README):
  FAIL  - any critical finding, OR any high finding backed by deterministic
          or empirical evidence (canary hits, harness signals, scanner hits)
  WARN  - any advisory high, medium finding, failed/partial analysis, or
          omitted skill units (coverage caveat)
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


def stage_coverage(result: StageResult) -> dict[str, Any] | None:
    """Describe execution independently of findings, for member propagation."""
    metrics = result.metrics or {}
    if not result.ok:
        state, reason = "failed", result.error or "analysis unavailable"
    elif "skipped" in metrics:
        state, reason = "skipped", str(metrics["skipped"])
    elif metrics.get("coverage_incomplete"):
        state, reason = "partial", str(metrics["coverage_incomplete"])
    elif result.stage in _LIVE_STAGES:
        state, reason = "completed", "analysis completed"
    else:
        return None
    executed = result.stage in _LIVE_STAGES and state in ("completed", "partial")
    if "executed" in metrics:
        executed = bool(metrics["executed"])
    return {"stage": result.stage, "state": state, "reason": reason, "executed": executed}


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

    records: list[dict[str, Any]] = []
    omitted_units = 0
    for result in stage_results:
        record = stage_coverage(result)
        if record is not None:
            records.append(record)
        records.extend((result.metrics or {}).get("member_coverage", []))
        omitted_units += (result.metrics or {}).get("omitted_units", 0)
    incomplete = [r for r in records if r["state"] in ("failed", "partial")]
    coverage = []
    for record in records:
        if record["state"] == "completed":
            continue
        prefix = (
            f"member {record['member']} ({record['job_id']}): "
            if "member" in record else ""
        )
        coverage.append(f"{prefix}{record['stage']}: {record['state']}")
    if omitted_units:
        coverage.append(f"{omitted_units} skill unit(s) omitted by fan-out cap")

    if has_critical or has_hard_high:
        status = "fail"
    elif has_advisory_high or has_medium or incomplete or omitted_units:
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
    if incomplete:
        affected = ", ".join(sorted({r["stage"] for r in incomplete}))
        reasons.append(f"{affected} analysis failed or partially completed - coverage incomplete")
    if omitted_units:
        reasons.append(f"{omitted_units} skill unit(s) not audited (fan-out cap)")
    if not reasons:
        reasons.append("no findings above low/info severity")

    return {
        "status": status,
        "total_findings": len(findings),
        "severity_counts": {k: sev_counts.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "max_confidence_tier": max_tier,
        "reasons": reasons,
        "coverage_caveats": coverage,
        "static_only": bool(coverage) and not any(r["executed"] for r in records),
        "partial_coverage": bool(coverage),
        "omitted_units": omitted_units,
    }


__all__ = ["aggregate_verdict", "stage_coverage"]
