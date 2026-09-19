"""Tests for verdict aggregation + S5 reputation (offline)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fugu.pipeline.stages.reputation import ReputationStage, extract_identifiers
from fugu.types import AuditJob, Finding, JobStatus, StageResult
from fugu.verdict import aggregate_verdict


def _f(sev: str, conf: str) -> Finding:
    return Finding(owasp_ids=["LLM01"], title="t", detail="d", severity=sev, confidence=conf, stage="static")


def _sr(stage: str, ok: bool = True, skipped: bool = False) -> StageResult:
    return StageResult(stage=stage, ok=ok, metrics={"skipped": "x"} if skipped else {})


def test_critical_fails():
    v = aggregate_verdict([_f("critical", "deterministic")], [_sr("static")])
    assert v["status"] == "fail"
    assert v["severity_counts"]["critical"] == 1
    assert v["max_confidence_tier"] == "deterministic"


def test_hard_high_fails_but_advisory_high_only_warns():
    assert aggregate_verdict([_f("high", "empirical")], [_sr("harness")])["status"] == "fail"
    v = aggregate_verdict([_f("high", "advisory")], [_sr("semantic")])
    assert v["status"] == "warn"
    assert "pending semantic confirmation" in v["reasons"][0]


def test_medium_warns_clean_passes():
    assert aggregate_verdict([_f("medium", "deterministic")], [])["status"] == "warn"
    v = aggregate_verdict([_f("info", "deterministic"), _f("low", "advisory")], [_sr("static")])
    assert v["status"] == "pass"
    assert v["coverage_caveats"] == []


def test_static_only_pass_is_flagged():
    results = [_sr("static"), _sr("semantic", skipped=True), _sr("detonation", skipped=True)]
    v = aggregate_verdict([], results)
    assert v["status"] == "pass"
    assert v["static_only"] is True
    assert len(v["coverage_caveats"]) == 2


def test_detonation_failure_downgrades_to_warn():
    v = aggregate_verdict([], [_sr("static"), _sr("detonation", ok=False)])
    assert v["status"] == "warn"
    assert any("detonation" in r for r in v["reasons"])


# --- reputation ------------------------------------------------------------------

def _target(tmp_path: Path) -> Path:
    d = tmp_path / "ext"
    d.mkdir()
    (d / "package.json").write_text(
        '{"name": "reaqt", "dependencies": {"lodahs": "1.0.0", "express": "4.0.0"}}'
    )
    (d / "index.js").write_text(
        "fetch('https://stats-collector.example.net/pixel')\n"
        "fetch('https://api.github.com/repos/x')\n"
    )
    return d


def test_extract_identifiers(tmp_path):
    ids = extract_identifiers(_target(tmp_path))
    assert "reaqt" in ids["packages"] and "lodahs" in ids["packages"]
    assert "stats-collector.example.net" in ids["domains"]
    assert "api.github.com" in ids["domains"]  # github.com skipped, subdomain kept


def test_reputation_offline_noop(tmp_path):
    import os

    saved = os.environ.pop("TAVILY_API_KEY", None)
    try:
        res = asyncio.run(ReputationStage().run(AuditJob(id="t", source="x", status=JobStatus.running), _target(tmp_path)))
    finally:
        if saved:
            os.environ["TAVILY_API_KEY"] = saved
    assert res.ok and res.findings == []
    assert "skipped" in res.metrics


def _fake_search(results_by_ident: dict[str, list[dict]]):
    def search(api_key: str, query: str):
        for ident, results in results_by_ident.items():
            if ident in query:
                return {"results": results}
        return {"results": []}

    return search


def test_reputation_adverse_hit_cited(tmp_path):
    search = _fake_search(
        {
            "reaqt": [
                {"title": "reaqt is a known typosquat of react", "url": "https://blog.example.net/reaqt", "content": "..."},
            ]
        }
    )
    stage = ReputationStage(search_fn=search)
    res = asyncio.run(stage.run(AuditJob(id="t", source="x", status=JobStatus.running), _target(tmp_path)))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.owasp_ids == ["MCP04", "LLM03"] and f.confidence == "advisory"
    assert f.evidence[0].source.startswith("tavily:")
    assert "typosquat" in f.evidence[0].excerpt
    assert res.metrics["queries"] >= 1


def test_reputation_clean_silent(tmp_path):
    search = _fake_search({"reaqt": [{"title": "reaqt changelog", "url": "https://example.net", "content": "bugfixes"}]})
    stage = ReputationStage(search_fn=search)
    res = asyncio.run(stage.run(AuditJob(id="t", source="x", status=JobStatus.running), _target(tmp_path)))
    assert res.findings == []
    assert res.metrics["queries"] >= 1


def test_reputation_call_error_is_degraded_not_failed(tmp_path):
    def boom(api_key, query):
        raise RuntimeError("network down")

    stage = ReputationStage(search_fn=boom)
    res = asyncio.run(stage.run(AuditJob(id="t", source="x", status=JobStatus.running), _target(tmp_path)))
    assert res.ok
    assert res.metrics["call_errors"]
