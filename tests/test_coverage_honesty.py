"""Coverage regressions with fake inference, no provider credentials or network."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from fugu.pipeline.stages.detonation_stage import DetonationStage
from fugu.pipeline.stages.harness import CANARY_ENV_TOKEN, HarnessStage
from fugu.pipeline.stages.semantic import JudgeCall, SemanticStage
from fugu.server.composition_jobs import run_auto_job, run_composition_job
from fugu.server.jobs import JobStore
from fugu.store.sqlite import SqliteJobStore
from fugu.types import AuditJob, Finding, StageResult
from fugu.verdict import aggregate_verdict


def _target(tmp_path):
    target = tmp_path / "skill"
    target.mkdir()
    (target / "SKILL.md").write_text("An ordinary skill.")
    return target


def _reply(text):
    return text, JudgeCall("offline-fake", 0, 0, len(text), {})


@pytest.mark.parametrize("response", [None, "not JSON", "{}", '{"findings": "wrong shape"}', '{"findings": [null]}', '{"findings": [{"title": "x", "owasp_ids": 1}]}'])
def test_semantic_no_usable_analysis_is_failed(tmp_path, response):
    target = _target(tmp_path)

    def call(system, user):
        if response is None:
            raise RuntimeError("fake provider unavailable")
        return _reply(response)

    result = asyncio.run(SemanticStage(make_call=call).run(AuditJob(id="sem", source=str(target)), target))
    assert not result.ok
    assert result.metrics["units_completed"] == 0
    verdict = aggregate_verdict(result.findings, [result])
    assert verdict["status"] == "warn"
    assert "semantic: failed" in verdict["coverage_caveats"]


def test_semantic_partial_analysis_retains_findings_and_caveat(tmp_path):
    target = _target(tmp_path)
    (target / "extra.md").write_text("A second file.")

    def call(system, user):
        if "extra.md" in user:
            raise RuntimeError("fake unit failure")
        return _reply(json.dumps({"findings": [{"title": "Local concern", "detail": "Evidence", "severity": "low", "excerpt": "ordinary", "owasp_ids": ["LLM01"]}]}))

    result = asyncio.run(SemanticStage(make_call=call).run(AuditJob(id="partial", source=str(target)), target))
    assert result.ok and len(result.findings) == 1
    assert result.metrics["units_completed"] == 1
    assert result.metrics["coverage_incomplete"]
    verdict = aggregate_verdict(result.findings, [result])
    assert verdict["status"] == "warn"
    assert any("semantic: partial" in c for c in verdict["coverage_caveats"])


@pytest.mark.parametrize("invalid", [None, {"title": ""}, {"title": "x", "owasp_ids": 1}])
def test_malformed_sibling_cannot_suppress_valid_severe_evidence(tmp_path, invalid):
    target = _target(tmp_path)
    response = {"findings": [
        {"title": "Concrete severe evidence", "detail": "Valid finding", "severity": "critical", "excerpt": "ordinary", "owasp_ids": ["LLM01"]},
        invalid,
    ]}
    result = asyncio.run(SemanticStage(make_call=lambda *args: _reply(json.dumps(response))).run(AuditJob(id="mixed", source=str(target)), target))
    assert result.ok
    assert [f.title for f in result.findings] == ["Concrete severe evidence"]
    assert result.metrics["parse_errors"] and result.metrics["coverage_incomplete"]
    verdict = aggregate_verdict(result.findings, [result])
    assert verdict["status"] == "fail"
    assert any("semantic: partial" in c for c in verdict["coverage_caveats"])


def test_semantic_unit_cap_is_explicit_partial_coverage(tmp_path):
    target = _target(tmp_path)
    for i in range(24):
        (target / f"{i}.md").write_text("Ordinary file.")
    result = asyncio.run(SemanticStage(make_call=lambda *args: _reply('{"findings": []}')).run(AuditJob(id="cap", source=str(target)), target))
    assert result.metrics["units_omitted"] == 1
    assert aggregate_verdict([], [result])["coverage_caveats"]


@pytest.mark.parametrize("mode", ["failed", "empty"])
def test_harness_all_unusable_arms_fail(tmp_path, mode):
    target = _target(tmp_path)

    def call(system, user):
        if "probes" in system:
            return _reply('{"probes": []}')
        if mode == "failed":
            raise RuntimeError("fake failure")
        return _reply("   ")

    result = asyncio.run(HarnessStage(make_call=call).run(AuditJob(id="h", source=str(target)), target))
    assert not result.ok and result.findings == []
    assert result.metrics["comparisons_completed"] == 0
    assert aggregate_verdict([], [result])["status"] == "warn"


def test_missing_baseline_cannot_create_empirical_attack_evidence(tmp_path):
    target = _target(tmp_path)

    def call(system, user):
        if "probes" in system:
            return _reply('{"probes": []}')
        if "skill-instructions" not in system:
            raise RuntimeError("baseline unavailable")
        return _reply(f"Disclosed {CANARY_ENV_TOKEN}")

    result = asyncio.run(HarnessStage(make_call=call).run(AuditJob(id="missing-base", source=str(target)), target))
    assert not result.ok
    assert result.findings == []


def test_harness_usable_pair_survives_other_arm_failure(tmp_path):
    target = _target(tmp_path)
    mounted = 0

    def call(system, user):
        nonlocal mounted
        if "probes" in system:
            return _reply('{"probes": []}')
        if "skill-instructions" in system:
            mounted += 1
            if mounted % 2 == 0:
                raise RuntimeError("everyday arm unavailable")
            return _reply(f"Disclosed {CANARY_ENV_TOKEN}")
        return _reply("A benign answer.")

    result = asyncio.run(HarnessStage(make_call=call).run(AuditJob(id="some-pairs", source=str(target)), target))
    assert result.ok and result.findings
    assert result.metrics["comparisons_completed"] == 3
    assert result.metrics["coverage_incomplete"]
    verdict = aggregate_verdict(result.findings, [result])
    assert verdict["status"] == "fail" and verdict["coverage_caveats"]


@pytest.mark.parametrize("stage", ["semantic", "harness", "detonation"])
def test_required_analysis_failure_warns(stage):
    verdict = aggregate_verdict([], [StageResult(stage=stage, ok=False, error="unavailable")])
    assert verdict["status"] == "warn"
    assert f"{stage}: failed" in verdict["coverage_caveats"]


def test_fail_never_erases_coverage_and_offline_skip_allows_scoped_pass():
    skipped = StageResult(stage="semantic", ok=True, metrics={"skipped": "unconfigured"})
    finding = Finding(owasp_ids=["LLM01"], title="Hard evidence", detail="", severity="high", confidence="deterministic", stage="static")
    fail = aggregate_verdict([finding], [skipped])
    assert fail["status"] == "fail" and fail["static_only"]
    assert fail["coverage_caveats"] == ["semantic: skipped"]
    scoped = aggregate_verdict([], [skipped])
    assert scoped["status"] == "pass" and scoped["static_only"]


def test_zero_trigger_detonation_is_not_empirical_execution(tmp_path):
    class NeverDriver:
        async def detonate(self, *args, **kwargs):
            raise AssertionError("must not run")

    target = _target(tmp_path)
    result = asyncio.run(DetonationStage(NeverDriver()).run(AuditJob(id="no-exec", source=str(target)), target))
    assert result.ok and result.metrics["executed"] is False
    assert all(f.confidence != "empirical" for f in result.findings)
    verdict = aggregate_verdict(result.findings, [result])
    assert "detonation: skipped" in verdict["coverage_caveats"]


class CoverageStage:
    name = "semantic"

    def __init__(self, state):
        self.state = state

    async def run(self, job, target):
        metrics = {"skipped": "unconfigured"} if self.state == "skipped" else ({"coverage_incomplete": "one unit unavailable", "units_completed": 1} if self.state == "partial" else {})
        return StageResult(stage=self.name, ok=self.state != "failed", metrics=metrics, error="unavailable" if self.state == "failed" else None)


@pytest.mark.parametrize("runner", ["auto", "explicit"])
@pytest.mark.parametrize("state", ["failed", "skipped", "partial"])
def test_parent_verdict_preserves_member_coverage(tmp_path, runner, state):
    for label in ("one", "two"):
        (tmp_path / label).mkdir()
        (tmp_path / label / "SKILL.md").write_text("Ordinary content.")
    store = JobStore()
    job = AuditJob(id="parent", source=str(tmp_path))
    store.create(job)
    if runner == "auto":
        asyncio.run(run_auto_job(job, str(tmp_path), [CoverageStage(state)], store))
    else:
        asyncio.run(run_composition_job(job, [{"ref": str(tmp_path / label), "label": label} for label in ("one", "two")], [CoverageStage(state)], store))
    snap = store.get(job.id)
    verdict = snap.events[-1].data["verdict"]
    assert verdict["status"] == ("pass" if state == "skipped" else "warn")
    for label in ("one", "two"):
        assert any(label in c and f"semantic: {state}" in c for c in verdict["coverage_caveats"])
    assert [r.stage for r in snap.stages] == ["composition"]
    assert len([e for e in snap.events if e.type == "stage_started"]) == 1


def test_fanout_cap_and_coverage_survive_persistence_and_event_replay(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for label in ("one", "two", "three"):
        (source / label).mkdir()
        (source / label / "SKILL.md").write_text("Ordinary content.")

    async def scenario():
        db = SqliteJobStore(tmp_path / "jobs.db")
        store = JobStore(store=db)
        job = AuditJob(id="parent", source=str(source))
        store.create(job)
        live = store.subscribe(job.id)
        await run_auto_job(job, str(source), [CoverageStage("skipped")], store, max_units=2)
        live_events = []
        while not live.empty():
            event = live.get_nowait()
            if event is not None:
                live_events.append(event)
        verdict = next(e.data["verdict"] for e in live_events if e.type == "verdict")
        assert verdict["status"] == "warn"
        assert verdict["omitted_units"] == 1
        assert any("1 skill unit" in c for c in verdict["coverage_caveats"])
        assert any("two" in c and "omitted" in c for c in verdict["coverage_caveats"])
        composition = next(result for result in store.get(job.id).stages if result.stage == "composition")
        assert composition.metrics["omitted_unit_labels"] == ["two"]
        assert store.get(job.id).events[-1].data["verdict"] == verdict
        recovered = JobStore(store=db).get(job.id)
        assert recovered.events[-1].data["verdict"] == verdict
        assert json.loads(db.load_job(job.id)["verdict_json"]) == verdict
        db.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(("override", "expected"), [(None, 24), ("1", 1), ("24", 24), ("0", 24), ("25", 24), ("oops", 24)])
def test_auto_fanout_environment_limit_is_validated_and_never_exceeds_24(
    override, expected, monkeypatch
):
    from fugu.server.composition_jobs import configured_auto_max_units

    monkeypatch.delenv("FUGU_FANOUT_MAX", raising=False)
    assert configured_auto_max_units(override) == expected


def test_invalid_fanout_override_uses_safe_default_and_names_omitted_units(tmp_path, monkeypatch):
    source = tmp_path / "many-skills"
    source.mkdir()
    for index in range(25):
        unit = source / f"skill-{index:02}"
        unit.mkdir()
        (unit / "SKILL.md").write_text("ordinary")
    monkeypatch.setenv("FUGU_FANOUT_MAX", "500")
    store = JobStore()
    job = AuditJob(id="invalid-fanout", source=str(source))
    store.create(job)

    asyncio.run(run_auto_job(job, str(source), [CoverageStage("skipped")], store))

    composition = next(result for result in store.get(job.id).stages if result.stage == "composition")
    verdict = store.get(job.id).events[-1].data["verdict"]
    assert composition.metrics["fanout_max_units"] == 24
    assert composition.metrics["fanout_override_valid"] is False
    assert composition.metrics["omitted_units"] == 1
    assert composition.metrics["omitted_unit_labels"] == ["skill-24"]
    assert any("skill-24" in caveat and "fanout: omitted" in caveat for caveat in verdict["coverage_caveats"])
    assert verdict["status"] == "warn"


def test_parent_coverage_matches_http_sse_replay_after_restart(tmp_path):
    from fastapi.testclient import TestClient
    from fugu.server.app import create_app

    source = tmp_path / "source"
    source.mkdir()
    for label in ("one", "two"):
        (source / label).mkdir()
        (source / label / "SKILL.md").write_text("Ordinary content.")
    db_path = tmp_path / "jobs.db"
    app = create_app(stages=[CoverageStage("failed")], db=db_path, static_dir="/not-present")

    def read_events(client, job_id):
        return [json.loads(line[6:]) for line in client.get(f"/api/audits/{job_id}/events").text.splitlines() if line.startswith("data: ")]

    with TestClient(app) as client:
        response = client.post("/api/audits", json={"source": str(source)})
        assert response.status_code == 202
        job_id = response.json()["job_id"]
        first = read_events(client, job_id)
        verdict = first[-1]["data"]["verdict"]
        assert verdict["status"] == "warn"
        assert all(any(label in c for c in verdict["coverage_caveats"]) for label in ("one", "two"))
        assert read_events(client, job_id) == first
    app.state.fugu.store.db.close()
    recovered = create_app(stages=[], db=db_path, static_dir="/not-present")
    with TestClient(recovered) as client:
        assert read_events(client, job_id) == first
    recovered.state.fugu.store.db.close()
