"""Stage-3 coverage tests with fake drivers; never start a chamber."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from fugu.pipeline.stages.detonation_stage import DetonationStage
from fugu.server.composition_jobs import run_composition_job
from fugu.server.jobs import JobStore, run_job
from fugu.types import AuditJob, DetonationEvidence, EvidenceSnippet
from fugu.verdict import aggregate_verdict, stage_coverage


class FakeDriver:
    def __init__(self, results):
        self.results = results
        self.calls = []

    async def detonate(self, target_dir: Path, triggers: list[str], timeout_s: int = 120):
        self.calls.append((target_dir, triggers, timeout_s))
        return self.results


def _canary_evidence(trigger: str, exit_code: int | None) -> DetonationEvidence:
    return DetonationEvidence(
        trigger=trigger,
        exit_code=exit_code,
        duration_s=0.25,
        canary_hits=[
            EvidenceSnippet(
                source="mitm.flow[0].body",
                excerpt="captured fabricated canary",
                meta={"vector": "http"},
            )
        ],
    )


def _plain_evidence(trigger: str, exit_code: int | None = 0) -> DetonationEvidence:
    return DetonationEvidence(trigger=trigger, exit_code=exit_code, duration_s=0.1)


def _run(stage: DetonationStage, target: Path):
    return asyncio.run(stage.run(AuditJob(id="detonation-reliability", source=str(target)), target))


def _run_job(stage: DetonationStage, target: Path, job_id: str = "detonation-job"):
    async def scenario():
        job = AuditJob(id=job_id, source=str(target))
        store = JobStore()
        store.create(job)
        await run_job(job, [stage], store)
        return store.get(job.id)

    return asyncio.run(scenario())


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "extension"
    target.mkdir()
    (target / "main.py").write_text("# test fixture; fake driver only")
    return target


def test_nonzero_exit_marks_partial_but_retains_findings_and_fail_verdict(tmp_path, monkeypatch):
    target = _target(tmp_path)
    triggers = ['python -c "import main"', 'python -c "import helper"']
    driver = FakeDriver([
        _canary_evidence(triggers[0], 0),
        _canary_evidence(triggers[1], 1),
    ])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: triggers)

    result = _run(DetonationStage(driver), target)

    assert result.ok
    assert len(result.findings) == 2
    assert all(finding.severity == "critical" for finding in result.findings)
    assert [row["exit_code"] for row in result.metrics["trigger_results"]] == [0, 1]
    assert [row["status"] for row in result.metrics["trigger_results"]] == ["completed", "nonzero_exit"]
    assert result.metrics["trigger_results_completed"] == 1
    assert result.metrics["coverage_incomplete"]
    assert "non-zero" in result.metrics["coverage_incomplete"]
    assert aggregate_verdict(result.findings, [result])["status"] == "fail"


def test_timeout_exit_none_marks_partial_without_dropping_canary_finding(tmp_path, monkeypatch):
    target = _target(tmp_path)
    trigger = "python -c 'import main'"
    driver = FakeDriver([_canary_evidence(trigger, None)])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: [trigger])

    result = _run(DetonationStage(driver), target)

    assert result.ok and len(result.findings) == 1
    assert result.metrics["trigger_results"][0]["exit_code"] is None
    assert result.metrics["trigger_results"][0]["status"] == "timed_out"
    assert result.metrics["coverage_incomplete"]
    assert "timed out" in result.metrics["coverage_incomplete"]
    assert aggregate_verdict(result.findings, [result])["status"] == "fail"


def test_missing_trigger_result_marks_partial_and_keeps_returned_findings(tmp_path, monkeypatch):
    target = _target(tmp_path)
    triggers = ["first selected trigger", "second selected trigger"]
    driver = FakeDriver([_canary_evidence(triggers[0], 0)])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: triggers)

    result = _run(DetonationStage(driver), target)

    assert result.ok and len(result.findings) == 1
    assert result.metrics["trigger_results_missing"] == 1
    assert [row["status"] for row in result.metrics["trigger_results"]] == ["completed", "missing_result"]
    assert result.metrics["coverage_incomplete"]
    assert "missing" in result.metrics["coverage_incomplete"]
    assert aggregate_verdict(result.findings, [result])["status"] == "fail"


def test_no_results_for_selected_trigger_is_not_a_complete_empty_audit(tmp_path, monkeypatch):
    target = _target(tmp_path)
    trigger = "selected trigger"
    driver = FakeDriver([])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: [trigger])

    result = _run(DetonationStage(driver), target)

    assert result.ok and result.findings == []
    assert result.metrics["trigger_results_missing"] == 1
    assert result.metrics["executed"] is False
    assert result.metrics["coverage_incomplete"]
    assert aggregate_verdict([], [result])["status"] == "warn"


def test_zero_exit_means_selected_trigger_completed_not_full_behavior_proven(tmp_path, monkeypatch):
    target = _target(tmp_path)
    trigger = "selected trigger"
    driver = FakeDriver([DetonationEvidence(trigger=trigger, exit_code=0, duration_s=0.1)])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: [trigger])

    result = _run(DetonationStage(driver), target)

    assert result.ok and not result.findings
    assert result.metrics["trigger_results"][0]["status"] == "completed"
    assert "coverage_incomplete" not in result.metrics
    assert result.metrics["coverage_scope"] == "selected_triggers_only"
    assert stage_coverage(result)["state"] == "completed"


@pytest.mark.parametrize(
    ("returned", "statuses", "completed", "missing", "duplicates", "unselected", "executed"),
    [
        (
            ["selected-a", "selected-a"],
            ["completed", "missing_result", "duplicate_result"],
            1,
            1,
            1,
            0,
            True,
        ),
        (
            ["unrequested-x", "unrequested-y"],
            ["missing_result", "missing_result", "unselected_result", "unselected_result"],
            0,
            2,
            0,
            2,
            False,
        ),
    ],
)
def test_result_identity_and_multiplicity_control_trigger_completion(
    tmp_path, monkeypatch, returned, statuses, completed, missing, duplicates, unselected, executed
):
    target = _target(tmp_path)
    selected = ["selected-a", "selected-b"]
    driver = FakeDriver([_plain_evidence(trigger) for trigger in returned])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: selected)

    result = _run(DetonationStage(driver), target)

    assert [row["status"] for row in result.metrics["trigger_results"]] == statuses
    assert result.metrics["trigger_results_completed"] == completed
    assert result.metrics["trigger_results_missing"] == missing
    assert result.metrics["trigger_results_duplicate"] == duplicates
    assert result.metrics["trigger_results_unselected"] == unselected
    assert result.metrics["trigger_results_unexpected"] == duplicates + unselected
    assert result.metrics["executed"] is executed
    assert result.metrics["coverage_incomplete"]
    assert stage_coverage(result)["state"] == "partial"
    assert aggregate_verdict(result.findings, [result])["status"] == "warn"


def test_reordered_results_match_selected_identity_and_preserve_exit_status(tmp_path, monkeypatch):
    target = _target(tmp_path)
    selected = ["selected-a", "selected-b"]
    driver = FakeDriver([
        _plain_evidence("selected-b", 1),
        _plain_evidence("selected-a", 0),
    ])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: selected)

    result = _run(DetonationStage(driver), target)

    assert [row["trigger"] for row in result.metrics["trigger_results"]] == selected
    assert [row["evidence_trigger"] for row in result.metrics["trigger_results"]] == selected
    assert [row["status"] for row in result.metrics["trigger_results"]] == ["completed", "nonzero_exit"]
    assert result.metrics["trigger_results_completed"] == 1
    assert result.metrics["trigger_results_missing"] == 0
    assert result.metrics["coverage_incomplete"]


def test_intentional_duplicate_selected_commands_match_by_occurrence(tmp_path, monkeypatch):
    target = _target(tmp_path)
    selected = ["same selected command", "same selected command"]
    driver = FakeDriver([_plain_evidence(selected[0]), _plain_evidence(selected[1])])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: selected)

    result = _run(DetonationStage(driver), target)

    assert [row["status"] for row in result.metrics["trigger_results"]] == ["completed", "completed"]
    assert result.metrics["trigger_results_completed"] == 2
    assert result.metrics["trigger_results_missing"] == 0
    assert result.metrics["trigger_results_unexpected"] == 0
    assert "coverage_incomplete" not in result.metrics


def test_unmatched_severe_evidence_is_retained_with_fail_precedence(tmp_path, monkeypatch):
    target = _target(tmp_path)
    selected = ["selected-a", "selected-b"]
    driver = FakeDriver([
        _canary_evidence("unselected-severe-evidence", 0),
        _plain_evidence("selected-a", 0),
    ])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: selected)

    result = _run(DetonationStage(driver), target)
    verdict = aggregate_verdict(result.findings, [result])

    assert len(result.findings) == 1
    assert result.findings[0].severity == "critical"
    assert result.metrics["trigger_results_completed"] == 1
    assert result.metrics["trigger_results_missing"] == 1
    assert result.metrics["trigger_results_unselected"] == 1
    assert result.metrics["coverage_incomplete"]
    assert verdict["status"] == "fail"
    assert any("detonation: partial" in caveat for caveat in verdict["coverage_caveats"])


def test_trigger_mismatch_is_serialized_into_job_coverage(tmp_path, monkeypatch):
    target = _target(tmp_path)
    selected = ["selected-a", "selected-b"]
    driver = FakeDriver([_plain_evidence("selected-a"), _plain_evidence("selected-a")])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: selected)

    snapshot = _run_job(DetonationStage(driver), target)
    stage_event = next(event for event in snapshot.events if event.type == "stage_done")
    verdict_event = next(event for event in snapshot.events if event.type == "verdict")
    serialized_stage = json.loads(json.dumps(stage_event.data))
    serialized_verdict = json.loads(json.dumps(verdict_event.data["verdict"]))

    assert serialized_stage["metrics"]["trigger_results_missing"] == 1
    assert serialized_stage["metrics"]["trigger_results_duplicate"] == 1
    assert [row["status"] for row in serialized_stage["metrics"]["trigger_results"]] == [
        "completed", "missing_result", "duplicate_result"
    ]
    assert "duplicate trigger result(s) received" in serialized_stage["metrics"]["coverage_incomplete"]
    assert serialized_verdict["status"] == "warn"
    assert any("detonation: partial" in caveat for caveat in serialized_verdict["coverage_caveats"])


def test_trigger_mismatch_coverage_propagates_to_composition_parent(tmp_path, monkeypatch):
    members = []
    for label in ("one", "two"):
        target = tmp_path / label
        target.mkdir()
        (target / "main.py").write_text("# fixture for fake driver only")
        members.append({"ref": str(target), "label": label})
    selected = ["selected-trigger"]
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", lambda *args, **kwargs: selected)
    stage = DetonationStage(FakeDriver([_plain_evidence("unselected-trigger", 0)]))

    async def scenario():
        job = AuditJob(id="composition-trigger-coverage", source=str(tmp_path))
        store = JobStore()
        store.create(job)
        await run_composition_job(job, members, [stage], store)
        return store.get(job.id)

    snapshot = asyncio.run(scenario())
    parent_stage = next(event for event in snapshot.events if event.type == "stage_done")
    verdict_event = next(event for event in snapshot.events if event.type == "verdict")
    member_coverage = parent_stage.data["metrics"]["member_coverage"]
    verdict = verdict_event.data["verdict"]

    assert {record["member"] for record in member_coverage} == {"one", "two"}
    assert all(record["stage"] == "detonation" and record["state"] == "partial" for record in member_coverage)
    assert all("unselected trigger result(s) received" in record["reason"] for record in member_coverage)
    assert verdict["status"] == "warn"
    assert all(any(f"member {label} (" in caveat and "detonation: partial" in caveat
                   for caveat in verdict["coverage_caveats"]) for label in ("one", "two"))
