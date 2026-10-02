"""Stage-3 coverage tests with fake drivers; never start a chamber."""
from __future__ import annotations

import asyncio
from pathlib import Path

from fugu.pipeline.stages.detonation_stage import DetonationStage
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


def _run(stage: DetonationStage, target: Path):
    return asyncio.run(stage.run(AuditJob(id="detonation-reliability", source=str(target)), target))


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
