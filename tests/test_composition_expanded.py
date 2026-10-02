"""Frozen composition-v2 coverage run through the production job path."""
from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from bench.composition_expanded import (
    CORPUS,
    ROOT,
    _aggregate,
    _case_result,
    _load_and_verify_corpus,
    run_suite,
)


@pytest.fixture(scope="module")
def composition_v2_run(tmp_path_factory: pytest.TempPathFactory) -> dict:
    output = tmp_path_factory.mktemp("composition-v2") / "checkout.json"
    return run_suite(ROOT / "src", output, label="after")


def test_composition_v2_corpus_is_frozen_balanced_and_split() -> None:
    freeze, cases = _load_and_verify_corpus(CORPUS)
    assert len(cases) == 24
    assert freeze["family_count"] == 8
    assert sum(case["kind"] == "attack" for case in cases) == 12
    assert sum(case["kind"] == "control" for case in cases) == 12
    assert sum(case["split"] == "development" for case in cases) == 16
    assert sum(case["split"] == "reserved" for case in cases) == 8
    assert freeze["split"]["reserved_is_blinded"] is False


@pytest.mark.parametrize(
    "case_id",
    ["v2-py-module-alias-post", "v2-py-symbol-alias-post"],
)
def test_import_alias_post_forms_complete_the_real_source_trifecta(
    composition_v2_run: dict, case_id: str
) -> None:
    row = next(case for case in composition_v2_run["cases"] if case["id"] == case_id)
    assert row["complete"]
    assert row["predicted"]["trifecta"] is True


@pytest.mark.parametrize(
    "case_id",
    ["v2-name-equal-different-servers-control", "v2-name-normalized-different-servers-control"],
)
def test_tool_name_overlap_without_namespace_evidence_is_not_shadowing(
    composition_v2_run: dict, case_id: str
) -> None:
    row = next(case for case in composition_v2_run["cases"] if case["id"] == case_id)
    assert row["complete"]
    assert any(row["harvested_tool_names"].values())
    assert row["predicted"]["shadowing"] is False


def test_composition_v2_preserves_every_complete_case_result(composition_v2_run: dict) -> None:
    assert composition_v2_run["summary"]["attempted"] == 24
    assert composition_v2_run["summary"]["completed"] == 24
    assert composition_v2_run["summary"]["incomplete_ids"] == []
    assert len(composition_v2_run["cases"]) == 24


def test_case_result_marks_partial_and_failed_member_stages_incomplete_and_keeps_findings(
    tmp_path: Path,
) -> None:
    from fugu.pipeline.stages.composition import CompositionStage
    from fugu.server.composition_jobs import harvest_tool_names, run_composition_job
    from fugu.server.jobs import JobStore
    from fugu.types import EvidenceSnippet, Finding, StageResult

    target = tmp_path / "case"
    code = {
        "reader": "import requests\nrequests.get('https://example.test/data')\n",
        "vault": "import os\nos.environ.get('API_TOKEN')\n",
        "reporter": "import requests\nrequests.post('https://example.test/report', json={})\n",
    }
    members = []
    for label, source in code.items():
        member_dir = target / label
        member_dir.mkdir(parents=True)
        (member_dir / "SKILL.md").write_text("Fabricated test fixture.", encoding="utf-8")
        (member_dir / f"{label}.py").write_text(source, encoding="utf-8")
        members.append({"dir": label, "label": label})

    note = Finding(
        owasp_ids=[], title="Fabricated stage note", detail="test-only evidence",
        severity="info", confidence="advisory", stage="static",
        evidence=[EvidenceSnippet(source="fixture", excerpt="synthetic note")],
    )

    class FakeStaticScanStage:
        name = "static"

        async def run(self, job, stage_target):
            if stage_target.name == "reader":
                return StageResult(
                    stage=self.name, ok=True, findings=[note],
                    metrics={"coverage_incomplete": "one fabricated unit omitted", "units_omitted": 1},
                )
            if stage_target.name == "vault":
                return StageResult(
                    stage=self.name, ok=False, findings=[note],
                    metrics={"coverage_incomplete": "fabricated stage failure"},
                    error="fabricated static failure",
                )
            return StageResult(stage=self.name, ok=True, findings=[note], metrics={})

    modules = {
        "composition": SimpleNamespace(CompositionStage=CompositionStage),
        "jobs": SimpleNamespace(JobStore=JobStore),
        "composition_jobs": SimpleNamespace(
            run_composition_job=run_composition_job,
            harvest_tool_names=harvest_tool_names,
        ),
        "static_scan": SimpleNamespace(StaticScanStage=FakeStaticScanStage),
    }
    case = {
        "id": "fabricated-partial-composition",
        "target": str(target),
        "family": "fabricated-coverage",
        "kind": "attack",
        "split": "development",
        "expected": {"trifecta": True, "shadowing": False},
        "members": members,
    }

    row = _case_result(case, tmp_path, modules)

    assert row["parent_status"] == "done" and row["composition_ok"]
    assert row["predicted"]["trifecta"]
    assert any("MCP06" in finding["owasp_ids"] for finding in row["findings"])
    assert all(child["findings"] == 1 for child in row["children"])
    assert row["complete"] is False
    child_stages = [child["stages"][0] for child in row["children"]]
    assert [stage["coverage_state"] for stage in child_stages] == [
        "partial", "failed", "completed"
    ]
    assert child_stages[0]["metrics"]["units_omitted"] == 1
    assert child_stages[1]["error"] == "fabricated static failure"
    parent_states = {
        (member["member"], member["state"])
        for member in row["composition_metrics"]["member_coverage"]
    }
    assert ("reader", "partial") in parent_states
    assert ("vault", "failed") in parent_states

    split = _aggregate([row], "split")["development"]
    assert split["incomplete_ids"] == [case["id"]]
    assert split["attacks"]["n"] == 1
    assert split["attacks"]["completed"] == 0


def test_aggregate_keeps_incomplete_attempts_in_attack_denominator() -> None:
    row = {
        "id": "incomplete-attack",
        "kind": "attack",
        "split": "development",
        "complete": False,
        "correct": False,
        "predicted": {"trifecta": False, "shadowing": False},
    }

    split = _aggregate([row], "split")["development"]

    assert split["attacks"]["n"] == 1
    assert split["attacks"]["completed"] == 0
    assert split["attacks"]["missed_ids"] == ["incomplete-attack"]
    assert split["incomplete_ids"] == ["incomplete-attack"]
