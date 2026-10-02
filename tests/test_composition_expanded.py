"""Frozen composition-v2 coverage run through the production job path."""
from __future__ import annotations

import hashlib
import json
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


def test_aggregate_reports_unavailable_detection_without_counting_a_false_negative() -> None:
    rows = [
        {
            "id": "unavailable-attack",
            "kind": "attack",
            "split": "development",
            "complete": False,
            "correct": False,
            "composition_available": False,
            "predicted": None,
        },
        {
            "id": "unavailable-control",
            "kind": "control",
            "split": "development",
            "complete": False,
            "correct": False,
            "composition_available": False,
            "predicted": None,
        },
    ]

    split = _aggregate(rows, "split")["development"]

    assert split["attempted"] == 2
    assert split["completed"] == 0
    assert split["unavailable_ids"] == ["unavailable-attack", "unavailable-control"]
    assert split["attacks"]["n"] == 1
    assert split["attacks"]["unavailable_ids"] == ["unavailable-attack"]
    assert split["attacks"]["trifecta_detected"] == 0
    assert split["attacks"]["missed_ids"] == []
    assert split["controls"]["n"] == 1
    assert split["controls"]["unavailable_ids"] == ["unavailable-control"]
    assert split["controls"]["trifecta_false_positives"] == 0
    assert split["controls"]["shadowing_findings"] == 0


def _case_record(
    case_id: str,
    target: Path,
    *,
    expected_trifecta: bool = True,
    member_count: int = 3,
) -> dict:
    return {
        "id": case_id,
        "target": str(target),
        "family": "fabricated-reliability",
        "kind": "attack",
        "split": "development",
        "expected": {"trifecta": expected_trifecta, "shadowing": False},
        "members": [
            {"dir": "reader", "label": "reader"},
            {"dir": "vault", "label": "vault"},
            {"dir": "reporter", "label": "reporter"},
        ][:member_count],
    }


def _write_case_sources(
    case_id: str,
    target: Path,
    *,
    reporter_source: str = (
        "import requests\n"
        "requests.post('https://example.test/report', json={})\n"
    ),
    expected_trifecta: bool = True,
) -> tuple[dict, list[Path]]:
    code = {
        "reader": {
            "server.json": '{"tools":[{"name":"fetch_note","inputSchema":{"type":"object"}}]}',
        },
        "vault": {"vault.py": "import os\nos.environ.get('FABRICATED_VALUE')\n"},
        "reporter": {
            "reporter.py": reporter_source,
            "requests.py": "def post(value):\n    return 'stored locally'\n",
        },
    }
    files: list[Path] = []
    for label, member_files in code.items():
        member_dir = target / label
        member_dir.mkdir(parents=True)
        skill = member_dir / "SKILL.md"
        skill.write_text("Fabricated source fixture; never execute.", encoding="utf-8")
        files.append(skill)
        for filename, content in member_files.items():
            path = member_dir / filename
            path.write_text(content, encoding="utf-8")
            files.append(path)
    return _case_record(case_id, target, expected_trifecta=expected_trifecta), files


def _production_modules() -> dict:
    import fugu.pipeline.stages.composition as composition
    import fugu.pipeline.stages.static_scan as static_scan
    import fugu.server.composition_jobs as composition_jobs
    import fugu.server.jobs as jobs

    return {
        "composition": composition,
        "static_scan": static_scan,
        "composition_jobs": composition_jobs,
        "jobs": jobs,
    }


@pytest.mark.parametrize(
    "reporter_source",
    [
        "import requests as client\n"
        "def save(payload):\n"
        "    match payload:\n"
        "        case {'writer': client}:\n"
        "            client.post('ordinary')\n",
        "import httpx as unused_client\n"
        "from .requests import post as store_locally\n"
        "store_locally('ordinary')\n",
    ],
    ids=["pattern-bound-alias", "relative-helper-import"],
)
def test_review_alias_controls_have_no_trifecta_through_production_fanout(
    tmp_path: Path, reporter_source: str
) -> None:
    case, _ = _write_case_sources(
        "alias-control", tmp_path / "alias-control", reporter_source=reporter_source,
        expected_trifecta=False,
    )

    row = _case_result(case, tmp_path, _production_modules())

    assert row["complete"] is True
    assert row["composition_metrics"]["capabilities"].get("EGRESS", 0) == 0
    assert row["predicted"]["trifecta"] is False
    assert not any("MCP06" in finding["owasp_ids"] for finding in row["findings"])


def test_all_child_extraction_failures_return_an_unavailable_case_row(tmp_path: Path) -> None:
    case = _case_record(
        "all-extraction-failed", tmp_path / "missing-target", member_count=2
    )

    row = _case_result(case, tmp_path, _production_modules())

    assert row["parent_status"] == "failed"
    assert row["parent_error_stage"] == "extraction"
    assert "all 2 members failed extraction" in row["parent_error"]
    assert row["composition_available"] is False
    assert row["composition_metrics"] is None
    assert row["predicted"] is None
    assert row["complete"] is False
    assert row["correct"] is False
    assert len(row["children"]) == 2
    assert all(child["status"] == "failed" for child in row["children"])
    assert all(child["error"] for child in row["children"])
    assert all(child["stages"][0]["stage"] == "extraction" for child in row["children"])
    assert all(child["stages"][0]["error"] for child in row["children"])
    assert all(child["stages"][0]["coverage_state"] == "failed" for child in row["children"])
    assert row["parent_stages"][0]["stage"] == "extraction"


@pytest.mark.parametrize("mode", ["missing-snapshot", "missing-composition-stage"])
def test_missing_parent_snapshot_or_composition_stage_is_unavailable(
    tmp_path: Path, mode: str
) -> None:
    from fugu.types import EvidenceSnippet, Finding, JobStatus

    modules = _production_modules()
    note = Finding(
        owasp_ids=["MCP06"], title="Fabricated retained parent finding",
        detail="A finding can exist even when composition stage evidence is missing.",
        severity="medium", confidence="measured", stage="static",
        evidence=[EvidenceSnippet(source="fixture", excerpt="synthetic finding")],
    )

    async def incomplete_runner(job, sources, stages, store):
        if mode == "missing-composition-stage":
            store.create(job).findings.append(note)
            job.status = JobStatus.done

    modules["composition_jobs"] = SimpleNamespace(
        run_composition_job=incomplete_runner,
        harvest_tool_names=modules["composition_jobs"].harvest_tool_names,
    )
    case = _case_record("missing-parent-evidence", tmp_path / "no-target")

    row = _case_result(case, tmp_path, modules)

    assert row["composition_available"] is False
    assert row["predicted"] is None
    assert row["complete"] is False
    assert row["correct"] is False
    assert row["composition_metrics"] is None
    assert row["detection_unavailable_reason"]
    if mode == "missing-composition-stage":
        assert row["parent_status"] == "done"
        assert row["parent_stages"] == []
        assert row["findings"][0]["title"] == note.title
        assert row["parent_findings"][0]["title"] == note.title
    else:
        assert row["parent_status"] == "missing"


def test_failed_composition_stage_keeps_findings_but_marks_detection_unavailable(
    tmp_path: Path,
) -> None:
    from fugu.types import EvidenceSnippet, Finding, JobStatus, StageResult

    modules = _production_modules()
    note = Finding(
        owasp_ids=["MCP06"], title="Fabricated partial-stage finding",
        detail="Retained evidence for an unavailable result.", severity="medium",
        confidence="measured", stage="composition",
        evidence=[EvidenceSnippet(source="fixture", excerpt="synthetic finding")],
    )

    async def failed_stage_runner(job, sources, stages, store):
        snapshot = store.create(job)
        snapshot.stages.append(StageResult(
            stage="composition", ok=False, findings=[note], error="fabricated stage error"
        ))
        snapshot.findings.append(note)
        job.status = JobStatus.failed

    modules["composition_jobs"] = SimpleNamespace(
        run_composition_job=failed_stage_runner,
        harvest_tool_names=modules["composition_jobs"].harvest_tool_names,
    )
    case = _case_record("composition-stage-failed", tmp_path / "no-target")

    row = _case_result(case, tmp_path, modules)

    assert row["composition_available"] is False
    assert row["predicted"] is None
    assert row["composition_error"] == "fabricated stage error"
    assert row["findings"][0]["title"] == note.title
    assert row["complete"] is False
    assert row["correct"] is False


def test_run_suite_persists_cases_around_all_extraction_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import bench.composition_expanded as benchmark

    suite_root = tmp_path / "suite"
    suite_root.mkdir()
    monkeypatch.setattr(benchmark, "ROOT", suite_root)
    corpus_root = suite_root / "corpus"
    corpus_root.mkdir()
    before, before_files = _write_case_sources(
        "healthy-before", suite_root / "sources" / "before"
    )
    failed = _case_record(
        "all-extraction-failed", suite_root / "sources" / "missing", member_count=2
    )
    after, after_files = _write_case_sources(
        "healthy-after", suite_root / "sources" / "after"
    )
    cases = [before, failed, after]
    cases_path = corpus_root / "cases.json"
    cases_path.write_text(json.dumps({"cases": cases}), encoding="utf-8")

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    source_hashes = {
        path.relative_to(suite_root).as_posix(): digest(path)
        for path in [*before_files, *after_files]
    }
    source_hashes[cases_path.relative_to(suite_root).as_posix()] = digest(cases_path)
    engine_path = _PROJECT_ROOT / "src/fugu/pipeline/stages/composition.py"
    engine_key = "src/fugu/pipeline/stages/composition.py"
    freeze = {
        "case_count": len(cases),
        "baseline_commit": "synthetic-test-freeze",
        "baseline_engine_source_hashes": {engine_key: digest(engine_path)},
        "source_hashes_sha256": source_hashes,
    }
    (corpus_root / "manifest.json").write_text(json.dumps(freeze), encoding="utf-8")
    output = suite_root / "results" / "suite.json"

    result = benchmark.run_suite(
        _PROJECT_ROOT / "src", output, label="after", corpus_root=corpus_root
    )
    persisted = json.loads(output.read_text(encoding="utf-8"))
    failure_row = next(row for row in result["cases"] if row["id"] == failed["id"])

    assert [row["id"] for row in persisted["cases"]] == [
        "healthy-before", "all-extraction-failed", "healthy-after"
    ]
    assert result["summary"]["attempted"] == 3
    assert result["summary"]["completed"] == 2
    assert result["summary"]["attacks"]["n"] == 3
    assert result["summary"]["attacks"]["completed"] == 2
    assert result["summary"]["unavailable_ids"] == ["all-extraction-failed"]
    assert result["summary"]["attacks"]["unavailable_ids"] == ["all-extraction-failed"]
    assert result["summary"]["attacks"]["missed_ids"] == []
    assert failure_row["predicted"] is None
    assert failure_row["parent_status"] == "failed"
    assert failure_row["parent_error"]
    assert failure_row["complete"] is False and failure_row["correct"] is False
    assert persisted["summary"] == result["summary"]
