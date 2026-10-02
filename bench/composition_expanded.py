"""Run the frozen composition-v2 corpus through Fugu's production runner.

This benchmark invokes the real composition fan-out, child ``run_job`` path,
static stage, tool-name harvest, and composition stage. Fixture content is
only read by those static stages; this module never executes member code.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus/composition-v2"
RESULTS = ROOT / "bench/results/2026-10-02-composition-v2"
BASELINE_MANIFEST = Path("/tmp/fugu-composition-showcase-baseline.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_and_verify_corpus(corpus_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    freeze = json.loads((corpus_root / "manifest.json").read_text(encoding="utf-8"))
    manifest_hashes = freeze["source_hashes_sha256"]
    mismatches: list[str] = []
    for relative, expected in manifest_hashes.items():
        path = ROOT / relative
        if not path.is_file() or _sha256(path) != expected:
            mismatches.append(relative)
    if mismatches:
        raise RuntimeError(f"frozen composition sources changed: {mismatches[:8]}")
    payload = json.loads((corpus_root / "cases.json").read_text(encoding="utf-8"))
    cases = payload["cases"]
    if len(cases) != freeze["case_count"]:
        raise RuntimeError("case count differs from the frozen manifest")
    return freeze, cases


def _engine_hashes(engine_root: Path, expected_paths: dict[str, str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    missing: list[str] = []
    for relative in sorted(expected_paths):
        repo_path = Path(relative)
        module_path = engine_root / "fugu" / repo_path.relative_to("src/fugu")
        if not module_path.is_file():
            missing.append(relative)
        else:
            hashes[relative] = _sha256(module_path)
    if missing:
        raise RuntimeError(f"engine source files missing under {engine_root}: {missing[:8]}")
    return hashes


def _stage_coverage(stage: Any) -> tuple[str, str | None]:
    """Return a conservative execution state for one child stage result."""
    metrics = stage.metrics or {}
    if not stage.ok:
        return "failed", stage.error or "analysis unavailable"
    if "skipped" in metrics:
        return "skipped", str(metrics["skipped"])
    if metrics.get("coverage_incomplete"):
        return "partial", str(metrics["coverage_incomplete"])
    omitted = {
        name: metrics[name]
        for name in ("units_omitted", "omitted_units")
        if isinstance(metrics.get(name), (int, float)) and metrics[name] > 0
    }
    if omitted:
        reason = ", ".join(f"{name}={count}" for name, count in sorted(omitted.items()))
        return "partial", f"omitted coverage: {reason}"
    return "completed", None


def _case_result(case: dict[str, Any], corpus_root: Path, modules: dict[str, Any]) -> dict[str, Any]:
    from fugu.types import AuditJob, JobStatus

    JobStore = modules["jobs"].JobStore
    run_composition_job = modules["composition_jobs"].run_composition_job
    harvest_tool_names = modules["composition_jobs"].harvest_tool_names
    StaticScanStage = modules["static_scan"].StaticScanStage

    target = ROOT / case["target"]
    sources = [
        {"ref": str(target / member["dir"]), "label": member["label"]}
        for member in case["members"]
    ]
    job = AuditJob(
        id=f"composition-v2-{case['id']}",
        source="composition:" + ", ".join(member["label"] for member in case["members"]),
        depth="standard",
    )
    store = JobStore()
    asyncio.run(
        run_composition_job(
            job,
            sources,
            [StaticScanStage()],
            store,
        )
    )
    snapshot = store.get(job.id)
    if snapshot is None:
        raise RuntimeError(f"production runner did not persist parent job {job.id}")
    composition = next((stage for stage in snapshot.stages if stage.stage == "composition"), None)
    if composition is None:
        raise RuntimeError(f"production runner emitted no composition stage for {case['id']}")

    child_ids = [
        event.data.get("child_job_id")
        for event in snapshot.events
        if event.data.get("stage") == "composition"
        and str(event.data.get("message", "")).startswith("member ")
        and event.data.get("child_job_id")
    ]
    children = []
    for child_id in child_ids:
        child = store.get(child_id)
        if child is None:
            children.append({"job_id": child_id, "status": "missing", "findings": None,
                             "stages": []})
        else:
            child_stages = []
            for stage in child.stages:
                state, reason = _stage_coverage(stage)
                child_stages.append({
                    "stage": stage.stage,
                    "ok": stage.ok,
                    "error": stage.error,
                    "metrics": stage.metrics or {},
                    "coverage_state": state,
                    "coverage_reason": reason,
                })
            children.append({
                "job_id": child_id,
                "status": child.job.status.value,
                "findings": len(child.findings),
                "stages": child_stages,
            })

    findings = [asdict(finding) for finding in composition.findings]
    trifecta = any("MCP06" in finding.owasp_ids for finding in composition.findings)
    confirmed_shadowing = any(
        "MCP03" in finding.owasp_ids and "MCP06" not in finding.owasp_ids
        for finding in composition.findings
    )
    harvested = {
        member["label"]: harvest_tool_names(target / member["dir"])
        for member in case["members"]
    }
    member_coverage = (composition.metrics or {}).get("member_coverage", [])
    member_coverage_complete = isinstance(member_coverage, list) and all(
        isinstance(record, dict) and record.get("state") == "completed"
        for record in member_coverage
    )
    composition_metrics = composition.metrics or {}
    parent_has_omissions = any(
        isinstance(composition_metrics.get(name), (int, float))
        and composition_metrics[name] > 0
        for name in ("units_omitted", "omitted_units")
    )
    complete = (
        snapshot.job.status is JobStatus.done
        and composition.ok
        and len(children) == len(case["members"])
        and all(child["status"] == JobStatus.done.value for child in children)
        and all(child["stages"] for child in children)
        and all(
            stage["coverage_state"] == "completed"
            for child in children
            for stage in child["stages"]
        )
        and member_coverage_complete
        and not composition_metrics.get("skipped")
        and not composition_metrics.get("coverage_incomplete")
        and not parent_has_omissions
    )
    predicted = {"trifecta": trifecta, "shadowing": confirmed_shadowing}
    return {
        "id": case["id"],
        "family": case["family"],
        "kind": case["kind"],
        "split": case["split"],
        "expected": case["expected"],
        "predicted": predicted,
        "complete": complete,
        "parent_status": snapshot.job.status.value,
        "composition_ok": composition.ok,
        "composition_error": composition.error,
        "composition_metrics": composition.metrics,
        "children": children,
        "harvested_tool_names": harvested,
        "findings": findings,
        "correct": complete and predicted == case["expected"],
    }


def _aggregate(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row[key])].append(row)
    result: dict[str, Any] = {}
    for name, group in sorted(groups.items()):
        complete = [row for row in group if row["complete"]]
        result[name] = _aggregate_group(group, complete)
    return result


def _aggregate_group(
    group: list[dict[str, Any]], complete: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Summarize every attempt while keeping completion as a separate count."""
    if complete is None:
        complete = [row for row in group if row["complete"]]
    attacks = [row for row in group if row["kind"] == "attack"]
    controls = [row for row in group if row["kind"] == "control"]
    complete_attacks = [row for row in complete if row["kind"] == "attack"]
    complete_controls = [row for row in complete if row["kind"] == "control"]
    return {
        "attempted": len(group),
        "completed": len(complete),
        "incomplete_ids": [row["id"] for row in group if not row["complete"]],
        "correct": sum(row["correct"] for row in complete),
        "attacks": {
            "n": len(attacks),
            "completed": len(complete_attacks),
            "trifecta_detected": sum(row["predicted"]["trifecta"] for row in attacks),
            "missed_ids": [row["id"] for row in attacks if not row["predicted"]["trifecta"]],
        },
        "controls": {
            "n": len(controls),
            "completed": len(complete_controls),
            "trifecta_false_positives": sum(row["predicted"]["trifecta"] for row in controls),
            "shadowing_findings": sum(row["predicted"]["shadowing"] for row in controls),
            "incorrect_ids": [row["id"] for row in controls if not row["correct"]],
        },
    }


def run_suite(engine_root: Path, output: Path, *, label: str, corpus_root: Path = CORPUS) -> dict[str, Any]:
    engine_root = engine_root.resolve()
    corpus_root = corpus_root.resolve()
    freeze, cases = _load_and_verify_corpus(corpus_root)
    expected_hashes = freeze["baseline_engine_source_hashes"]
    actual_hashes = _engine_hashes(engine_root, expected_hashes)
    if label == "baseline" and actual_hashes != expected_hashes:
        changed = [path for path in expected_hashes if actual_hashes[path] != expected_hashes[path]]
        raise RuntimeError(f"baseline engine does not match frozen source hashes: {changed[:8]}")
    sys.path.insert(0, str(engine_root))

    # These imports are intentionally resolved only after selecting the frozen
    # snapshot or checkout engine root.
    import fugu.pipeline.stages.composition as composition
    import fugu.pipeline.stages.static_scan as static_scan
    import fugu.server.composition_jobs as composition_jobs
    import fugu.server.jobs as jobs

    loaded_module = Path(composition.__file__).resolve()
    if engine_root not in loaded_module.parents:
        raise RuntimeError(f"wrong engine imported: {loaded_module}; expected below {engine_root}")
    modules = {
        "composition": composition,
        "static_scan": static_scan,
        "composition_jobs": composition_jobs,
        "jobs": jobs,
    }
    rows = [_case_result(case, corpus_root, modules) for case in cases]
    result = {
        "schema": "fugu-composition-v2-run-v1",
        "label": label,
        "engine_root": str(engine_root),
        "engine_module": str(loaded_module),
        "engine_source_hashes": actual_hashes,
        "baseline_commit": freeze["baseline_commit"],
        "corpus_manifest": str((corpus_root / "manifest.json").relative_to(ROOT)),
        "corpus_source_hashes": freeze["source_hashes_sha256"],
        "scope": "local inert fixtures through real run_composition_job, child run_job with StaticScanStage, production tool-name harvest, and CompositionStage; no member code execution or model inference",
        "summary": _aggregate_group(rows),
        "by_family": _aggregate(rows, "family"),
        "by_split": _aggregate(rows, "split"),
        "cases": rows,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-root", type=Path, required=True,
                        help="package root containing fugu/; use the frozen snapshot for baseline")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", choices=("baseline", "after"), required=True)
    parser.add_argument("--corpus-root", type=Path, default=CORPUS)
    args = parser.parse_args()
    result = run_suite(args.engine_root, args.output, label=args.label, corpus_root=args.corpus_root)
    print(json.dumps({"label": result["label"], "engine_module": result["engine_module"],
                      "summary": result["summary"], "by_family": result["by_family"],
                      "by_split": result["by_split"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
