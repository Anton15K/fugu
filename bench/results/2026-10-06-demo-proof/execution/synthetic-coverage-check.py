"""Fake-only check of canary parsing and detonation coverage propagation.

All collector records and the tiny target tree are synthetic. The driver
implementations below never start a process or access a chamber.
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "src"))

from fugu.detonation.docker_driver import evidence_to_findings, scan_for_canaries  # noqa: E402
from fugu.pipeline.stages.detonation_stage import DetonationStage  # noqa: E402
from fugu.types import AuditJob, DetonationEvidence  # noqa: E402
from fugu.verdict import aggregate_verdict, stage_coverage  # noqa: E402

SCRATCH = Path("/tmp/fugu-demo-proof-execution-20261006-scratch/tmp")


class MustNotRun:
    def __init__(self) -> None:
        self.calls = 0

    async def detonate(self, *args: object, **kwargs: object) -> list[object]:
        self.calls += 1
        raise AssertionError("a no-trigger result must not call the driver")


class SyntheticDriverFailure:
    def __init__(self) -> None:
        self.calls = 0

    async def detonate(self, *args: object, **kwargs: object) -> list[object]:
        self.calls += 1
        raise RuntimeError("synthetic chamber unavailable")


async def main() -> dict[str, object]:
    # The canary value is a fake fixture string, never a credential.
    value = "FUGU-CANARY-TEST-ONLY"
    hits = scan_for_canaries(
        [value],
        flows=[
            SimpleNamespace(
                host="example.invalid", path="/upload", method="POST", body=value
            )
        ],
        dns=[SimpleNamespace(query="x-" + value.encode().hex() + ".example.invalid")],
        fs_changes=["/tmp/" + value.encode().hex()],
    )
    by_vector = Counter(hit.meta["vector"] for hit in hits)
    assert by_vector == {"http": 1, "dns": 1, "fs": 1}, by_vector
    findings = evidence_to_findings(
        DetonationEvidence(
            trigger="synthetic-only",
            exit_code=0,
            duration_s=0.1,
            canary_hits=hits,
        )
    )
    severities = sorted(finding.severity for finding in findings)
    assert severities == ["critical", "high"], severities

    with tempfile.TemporaryDirectory(prefix="fugu-no-trigger-", dir=SCRATCH) as empty_dir:
        skip_driver = MustNotRun()
        skipped = await DetonationStage(skip_driver).run(
            AuditJob(id="synthetic-no-trigger", source="local"), Path(empty_dir)
        )
        assert skip_driver.calls == 0
        assert skipped.metrics["triggers"] == 0
        assert skipped.metrics["executed"] is False
        assert stage_coverage(skipped)["state"] == "skipped"
        skip_verdict = aggregate_verdict(skipped.findings, [skipped])
        assert skip_verdict["status"] == "pass"
        assert skip_verdict["static_only"] is True
        assert skip_verdict["coverage_caveats"]

    with tempfile.TemporaryDirectory(prefix="fugu-fake-failure-", dir=SCRATCH) as target_dir:
        target = Path(target_dir)
        (target / "main.py").write_text("# inert fixture; fake driver only\n")
        fail_driver = SyntheticDriverFailure()
        failed = await DetonationStage(fail_driver).run(
            AuditJob(id="synthetic-driver-failure", source="local"), target
        )
        assert fail_driver.calls == 1
        assert failed.ok is False
        assert stage_coverage(failed)["state"] == "failed"
        failed_verdict = aggregate_verdict([], [failed])
        assert failed_verdict["status"] == "warn"

    return {
        "synthetic_collector_hits_by_vector": dict(by_vector),
        "synthetic_finding_severities": severities,
        "no_trigger": {
            "driver_calls": skip_driver.calls,
            "metrics_executed": skipped.metrics["executed"],
            "coverage_state": stage_coverage(skipped)["state"],
            "verdict": skip_verdict["status"],
            "static_only": skip_verdict["static_only"],
        },
        "whole_driver_failure": {
            "driver_calls": fail_driver.calls,
            "stage_ok": failed.ok,
            "coverage_state": stage_coverage(failed)["state"],
            "verdict": failed_verdict["status"],
        },
        "docker_cli_invocations": 0,
        "target_processes_started": 0,
        "collector_processes_started": 0,
    }


print(json.dumps(asyncio.run(main()), sort_keys=True))
