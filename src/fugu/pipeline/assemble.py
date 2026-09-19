"""Assembly + stable entrypoints for the Fugu audit pipeline.

`run_audit(target)` is THE canonical pipeline entry (requested by the eval
workstream): stages 0-1 + detonation (when Docker is available) against a
local target directory. The FastAPI server uses `build_stages()` via
create_app; the CLI and eval harness call run_audit directly.

Later stages (semantic S2, harness S4, reputation S5, composition) plug in
here without changing any caller.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from fugu.pipeline.stages.concealment import ConcealmentStage
from fugu.pipeline.stages.static_scan import StaticScanStage
from fugu.types import AuditJob, Finding, JobStatus, StageResult

__all__ = ["build_stages", "run_audit", "run_stages"]


def build_stages(
    include_detonation: bool = True,
    include_semantic: bool = True,
    include_harness: bool = True,
) -> list:
    """Assemble the currently-implemented stages in execution order.

    Detonation is skipped when Docker is unavailable (eval/CI) or when
    include_detonation=False (pure static pass). Semantic self-no-ops
    without NEBIUS_API_KEY, so include_semantic=True is safe offline.
    """
    stages: list = [ConcealmentStage(), StaticScanStage()]
    if include_semantic:
        from fugu.pipeline.stages.semantic import SemanticStage

        stages.append(SemanticStage())
    if include_harness:
        from fugu.pipeline.stages.harness import HarnessStage

        stages.append(HarnessStage())
    if include_detonation:
        try:
            from fugu.detonation.docker_driver import DockerDriver
            from fugu.pipeline.stages.detonation_stage import DetonationStage
        except ImportError:
            return stages
        try:
            driver = DockerDriver()
        except Exception:
            return stages
        stages.append(DetonationStage(driver))
    return stages


async def run_stages(job: AuditJob, target: Path, stages: list) -> list[StageResult]:
    """Run stages sequentially, never raising; per-stage failures become
    StageResult(ok=False, error=...) so partial audits stay useful."""
    results: list[StageResult] = []
    for stage in stages:
        try:
            results.append(await stage.run(job, target))
        except Exception as exc:  # noqa: BLE001 - isolation by design
            results.append(
                StageResult(stage=stage.name, ok=False, error=f"{type(exc).__name__}: {exc}")
            )
    return results


def run_audit(
    target: Path | str,
    include_detonation: bool = True,
    include_semantic: bool = True,
    include_harness: bool = True,
) -> list[Finding]:
    """Canonical entry: audit a local directory, return all findings.

    Used by the eval harness (--results auto mode) and the CLI. LLM-backed
    stages (semantic, harness) self-no-op without NEBIUS_API_KEY.
    """
    target = Path(target).resolve()
    if not target.is_dir():
        raise NotADirectoryError(f"audit target must be a directory: {target}")
    job = AuditJob(id="cli", source=str(target), status=JobStatus.running)
    results = asyncio.run(
        run_stages(
            job,
            target,
            build_stages(
                include_detonation=include_detonation,
                include_semantic=include_semantic,
                include_harness=include_harness,
            ),
        )
    )
    findings: list[Finding] = []
    for r in results:
        findings.extend(r.findings)
    return findings
