"""Stage 3 wrapper: detonate the target in an isolated chamber (Docker today,
Nebius Sandboxes driver when beta access lands) and turn evidence into findings.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from fugu.types import AuditJob, StageResult


class DetonationDriverProtocol(Protocol):
    async def detonate(self, target_dir: Path, triggers: list[str], timeout_s: int = 120) -> list: ...


class DetonationStage:
    name = "detonation"

    def __init__(self, driver: DetonationDriverProtocol, timeout_s: int = 120):
        self._driver = driver
        self._timeout_s = timeout_s

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        try:
            from fugu.detonation.docker_driver import evidence_to_findings
            from fugu.detonation.triggers import derive_triggers
        except ImportError as exc:
            return StageResult(stage=self.name, ok=False, error=f"driver unavailable: {exc}")

        triggers = derive_triggers(target)
        if not triggers:
            return StageResult(
                stage=self.name,
                ok=True,
                metrics={"triggers": 0, "note": "no runnable triggers found"},
            )
        try:
            evidences = await self._driver.detonate(target, triggers, timeout_s=self._timeout_s)
        except Exception as exc:  # noqa: BLE001 - chamber failures must not kill the audit
            return StageResult(stage=self.name, ok=False, error=f"{type(exc).__name__}: {exc}")

        findings: list = []
        for ev in evidences:
            findings.extend(evidence_to_findings(ev))
        return StageResult(
            stage=self.name,
            ok=True,
            findings=findings,
            metrics={
                "triggers": len(triggers),
                "detonations": len(evidences),
                "canary_hits": sum(len(e.canary_hits) for e in evidences),
                "flows": sum(len(e.flows) for e in evidences),
                "dns": sum(len(e.dns) for e in evidences),
            },
        )
