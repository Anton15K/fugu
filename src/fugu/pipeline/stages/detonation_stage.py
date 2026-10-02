"""Stage 3 wrapper: detonate the target in an isolated chamber (Docker today,
Nebius Sandboxes driver when beta access lands) and turn evidence into findings.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from fugu.source_safety import validate_source_tree
from fugu.types import AuditJob, Finding, StageResult


class DetonationDriverProtocol(Protocol):
    async def detonate(self, target_dir: Path, triggers: list[str], timeout_s: int = 120) -> list: ...


class DetonationStage:
    name = "detonation"

    def __init__(self, driver: DetonationDriverProtocol, timeout_s: int = 120, on_progress=None):
        self._driver = driver
        self._timeout_s = timeout_s
        self._on_progress = on_progress

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        try:
            target = validate_source_tree(target)
        except (ValueError, OSError) as exc:
            return StageResult(stage=self.name, ok=False, error=str(exc))
        try:
            from fugu.detonation.docker_driver import evidence_to_findings
            from fugu.detonation.triggers import derive_triggers
        except ImportError as exc:
            return StageResult(stage=self.name, ok=False, error=f"driver unavailable: {exc}")

        def emit_progress(msg: str) -> None:
            if self._on_progress is not None:
                try:
                    self._on_progress(msg)
                except Exception:  # noqa: BLE001 - progress must never kill the stage
                    pass

        triggers = derive_triggers(target, source=getattr(job, "source", None))
        if triggers:
            emit_progress(
                "derived %d trigger(s): %s"
                % (len(triggers), "; ".join(t[:60] for t in triggers))
            )
        else:
            emit_progress("no runnable triggers derived — target never executed")
        if not triggers:
            # A third of real registry servers never start (arXiv 2609.10962:
            # 37.5% fail to boot, only 48.8% complete the handshake). That is
            # evidence about the target, not an error in the audit: record it
            # as an informational finding so the verdict reflects "static-only
            # coverage" instead of silently skipping the stage.
            return StageResult(
                stage=self.name,
                ok=True,
                findings=[
                    Finding(
                        owasp_ids=["MCP08"],
                        title="Target produced no runnable triggers",
                        detail=(
                            "No install hook, importable module, or MCP entrypoint could be "
                            "derived, so the target was never executed. 37.5% of real registry "
                            "servers never start (arXiv 2609.10962); treat this verdict as "
                            "static-analysis-only coverage."
                        ),
                        severity="info",
                        confidence="deterministic",
                        stage=self.name,
                        evidence=[],
                    )
                ],
                metrics={
                    "triggers": 0, "executed": False,
                    "skipped": "no runnable triggers found; target not executed",
                },
            )
        try:
            detonate_kwargs = {"timeout_s": self._timeout_s}
            # drivers that accept on_progress get live narration; older
            # protocol drivers simply run without it
            import inspect
            if "on_progress" in inspect.signature(self._driver.detonate).parameters:
                detonate_kwargs["on_progress"] = emit_progress
            evidences = await self._driver.detonate(target, triggers, **detonate_kwargs)
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
                "executed": bool(evidences),
                "detonations": len(evidences),
                "canary_hits": sum(len(e.canary_hits) for e in evidences),
                "flows": sum(len(e.flows) for e in evidences),
                "dns": sum(len(e.dns) for e in evidences),
            },
        )
