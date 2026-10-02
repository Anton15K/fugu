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

        evidences = evidences or []
        findings: list = []
        for ev in evidences:
            findings.extend(evidence_to_findings(ev))
        # Match each returned row to one selected occurrence by trigger identity.
        # Driver order is not a contract, and repeated selected commands are valid
        # occurrences; an extra row for an already-matched identity is a duplicate.
        selected_occurrences: dict[str, list[int]] = {}
        for index, trigger in enumerate(triggers):
            selected_occurrences.setdefault(trigger, []).append(index)
        matched_by_identity: dict[str, int] = {}
        selected_results: list[dict | None] = [None] * len(triggers)
        unexpected_rows: list[dict] = []
        for evidence in evidences:
            identity = evidence.trigger
            occurrences = selected_occurrences.get(identity, [])
            occurrence = matched_by_identity.get(identity, 0)
            if occurrence < len(occurrences):
                selected_index = occurrences[occurrence]
                matched_by_identity[identity] = occurrence + 1
                if evidence.exit_code == 0:
                    status = "completed"
                elif evidence.exit_code is None:
                    status = "timed_out"
                else:
                    status = "nonzero_exit"
                selected_results[selected_index] = {
                    "trigger": triggers[selected_index],
                    "evidence_trigger": identity,
                    "exit_code": evidence.exit_code,
                    "status": status,
                }
                continue

            status = "duplicate_result" if identity in selected_occurrences else "unselected_result"
            unexpected_rows.append({
                "trigger": identity,
                "evidence_trigger": identity,
                "exit_code": evidence.exit_code,
                "status": status,
            })

        missing_results = sum(result is None for result in selected_results)
        trigger_results = [
            result if result is not None else {
                "trigger": trigger,
                "exit_code": None,
                "status": "missing_result",
            }
            for trigger, result in zip(triggers, selected_results)
        ] + unexpected_rows
        matched_results = [result for result in selected_results if result is not None]
        duplicate_results = sum(row["status"] == "duplicate_result" for row in unexpected_rows)
        unselected_results = sum(row["status"] == "unselected_result" for row in unexpected_rows)

        completed_triggers = sum(result["exit_code"] == 0 for result in matched_results)
        nonzero_exits = sum(
            result["exit_code"] is not None and result["exit_code"] != 0
            for result in matched_results
        )
        timeouts = sum(result["exit_code"] is None for result in matched_results)
        coverage_reasons = []
        if nonzero_exits:
            coverage_reasons.append(f"{nonzero_exits} trigger(s) exited non-zero")
        if timeouts:
            coverage_reasons.append(f"{timeouts} trigger(s) timed out")
        if missing_results:
            coverage_reasons.append(f"{missing_results} trigger result(s) missing")
        if duplicate_results:
            coverage_reasons.append(f"{duplicate_results} duplicate trigger result(s) received")
        if unselected_results:
            coverage_reasons.append(f"{unselected_results} unselected trigger result(s) received")

        metrics = {
            "triggers": len(triggers),
            "executed": bool(matched_results),
            "detonations": len(evidences),
            "trigger_results": trigger_results,
            "trigger_results_completed": completed_triggers,
            "trigger_results_missing": missing_results,
            "trigger_results_duplicate": duplicate_results,
            "trigger_results_unselected": unselected_results,
            "trigger_results_unexpected": duplicate_results + unselected_results,
            "coverage_scope": "selected_triggers_only",
            "canary_hits": sum(len(e.canary_hits) for e in evidences),
            "flows": sum(len(e.flows) for e in evidences),
            "dns": sum(len(e.dns) for e in evidences),
        }
        if coverage_reasons:
            metrics["coverage_incomplete"] = (
                f"{completed_triggers}/{len(triggers)} selected trigger(s) returned exit code 0; "
                + "; ".join(coverage_reasons)
            )
        return StageResult(stage=self.name, ok=True, findings=findings, metrics=metrics)
