"""Multi-source (composition) audit runner for the Fugu server.

run_composition_job() fans one parent audit out over 2..8 member sources
(contracts §3, workstream W3). Each member runs through the EXISTING
single-source run_job() as its own child AuditJob — members get their own
SSE streams, findings and verdicts exactly like today. The parent then
harvests MemberResults (child findings + tool names scanned from each
child's extracted target with static_scan's tool-name regex), cleans up
cloned child targets (never the user's local dirs), and runs the
CompositionStage as its only stage — the same emit/persist pattern as
run_job, minus cross-stage dedupe (composition findings are about member
COMBINATIONS, never echoes). A parent verdict closes the stream.

Known quirk (documented for the lead): with the CURRENT jobs.py,
run_job's final cleanup deletes a successfully cloned target even when
keep_target=True — keep_target only preserves a FAILED clone dir inside
extract_source. This module is written to be correct under either
semantics: harvest tolerates an already-deleted dir (empty tool_names),
and the parent-side cleanup mirrors run_job's own "cloned iff it differs
from the literal source path" rule and is a no-op on missing dirs.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Sequence

from fugu.config import DEFAULT_PRODUCTION_LIMITS
from fugu.pipeline.stages.static_scan import _TOOL_NAME_RE
from fugu.source_safety import validate_source_tree
from fugu.server.jobs import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    ExtractionError,
    JobStore,
    _emit,
    extract_source,
    find_skill_units,
    finding_public,
    new_job_id,
    run_job,
    run_stage_loop,
    stage_public,
)
from fugu.types import AuditJob, EvidenceSnippet, Finding, JobStatus, StageResult

__all__ = [
    "MAX_LABEL_CHARS",
    "MAX_SOURCES",
    "MIN_SOURCES",
    "SourceSpec",
    "configured_auto_max_units",
    "harvest_tool_names",
    "normalize_sources",
    "run_auto_job",
    "run_composition_job",
]

MIN_SOURCES = 2
MAX_SOURCES = 8
MAX_LABEL_CHARS = 64

# Tool-name harvest: same regex as static_scan (_TOOL_NAME_RE, reused —
# never forked), applied per line like static_scan does. Text-ish files
# only, with size/count caps so a hostile member cannot stall the parent.
_HARVEST_SUFFIXES = frozenset(
    {".py", ".js", ".ts", ".json", ".jsonc", ".md", ".txt", ".yaml", ".yml", ".toml"}
)
_HARVEST_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv"})
_HARVEST_MAX_FILES = 2000
_HARVEST_MAX_BYTES = 512 * 1024  # per file


# --- Request normalization -------------------------------------------------------


@dataclass
class SourceSpec:
    """One normalized member source: a ref plus its display label."""

    ref: str
    label: str


def _member_coverage(summaries: list[dict[str, Any]], store: JobStore) -> list[dict[str, Any]]:
    """Keep child execution facts separate from the parent's stage lifecycle."""
    from fugu.verdict import stage_coverage

    records: list[dict[str, Any]] = []
    for summary in summaries:
        child = store.get(summary["job_id"])
        results = child.stages if child is not None else []
        for result in results:
            record = stage_coverage(result)
            if record is not None:
                records.append({**record, "member": summary["label"], "job_id": summary["job_id"]})
        if summary["status"] == "failed" and not any(not r.ok for r in results):
            records.append({
                "member": summary["label"], "job_id": summary["job_id"],
                "stage": "analysis", "state": "failed",
                "reason": "member runner failed", "executed": False,
            })
    return records


def _ref_label(item: Any, index: int) -> tuple[str, str | None]:
    """Extract (ref, label) from a SourceSpec / mapping / attribute object."""
    if isinstance(item, SourceSpec):
        return item.ref.strip(), item.label
    if isinstance(item, dict):
        raw_ref = item.get("ref")
        if raw_ref is None:
            raise ValueError(f"sources[{index}].ref is required")
        return str(raw_ref).strip(), item.get("label")
    ref = getattr(item, "ref", None)
    if ref is None:
        raise ValueError(f"sources[{index}].ref is required")
    return str(ref).strip(), getattr(item, "label", None)


def normalize_sources(raw: Sequence[Any]) -> list[SourceSpec]:
    """Validate + normalize a `sources` payload into SourceSpecs.

    Rules (contracts §3): 2..8 entries; refs stripped and non-empty, no
    duplicates; labels default to the ref basename and are capped at
    MAX_LABEL_CHARS. Raises ValueError with a human-readable reason.
    """
    items = list(raw)
    if not MIN_SOURCES <= len(items) <= MAX_SOURCES:
        raise ValueError(
            f"sources must contain {MIN_SOURCES}..{MAX_SOURCES} entries, "
            f"got {len(items)}"
        )
    specs: list[SourceSpec] = []
    seen: set[str] = set()
    for i, item in enumerate(items):
        ref, label = _ref_label(item, i)
        if not ref:
            raise ValueError(f"sources[{i}].ref must not be empty")
        if ref in seen:
            raise ValueError(f"duplicate source ref: {ref}")
        seen.add(ref)
        label = (label or "").strip()
        if not label:
            label = Path(ref).name or ref
        if len(label) > MAX_LABEL_CHARS:
            raise ValueError(
                f"sources[{i}].label is too long (max {MAX_LABEL_CHARS} chars)"
            )
        specs.append(SourceSpec(ref=ref, label=label))
    return specs


def _slugify(label: str) -> str:
    """Member slug used in evidence sources (`member:<slug>:...`)."""
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
    return slug or "member"


# --- Tool-name harvest -------------------------------------------------------------


def harvest_tool_names(target_dir: Path | None) -> list[str]:
    """Collect tool names from text files under a member's target dir.

    Uses static_scan's _TOOL_NAME_RE per line (same semantics as the
    mcp_duplicate_tool_names rule). Tolerates a missing/None dir (e.g. a
    child whose cloned target was already reclaimed) → empty list.
    """
    if target_dir is None or not Path(target_dir).is_dir():
        return []
    target_dir = validate_source_tree(target_dir)
    names: set[str] = set()
    scanned = 0
    for path in sorted(Path(target_dir).rglob("*")):
        if scanned >= _HARVEST_MAX_FILES:
            break
        if any(part in _HARVEST_SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file() or path.suffix.lower() not in _HARVEST_SUFFIXES:
            continue
        scanned += 1
        try:
            with path.open("rb") as fh:
                chunk = fh.read(_HARVEST_MAX_BYTES)
        except OSError:
            continue
        text = chunk.decode("utf-8", errors="replace")
        for line in text.splitlines():
            for match in _TOOL_NAME_RE.finditer(line):
                names.add(match.group(1))
    return sorted(names)


def _is_cloned_target(ref: str, target: Path | None) -> bool:
    """Mirror run_job's rule: we created the target iff it differs from
    the literal (expanded) source path. Local user dirs are never cloned."""
    if target is None:
        return False
    return Path(target) != Path(ref.strip()).expanduser()


# --- Composition stage fallbacks (W1 may not have landed yet) ----------------------


@dataclass
class _FallbackMemberResult:
    """Field-compatible stand-in for composition.MemberResult (contracts §1)."""

    label: str
    slug: str
    findings: list[Finding]
    tool_names: list[str]
    target_dir: Path | None


class _StubCompositionStage:
    """Zero-finding stand-in with the same `_member_results` contract.

    Keeps the parent fan-out testable and unblocked until
    fugu.pipeline.stages.composition (workstream W1) lands.
    """

    name = "composition"

    def __init__(self) -> None:
        self._member_results: list[Any] = []

    async def run(self, job: AuditJob, target: Path | None) -> StageResult:
        return StageResult(
            stage=self.name,
            ok=True,
            metrics={
                "stub": "composition stage module not available",
                "members": len(self._member_results),
            },
        )


def _member_result_class() -> type:
    """MemberResult (real module) or the field-compatible fallback."""
    try:
        from fugu.pipeline.stages.composition import MemberResult  # type: ignore[no-redef]

        return MemberResult
    except ImportError:
        return _FallbackMemberResult


MemberResult = _member_result_class()


# --- The runner ---------------------------------------------------------------------


async def run_composition_job(
    job: AuditJob,
    sources: Sequence[Any],
    stages_for_children: Iterable[Any],
    store: JobStore,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> None:
    """Fan a parent audit out over member sources, then compose.

    1. Sequentially per source: child AuditJob(depth='standard') through
       the existing run_job (keep_target=True), then a parent log event
       `member <label>: job <child_id> <status>, <N> findings` with a
       child_job_id key.
    2. Harvest MemberResults (findings snapshot + tool names from the
       child target) and reclaim cloned child targets (never local dirs).
    3. Run the CompositionStage as the parent's only stage — run_job's
       emit/persist pattern, cross-stage dedupe skipped.
    4. aggregate_verdict → verdict event → status done → close stream.
       Every child failing extraction → parent failed with an error event.
    """
    specs = normalize_sources(sources)
    snap = store.get(job.id)
    if snap is None:  # internal wiring bug; mirror run_job's defense
        snap = store.create(job)

    # Composition stage classes: import INSIDE the function (parallel
    # workstream may not have landed); fall back to zero-finding stubs
    # with the same attribute contract.
    try:
        from fugu.pipeline.stages.composition import (  # type: ignore[no-redef]
            CompositionStage,
            MemberResult,
        )
    except ImportError:
        CompositionStage = _StubCompositionStage  # type: ignore[assignment]
        MemberResult = _FallbackMemberResult  # type: ignore[assignment]

    stages = list(stages_for_children)
    loop = asyncio.get_running_loop()

    job.status = JobStatus.running
    _emit(
        store,
        job,
        "log",
        {
            "message": "composition job started",
            "source": job.source,
            "members": [s.label for s in specs],
        },
    )
    store._persist_status(job)

    members: list[Any] = []
    summaries: list[dict[str, Any]] = []
    for spec in specs:
        child = AuditJob(id=new_job_id(), source=spec.ref, depth="standard")
        store.create(child)
        crashed: str | None = None
        try:
            await run_job(
                child,
                stages,
                store,
                max_files=max_files,
                max_bytes=max_bytes,
                keep_target=True,
            )
        except Exception as exc:  # noqa: BLE001 - a runner bug must not kill the fan-out
            crashed = f"{type(exc).__name__}: {exc}"
        child_snap = store.get(child.id)
        if child_snap is None:  # pragma: no cover - create() just made it
            child_snap = store.create(child)
        status = "failed" if crashed else child_snap.job.status.value
        n_findings = len(child_snap.findings)

        _emit(
            store,
            job,
            "log",
            {
                "stage": "composition",
                "message": f"member {spec.label}: job {child.id} {status}, {n_findings} findings",
                "child_job_id": child.id,
            },
        )
        if crashed:
            _emit(
                store,
                job,
                "log",
                {
                    "stage": "composition",
                    "message": f"member {spec.label}: runner error ({crashed})",
                    "child_job_id": child.id,
                },
            )

        target_dir = child_snap.target_dir
        tool_names = harvest_tool_names(target_dir)
        members.append(
            MemberResult(
                label=spec.label,
                slug=_slugify(spec.label),
                findings=list(child_snap.findings),
                tool_names=tool_names,
                target_dir=target_dir,
            )
        )
        # Reclaim cloned child targets after harvest (git sources). Local
        # dirs are the user's own — never deleted. No-op if run_job's own
        # cleanup already removed the clone (current jobs.py behavior).
        if _is_cloned_target(spec.ref, target_dir) and target_dir is not None:
            clone = Path(target_dir)
            await loop.run_in_executor(None, shutil.rmtree, clone, True)
        summaries.append(
            {
                "label": spec.label,
                "job_id": child.id,
                "status": status,
                "findings": n_findings,
            }
        )

    failed = [s for s in summaries if s["status"] == "failed"]
    if failed and len(failed) == len(summaries):
        # Every member failed extraction → the parent has nothing to compose.
        job.status = JobStatus.failed
        result = StageResult(
            stage="extraction",
            ok=False,
            error="composition failed: all "
            f"{len(failed)} members failed extraction "
            f"({', '.join(s['label'] for s in failed)})",
        )
        snap.stages.append(result)
        _emit(
            store,
            job,
            "error",
            {
                "error": result.error,
                "stage": "extraction",
                "stage_results": [stage_public(r) for r in snap.stages],
            },
        )
        store.close(job.id)
        return
    if failed:
        _emit(
            store,
            job,
            "log",
            {
                "stage": "composition",
                "message": (
                    f"{len(failed)} of {len(summaries)} members failed "
                    f"extraction; continuing with the remaining "
                    f"{len(summaries) - len(failed)}"
                ),
            },
        )

    # --- composition stage: the parent's only stage --------------------------
    stage = CompositionStage()
    try:
        stage._member_results = members  # runner-injected, contracts §2
    except Exception:  # pragma: no cover - slots/property guard in W1's stage
        _emit(
            store,
            job,
            "log",
            {
                "stage": "composition",
                "message": "could not inject _member_results; stage sees no members",
            },
        )
    name = getattr(stage, "name", "composition")
    parent_target = next(
        (m.target_dir for m in members if getattr(m, "target_dir", None) is not None),
        None,
    )

    _emit(store, job, "stage_started", {"stage": name})
    started = loop.time()
    try:
        result = await stage.run(job, parent_target)
        if result is None:  # defensive: broken stage returned nothing
            raise TypeError("stage.run() returned None, expected StageResult")
    except Exception as exc:  # noqa: BLE001 - stage bugs become results
        result = StageResult(
            stage=name,
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
        )
    elapsed = loop.time() - started
    result.metrics.setdefault("duration_s", round(elapsed, 3))
    result.metrics.setdefault("members", len(members))
    result.metrics["member_coverage"] = _member_coverage(summaries, store)
    snap.stages.append(result)
    # Cross-stage dedupe is intentionally SKIPPED: composition findings
    # describe member combinations — they are never echoes of member
    # findings, and the parent has no earlier stages to echo anyway.
    snap.findings.extend(result.findings)
    for finding in result.findings:
        _emit(
            store,
            job,
            "finding",
            {"stage": name, "finding": finding_public(finding)},
        )
    _emit(
        store,
        job,
        "stage_done",
        {
            "stage": name,
            "ok": result.ok,
            "error": result.error,
            "findings_count": len(result.findings),
            "metrics": result.metrics,
        },
    )

    from fugu.verdict import aggregate_verdict

    _merge_member_findings(job, snap, members, store)
    verdict = aggregate_verdict(snap.findings, snap.stages)
    _emit(
        store,
        job,
        "verdict",
        {
            "status": "done",
            "verdict": verdict,
            "total_findings": verdict["total_findings"],
            "severity_counts": verdict["severity_counts"],
            "stages": [stage_public(r) for r in snap.stages],
        },
    )
    job.status = JobStatus.done
    store.close(job.id)


# --- Auto fan-out: one source, many skill units ---------------------------------------

_AUTO_MIN_UNITS = 2
#: Fan-out cap: audited units per repo. Cost guard (each unit runs the
#: full pipeline incl. harness A/B); env-tunable. Truncation is announced
#: in the event stream and the remaining units are listed in the log.
_AUTO_MAX_UNITS = DEFAULT_PRODUCTION_LIMITS.fanout_max_units


def configured_auto_max_units(raw: str | None = None) -> int:
    """Read the optional fan-out override, rejecting values outside 1..24."""
    if raw is None:
        raw = os.environ.get("FUGU_FANOUT_MAX")
    if raw is None or not raw.strip():
        return DEFAULT_PRODUCTION_LIMITS.fanout_max_units
    try:
        parsed = int(raw)
    except ValueError:
        return DEFAULT_PRODUCTION_LIMITS.fanout_max_units
    if not 1 <= parsed <= DEFAULT_PRODUCTION_LIMITS.fanout_max_units:
        return DEFAULT_PRODUCTION_LIMITS.fanout_max_units
    return parsed


def _fanout_limit(max_units: int | None) -> tuple[int, str | None, bool]:
    raw = os.environ.get("FUGU_FANOUT_MAX") if max_units is None else str(max_units)
    if raw is None or not raw.strip():
        return DEFAULT_PRODUCTION_LIMITS.fanout_max_units, raw, True
    try:
        parsed = int(raw.strip())
    except ValueError:
        return DEFAULT_PRODUCTION_LIMITS.fanout_max_units, raw, False
    if not 1 <= parsed <= DEFAULT_PRODUCTION_LIMITS.fanout_max_units:
        return DEFAULT_PRODUCTION_LIMITS.fanout_max_units, raw, False
    return parsed, raw, True


async def run_auto_job(
    job: AuditJob,
    source: str,
    stages_for_children: Iterable[Any],
    store: JobStore,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    min_units: int = _AUTO_MIN_UNITS,
    max_units: int | None = None,
) -> None:
    """Auto fan-out: audit one source's skill UNITS, then compose.

    Extracts the source once (clone or local dir), discovers skill units
    (directories directly containing a SKILL.md, excluding vendored
    trees). Fewer than `min_units` units -> falls back to a plain
    single-source audit over the whole tree (no composition). Otherwise
    each unit becomes a member: its own child AuditJob driven through
    run_stage_loop against the unit dir (shared, read-only extraction —
    never per-member clones), then run_composition_job's composition
    stage over the harvested members. Child SSE streams are real
    (children get job ids and run through the same emit path); the
    extraction is cleaned up once at the end.

    Parent job.source keeps the original ref; a `source` log event names
    the detected units so the UI member strip has something to show.
    """
    snap = store.get(job.id)
    if snap is None:  # pragma: no cover - internal wiring bug
        snap = store.create(job)

    job.status = JobStatus.running
    _emit(store, job, "log", {"message": "job started", "source": job.source})
    store._persist_status(job)

    loop = asyncio.get_running_loop()
    cloned_dir: Path | None = None
    try:
        target = await extract_source(
            job, max_files=max_files, max_bytes=max_bytes, keep_target=True
        )
        snap.target_dir = target
        if target != Path(job.source.strip()).expanduser():
            cloned_dir = target
    except ExtractionError as exc:
        job.status = JobStatus.failed
        result = StageResult(
            stage="extraction",
            ok=False,
            error=f"source extraction failed: {exc}",
        )
        snap.stages.append(result)
        _emit(
            store,
            job,
            "error",
            {
                "error": result.error,
                "stage": "extraction",
                "stage_results": [stage_public(r) for r in snap.stages],
            },
        )
        store.close(job.id)
        return

    try:
        units = find_skill_units(target)
        if len(units) < min_units:
            # Single skill (or none): plain audit over the whole tree.
            await run_stage_loop(job, snap, target, stages_for_children, store)
            return

        max_units, fanout_override, fanout_override_valid = _fanout_limit(max_units)
        omitted_unit_labels = [label for label, _ in units[max_units:]]
        omitted_units = len(omitted_unit_labels)
        if omitted_units:
            kept = units[:max_units]
            _emit(
                store,
                job,
                "log",
                {
                    "stage": "composition",
                    "message": (
                        f"{len(units)} skill units found; auditing the first "
                        f"{max_units} (cap)"
                    ),
                },
            )
            units = kept

        labels = [label for label, _ in units]
        _emit(
            store,
            job,
            "log",
            {
                "stage": "composition",
                "message": (
                    f"auto fan-out: {len(units)} skill units "
                    f"({', '.join(labels)})"
                ),
                "units": labels,
            },
        )

        stages = list(stages_for_children)
        members: list[Any] = []
        summaries: list[dict[str, Any]] = []
        for label, unit_dir in units:
            child = AuditJob(id=new_job_id(), source=str(unit_dir), depth="full")
            store.create(child)
            child_snap = store.get(child.id)
            try:
                await run_stage_loop(child, child_snap, unit_dir, stages, store)
            except Exception:  # noqa: BLE001 - one unit must not kill the run
                child_snap.job.status = JobStatus.failed
                store.close(child.id)
            status = child_snap.job.status.value
            n_findings = len(child_snap.findings)
            _emit(
                store,
                job,
                "log",
                {
                    "stage": "composition",
                    "message": (
                        f"member {label}: job {child.id} {status}, "
                        f"{n_findings} findings"
                    ),
                    "child_job_id": child.id,
                },
            )
            members.append(
                MemberResult(
                    label=label,
                    slug=_slugify(label),
                    findings=list(child_snap.findings),
                    tool_names=harvest_tool_names(unit_dir),
                    target_dir=unit_dir,
                )
            )
            summaries.append(
                {
                    "label": label,
                    "job_id": child.id,
                    "status": status,
                    "findings": n_findings,
                }
            )

        failed = [s for s in summaries if s["status"] == "failed"]
        if failed and len(failed) == len(summaries):
            job.status = JobStatus.failed
            result = StageResult(
                stage="extraction",
                ok=False,
                error="auto fan-out failed: all "
                f"{len(failed)} skill units failed ({', '.join(s['label'] for s in failed)})",
            )
            snap.stages.append(result)
            _emit(
                store,
                job,
                "error",
                {
                    "error": result.error,
                    "stage": "extraction",
                    "stage_results": [stage_public(r) for r in snap.stages],
                },
            )
            store.close(job.id)
            return

        await _compose_members(
            job,
            snap,
            members,
            store,
            summaries,
            omitted_units,
            omitted_unit_labels=omitted_unit_labels,
            fanout_max_units=max_units,
            fanout_override=fanout_override,
            fanout_override_valid=fanout_override_valid,
        )
    finally:
        if cloned_dir is not None:
            await loop.run_in_executor(None, shutil.rmtree, cloned_dir, True)


async def _compose_members(
    job: AuditJob,
    snap: Any,
    members: list[Any],
    store: JobStore,
    summaries: list[dict[str, Any]],
    omitted_units: int = 0,
    *,
    omitted_unit_labels: list[str] | None = None,
    fanout_max_units: int | None = None,
    fanout_override: str | None = None,
    fanout_override_valid: bool | None = None,
) -> None:
    """Run the composition stage over harvested members + parent verdict.

    Shared tail of run_composition_job and run_auto_job.
    """
    try:
        from fugu.pipeline.stages.composition import CompositionStage
    except ImportError:
        CompositionStage = _StubCompositionStage  # type: ignore[assignment]

    loop = asyncio.get_running_loop()
    stage = CompositionStage()
    try:
        stage._member_results = members  # runner-injected, contracts §2
    except Exception:  # pragma: no cover
        _emit(
            store,
            job,
            "log",
            {
                "stage": "composition",
                "message": "could not inject _member_results; stage sees no members",
            },
        )
    name = getattr(stage, "name", "composition")
    parent_target = next(
        (m.target_dir for m in members if getattr(m, "target_dir", None) is not None),
        None,
    )

    _emit(store, job, "stage_started", {"stage": name})
    started = loop.time()
    try:
        result = await stage.run(job, parent_target)
        if result is None:  # defensive
            raise TypeError("stage.run() returned None, expected StageResult")
    except Exception as exc:  # noqa: BLE001
        result = StageResult(
            stage=name,
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
        )
    elapsed = loop.time() - started
    result.metrics.setdefault("duration_s", round(elapsed, 3))
    result.metrics.setdefault("members", len(members))
    member_coverage = _member_coverage(summaries, store)
    omitted_unit_labels = omitted_unit_labels or []
    member_coverage.extend(
        {
            "member": label,
            "job_id": job.id,
            "stage": "fanout",
            "state": "omitted",
            "reason": "unit omitted by fan-out cap",
            "executed": False,
        }
        for label in omitted_unit_labels
    )
    result.metrics["member_coverage"] = member_coverage
    result.metrics["omitted_units"] = omitted_units
    result.metrics["omitted_unit_labels"] = omitted_unit_labels
    effective_profile = (
        replace(DEFAULT_PRODUCTION_LIMITS, fanout_max_units=fanout_max_units)
        if fanout_max_units is not None
        else DEFAULT_PRODUCTION_LIMITS
    )
    result.metrics["effective_limits"] = effective_profile.to_dict()
    if fanout_max_units is not None:
        result.metrics["fanout_max_units"] = fanout_max_units
        result.metrics["fanout_override"] = fanout_override
        result.metrics["fanout_override_valid"] = fanout_override_valid
    snap.stages.append(result)
    # No cross-stage dedupe: composition findings are about member
    # combinations, never echoes (the parent ran no other stages).
    snap.findings.extend(result.findings)
    for finding in result.findings:
        _emit(
            store,
            job,
            "finding",
            {"stage": name, "finding": finding_public(finding)},
        )
    _emit(
        store,
        job,
        "stage_done",
        {
            "stage": name,
            "ok": result.ok,
            "error": result.error,
            "findings_count": len(result.findings),
            "metrics": result.metrics,
        },
    )

    from fugu.verdict import aggregate_verdict

    _merge_member_findings(job, snap, members, store)
    verdict = aggregate_verdict(snap.findings, snap.stages)
    _emit(
        store,
        job,
        "verdict",
        {
            "status": "done",
            "verdict": verdict,
            "total_findings": verdict["total_findings"],
            "severity_counts": verdict["severity_counts"],
            "stages": [stage_public(r) for r in snap.stages],
        },
    )
    job.status = JobStatus.done
    store.close(job.id)


def _merge_member_findings(
    job: AuditJob,
    snap: Any,
    members: list[Any],
    store: JobStore,
) -> None:
    """Union view: the parent IS the audit of the whole set.

    Member findings join the parent's findings — each attributed with a
    member:<slug> evidence snippet AND re-emitted as parent-stream finding
    events so live and replay views agree — so totals, severity mix, the
    OWASP matrix and the verdict reflect everything found. A set whose
    members produced 21 findings must never render as "PASS · 0 findings".
    Child jobs remain the per-member drill-down.
    """
    for m in members:
        for finding in list(getattr(m, "findings", [])):
            if any(f is finding for f in snap.findings):
                continue
            finding.evidence.append(
                EvidenceSnippet(
                    source=f"member:{m.slug}",
                    excerpt=f"finding from member '{m.label}'",
                    meta={"member": m.slug, "member_label": m.label},
                )
            )
            snap.findings.append(finding)
            _emit(
                store,
                job,
                "finding",
                {
                    "stage": getattr(finding, "stage", "static"),
                    "finding": finding_public(finding),
                },
            )
