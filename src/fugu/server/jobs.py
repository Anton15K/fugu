"""In-memory job store and sequential stage runner for the Fugu server.

Everything here is asyncio-safe and process-local: the JobStore keeps a
dict of job snapshots plus per-job subscriber queues (plain asyncio.Queue
objects) that the SSE endpoint consumes. Persistence (SQLite) comes later.

run_job() drives the injected stages sequentially, publishing
stage_started / finding / stage_done StageEvents as work happens and a
final `verdict` (or `error`) event, then marks the job done/failed.
Source extraction (local dir sanity checks or git clone depth 1) also
lives here so POST /audits stays thin.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from fugu.types import (
    AuditJob,
    Finding,
    JobStatus,
    StageEvent,
    StageResult,
)

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_FILES",
    "ExtractionError",
    "JobSnapshot",
    "JobStore",
    "extract_source",
    "finding_public",
    "is_git_source",
    "new_job_id",
    "run_job",
    "stage_public",
]

# --- Extraction config ---------------------------------------------------------

DEFAULT_MAX_BYTES = 512 * 1024 * 1024      # 512 MiB total size cap
DEFAULT_MAX_FILES = 20_000                 # file-count cap


class ExtractionError(Exception):
    """Source validation / extraction failed (maps to HTTP 422)."""


def is_git_source(source: str) -> bool:
    """Heuristic: does this source string look like a git remote?

    Scheme-prefixed URLs and git@/scp-like remotes count, as do
    ``.../repo.git`` tails. Bare local paths stay local.
    """
    s = source.strip()
    if not s:
        return False
    if s.startswith(("git@", "ssh://", "http://", "https://")):
        return True
    if s.endswith(".git"):
        return True
    return False


# --- Job store ------------------------------------------------------------------

@dataclass
class JobSnapshot:
    """What we know about a job right now (mutated only on the loop)."""

    job: AuditJob
    target_dir: Path | None = None
    stages: list[StageResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    events: list[StageEvent] = field(default_factory=list)
    ended: bool = False


class JobStore:
    """In-memory, asyncio-safe job registry + event bus.

    All mutation happens on the event loop (endpoints and run_job are
    coroutines), so plain dict access needs no lock. Each subscriber gets
    its own bounded asyncio.Queue; publishing never blocks the runner.
    """

    def __init__(self, queue_size: int = 512, history_limit: int = 10_000) -> None:
        self._jobs: dict[str, JobSnapshot] = {}
        self._subs: dict[str, list[asyncio.Queue[StageEvent | None]]] = {}
        self._queue_size = queue_size
        self._history_limit = history_limit

    # -- job lifecycle ----------------------------------------------------------

    def create(self, job: AuditJob) -> JobSnapshot:
        if job.id in self._jobs:
            raise ValueError(f"duplicate job id {job.id!r}")
        snap = JobSnapshot(job=job)
        self._jobs[job.id] = snap
        return snap

    def get(self, job_id: str) -> JobSnapshot | None:
        return self._jobs.get(job_id)

    def all_ids(self) -> list[str]:
        return list(self._jobs.keys())

    # -- event bus --------------------------------------------------------------

    def subscribe(self, job_id: str) -> asyncio.Queue[StageEvent | None]:
        """Register a subscriber queue for a job. None sentinel = EOF."""
        q: asyncio.Queue[StageEvent | None] = asyncio.Queue(maxsize=self._queue_size)
        self._subs.setdefault(job_id, []).append(q)
        return q

    def unsubscribe(self, job_id: str, q: asyncio.Queue[StageEvent | None]) -> None:
        subs = self._subs.get(job_id)
        if subs and q in subs:
            subs.remove(q)
        if subs is not None and not subs:
            self._subs.pop(job_id, None)

    def publish(self, job_id: str, event: StageEvent) -> None:
        """Broadcast to every subscriber without blocking the runner.

        Also appends to the job's event history so SSE clients that
        connect late (e.g. after polling GET /audits/ID) can replay.
        A full queue means the client is too slow; drop the oldest
        pending event rather than stall the pipeline.
        """
        snap = self._jobs.get(job_id)
        if snap is not None and len(snap.events) < self._history_limit:
            snap.events.append(event)
        for q in self._subs.get(job_id, []):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:  # pragma: no cover - raced
                    pass
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:  # pragma: no cover - raced
                pass

    def close(self, job_id: str) -> None:
        """Mark the job's stream ended and send EOF to subscribers."""
        snap = self._jobs.get(job_id)
        if snap is not None:
            snap.ended = True
        for q in self._subs.pop(job_id, []):
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:  # pragma: no cover - raced
                pass


# --- Extraction ------------------------------------------------------------------

async def extract_source(
    job: AuditJob,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    keep_target: bool = False,
) -> Path:
    """Materialize the audited source into a usable target directory.

    Local sources are used as-is after sanity checks (exists, is a dir,
    non-empty, under file/size caps). Git sources are cloned with
    ``--depth 1`` via an asyncio subprocess into a fresh temp dir which
    the caller should rmtree when done (run_job does; keep_target is a
    testing escape hatch so tmp_path fixtures survive).

    Raises ExtractionError on any validation or clone failure.
    """
    source = job.source.strip()
    if not source:
        raise ExtractionError("source must not be empty")

    if is_git_source(source):
        loop = asyncio.get_running_loop()
        tmp = await loop.run_in_executor(
            None, lambda: tempfile.mkdtemp(prefix="fugu-git-")
        )
        target = Path(tmp)
        try:
            await _git_clone(source, target)
        except ExtractionError:
            if not keep_target:
                await loop.run_in_executor(None, shutil.rmtree, tmp, True)
            raise
        return target

    # --- local path ------------------------------------------------------------
    p = Path(source).expanduser()
    if not p.exists():
        raise ExtractionError(f"local source path does not exist: {source}")
    if not p.is_dir():
        raise ExtractionError(f"local source path is not a directory: {source}")
    try:
        if not any(p.iterdir()):
            raise ExtractionError(f"local source directory is empty: {source}")
    except PermissionError as exc:
        raise ExtractionError(f"local source not readable: {source} ({exc})") from exc

    n_files = 0
    n_bytes = 0
    for f in p.rglob("*"):
        n_files += 1
        if n_files > max_files:
            raise ExtractionError(
                f"source has too many files (> {max_files}): {source}"
            )
        try:
            if f.is_file():
                n_bytes += f.stat().st_size
        except OSError:
            pass  # broken symlink / race: ignore
        if n_bytes > max_bytes:
            raise ExtractionError(
                f"source is too large (> {max_bytes} bytes): {source}"
            )
    return p


async def _git_clone(source: str, target: Path) -> None:
    """Clone `source` (depth 1) into `target` via asyncio subprocess."""
    proc = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--depth",
        "1",
        "--quiet",
        source,
        str(target),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        detail = (stderr or b"").decode(errors="replace").strip()
        raise ExtractionError(
            f"git clone failed (exit {proc.returncode}): {detail[:500]}"
        )


# --- Runner ------------------------------------------------------------------------

async def run_job(
    job: AuditJob,
    stages: Iterable[Any],
    store: JobStore,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    keep_target: bool = False,
) -> None:
    """Execute all stages sequentially for `job`, publishing SSE events.

    Stage exceptions are caught and converted into StageResult(ok=False,
    error=...) — a failing stage must never 500 the job. The final event
    is `verdict` (severity counts + per-stage summary) on success or
    `error` when extraction itself failed. Either way the stream is then
    closed (EOF sentinel) and the job status set to done/failed.
    """
    snap = store.get(job.id)
    if snap is None:  # pragma: no cover - internal wiring bug
        snap = store.create(job)

    job.status = JobStatus.running
    _emit(store, job, "log", {"message": "job started", "source": job.source})

    cloned_dir: Path | None = None
    try:
        target = await extract_source(
            job, max_files=max_files, max_bytes=max_bytes, keep_target=keep_target
        )
        snap.target_dir = target
        if target != Path(job.source.strip()).expanduser():
            cloned_dir = target  # we created it (git clone); clean up later
    except ExtractionError as exc:
        job.status = JobStatus.failed
        result = StageResult(
            stage="extraction",
            ok=False,
            error=f"source extraction failed: {exc}",
        )
        snap.stages.append(result)
        _emit(store, job, "error", {
            "error": result.error,
            "stage": "extraction",
            "stage_results": [stage_public(r) for r in snap.stages],
        })
        store.close(job.id)
        return

    loop = asyncio.get_running_loop()
    for stage in stages:
        name = getattr(stage, "name", type(stage).__name__)
        _emit(store, job, "stage_started", {"stage": name})
        started = loop.time()
        try:
            result = await stage.run(job, target)
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
        snap.stages.append(result)
        for finding in result.findings:
            snap.findings.append(finding)
            _emit(store, job, "finding", {
                "stage": name,
                "finding": finding_public(finding),
            })
        _emit(store, job, "stage_done", {
            "stage": name,
            "ok": result.ok,
            "error": result.error,
            "findings_count": len(result.findings),
            "metrics": result.metrics,
        })

    counts: dict[str, int] = {}
    for f in snap.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    _emit(store, job, "verdict", {
        "status": "done",
        "total_findings": len(snap.findings),
        "severity_counts": counts,
        "stages": [stage_public(r) for r in snap.stages],
    })
    job.status = JobStatus.done
    store.close(job.id)

    if cloned_dir is not None:
        await loop.run_in_executor(None, shutil.rmtree, cloned_dir, True)


def _emit(store: JobStore, job: AuditJob, etype: str, data: dict[str, Any]) -> None:
    store.publish(job.id, StageEvent(type=etype, job_id=job.id, data=data))  # type: ignore[arg-type]


# --- JSON-safe serializers -----------------------------------------------------------

def stage_public(r: StageResult) -> dict[str, Any]:
    """JSON-safe view of a StageResult (findings collapsed to a count)."""
    return {
        "stage": r.stage,
        "ok": r.ok,
        "error": r.error,
        "findings_count": len(r.findings),
        "metrics": r.metrics,
    }


def finding_public(f: Finding) -> dict[str, Any]:
    """JSON-safe view of a Finding."""
    return {
        "owasp_ids": list(f.owasp_ids),
        "title": f.title,
        "detail": f.detail,
        "severity": f.severity,
        "confidence": f.confidence,
        "stage": f.stage,
        "evidence": [
            {"source": e.source, "excerpt": e.excerpt, "meta": e.meta}
            for e in f.evidence
        ],
    }


def new_job_id() -> str:
    return uuid.uuid4().hex[:12]
