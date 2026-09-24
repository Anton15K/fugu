"""In-memory job store and sequential stage runner for the Fugu server.

Everything here is asyncio-safe and process-local: the JobStore keeps a
dict of job snapshots plus per-job subscriber queues (plain asyncio.Queue
objects) that the SSE endpoint consumes. Persistence is optional: pass
``store=SqliteJobStore(path)`` and every snapshot/event/finding is
mirrored to SQLite; ``get()`` then transparently recovers jobs that
predate this process (server restart). With store=None the fast path is
purely in-memory, byte-for-byte the original behavior.

run_job() drives the injected stages sequentially, publishing
stage_started / finding / stage_done StageEvents as work happens and a
final `verdict` (or `error`) event, then marks the job done/failed.
Source extraction (local dir sanity checks or git clone depth 1) also
lives here so POST /audits stays thin.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from fugu.store.sqlite import SqliteJobStore
from fugu.types import (
    AuditJob,
    EvidenceSnippet,
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
    "run_job", "run_stage_loop", "find_skill_units",
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

    With ``store=`` (a SqliteJobStore) every create/publish/close is
    mirrored to SQLite and ``get()`` recovers snapshots that predate
    this process, so GET /audits/<id> survives a server restart.
    """

    def __init__(
        self,
        queue_size: int = 512,
        history_limit: int = 10_000,
        store: SqliteJobStore | None = None,
    ) -> None:
        self._jobs: dict[str, JobSnapshot] = {}
        self._subs: dict[str, list[asyncio.Queue[StageEvent | None]]] = {}
        self._queue_size = queue_size
        self._history_limit = history_limit
        self._db: SqliteJobStore | None = store

    @property
    def db(self) -> SqliteJobStore | None:
        """The backing SQLite store, when persistence is enabled."""
        return self._db

    # -- job lifecycle ----------------------------------------------------------

    def create(self, job: AuditJob) -> JobSnapshot:
        if job.id in self._jobs:
            raise ValueError(f"duplicate job id {job.id!r}")
        snap = JobSnapshot(job=job)
        self._jobs[job.id] = snap
        if self._db is not None:
            self._db.save_job(
                job.id,
                source=job.source,
                depth=job.depth,
                status=job.status.value,
                created_at=job.created_at,
            )
        return snap

    def get(self, job_id: str) -> JobSnapshot | None:
        snap = self._jobs.get(job_id)
        if snap is not None or self._db is None:
            return snap
        return self._recover(job_id)

    def all_ids(self) -> list[str]:
        if self._db is None:
            return list(self._jobs.keys())
        seen = set(self._jobs.keys())
        ids = list(self._jobs.keys())
        for jid in self._db.job_ids():
            if jid not in seen:
                ids.append(jid)
        return ids

    # -- persistence helpers ------------------------------------------------------

    def _persist_status(self, job: AuditJob, finished_at: str | None = None,
                        verdict: dict[str, Any] | None = None) -> None:
        if self._db is not None:
            self._db.save_job(
                job.id,
                source=job.source,
                depth=job.depth,
                status=job.status.value,
                created_at=job.created_at,
                finished_at=finished_at,
                verdict=verdict,
            )

    def _recover(self, job_id: str) -> JobSnapshot | None:
        """Rebuild a JobSnapshot from SQLite (server-restart path).

        Reconstructs AuditJob / StageResult / Finding objects from the
        persisted JSON (projectors are lossy by design — findings lose
        nothing, stages lose their Finding objects, which GET /audits
        never returns anyway). Marks the snapshot ended when the stored
        event history already contains a terminal event.
        """
        assert self._db is not None  # only called when backing store present
        row = self._db.load_job(job_id)
        if row is None:
            return None
        try:
            job = AuditJob(
                id=row["job_id"],
                source=row["source"],
                created_at=row["created_at"],
                status=JobStatus(row["status"]),
                depth=row["depth"],  # type: ignore[arg-type]
            )
        except ValueError:  # unknown status/depth enum → sanitized fallback
            return None
        snap = JobSnapshot(job=job)

        stages: list[StageResult] = []
        for ev in self._db.load_events(job_id):
            try:
                data = json.loads(ev["data_json"])
            except (TypeError, ValueError):
                data = {}
            snap.events.append(
                StageEvent(type=ev["type"], job_id=job_id, ts=ev["ts"], data=data)  # type: ignore[arg-type]
            )
            if ev["type"] == "stage_done":
                stages.append(
                    StageResult(
                        stage=str(data.get("stage", "?")),
                        ok=bool(data.get("ok")),
                        metrics=dict(data.get("metrics") or {}),
                        error=str(data["error"]) if data.get("error") else None,
                    )
                )
            elif ev["type"] == "error":
                stages.append(
                    StageResult(
                        stage=str(data.get("stage", "extraction")),
                        ok=False,
                        error=str(data.get("error", "unknown error")),
                    )
                )
        snap.stages = stages

        for fr in self._db.load_findings(job_id):
            try:
                snap.findings.append(_finding_from_public(json.loads(fr["finding_json"])))
            except (TypeError, ValueError, KeyError):
                continue  # tolerate a corrupt row; the audit stays readable

        snap.ended = (
            job.status in (JobStatus.done, JobStatus.failed)
            and any(e.type in ("verdict", "error") for e in snap.events)
        )
        self._jobs[job_id] = snap
        return snap

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
        if self._db is not None:
            finding_payload = (
                event.data.get("finding")
                if event.type == "finding"
                else None
            )
            try:
                self._db.record_event(
                    job_id, event.ts, event.type, event.data,
                    finding=finding_payload,
                )
            except Exception:  # noqa: BLE001 - persistence must not kill a job
                pass
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
        if self._db is not None and snap is not None:
            verdict = None
            for e in reversed(snap.events):
                if e.type == "verdict":
                    verdict = e.data.get("verdict")
                    break
            self._persist_status(
                snap.job,
                finished_at=datetime.now(timezone.utc).isoformat(),
                verdict=verdict,
            )
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
        from fugu.server.giturls import extract_git_parts

        loop = asyncio.get_running_loop()
        parts = extract_git_parts(source)
        if parts is not None:
            # Pasted web-UI URL (tree/blob view): clone the REPO at the ref,
            # then audit the subdirectory the URL pointed at.
            base, ref, subpath = parts
            attempts: list[tuple[str, str]] = [(ref, subpath)]
            # Refs may contain slashes ("release/1.2"): if the single-segment
            # ref misses, retry consuming one more segment into the ref.
            if subpath and "/" in subpath:
                head, _, tail = subpath.partition("/")
                attempts.append((f"{ref}/{head}" if ref else head, tail))
            last_err: ExtractionError | None = None
            for clone_ref, clone_sub in attempts:
                tmp = await loop.run_in_executor(
                    None, lambda: tempfile.mkdtemp(prefix="fugu-git-")
                )
                root = Path(tmp) / "clone"
                try:
                    await _git_clone(base, root, branch=clone_ref or None)
                    audit_dir = _resolve_audit_subdir(
                        root, clone_sub, source_display=source
                    )
                    # Re-parent the audit dir to the tmp root so the caller's
                    # single rmtree(target) contract keeps working.
                    if audit_dir == root:
                        return root
                    final = Path(tmp) / "src"
                    await loop.run_in_executor(
                        None, shutil.move, str(audit_dir), str(final)
                    )
                    await loop.run_in_executor(
                        None, shutil.rmtree, str(root), True
                    )
                    return final
                except ExtractionError as exc:
                    last_err = exc
                    await loop.run_in_executor(None, shutil.rmtree, tmp, True)
                    continue
            raise last_err or ExtractionError(f"git clone failed: {source}")

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


async def _git_clone(source: str, target: Path, branch: str | None = None) -> None:
    """Clone `source` (depth 1, optionally pinned to `branch`) into `target`."""
    cmd = ["git", "clone", "--quiet"]
    if branch:
        # --branch also accepts tags & commit ids; --depth keeps it shallow.
        cmd += ["--branch", branch]
    cmd += ["--depth", "1", source, str(target)]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        detail = (stderr or b"").decode(errors="replace").strip()
        raise ExtractionError(
            f"git clone failed (exit {proc.returncode}): {detail[:500]}"
        )


def _resolve_audit_subdir(root: Path, subpath: str, *, source_display: str) -> Path:
    """Resolve the URL's subpath inside the freshly cloned repo.

    Raises ExtractionError with an actionable message when the path doesn't
    exist (e.g. the pasted URL's ref was misparsed) — the caller retries or
    surfaces the error to the user.
    """
    sub = (subpath or "").strip().strip("/")
    if not sub:
        return root
    cand = (root / sub).resolve()
    if not cand.is_relative_to(root.resolve()):
        raise ExtractionError(
            f"git source subpath escapes the repository: {source_display}"
        )
    if not cand.exists():
        raise ExtractionError(
            f"cloned repository has no '{sub}' path (from {source_display})"
        )
    return cand


# --- Runner ------------------------------------------------------------------------

async def run_stage_loop(
    job: AuditJob,
    snap: Any,
    target: Path,
    stages: Iterable[Any],
    store: JobStore,
) -> None:
    """Run `stages` sequentially against `target`, publishing SSE events.

    Extracted from run_job so the auto fan-out runner can drive a
    single-source audit over an already-materialized target. Closes the
    stream (verdict event + status done) exactly like run_job.
    """
    loop = asyncio.get_running_loop()
    for stage in stages:
        name = getattr(stage, "name", type(stage).__name__)
        # Per-stage progress narration: stages may accept on_progress(msg) and
        # emit human-readable log lines mid-run (chamber builds, per-trigger
        # execution...). Wired per-stage before the run so it reaches the SSE
        # stream and the persisted event history (resume replays it too).
        def _stage_progress(msg: str, _stage_name: str = name) -> None:
            _emit(store, job, "log", {"stage": _stage_name, "message": msg})
        if hasattr(stage, "_on_progress"):
            try:
                stage._on_progress = _stage_progress
            except Exception:  # noqa: BLE001
                pass
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
        # Cross-stage dedup: a weaker (advisory/measured) finding whose
        # high-specificity evidence token (URL/command/file) is already
        # covered by an earlier stronger finding is a redundant echo — drop
        # it before it reaches the stream/verdict. Deterministic/empirical
        # findings are never dropped (different rules = different evidence).
        from fugu.dedupe import dedupe_findings
        before = len(snap.findings)
        snap.findings.extend(result.findings)
        deduped = dedupe_findings(snap.findings)
        survivors = deduped[before:]  # this stage's findings that survived
        dropped_echoes = len(result.findings) - len(survivors)
        snap.findings = deduped if len(deduped) < len(snap.findings) else snap.findings
        if dropped_echoes:
            _emit(store, job, "log", {
                "stage": name,
                "message": f"dedup: dropped {dropped_echoes} subsumed echo(es) of stronger findings",
            })
        for finding in survivors:
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

    from fugu.verdict import aggregate_verdict

    verdict = aggregate_verdict(snap.findings, snap.stages)
    _emit(store, job, "verdict", {
        "status": "done",
        "verdict": verdict,
        "total_findings": verdict["total_findings"],
        "severity_counts": verdict["severity_counts"],
        "stages": [stage_public(r) for r in snap.stages],
    })
    job.status = JobStatus.done
    store.close(job.id)


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
    store._persist_status(job)

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

    await run_stage_loop(job, snap, target, stages, store)

    if cloned_dir is not None and not keep_target:
        # keep_target=True: caller (e.g. run_composition_job harvesting tool
        # names from the extracted tree) owns the clone's lifetime now.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, shutil.rmtree, cloned_dir, True)


# --- Skill-unit discovery (auto fan-out) ---------------------------------------------

#: vendored/dependency trees that never constitute skill units
_VENDOR_DIRS = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", "vendor", "site-packages"}
)


def find_skill_units(target: Path) -> list[tuple[str, Path]]:
    """Skill-unit discovery for the auto fan-out path.

    A skill *unit* is a directory that DIRECTLY contains a SKILL.md — the
    packaging unit agents actually install. Only units strictly below the
    root count: a root-level SKILL.md means the repo IS one skill (an
    ordinary single-source audit, decided by the caller). Vendored trees
    (node_modules, .venv, ...) are skipped. Deterministic order (sorted
    by path). Returns [(label, dir)] where label is the unit's directory
    name.
    """
    root = Path(target)
    hits: list[Path] = []
    for skill_md in root.rglob("SKILL.md"):
        rel = skill_md.parent.relative_to(root)
        if not rel.parts:  # root-level SKILL.md: repo is a single skill
            continue
        if any(part in _VENDOR_DIRS for part in rel.parts):
            continue
        hits.append(skill_md.parent)
    # deterministic order: by full relative path (depth-first, alphabetical)
    hits.sort(key=lambda d: d.relative_to(root).as_posix())
    return [(d.relative_to(root).parts[-1], d) for d in hits]


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


def _finding_from_public(d: dict[str, Any]) -> Finding:
    """Rebuild a Finding from finding_public() output (restart recovery)."""
    return Finding(
        owasp_ids=[str(i) for i in d.get("owasp_ids", [])],
        title=str(d.get("title", "")),
        detail=str(d.get("detail", "")),
        severity=d.get("severity", "info"),  # type: ignore[arg-type]
        confidence=d.get("confidence", "advisory"),  # type: ignore[arg-type]
        stage=str(d.get("stage", "?")),
        evidence=[
            EvidenceSnippet(
                source=str(e.get("source", "")),
                excerpt=str(e.get("excerpt", "")),
                meta=dict(e.get("meta") or {}),
            )
            for e in d.get("evidence", [])
        ],
    )


def new_job_id() -> str:
    return uuid.uuid4().hex[:12]
