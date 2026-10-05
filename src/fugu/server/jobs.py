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
Source extraction creates an owned regular-file snapshot from local paths or
a shallow Git clone, so POST /audits stays thin.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from fugu.config import DEFAULT_PRODUCTION_LIMITS
from fugu.store.sqlite import SqliteJobStore
from fugu.source_safety import (
    SourceLinkTarget,
    SourceSafetyError,
    inspect_source_tree,
)
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

DEFAULT_MAX_BYTES = DEFAULT_PRODUCTION_LIMITS.source_max_bytes
DEFAULT_MAX_FILES = DEFAULT_PRODUCTION_LIMITS.source_max_entries
DEFAULT_GIT_CLONE_TIMEOUT_SECONDS = DEFAULT_PRODUCTION_LIMITS.git_clone_timeout_seconds
_GIT_CLONE_TIMEOUT_DRAIN_SECONDS = 0.1
_GIT_CLONE_TIMEOUT_WAIT_SECONDS = 0.1


class ExtractionError(Exception):
    """Source validation / extraction failed (maps to HTTP 422)."""


async def _materialize_owned_snapshot(
    loop: asyncio.AbstractEventLoop, copy_snapshot: Any
) -> Path:
    """Transfer the snapshot to the caller or reclaim it if cancellation wins."""
    cancellation_requested = threading.Event()

    def copy_or_reclaim() -> Path | None:
        if cancellation_requested.is_set():
            return None
        snapshot = copy_snapshot()
        if cancellation_requested.is_set():
            shutil.rmtree(snapshot, ignore_errors=True)
            return None
        return snapshot

    future = loop.run_in_executor(None, copy_or_reclaim)
    try:
        snapshot = await asyncio.shield(future)
    except asyncio.CancelledError:
        cancellation_requested.set()

        def reclaim_unclaimed(completed: asyncio.Future[Path | None]) -> None:
            try:
                unclaimed = completed.result()
            except BaseException:
                return
            if unclaimed is None:
                return
            try:
                cleanup = loop.run_in_executor(None, shutil.rmtree, unclaimed, True)
            except RuntimeError:  # loop/executor shutdown; best-effort final cleanup
                shutil.rmtree(unclaimed, ignore_errors=True)
                return
            cleanup.add_done_callback(_consume_task_outcome)

        # Shield preserves the executor result after caller cancellation. The
        # worker checks the signal before returning; this callback covers the
        # race where cancellation arrives after that check but before handoff.
        future.add_done_callback(reclaim_unclaimed)
        raise

    if snapshot is None:  # pragma: no cover - only cancellation sets the signal
        raise RuntimeError("snapshot materialization was cancelled before handoff")
    return snapshot


def _validate_source(target: Path) -> tuple[Path, dict[str, SourceLinkTarget]]:
    """Inspect an intake tree and return its authorized anchor and safe links."""
    try:
        return inspect_source_tree(target)
    except (SourceSafetyError, OSError) as exc:
        raise ExtractionError(str(exc)) from exc


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
    git_timeout_s: float = DEFAULT_GIT_CLONE_TIMEOUT_SECONDS,
    link_provenance: list[dict[str, str | int]] | None = None,
) -> Path:
    """Materialize the audited source into an owned regular-file snapshot.

    The explicit local root may be a symlink. Descendant links are inspected
    against the resolved root; only direct links to in-root regular files are
    accepted, and their contents are copied into regular files before any
    pipeline reader sees the snapshot. Relative references are resolved against
    the complete Git clone before a selected subdirectory is copied. Materialized
    entry/byte limits include each duplicate link copy.

    Git clone directories and returned snapshots are caller-owned cleanup
    obligations. ``keep_target`` remains a compatibility hint for the runner;
    successful extraction always returns an owned snapshot. Accepted link
    provenance is appended to ``link_provenance`` when supplied.

    Raises ExtractionError on any validation, limit, or clone failure.
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
            # then select from its fully inspected root.
            base, ref, subpath = parts
            attempts: list[tuple[str, str]] = [(ref, subpath)]
            if subpath and "/" in subpath and not any(
                part in (".", "..") for part in subpath.split("/")
            ):
                head, _, tail = subpath.partition("/")
                attempts.append((f"{ref}/{head}" if ref else head, tail))
            last_err: ExtractionError | None = None
            for clone_ref, clone_sub in attempts:
                tmp = await loop.run_in_executor(
                    None, lambda: tempfile.mkdtemp(prefix="fugu-git-")
                )
                root = Path(tmp) / "clone"
                try:
                    await _git_clone(
                        base, root, branch=clone_ref or None, timeout_s=git_timeout_s
                    )
                    anchor, links = _validate_source(root)
                    audit_path = _resolve_audit_subdir(
                        anchor, clone_sub, source_display=source
                    )
                    return await _materialize_owned_snapshot(
                        loop,
                        lambda: _materialize_git_selection(
                            audit_path,
                            anchor=anchor,
                            link_targets=links,
                            max_files=max_files,
                            max_bytes=max_bytes,
                            link_provenance=link_provenance,
                        ),
                    )
                except (ExtractionError, OSError) as exc:
                    last_err = (
                        exc if isinstance(exc, ExtractionError)
                        else ExtractionError(f"source materialization failed: {exc}")
                    )
                    continue
                finally:
                    await loop.run_in_executor(None, shutil.rmtree, tmp, True)
            raise last_err or ExtractionError(f"git clone failed: {source}")

        tmp = await loop.run_in_executor(
            None, lambda: tempfile.mkdtemp(prefix="fugu-git-")
        )
        root = Path(tmp) / "clone"
        try:
            await _git_clone(source, root, timeout_s=git_timeout_s)
            anchor, links = _validate_source(root)
            return await _materialize_owned_snapshot(
                loop,
                lambda: _materialize_git_selection(
                    anchor,
                    anchor=anchor,
                    link_targets=links,
                    max_files=max_files,
                    max_bytes=max_bytes,
                    link_provenance=link_provenance,
                ),
            )
        except ExtractionError:
            raise
        except OSError as exc:
            raise ExtractionError(f"source extraction failed: {exc}") from exc
        finally:
            await loop.run_in_executor(None, shutil.rmtree, tmp, True)

    # --- local path ------------------------------------------------------------
    p = Path(source).expanduser()
    if not p.exists():
        raise ExtractionError(f"local source path does not exist: {source}")
    if not p.is_dir():
        raise ExtractionError(f"local source path is not a directory: {source}")
    anchor, links = _validate_source(p)
    try:
        if not any(anchor.iterdir()):
            raise ExtractionError(f"local source directory is empty: {source}")
    except PermissionError as exc:
        raise ExtractionError(f"local source not readable: {source} ({exc})") from exc

    loop = asyncio.get_running_loop()
    return await _materialize_owned_snapshot(
        loop,
        lambda: _materialize_git_selection(
            anchor,
            anchor=anchor,
            link_targets=links,
            max_files=max_files,
            max_bytes=max_bytes,
            link_provenance=link_provenance,
        ),
    )


def _enforce_source_limits(root: Path, *, max_files: int, max_bytes: int) -> None:
    """Apply the local source entry/byte limits to a materialized tree."""
    n_entries = 0
    n_bytes = 0
    for path in root.rglob("*"):
        n_entries += 1
        if n_entries > max_files:
            raise ExtractionError(f"source has too many files/entries (> {max_files})")
        try:
            if path.is_file():
                n_bytes += path.stat().st_size
        except OSError:
            pass  # broken symlink / race: ignore as in the local-path walk
        if n_bytes > max_bytes:
            raise ExtractionError(f"source is too large (> {max_bytes} bytes)")


@dataclass
class _MaterializationBudget:
    entries: int = 0
    bytes: int = 0

    def add_entry(self, max_files: int) -> None:
        self.entries += 1
        if self.entries > max_files:
            raise ExtractionError(f"source has too many files/entries (> {max_files})")


def _copy_regular_file(
    source: Path,
    destination: Path,
    *,
    budget: _MaterializationBudget,
    max_files: int,
    max_bytes: int,
    source_link: SourceLinkTarget | None = None,
) -> dict[str, str | int] | None:
    budget.add_entry(max_files)
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(source, flags)
    except OSError as exc:
        raise ExtractionError("source changed during materialization; retry intake") from exc

    try:
        source_stat = os.fstat(fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ExtractionError("source link target is no longer a regular file")
        if budget.bytes + source_stat.st_size > max_bytes:
            raise ExtractionError(f"source is too large (> {max_bytes} bytes)")
        digest = hashlib.sha256() if source_link is not None else None
        copied = 0
        source_file = os.fdopen(fd, "rb")
        fd = -1
        try:
            with source_file, destination.open("xb") as output:
                while block := source_file.read(1024 * 1024):
                    copied += len(block)
                    if budget.bytes + copied > max_bytes:
                        raise ExtractionError(f"source is too large (> {max_bytes} bytes)")
                    output.write(block)
                    if digest is not None:
                        digest.update(block)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        budget.bytes += copied
        os.chmod(destination, stat.S_IMODE(source_stat.st_mode))
    finally:
        if fd >= 0:
            os.close(fd)

    if source_link is None:
        return None
    return {
        "link_path": source_link.link_path,
        "link_target": source_link.link_target,
        "resolved_path": source_link.resolved_repo_path,
        "sha256": digest.hexdigest() if digest is not None else "",
        "size_bytes": copied,
    }


def _copy_directory_contents(
    source: Path,
    destination: Path,
    *,
    anchor: Path,
    link_targets: dict[str, SourceLinkTarget],
    budget: _MaterializationBudget,
    max_files: int,
    max_bytes: int,
    link_records: list[dict[str, str | int]],
) -> None:
    try:
        entries = sorted(os.scandir(source), key=lambda item: item.name)
    except OSError as exc:
        raise ExtractionError("source tree cannot be read safely") from exc

    for entry in entries:
        original = Path(entry.path)
        output = destination / entry.name
        try:
            if entry.is_symlink():
                rel = original.relative_to(anchor).as_posix()
                source_link = link_targets.get(rel)
                if source_link is None:
                    raise ExtractionError(f"source link changed during materialization: {rel}")
                record = _copy_regular_file(
                    source_link.resolved_path,
                    output,
                    budget=budget,
                    max_files=max_files,
                    max_bytes=max_bytes,
                    source_link=source_link,
                )
                if record is not None:
                    link_records.append(record)
            elif entry.is_dir(follow_symlinks=False):
                budget.add_entry(max_files)
                output.mkdir()
                _copy_directory_contents(
                    original,
                    output,
                    anchor=anchor,
                    link_targets=link_targets,
                    budget=budget,
                    max_files=max_files,
                    max_bytes=max_bytes,
                    link_records=link_records,
                )
                os.chmod(output, stat.S_IMODE(os.stat(original, follow_symlinks=False).st_mode))
            elif entry.is_file(follow_symlinks=False):
                _copy_regular_file(
                    original,
                    output,
                    budget=budget,
                    max_files=max_files,
                    max_bytes=max_bytes,
                )
            else:
                rel = original.relative_to(anchor).as_posix()
                raise ExtractionError(f"source contains unsupported special file '{rel}'")
        except OSError as exc:
            raise ExtractionError("source tree changed during materialization; retry intake") from exc


def _materialize_git_selection(
    selected: Path,
    *,
    anchor: Path,
    link_targets: dict[str, SourceLinkTarget],
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    link_provenance: list[dict[str, str | int]] | None = None,
) -> Path:
    """Copy the selected view into an owned, bounded, link-free directory."""
    target = Path(tempfile.mkdtemp(prefix="fugu-source-"))
    budget = _MaterializationBudget()
    records: list[dict[str, str | int]] = []
    try:
        selected = Path(selected)
        anchor = Path(anchor)
        try:
            selected_rel = selected.relative_to(anchor).as_posix()
            selected_stat = os.lstat(selected)
        except (OSError, ValueError) as exc:
            raise ExtractionError("selected source is outside the authorized repository") from exc

        if stat.S_ISLNK(selected_stat.st_mode):
            source_link = link_targets.get(selected_rel)
            if source_link is None:
                raise ExtractionError(f"selected source link changed during materialization: {selected_rel}")
            record = _copy_regular_file(
                source_link.resolved_path,
                target / selected.name,
                budget=budget,
                max_files=max_files,
                max_bytes=max_bytes,
                source_link=source_link,
            )
            if record is not None:
                records.append(record)
        elif stat.S_ISREG(selected_stat.st_mode):
            _copy_regular_file(
                selected,
                target / selected.name,
                budget=budget,
                max_files=max_files,
                max_bytes=max_bytes,
            )
        elif stat.S_ISDIR(selected_stat.st_mode):
            _copy_directory_contents(
                selected,
                target,
                anchor=anchor,
                link_targets=link_targets,
                budget=budget,
                max_files=max_files,
                max_bytes=max_bytes,
                link_records=records,
            )
        else:
            raise ExtractionError("selected git source is not a regular file or directory")

        # Recheck the concrete output so caps cover the resulting tree, including
        # every duplicate file created from an accepted internal link.
        _enforce_source_limits(target, max_files=max_files, max_bytes=max_bytes)
        if link_provenance is not None:
            link_provenance.extend(records)
        return target
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise


async def _git_clone(
    source: str,
    target: Path,
    branch: str | None = None,
    *,
    timeout_s: float = DEFAULT_GIT_CLONE_TIMEOUT_SECONDS,
) -> None:
    """Clone `source` into `target` with one bounded subprocess attempt."""
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
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:  # process exited at the timeout boundary
            pass
        try:
            drained = await _bounded_process_cleanup(
                proc.communicate(), _GIT_CLONE_TIMEOUT_DRAIN_SECONDS
            )
        finally:
            _close_subprocess_transport(proc)
        if not drained:
            await _bounded_process_cleanup(
                proc.wait(), _GIT_CLONE_TIMEOUT_WAIT_SECONDS
            )
        raise ExtractionError(f"git clone timed out after {timeout_s:g} seconds") from None
    if proc.returncode != 0:
        detail = (stderr or b"").decode(errors="replace").strip()
        raise ExtractionError(
            f"git clone failed (exit {proc.returncode}): {detail[:500]}"
        )


async def _bounded_process_cleanup(awaitable: Any, timeout_s: float) -> bool:
    """Run one cleanup awaitable without extending clone timeout indefinitely."""
    task = asyncio.create_task(awaitable)
    try:
        done, _ = await asyncio.wait({task}, timeout=timeout_s)
        if task not in done:
            return False
        try:
            task.result()
        except Exception:  # noqa: BLE001 - cleanup is best effort after timeout
            return False
        except asyncio.CancelledError:
            return False
        return True
    finally:
        if not task.done():
            task.cancel()
            task.add_done_callback(_consume_task_outcome)


def _consume_task_outcome(task: asyncio.Task[Any]) -> None:
    """Retrieve a late cleanup-task exception without awaiting it indefinitely."""
    try:
        task.exception()
    except asyncio.CancelledError:
        pass


def _close_subprocess_transport(proc: Any) -> None:
    """Close owned subprocess pipes after a timed-out drain attempt.

    asyncio.Process has no public close method; its SubprocessTransport owns
    the stdout/stderr pipes and closes them when closed.
    """
    transport = getattr(proc, "_transport", None)
    close = getattr(transport, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001 - preserve the timeout error
            pass


def _resolve_audit_subdir(root: Path, subpath: str, *, source_display: str) -> Path:
    """Select a lexical path under the clone without dereferencing file links."""
    sub = (subpath or "").strip().strip("/")
    if not sub:
        return root
    cand = Path(os.path.abspath(os.path.normpath(os.fspath(root / sub))))
    if not cand.is_relative_to(root):
        raise ExtractionError(
            f"git source subpath escapes the repository: {source_display}"
        )
    if not os.path.lexists(cand):
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
        link_provenance: list[dict[str, str | int]] = []
        target = await extract_source(
            job,
            max_files=max_files,
            max_bytes=max_bytes,
            keep_target=keep_target,
            link_provenance=link_provenance,
        )
        snap.target_dir = target
        if link_provenance:
            _emit(
                store,
                job,
                "log",
                {
                    "stage": "extraction",
                    "message": f"materialized {len(link_provenance)} internal file link(s)",
                    "source_links": link_provenance,
                },
            )
        if target != Path(job.source.strip()).expanduser():
            cloned_dir = target  # owned snapshot; clean up after the stage loop
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

    completed = False
    try:
        await run_stage_loop(job, snap, target, stages, store)
        completed = True
    finally:
        if cloned_dir is not None and (not keep_target or not completed):
            # Successful keep_target callers harvest then reclaim the target.
            # A runner exception must not strand files even with keep_target.
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
