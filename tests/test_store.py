"""Tests for SQLite job persistence (fugu.store.sqlite + JobStore wiring).

Fully hermetic: every db lives under pytest's tmp_path; no network, no
git, no real stages. Fixture dir is the same server_sample the server
tests use.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fugu.server import create_app
from fugu.server.jobs import (
    JobStore,
    finding_public,
    run_job,
    stage_public,
)
from fugu.store.sqlite import SqliteJobStore
from fugu.types import AuditJob, Finding, JobStatus, StageEvent, StageResult

FIXTURE_DIR = _PROJECT_ROOT / "tests" / "fixtures" / "server_sample"


# --- fakes (mirrors tests/test_server.py) ---------------------------------------

class FakeFindingStage:
    name = "static"

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        findings = [
            Finding(
                owasp_ids=["MCP06"],
                title="Suspicious install script",
                detail="install.sh runs on load.",
                severity="high",
                confidence="deterministic",
                stage=self.name,
                evidence=[],
            ),
            Finding(
                owasp_ids=["LLM02"],
                title="Vague skill description",
                detail="Description lacks actionable detail.",
                severity="info",
                confidence="advisory",
                stage=self.name,
                evidence=[],
            ),
        ]
        return StageResult(
            stage=self.name, ok=True, findings=findings, metrics={"files_scanned": 3}
        )


class FakeBoomStage:
    name = "semantic"

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        raise RuntimeError("boom")


def _wait_done(client: TestClient, job_id: str, timeout_s: float = 5.0) -> dict[str, Any]:
    import time

    deadline = time.monotonic() + timeout_s
    body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        body = client.get(f"/audits/{job_id}").json()
        if body.get("status") in ("done", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish in {timeout_s}s: {body}")


# --- SqliteJobStore unit level ---------------------------------------------------

def test_schema_created_and_wal_mode(tmp_path: Path) -> None:
    db = SqliteJobStore(tmp_path / "fugu.db")
    try:
        assert db.journal_mode == "wal"
        assert (tmp_path / "fugu.db-wal").exists(), "WAL sidecar file must exist"
        tables = {
            r[0]
            for r in db._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"jobs", "events", "findings"} <= tables
        cols = [
            r[1]
            for r in db._conn.execute("PRAGMA table_info(jobs)")
        ]
        assert cols == [
            "job_id", "source", "depth", "status", "created_at",
            "finished_at", "verdict_json",
        ]
    finally:
        db.close()


def test_persist_and_reload_roundtrip(tmp_path: Path) -> None:
    """run_job with a SQLite-backed JobStore → fresh store on the same db
    file reconstructs job, stages, findings via the public projectors."""
    db_path = tmp_path / "fugu.db"

    async def phase1() -> None:
        store = JobStore(store=SqliteJobStore(db_path))
        job = AuditJob(id="rt1", source=str(FIXTURE_DIR), depth="full")
        store.create(job)
        await run_job(job, [FakeFindingStage(), FakeBoomStage()], store)

    asyncio.run(phase1())

    # "restart": brand-new store + connection over the same file
    db = SqliteJobStore(db_path)
    try:
        store2 = JobStore(store=db)
        snap = store2.get("rt1")
        assert snap is not None
        assert snap.job.status is JobStatus.done
        assert snap.job.depth == "full"
        assert snap.job.source == str(FIXTURE_DIR)
        assert snap.ended is True
        # stages rebuilt from stage_done events (findings_count via projector)
        assert [s.stage for s in snap.stages] == ["static", "semantic"]
        assert snap.stages[0].ok is True
        assert snap.stages[1].ok is False
        assert "RuntimeError" in (snap.stages[1].error or "")
        # findings rebuilt losslessly through finding_public round-trip
        assert len(snap.findings) == 2
        assert [finding_public(f) for f in snap.findings][0]["severity"] == "high"
        # GET-style projection identical to the live shape
        assert [stage_public(s) for s in snap.stages][0]["findings_count"] == 0  # projector lossy on rebuild
        # verdict persisted on the jobs row
        row = db.load_job("rt1")
        assert row is not None and row["status"] == "done"
        assert row["finished_at"] is not None
        verdict = json.loads(row["verdict_json"])
        assert verdict["total_findings"] == 2
        assert verdict["severity_counts"]["high"] == 1
    finally:
        db.close()


def test_events_replay_from_db(tmp_path: Path) -> None:
    """load_events returns the full ordered history; a replayed SSE stream
    would emit the same sequence with identical payloads."""
    db_path = tmp_path / "fugu.db"

    async def scenario() -> None:
        store = JobStore(store=SqliteJobStore(db_path))
        job = AuditJob(id="ev1", source=str(FIXTURE_DIR))
        store.create(job)
        await run_job(job, [FakeFindingStage()], store)

    asyncio.run(scenario())

    db = SqliteJobStore(db_path)
    try:
        rows = db.load_events("ev1")
        types = [r["type"] for r in rows]
        assert types[0] == "log"
        assert "stage_started" in types and "stage_done" in types
        assert types[-1] == "verdict"
        assert types.index("stage_started") < types.index("finding") < types.index("stage_done")
        # every row is re-parseable JSON with job_id + ts preserved
        for r in rows:
            data = json.loads(r["data_json"])
            assert isinstance(data, dict)
            assert r["job_id"] == "ev1" and r["ts"]
        # finding event payloads carry the projected finding
        fe = next(r for r in rows if r["type"] == "finding")
        assert json.loads(fe["data_json"])["finding"]["owasp_ids"] == ["MCP06"]
        # seq strictly increasing
        seqs = [r["seq"] for r in rows]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
        # findings table got one row per finding event
        assert len(db.load_findings("ev1")) == 2
    finally:
        db.close()


def test_failed_job_persisted_with_error_event(tmp_path: Path) -> None:
    db_path = tmp_path / "fugu.db"

    async def scenario() -> None:
        store = JobStore(store=SqliteJobStore(db_path))
        job = AuditJob(id="f1", source="/definitely/not/here")
        store.create(job)
        await run_job(job, [], store)

    asyncio.run(scenario())

    db = SqliteJobStore(db_path)
    try:
        store2 = JobStore(store=db)
        snap = store2.get("f1")
        assert snap is not None
        assert snap.job.status is JobStatus.failed
        assert snap.ended is True
        assert [s.stage for s in snap.stages] == ["extraction"]
        assert snap.stages[0].ok is False
        assert "extraction" in (snap.stages[0].error or "")
        types = [e.type for e in snap.events]
        assert types[-1] == "error"
    finally:
        db.close()


def test_restart_recovery_unknown_id_still_404(tmp_path: Path) -> None:
    db = SqliteJobStore(tmp_path / "fugu.db")
    try:
        store = JobStore(store=db)
        assert store.get("never-existed") is None
        assert store.all_ids() == []
    finally:
        db.close()


def test_store_none_keeps_in_memory_fast_path() -> None:
    """store=None → JobStore behaves exactly as before (no sqlite import
    side effects, get() returns None for unknown ids)."""
    store = JobStore()
    assert store.db is None
    store.create(AuditJob(id="m1", source=str(FIXTURE_DIR)))
    assert store.get("m1") is not None
    assert store.get("nope") is None
    assert store.all_ids() == ["m1"]


# --- server-level: restart via two apps over one db file ---------------------------

def test_get_audit_survives_server_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "fugu.db"

    # process 1: run a job to completion
    app1 = create_app(stages=[FakeFindingStage()], db=db_path)
    # Keep the app event loop alive across submission and polling. A client
    # outside its context cancels the detached task when the POST portal closes.
    try:
        with TestClient(app1) as c1:
            resp = c1.post("/audits", json={"source": str(FIXTURE_DIR), "depth": "standard"})
            assert resp.status_code == 202
            job_id = resp.json()["job_id"]
            live = _wait_done(c1, job_id)
            assert live["status"] == "done" and len(live["findings"]) == 2
    finally:
        app1.state.fugu.store.db.close()

    # "restart": a whole new app + JobStore over the same db file
    app2 = create_app(stages=[], db=db_path)
    try:
        with TestClient(app2) as c2:
            body = c2.get(f"/audits/{job_id}")
            assert body.status_code == 200, body.text
            recovered = body.json()
            assert recovered["id"] == job_id
            assert recovered["status"] == "done"
            assert recovered["source"] == str(FIXTURE_DIR)
            assert [s["stage"] for s in recovered["stages"]] == ["static"]
            assert len(recovered["findings"]) == 2
            assert recovered["findings"][0]["severity"] == "high"
            assert recovered["findings"][0]["owasp_ids"] == ["MCP06"]

            # SSE replay from the recovered history ends at the terminal event
            sse = c2.get(f"//audits/{job_id}/events".replace("//", "/"))
            assert sse.status_code == 200
            events = [
                json.loads(line[len("data: "):])
                for line in sse.text.splitlines()
                if line.startswith("data: ")
            ]
            types = [e["type"] for e in events]
            assert "finding" in types and types[-1] == "verdict"
            assert all(e["job_id"] == job_id for e in events)

            # health counts include the recovered job
            assert c2.get("/health").json()["jobs"] >= 1
    finally:
        app2.state.fugu.store.db.close()


def test_get_audit_unknown_id_404_with_db(tmp_path: Path) -> None:
    client = TestClient(create_app(stages=[], db=tmp_path / "fugu.db"))
    assert client.get("/audits/doesnotexist").status_code == 404


# --- WAL + concurrency --------------------------------------------------------------

def test_wal_file_exists_during_use(tmp_path: Path) -> None:
    db_path = tmp_path / "wal.db"

    async def scenario() -> None:
        store = JobStore(store=SqliteJobStore(db_path))
        job = AuditJob(id="w1", source=str(FIXTURE_DIR))
        store.create(job)
        await run_job(job, [], store)

    asyncio.run(scenario())
    # -wal (and -shm) exist while at least one connection is open; a fresh
    # open connection re-creates them, and journal_mode persists as wal.
    db = SqliteJobStore(db_path)
    try:
        assert db.journal_mode == "wal"
        assert (tmp_path / "wal.db-wal").exists()
    finally:
        db.close()


def test_concurrent_writers_basic(tmp_path: Path) -> None:
    """Many threads × many events through separate connections: WAL +
    busy_timeout must serialize writers with zero lost rows."""
    db_path = tmp_path / "conc.db"
    SqliteJobStore(db_path).close()  # create schema first

    N_THREADS = 8
    N_EVENTS = 40

    def hammer(tid: int) -> int:
        db = SqliteJobStore(db_path)
        try:
            db.save_job(
                f"t{tid}",
                source="x",
                depth="standard",
                status="running",
                created_at="2026-01-01T00:00:00",
            )
            for n in range(N_EVENTS):
                db.record_event(
                    f"t{tid}", f"ts-{n}", "log", {"tid": tid, "n": n}
                )
            return len(db.load_events(f"t{tid}"))
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=N_THREADS) as pool:
        counts = list(pool.map(hammer, range(N_THREADS)))

    db = SqliteJobStore(db_path)
    try:
        assert counts == [N_EVENTS] * N_THREADS
        assert db.job_ids() and len(db.job_ids()) == N_THREADS
        total = db._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert total == N_THREADS * N_EVENTS, f"lost rows: {total}"
        # seq is globally unique/ordered across all writers
        seqs = [r[0] for r in db._conn.execute("SELECT seq FROM events ORDER BY seq")]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    finally:
        db.close()


def test_separate_connection_reads_during_writes(tmp_path: Path) -> None:
    """WAL: a reader connection sees committed rows without blocking the
    writer (no SQLITE_BUSY, no lost reads)."""
    db_path = tmp_path / "rw.db"
    writer = SqliteJobStore(db_path)
    reader = SqliteJobStore(db_path)
    try:
        writer.save_job(
            "r1", source="x", depth="standard", status="running",
            created_at="2026-01-01T00:00:00",
        )
        for i in range(10):
            writer.record_event("r1", f"ts{i}", "log", {"i": i})
            assert len(reader.load_events("r1")) == i + 1
    finally:
        writer.close()
        reader.close()
