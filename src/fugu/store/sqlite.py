"""SQLite persistence for Fugu audit jobs (stdlib sqlite3, no ORM).

Schema (CREATE IF NOT EXISTS is the whole migration story for now):
    jobs(job_id PK, source, depth, status, created_at, finished_at, verdict_json)
    events(seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id, ts, type, data_json)
    findings(job_id, seq, finding_json)          -- PK (job_id, seq)

Design notes:
- One connection per store instance, check_same_thread=False + an RLock:
  every method is one short transaction, so in-process cross-thread use
  is serialized by the lock; busy_timeout rides out writers from OTHER
  connections (WAL allows concurrent readers + one writer).
- WAL + synchronous=NORMAL: readers never block the writer, and a crash
  costs at most the last un-committed event — no corruption. Audit runs
  tolerate a lost tail; they do not tolerate a stuck server.
- The JobStore calls into this synchronously from the event loop. Writes
  are single-row inserts (sub-millisecond under WAL), which is cheaper
  than an executor hop per event; see caveats in the workstream summary.
- Reconstruction of a JobSnapshot after restart lives in jobs.py
  (JobStore._recover); this module deliberately speaks rows/JSON only.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

__all__ = ["SqliteJobStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id      TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    depth       TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    finished_at TEXT,
    verdict_json TEXT
);
CREATE TABLE IF NOT EXISTS events (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id    TEXT NOT NULL,
    ts        TEXT NOT NULL,
    type      TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_job ON events (job_id, seq);
CREATE TABLE IF NOT EXISTS findings (
    job_id       TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    finding_json TEXT NOT NULL,
    PRIMARY KEY (job_id, seq)
);
"""

SCHEMA_VERSION = 1


class SqliteJobStore:
    """Durable jobs/events/findings store; thread-safe within the process.

    Duck-typed consumer: ``JobStore(store=SqliteJobStore(path))`` calls
    save_job / record_event / load_job / load_events / load_findings /
    job_ids. Nothing here imports fugu.server (keeps the dependency
    arrow one-way: server -> store).
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, timeout=30.0
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._conn.commit()

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Close the connection (the -wal file is checkpointed away by the
        last connection to close; earlier connections keep it alive)."""
        with self._lock:
            self._conn.close()

    @property
    def journal_mode(self) -> str:
        with self._lock:
            return str(self._conn.execute("PRAGMA journal_mode").fetchone()[0])

    # -- writes ------------------------------------------------------------

    def save_job(
        self,
        job_id: str,
        *,
        source: str,
        depth: str,
        status: str,
        created_at: str,
        finished_at: str | None = None,
        verdict: dict[str, Any] | None = None,
    ) -> None:
        """Insert or refresh a job row.

        source/depth/created_at are immutable after insert; status and
        finished_at always follow the caller; verdict_json is only
        overwritten when a verdict is supplied (COALESCE keeps the old).
        """
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO jobs (job_id, source, depth, status, created_at,
                                  finished_at, verdict_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status = excluded.status,
                    finished_at = excluded.finished_at,
                    verdict_json = COALESCE(excluded.verdict_json, jobs.verdict_json)
                """,
                (
                    job_id,
                    source,
                    depth,
                    status,
                    created_at,
                    finished_at,
                    json.dumps(verdict, default=str) if verdict is not None else None,
                ),
            )
            self._conn.commit()

    def record_event(
        self,
        job_id: str,
        ts: str,
        etype: str,
        data: dict[str, Any],
        finding: dict[str, Any] | None = None,
    ) -> int:
        """Append one event row (and, atomically, its finding row when the
        event is a `finding` event). Returns the event seq."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (job_id, ts, type, data_json) VALUES (?, ?, ?, ?)",
                (job_id, ts, etype, json.dumps(data, default=str)),
            )
            seq = int(cur.lastrowid or 0)
            if finding is not None:
                next_seq = self._conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 FROM findings WHERE job_id = ?",
                    (job_id,),
                ).fetchone()[0]
                self._conn.execute(
                    "INSERT INTO findings (job_id, seq, finding_json) VALUES (?, ?, ?)",
                    (job_id, next_seq, json.dumps(finding, default=str)),
                )
            self._conn.commit()
            return seq

    # -- reads -------------------------------------------------------------

    def load_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT job_id, source, depth, status, created_at, finished_at,"
                " verdict_json FROM jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def load_events(self, job_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, job_id, ts, type, data_json FROM events"
                " WHERE job_id = ? ORDER BY seq",
                (job_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def load_findings(self, job_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT job_id, seq, finding_json FROM findings"
                " WHERE job_id = ? ORDER BY seq",
                (job_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def job_ids(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT job_id FROM jobs ORDER BY created_at, job_id"
            ).fetchall()
        return [r["job_id"] for r in rows]
