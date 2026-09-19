"""SQLite persistence for Fugu audit jobs (stdlib sqlite3, no ORM).

Public surface:
    SqliteJobStore(path)  — durable jobs/events/findings store

Wired into the server via ``JobStore(store=SqliteJobStore(path))`` or
``create_app(db=path)`` / ``python -m fugu.server --db PATH``.
"""
from __future__ import annotations

from fugu.store.sqlite import SqliteJobStore

__all__ = ["SqliteJobStore"]
