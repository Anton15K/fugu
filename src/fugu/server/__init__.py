"""Fugu audit server: FastAPI app factory, in-memory job store, SSE.

Public surface:
    create_app(stages=None, ...) -> FastAPI
    JobStore, run_job, extract_source, ExtractionError
"""
from __future__ import annotations

from fugu.server.app import create_app
from fugu.server.jobs import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    ExtractionError,
    JobStore,
    extract_source,
    is_git_source,
    run_job,
)

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_FILES",
    "ExtractionError",
    "JobStore",
    "create_app",
    "extract_source",
    "is_git_source",
    "run_job",
]
