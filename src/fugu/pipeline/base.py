"""Stage protocol for the Fugu pipeline.

READ-ONLY for bot workstreams (see types.py header).

A stage is a unit of audit work. Stages receive the extracted target
directory and return a StageResult. Heavy dependencies (LLM client,
detonation driver) are injected at construction time, not passed per-call,
so stages stay testable with fakes.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from fugu.types import AuditJob, StageResult


@runtime_checkable
class Stage(Protocol):
    """One audit stage. `name` matches a StageName literal in types.py."""

    name: str

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        """Execute the stage against the extracted target directory.

        MUST NOT raise for expected analysis findings — return
        StageResult(ok=False, error=...) instead. Raising is for bugs.
        """
        ...
