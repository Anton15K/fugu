"""Concrete Fugu pipeline stages.

This package owns the local, deterministic analysis stages:

- ``ConcealmentStage``  (S0) — Unicode-smuggling detection + payload decoding.
- ``StaticScanStage``   (S1) — regex/rule scanner for secrets, dangerous
  patterns and packaging traps.

Both stages implement the ``Stage`` protocol from ``fugu.pipeline.base``
(``name`` attribute + ``async run(job, target) -> StageResult``) and never
raise for expected analysis conditions — failures come back as
``StageResult(ok=False, error=...)``.

Import them from the package root::

    from fugu.pipeline.stages import ConcealmentStage, StaticScanStage
"""
from __future__ import annotations

from fugu.pipeline.stages.concealment import ConcealmentStage
from fugu.pipeline.stages.static_scan import StaticScanStage

__all__ = ["ConcealmentStage", "StaticScanStage"]
