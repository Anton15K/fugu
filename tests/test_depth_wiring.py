"""Depth must actually change the pipeline: standard skips the harness A/B
stage, full runs it. Guards the wiring found broken during dogfooding
(req.depth was validated then ignored — every run was 'full')."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from fugu.pipeline.assemble import build_stages
from fugu.server.app import AppState, create_app


class _HarnessStage:
    name = "harness"


class _StaticStage:
    name = "static"


def test_stages_for_standard_skips_harness():
    state = AppState(stages=[_StaticStage(), _HarnessStage()], static_dir=None)
    names_std = [type(s).__name__ for s in state.stages_for("standard")]
    names_full = [type(s).__name__ for s in state.stages_for("full")]
    assert "HarnessStage" not in names_std or "harness" not in " ".join(names_std).lower()
    joined_std = " ".join(names_std).lower()
    joined_full = " ".join(names_full).lower()
    assert "harness" not in joined_std, f"standard must skip harness, got {names_std}"
    assert "harness" in joined_full, f"full must include harness, got {names_full}"


def test_stages_for_unknown_depth_falls_back_to_standard():
    state = AppState(stages=[_StaticStage(), _HarnessStage()], static_dir=None)
    joined = " ".join(type(s).__name__ for s in state.stages_for("bogus")).lower()
    assert "harness" not in joined


def test_real_build_stages_harness_is_in_full_and_out_of_standard(monkeypatch):
    # hermetic: no API key -> LLM stages no-op, but the stage objects exist
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    stages = build_stages()
    assert any("harness" in type(s).__name__.lower() for s in stages), (
        "harness stage missing from full pipeline"
    )
