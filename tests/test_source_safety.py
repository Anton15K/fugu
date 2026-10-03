"""Source boundaries use fabricated notes and fake transports, never credentials."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import Mock

import pytest

from fugu.detonation.contree_driver import _bootstrap_files_cmd
from fugu.pipeline.assemble import run_audit, run_stages
from fugu.pipeline.stages.concealment import collect_text_files
from fugu.pipeline.stages.detonation_stage import DetonationStage
from fugu.pipeline.stages.harness import HarnessStage
from fugu.pipeline.stages.reputation import extract_identifiers
from fugu.pipeline.stages.semantic import JudgeCall, SemanticStage
from fugu.server.jobs import ExtractionError, JobStore, extract_source, run_job
from fugu.server.composition_jobs import harvest_tool_names
from fugu.types import AuditJob


def _unsafe_source(tmp_path: Path, kind: str) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text("Ordinary documentation.")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "note.txt").write_text("FABRICATED OUTSIDE NOTE")
    if kind == "file":
        (target / "note.txt").symlink_to(outside / "note.txt")
    elif kind == "directory":
        (target / "linked-directory").symlink_to(outside, target_is_directory=True)
    elif kind == "broken":
        (target / "broken.txt").symlink_to(outside / "missing.txt")
    elif kind == "internal":
        (target / "note.txt").symlink_to(target / "SKILL.md")
    else:
        (target / ".hidden").mkdir()
        (target / ".hidden" / "note.txt").symlink_to(outside / "note.txt")
    return target


@pytest.mark.parametrize("kind", ["file", "directory", "broken", "internal", "hidden"])
def test_collector_rejects_descendant_symlinks_before_read(tmp_path, kind):
    target = _unsafe_source(tmp_path, kind)
    with pytest.raises(ValueError, match="symlink"):
        collect_text_files(target)


def test_explicit_root_symlink_can_anchor_regular_source(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text("Ordinary documentation.")
    alias = tmp_path / "root-alias"
    alias.symlink_to(target, target_is_directory=True)
    files, _ = collect_text_files(alias)
    assert [f.rel for f in files] == ["SKILL.md"]
    assert files[0].text == "Ordinary documentation."
    store = JobStore()
    job = AuditJob(id="alias", source=str(alias))
    store.create(job)
    asyncio.run(run_job(job, [], store))
    assert job.status.value == "done"
    assert alias.is_symlink() and (target / "SKILL.md").is_file()


@pytest.mark.parametrize("kind", ["file", "directory", "broken"])
def test_extraction_rejects_unsafe_local_source(tmp_path, kind):
    target = _unsafe_source(tmp_path, kind)
    with pytest.raises(ExtractionError, match="symlink"):
        asyncio.run(extract_source(AuditJob(id="extract", source=str(target))))


@pytest.mark.parametrize("source", ["https://example.test/repo.git", "https://github.com/example/repo/tree/main/skill"])
def test_cloned_source_rejected_and_local_source_never_deleted(tmp_path, monkeypatch, source):
    target = _unsafe_source(tmp_path, "file")
    clone_timeouts = []

    async def fake_clone(source, dest, branch=None, *, timeout_s):
        clone_timeouts.append(timeout_s)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "SKILL.md").symlink_to(target / "SKILL.md")

    monkeypatch.setattr("fugu.server.jobs._git_clone", fake_clone)
    with pytest.raises(ExtractionError, match="symlink"):
        asyncio.run(extract_source(AuditJob(id="clone", source=source)))
    assert clone_timeouts == [120]
    assert (target / "SKILL.md").exists()


@pytest.mark.parametrize("stage_class", [SemanticStage, HarnessStage])
def test_direct_remote_stage_rejects_links_without_calling_inference(tmp_path, stage_class):
    target = _unsafe_source(tmp_path, "file")
    call = Mock(return_value=('{"findings": []}', JudgeCall("fake", 0, 0, 0, {})))
    result = asyncio.run(stage_class(make_call=call).run(AuditJob(id="direct", source=str(target)), target))
    assert not result.ok
    assert "symlink" in result.error
    call.assert_not_called()


def test_reputation_separate_manifest_reads_reject_directory_links(tmp_path):
    target = _unsafe_source(tmp_path, "directory")
    with pytest.raises(ValueError, match="symlink"):
        extract_identifiers(target)


def test_contree_packaging_rejects_symlinks_before_payload_creation(tmp_path):
    target = _unsafe_source(tmp_path, "file")
    with pytest.raises(ValueError, match="symlink"):
        _bootstrap_files_cmd(target)


def test_direct_detonation_rejects_links_before_deriving_triggers(tmp_path, monkeypatch):
    target = _unsafe_source(tmp_path, "file")
    derive = Mock(return_value=[])
    monkeypatch.setattr("fugu.detonation.triggers.derive_triggers", derive)
    result = asyncio.run(DetonationStage(Mock()).run(AuditJob(id="det", source=str(target)), target))
    assert not result.ok and "symlink" in result.error
    derive.assert_not_called()


def test_direct_tool_name_harvest_rejects_links_before_reads(tmp_path):
    target = _unsafe_source(tmp_path, "file")
    with pytest.raises(ValueError, match="symlink"):
        harvest_tool_names(target)


def test_cli_rejects_source_before_building_live_stages(tmp_path, monkeypatch):
    target = _unsafe_source(tmp_path, "file")
    build = Mock()
    monkeypatch.setattr("fugu.pipeline.assemble.build_stages", build)
    with pytest.raises(ValueError, match="symlink"):
        run_audit(target)
    build.assert_not_called()


def test_direct_stage_runner_rejects_source_before_invoking_stages(tmp_path):
    target = _unsafe_source(tmp_path, "file")
    stage = Mock()
    with pytest.raises(ValueError, match="symlink"):
        asyncio.run(run_stages(AuditJob(id="direct-runner", source=str(target)), target, [stage]))
    stage.run.assert_not_called()


def test_server_rejection_is_terminal_error_and_preserves_source(tmp_path):
    target = _unsafe_source(tmp_path, "directory")
    store = JobStore()
    job = AuditJob(id="unsafe", source=str(target))
    store.create(job)
    asyncio.run(run_job(job, [], store))
    snap = store.get(job.id)
    assert job.status.value == "failed"
    assert snap.ended and snap.events[-1].type == "error"
    assert "symlink" in snap.events[-1].data["error"]
    assert (target / "SKILL.md").is_file()
