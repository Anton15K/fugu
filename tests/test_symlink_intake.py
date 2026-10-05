"""Safe in-repository symlink materialization at source intake."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import shutil
import threading
from pathlib import Path
from unittest.mock import Mock

import pytest

from fugu.detonation.contree_driver import _bootstrap_files_cmd
from fugu.pipeline.stages.detonation_stage import DetonationStage
from fugu.pipeline.stages.harness import HarnessStage
from fugu.pipeline.stages.semantic import JudgeCall, SemanticStage
from fugu.server import composition_jobs
from fugu.server import jobs as server_jobs
from fugu.server.jobs import ExtractionError, JobStore, extract_source
from fugu.types import AuditJob, JobStatus


_LINK_CONTENT = "ROOT_REFERENCE_CONTENT_8bb290b1"


def _repo_with_unit(root: Path) -> tuple[Path, Path]:
    unit = root / "skills" / "unit-one"
    unit.mkdir(parents=True)
    (root / "OVERVIEW.md").write_text(_LINK_CONTENT, encoding="utf-8")
    (unit / "SKILL.md").write_text("A small, inert skill description.\n", encoding="utf-8")
    (unit / "OVERVIEW.md").symlink_to("../../OVERVIEW.md")
    return root, unit


def test_local_intake_materializes_internal_link_and_records_provenance(tmp_path):
    source, unit = _repo_with_unit(tmp_path / "local-repo")
    source_links: list[dict[str, str | int]] = []

    target = asyncio.run(
        extract_source(
            AuditJob(id="local-links", source=str(source)),
            link_provenance=source_links,
        )
    )
    try:
        materialized = target / "skills" / "unit-one" / "OVERVIEW.md"
        assert target != source
        assert materialized.is_file() and not materialized.is_symlink()
        assert materialized.read_text(encoding="utf-8") == _LINK_CONTENT
        assert (unit / "OVERVIEW.md").is_symlink()
        assert (unit / "OVERVIEW.md").readlink().as_posix() == "../../OVERVIEW.md"
        assert source_links == [
            {
                "link_path": "skills/unit-one/OVERVIEW.md",
                "link_target": "../../OVERVIEW.md",
                "resolved_path": "OVERVIEW.md",
                "sha256": hashlib.sha256(_LINK_CONTENT.encode()).hexdigest(),
                "size_bytes": len(_LINK_CONTENT.encode()),
            }
        ]
    finally:
        shutil.rmtree(target, ignore_errors=True)


def test_explicit_root_symlink_is_allowed_and_materialized(tmp_path):
    source, _unit = _repo_with_unit(tmp_path / "root-target")
    alias = tmp_path / "root-alias"
    alias.symlink_to(source, target_is_directory=True)

    target = asyncio.run(extract_source(AuditJob(id="root-alias", source=str(alias))))
    try:
        link_copy = target / "skills" / "unit-one" / "OVERVIEW.md"
        assert target != alias
        assert link_copy.read_text(encoding="utf-8") == _LINK_CONTENT
        assert not link_copy.is_symlink()
        assert alias.is_symlink() and alias.resolve() == source.resolve()
    finally:
        shutil.rmtree(target, ignore_errors=True)


@pytest.mark.parametrize(
    ("kind", "reason"),
    [
        ("relative_escape", "escapes source root"),
        ("absolute_escape", "escapes source root"),
        ("broken", "broken symlink"),
        ("cycle", "cyclic symlink"),
        ("directory", "directory symlink"),
        ("chain", "chained symlink"),
    ],
)
def test_local_intake_rejects_unsafe_link_shapes_deterministically(tmp_path, kind, reason):
    source = tmp_path / "unsafe-repo"
    source.mkdir()
    (source / "SKILL.md").write_text("Inert text.\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("must never enter the audit snapshot", encoding="utf-8")

    if kind == "relative_escape":
        (source / "link.txt").symlink_to("../outside.txt")
    elif kind == "absolute_escape":
        (source / "link.txt").symlink_to(outside)
    elif kind == "broken":
        (source / "link.txt").symlink_to(source / "missing.txt")
    elif kind == "cycle":
        (source / "one.txt").symlink_to("two.txt")
        (source / "two.txt").symlink_to("one.txt")
    elif kind == "directory":
        (source / "folder").mkdir()
        (source / "link-dir").symlink_to("folder", target_is_directory=True)
    else:
        (source / "real.txt").write_text("regular", encoding="utf-8")
        (source / "first.txt").symlink_to("real.txt")
        (source / "second.txt").symlink_to("first.txt")

    with pytest.raises(ExtractionError, match=reason):
        asyncio.run(extract_source(AuditJob(id=f"unsafe-{kind}", source=str(source))))
    assert outside.read_text(encoding="utf-8") == "must never enter the audit snapshot"


def test_materialized_duplicate_link_content_counts_toward_limits(tmp_path):
    source = tmp_path / "bounded-repo"
    source.mkdir()
    (source / "original.txt").write_bytes(b"1234")
    (source / "copy.txt").symlink_to("original.txt")

    with pytest.raises(ExtractionError, match="too large"):
        asyncio.run(
            extract_source(
                AuditJob(id="bounded-bytes", source=str(source)), max_bytes=7
            )
        )
    with pytest.raises(ExtractionError, match="too many files"):
        asyncio.run(
            extract_source(
                AuditJob(id="bounded-entries", source=str(source)), max_files=1
            )
        )


def test_git_subdirectory_link_resolves_against_full_clone_anchor(tmp_path, monkeypatch):
    source, _unit = _repo_with_unit(tmp_path / "repository")
    clone_parents: list[Path] = []

    async def fake_clone(_remote, target, branch=None, *, timeout_s):
        clone_parents.append(target.parent)
        shutil.copytree(source, target, symlinks=True)

    monkeypatch.setattr("fugu.server.jobs._git_clone", fake_clone)
    source_links: list[dict[str, str | int]] = []
    target = asyncio.run(
        extract_source(
            AuditJob(
                id="git-subdir",
                source="https://github.com/example/repository/tree/main/skills/unit-one",
            ),
            link_provenance=source_links,
        )
    )
    try:
        materialized = target / "OVERVIEW.md"
        assert materialized.read_text(encoding="utf-8") == _LINK_CONTENT
        assert not materialized.is_symlink()
        assert source_links[0]["resolved_path"] == "OVERVIEW.md"
        assert clone_parents and all(not parent.exists() for parent in clone_parents)
        assert (source / "skills" / "unit-one" / "OVERVIEW.md").is_symlink()
    finally:
        shutil.rmtree(target, ignore_errors=True)


def test_materialized_snapshot_is_readable_by_semantic_harness_and_fake_chamber(
    tmp_path, monkeypatch
):
    source, _unit = _repo_with_unit(tmp_path / "consumer-repo")
    target = asyncio.run(
        extract_source(AuditJob(id="consumers", source=str(source)))
    )
    try:
        call = Mock(
            return_value=(
                '{"findings": [], "quality_summary": "no issue"}',
                JudgeCall("fake", 0, 0, 0, {}),
            )
        )
        result = asyncio.run(
            SemanticStage(make_call=call).run(AuditJob(id="semantic", source=str(source)), target)
        )
        assert result.ok
        assert any(_LINK_CONTENT in args[1] for args, _kwargs in call.call_args_list)

        mounted, _stats = HarnessStage()._mount_content_with_stats(target)
        assert _LINK_CONTENT in mounted

        class FakeDriver:
            received: Path | None = None

            async def detonate(self, target_dir, triggers, timeout_s=120):
                self.received = Path(target_dir)
                assert triggers == ["echo inert"]
                assert not (target_dir / "skills/unit-one/OVERVIEW.md").is_symlink()
                assert (target_dir / "skills/unit-one/OVERVIEW.md").read_text() == _LINK_CONTENT
                return []

        monkeypatch.setattr(
            "fugu.detonation.triggers.derive_triggers", lambda *_args, **_kwargs: ["echo inert"]
        )
        driver = FakeDriver()
        detonation = asyncio.run(
            DetonationStage(driver).run(AuditJob(id="detonation", source=str(source)), target)
        )
        assert detonation.ok and driver.received == target.resolve()

        bootstrap = _bootstrap_files_cmd(target)
        assert base64.b64encode(_LINK_CONTENT.encode()).decode() in bootstrap
    finally:
        shutil.rmtree(target, ignore_errors=True)


def test_auto_fanout_reads_materialized_unit_reference_and_retains_provenance(
    tmp_path, monkeypatch
):
    source, unit = _repo_with_unit(tmp_path / "fanout-repo")
    second = source / "skills" / "unit-two"
    second.mkdir()
    (second / "SKILL.md").write_text("Another inert skill.\n", encoding="utf-8")
    (second / "OVERVIEW.md").symlink_to("../../OVERVIEW.md")
    observed: list[Path] = []
    composed: list[object] = []

    async def fake_run_stage_loop(job, _snap, target, _stages, store):
        linked_file = Path(target) / "OVERVIEW.md"
        assert linked_file.is_file() and not linked_file.is_symlink()
        assert linked_file.read_text(encoding="utf-8") == _LINK_CONTENT
        observed.append(Path(target))
        job.status = JobStatus.done
        store.close(job.id)

    async def fake_compose(job, _snap, members, store, _summaries, *_args, **_kwargs):
        composed.extend(members)
        assert len(members) == 2
        job.status = JobStatus.done
        store.close(job.id)

    monkeypatch.setattr(composition_jobs, "run_stage_loop", fake_run_stage_loop)
    monkeypatch.setattr(composition_jobs, "_compose_members", fake_compose)
    store = JobStore()
    job = AuditJob(id="auto-links", source=str(source))
    store.create(job)

    asyncio.run(composition_jobs.run_auto_job(job, str(source), [], store, min_units=2))

    snap = store.get(job.id)
    assert snap is not None and job.status is JobStatus.done
    assert len(observed) == 2 and len(composed) == 2
    assert (unit / "OVERVIEW.md").is_symlink()
    assert snap.target_dir is not None and not snap.target_dir.exists()
    provenance_events = [
        event.data["source_links"]
        for event in snap.events
        if event.type == "log" and "source_links" in event.data
    ]
    assert provenance_events and provenance_events[0][0]["link_path"] == (
        "skills/unit-one/OVERVIEW.md"
    )


def test_very_long_rejected_symlink_chain_uses_failed_extraction_path(tmp_path, monkeypatch):
    source = tmp_path / "long-chain-repo"
    source.mkdir()
    (source / "payload.md").write_text("inert linked content\n", encoding="utf-8")

    link_count = 1100
    for index in range(link_count):
        name = f"link-{index:04d}"
        target = f"link-{index + 1:04d}" if index + 1 < link_count else "payload.md"
        (source / name).symlink_to(target)

    async def unexpected_stage(*_args, **_kwargs):
        pytest.fail("stage execution must not start for a rejected symlink chain")

    monkeypatch.setattr(composition_jobs, "run_stage_loop", unexpected_stage)
    store = JobStore()
    job = AuditJob(id="long-symlink-chain", source=str(source))
    store.create(job)

    asyncio.run(composition_jobs.run_auto_job(job, str(source), [], store))

    snap = store.get(job.id)
    assert snap is not None
    assert job.status is JobStatus.failed
    assert snap.ended
    assert len(snap.stages) == 1
    assert snap.stages[0].stage == "extraction"
    assert not snap.stages[0].ok
    assert "chained symlink" in (snap.stages[0].error or "")
    assert "resolution limit exceeded" in (snap.stages[0].error or "")


@pytest.mark.parametrize("component_kind", ["missing", "regular_file", "symlink"])
def test_dotdot_does_not_erase_missing_or_non_directory_link_prefix(
    tmp_path, component_kind
):
    source = tmp_path / f"invalid-prefix-{component_kind}"
    source.mkdir()
    (source / "payload.txt").write_text("inert local payload\n", encoding="utf-8")
    component = {
        "missing": "missing",
        "regular_file": "regular-file",
        "symlink": "symlink-directory",
    }[component_kind]
    if component_kind == "regular_file":
        (source / component).write_text("not a directory\n", encoding="utf-8")
    elif component_kind == "symlink":
        real_directory = source / "real-directory"
        real_directory.mkdir()
        (source / component).symlink_to(real_directory, target_is_directory=True)
    alias = source / "alias.txt"
    alias.symlink_to(f"{component}/../payload.txt")
    if component_kind != "symlink":
        assert not alias.exists()

    provenance: list[dict[str, str | int]] = []
    snapshot: Path | None = None
    try:
        with pytest.raises(ExtractionError):
            snapshot = asyncio.run(
                extract_source(
                    AuditJob(id=f"invalid-prefix-{component_kind}", source=str(source)),
                    link_provenance=provenance,
                )
            )
    finally:
        if snapshot is not None:
            shutil.rmtree(snapshot, ignore_errors=True)

    assert provenance == []


@pytest.mark.parametrize("raw_target", ["payload.txt/.", "payload.txt/"])
def test_link_paths_requiring_directory_reject_regular_file_target(
    tmp_path, raw_target
):
    source = tmp_path / "directory-required-link"
    source.mkdir()
    payload = source / "payload.txt"
    payload.write_text("inert payload\n", encoding="utf-8")
    alias = source / "alias.txt"
    alias.symlink_to(raw_target)
    assert not alias.exists()

    provenance: list[dict[str, str | int]] = []
    with pytest.raises(ExtractionError):
        asyncio.run(
            extract_source(
                AuditJob(id="directory-required-link", source=str(source)),
                link_provenance=provenance,
            )
        )

    assert provenance == []


def test_absolute_in_root_file_link_remains_accepted(tmp_path):
    source = tmp_path / "absolute-in-root"
    source.mkdir()
    payload = source / "payload.txt"
    payload.write_text("inert absolute-link payload\n", encoding="utf-8")
    (source / "alias.txt").symlink_to(payload.resolve())

    snapshot = asyncio.run(
        extract_source(AuditJob(id="absolute-in-root", source=str(source)))
    )
    try:
        copied = snapshot / "alias.txt"
        assert copied.is_file() and not copied.is_symlink()
        assert copied.read_text(encoding="utf-8") == payload.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(snapshot, ignore_errors=True)


@pytest.mark.parametrize("source_kind", ["local", "git_selected"])
def test_cancelled_extract_cleans_snapshot_when_worker_finishes(
    tmp_path, monkeypatch, source_kind
):
    source_root = tmp_path / "source-root"
    if source_kind == "git_selected":
        selected = source_root / "skills" / "unit-one"
        selected.mkdir(parents=True)
        audit_source = "https://github.com/example/repository/tree/main/skills/unit-one"

        async def fake_clone(_remote, target, branch=None, *, timeout_s):
            shutil.copytree(source_root, target, symlinks=True)

        monkeypatch.setattr("fugu.server.jobs._git_clone", fake_clone)
    else:
        source_root.mkdir()
        selected = source_root
        audit_source = str(source_root)
    (selected / "payload.txt").write_text("inert cancellation payload\n", encoding="utf-8")

    original_materialize = server_jobs._materialize_git_selection
    snapshots: list[Path] = []
    worker_entered = threading.Event()
    release_worker = threading.Event()
    worker_finished = threading.Event()

    def gated_materialize(*args, **kwargs):
        snapshot = original_materialize(*args, **kwargs)
        snapshots.append(snapshot)
        worker_entered.set()
        if not release_worker.wait(3):
            raise RuntimeError("materialization test gate timed out")
        worker_finished.set()
        return snapshot

    monkeypatch.setattr(server_jobs, "_materialize_git_selection", gated_materialize)

    async def cancel_during_materialization():
        loop = asyncio.get_running_loop()
        task = asyncio.create_task(
            extract_source(AuditJob(id=f"cancel-{source_kind}", source=audit_source))
        )
        assert await loop.run_in_executor(None, worker_entered.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        release_worker.set()
        assert await loop.run_in_executor(None, worker_finished.wait, 2)
        deadline = loop.time() + 2
        while snapshots and snapshots[0].exists() and loop.time() < deadline:
            await asyncio.sleep(0.01)
        assert len(snapshots) == 1
        assert not snapshots[0].exists()

    try:
        asyncio.run(cancel_during_materialization())
    finally:
        release_worker.set()
        for snapshot in snapshots:
            shutil.rmtree(snapshot, ignore_errors=True)
