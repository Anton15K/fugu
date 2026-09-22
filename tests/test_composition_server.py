"""Tests for multi-source (composition) audits on the Fugu server.

Covers contracts §3 (workstream W3): the `sources` request field, the
create_audit branch into run_composition_job, parent/child event
sequences, member-result harvest + local-dir safety, and failure modes.

Hermetic: fake child stages fabricate findings; the composition stage is
W1's module when present, otherwise the in-module stub (attribute
contract `_member_results`). Tests assert the event sequence, which both
satisfy — no dependency on wave landing order.

NOTE on clients: HTTP tests use `with TestClient(app) as client:`. The
context manager pins ONE anyio portal (event loop) for the client's
lifetime; a bare TestClient builds a fresh loop per request and its
teardown cancels the server's fire-and-forget audit task mid-flight
(e.g. while a git clone subprocess is open), which can hang the runner.
The existing test_server.py suite gets away with bare clients because
its fake stages complete before teardown; composition tests deliberately
exercise slower paths (clones, subprocesses) so they pin the portal.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Iterator

import pytest
from starlette.testclient import TestClient

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fugu.server import create_app, run_composition_job
from fugu.server.composition_jobs import (
    harvest_tool_names,
    normalize_sources,
)
from fugu.server.jobs import JobStore
from fugu.types import AuditJob, Finding, JobStatus, StageResult


# --- fakes --------------------------------------------------------------------------


class FakeMemberStage:
    """Fabricates one finding + writes a tool manifest into the target dir."""

    name = "static"

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        manifest = target / "server.json"
        if not manifest.exists():
            manifest.write_text(
                '{"tools": [{"name": "web_fetch", "inputSchema": {}}, '
                '{"name": "fs_read", "inputSchema": {}}]}'
            )
        return StageResult(
            stage=self.name,
            ok=True,
            findings=[
                Finding(
                    owasp_ids=["MCP06"],
                    title=f"Fabricated finding for {job.source}",
                    detail="hermetic test finding",
                    severity="medium",
                    confidence="measured",
                    stage=self.name,
                    evidence=[],
                )
            ],
            metrics={"files_scanned": 1},
        )


@contextlib.contextmanager
def _client(stages: list[Any] | None = None, **kwargs: Any) -> Iterator[TestClient]:
    """Pinned-portal TestClient (see module docstring)."""
    with TestClient(create_app(stages=stages, **kwargs)) as client:
        yield client


def _wait_done(
    client: TestClient, job_id: str, timeout_s: float = 5.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        body = client.get(f"/audits/{job_id}").json()
        if body["status"] in ("done", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish in {timeout_s}s: {body}")


def _events(client: TestClient, job_id: str) -> list[dict[str, Any]]:
    text = client.get(f"/audits/{job_id}/events").text
    out = []
    for line in text.splitlines():
        if line.startswith("data: "):
            out.append(json.loads(line[len("data: "):]))
    return out


def _two_local_dirs(tmp_path: Path) -> tuple[Path, Path]:
    a = tmp_path / "member-a"
    b = tmp_path / "member-b"
    a.mkdir()
    b.mkdir()
    (a / "SKILL.md").write_text("# member a\n")
    (b / "SKILL.md").write_text("# member b\n")
    return a, b


def _member_lines(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parent log events with the member summary + child_job_id."""
    return [
        e
        for e in events
        if e["type"] == "log"
        and e["data"].get("message", "").startswith("member ")
        and "child_job_id" in e["data"]
    ]


def _is_member(data: dict[str, Any]) -> bool:
    return data.get("message", "").startswith("member ") and "child_job_id" in data


# --- multi-source happy path ---------------------------------------------------------


def test_multi_source_happy_path(tmp_path: Path) -> None:
    a, b = _two_local_dirs(tmp_path)

    with _client([FakeMemberStage()]) as client:
        resp = client.post(
            "/audits",
            json={
                "sources": [
                    {"ref": str(a), "label": "alpha"},
                    {"ref": str(b)},  # label defaults to basename
                ]
            },
        )
        assert resp.status_code == 202, resp.text
        parent_id = resp.json()["job_id"]

        parent = _wait_done(client, parent_id)
        assert parent["status"] == "done"
        assert parent["source"] == "composition:alpha, member-b"

        events = _events(client, parent_id)
        types = [e["type"] for e in events]

        # member log events carry child_job_id + the contract message format
        member_lines = _member_lines(events)
        assert len(member_lines) == 2
        assert member_lines[0]["data"]["message"] == (
            f"member alpha: job {member_lines[0]['data']['child_job_id']} "
            "done, 1 findings"
        )
        assert member_lines[1]["data"]["message"] == (
            f"member member-b: job {member_lines[1]['data']['child_job_id']} "
            "done, 1 findings"
        )

        # composition stage lifecycle on the parent stream
        comp_started = [
            e
            for e in events
            if e["type"] == "stage_started" and e["data"]["stage"] == "composition"
        ]
        comp_done = [
            e
            for e in events
            if e["type"] == "stage_done" and e["data"]["stage"] == "composition"
        ]
        assert comp_started and comp_done
        assert types[-1] == "verdict"
        verdict = events[-1]["data"]
        assert verdict["status"] == "done"
        assert "stages" in verdict

        # parent findings = composition-stage findings only (member findings
        # live on the child jobs). Stub → zero; W1 → whatever it emits — the
        # count must equal the composition stage_done findings_count.
        done_count = comp_done[0]["data"]["findings_count"]
        comp_findings = [f for f in parent["findings"] if f["stage"] == "composition"]
        assert len(comp_findings) == done_count

        # child jobs exist in the store with their own findings
        for e in member_lines:
            child = client.get(f"/audits/{e['data']['child_job_id']}").json()
            assert child["status"] == "done"
            assert len(child["findings"]) == 1
            assert child["depth"] == "standard"

    # local member dirs were NOT deleted
    assert a.is_dir() and (a / "SKILL.md").exists()
    assert b.is_dir() and (b / "SKILL.md").exists()


def test_multi_source_event_sequence_order(tmp_path: Path) -> None:
    """Exact parent event sequence: start log → member logs → stage
    lifecycle → verdict."""
    a, b = _two_local_dirs(tmp_path)
    with _client([FakeMemberStage()]) as client:
        parent_id = client.post(
            "/audits",
            json={"sources": [{"ref": str(a)}, {"ref": str(b)}]},
        ).json()["job_id"]
        _wait_done(client, parent_id)
        events = _events(client, parent_id)

    seq = []
    for e in events:
        if e["type"] == "log":
            msg = e["data"].get("message", "")
            if msg == "composition job started":
                seq.append("start")
            elif msg.startswith("member ") and "child_job_id" in e["data"]:
                seq.append("member")
        elif e["type"] in ("stage_started", "stage_done", "verdict"):
            seq.append(e["type"])
    assert seq == [
        "start",
        "member",
        "member",
        "stage_started",
        "stage_done",
        "verdict",
    ]


# --- sources validation ----------------------------------------------------------------


def test_sources_count_validation(tmp_path: Path) -> None:
    a, b = _two_local_dirs(tmp_path)
    with _client([]) as client:
        # 1 source → 422
        resp = client.post("/audits", json={"sources": [{"ref": str(a)}]})
        assert resp.status_code == 422
        # 9 sources → 422
        nine = [{"ref": f"{tmp_path}/m{i}"} for i in range(9)]
        resp = client.post("/audits", json={"sources": nine})
        assert resp.status_code == 422
        # empty ref → 422
        resp = client.post(
            "/audits", json={"sources": [{"ref": str(a)}, {"ref": "  "}]}
        )
        assert resp.status_code == 422
        # duplicate refs → 422
        resp = client.post(
            "/audits", json={"sources": [{"ref": str(a)}, {"ref": str(a)}]}
        )
        assert resp.status_code == 422
        # sources + source together → 422
        resp = client.post(
            "/audits",
            json={"sources": [{"ref": str(a)}, {"ref": str(b)}], "source": str(a)},
        )
        assert resp.status_code == 422
        # nonexistent local member dir → 422
        resp = client.post(
            "/audits",
            json={"sources": [{"ref": str(a)}, {"ref": "/definitely/not/here"}]},
        )
        assert resp.status_code == 422
        # git-style member accepted at submit time (runtime clone) → 202.
        # file:///...git counts as git-style (is_git_source .git tail) but
        # fails fast at clone time with zero network access.
        resp = client.post(
            "/audits",
            json={
                "sources": [
                    {"ref": str(a)},
                    {"ref": "file:///definitely/not/a/repo.git", "label": "remote"},
                ]
            },
        )
        assert resp.status_code == 202
        # that job's remote child fails extraction at runtime; the parent
        # still completes (partial failure path)
        body = _wait_done(client, resp.json()["job_id"], timeout_s=30)
        assert body["status"] == "done"


def test_label_defaults_and_length_cap(tmp_path: Path) -> None:
    a, b = _two_local_dirs(tmp_path)
    with _client([]) as client:
        # label longer than 64 chars → 422
        resp = client.post(
            "/audits",
            json={"sources": [{"ref": str(a)}, {"ref": str(b), "label": "x" * 65}]},
        )
        assert resp.status_code == 422

    specs = normalize_sources(
        [
            {"ref": "/tmp/one/two", "label": None},
            {"ref": "https://h/x/y.git", "label": "  "},
        ]
    )
    assert specs[0].label == "two"
    assert specs[1].label == "y.git"


def test_normalize_sources_direct_rules() -> None:
    # 0 and 1 entries rejected; boundary values 2 and 8 accepted
    with pytest.raises(ValueError):
        normalize_sources([])
    with pytest.raises(ValueError):
        normalize_sources([{"ref": "/a"}])
    ok2 = normalize_sources([{"ref": "/a"}, {"ref": "/b"}])
    assert [s.label for s in ok2] == ["a", "b"]
    ok8 = normalize_sources([{"ref": f"/d{i}"} for i in range(8)])
    assert len(ok8) == 8
    with pytest.raises(ValueError):
        normalize_sources([{"ref": f"/d{i}"} for i in range(9)])
    # ref stripped
    assert normalize_sources([{"ref": " /a "}, {"ref": "/b"}])[0].ref == "/a"
    with pytest.raises(ValueError, match="duplicate"):
        normalize_sources([{"ref": "/a"}, {"ref": "/a"}])
    with pytest.raises(ValueError, match="empty"):
        normalize_sources([{"ref": ""}, {"ref": "/b"}])


# --- single-source path is unchanged ----------------------------------------------


def test_single_source_path_unchanged(tmp_path: Path, monkeypatch) -> None:
    """POST /audits without `sources` must go through run_job exactly as
    before — asserted via monkeypatched run_job."""
    import fugu.server.app as app_mod

    target = tmp_path / "solo"
    target.mkdir()
    (target / "SKILL.md").write_text("# solo\n")

    seen: list[dict[str, Any]] = []

    real_run_job = app_mod.run_job

    async def spy_run_job(job, stages, store, **kwargs):
        seen.append({"job_id": job.id, "kwargs": kwargs, "stages": stages})
        return await real_run_job(job, stages, store, **kwargs)

    monkeypatch.setattr(app_mod, "run_job", spy_run_job)

    with _client([FakeMemberStage()]) as client:
        resp = client.post("/audits", json={"source": str(target)})
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]
        body = _wait_done(client, job_id)

        assert body["status"] == "done"
        assert body["source"] == str(target)  # NOT composition-prefixed
        assert len(seen) == 1
        assert seen[0]["job_id"] == job_id
        assert seen[0]["kwargs"].get("keep_target") is None  # not passed
        # findings flow exactly as the old path
        assert len(body["findings"]) == 1
        # explicit null source with no sources → 422
        resp = client.post("/audits", json={"source": None})
        assert resp.status_code == 422


def test_single_source_null_source_no_sources_422() -> None:
    with _client([]) as client:
        resp = client.post("/audits", json={})
        assert resp.status_code == 422


# --- harvest + local-dir safety ----------------------------------------------------------


def test_harvest_tool_names_from_target(tmp_path: Path) -> None:
    t = tmp_path / "ext"
    t.mkdir()
    (t / "s.py").write_text('tools = [{"name": "get_weather", "inputSchema": {}}]')
    (t / "skip.bin").write_bytes(b"\x00\x01")  # not a text suffix
    names = harvest_tool_names(t)
    assert "get_weather" in names
    assert harvest_tool_names(None) == []
    assert harvest_tool_names(tmp_path / "missing") == []


def test_local_dirs_never_deleted(tmp_path: Path) -> None:
    """Direct run_composition_job: local member dirs survive the run."""
    a, b = _two_local_dirs(tmp_path)
    store = JobStore()
    parent = AuditJob(id="p1", source="composition:x, y")
    store.create(parent)

    asyncio.run(
        run_composition_job(
            parent,
            [{"ref": str(a), "label": "x"}, {"ref": str(b), "label": "y"}],
            [FakeMemberStage()],
            store,
        )
    )
    assert parent.status is JobStatus.done
    assert a.is_dir() and (a / "SKILL.md").exists()
    assert b.is_dir() and (b / "SKILL.md").exists()
    snap = store.get("p1")
    assert snap is not None
    types = [e.type for e in snap.events]
    assert types[-1] == "verdict"


def test_cloned_target_cleanup_git_style(tmp_path: Path, monkeypatch) -> None:
    """A git-style member gets its cloned temp target cleaned up by the
    parent after harvest; the local member dir is left alone."""
    local = tmp_path / "local-member"
    local.mkdir()
    (local / "SKILL.md").write_text("# local\n")

    cloned = tmp_path / "fugu-git-clone"
    cloned.mkdir()
    (cloned / "server.json").write_text('{"tools": [{"name": "t1"}]}')

    import fugu.server.jobs as jobs_mod

    real_extract = jobs_mod.extract_source

    async def fake_extract(job, *args: Any, **kwargs: Any) -> Path:
        if job.source.startswith("file:///"):
            return cloned  # pretend the clone landed here
        return await real_extract(job, *args, **kwargs)

    monkeypatch.setattr(jobs_mod, "extract_source", fake_extract)
    # run_job looks up extract_source at module level → the patch applies.

    store = JobStore()
    parent = AuditJob(id="p2", source="composition:a, b")
    store.create(parent)

    asyncio.run(
        run_composition_job(
            parent,
            [
                {"ref": str(local), "label": "a"},
                {"ref": "file:///example/fake/repo.git", "label": "b"},
            ],
            [FakeMemberStage()],
            store,
        )
    )
    assert parent.status is JobStatus.done
    # the local member dir survived; the clone dir was reclaimed
    assert local.is_dir()
    assert not cloned.exists()
    snap = store.get("p2")
    assert snap is not None
    member_msgs = [
        e.data["message"] for e in snap.events if e.type == "log" and _is_member(e.data)
    ]
    assert len(member_msgs) == 2
    assert member_msgs[1].endswith("done, 1 findings")


# --- failure modes -----------------------------------------------------------------------


def test_partial_failure_continues(tmp_path: Path) -> None:
    a, b = _two_local_dirs(tmp_path)
    store = JobStore()
    parent = AuditJob(id="p3", source="composition:good, bad")
    store.create(parent)

    asyncio.run(
        run_composition_job(
            parent,
            [
                {"ref": str(a), "label": "good"},
                {"ref": "/definitely/not/here", "label": "bad"},
            ],
            [FakeMemberStage()],
            store,
        )
    )
    assert parent.status is JobStatus.done  # ≥1 success → proceed
    snap = store.get("p3")
    assert snap is not None
    msgs = [e.data.get("message", "") for e in snap.events if e.type == "log"]
    assert any("member good: job" in m and "done, 1 findings" in m for m in msgs)
    assert any("member bad: job" in m and "failed, 0 findings" in m for m in msgs)
    assert any("failed extraction" in m for m in msgs)
    types = [e.type for e in snap.events]
    assert types[-1] == "verdict"


def test_all_children_failed_parent_fails(tmp_path: Path) -> None:
    store = JobStore()
    parent = AuditJob(id="p4", source="composition:x, y")
    store.create(parent)

    asyncio.run(
        run_composition_job(
            parent,
            [
                {"ref": "/definitely/not/here", "label": "x"},
                {"ref": "/also/not/here", "label": "y"},
            ],
            [FakeMemberStage()],
            store,
        )
    )
    assert parent.status is JobStatus.failed
    snap = store.get("p4")
    assert snap is not None
    types = [e.type for e in snap.events]
    assert types[-1] == "error"
    assert "all" in snap.events[-1].data["error"]
    assert snap.ended


def test_all_children_failed_via_api(tmp_path: Path) -> None:
    """Git-style members pass submit-time validation; both then fail at
    clone time (file:/// nonexistent repos, no network) → parent failed."""
    with _client([FakeMemberStage()]) as client:
        resp = client.post(
            "/audits",
            json={
                "sources": [
                    {"ref": "file:///definitely/not/a.git", "label": "a"},
                    {"ref": "file:///definitely/not/b.git", "label": "b"},
                ]
            },
        )
        assert resp.status_code == 202
        parent = _wait_done(client, resp.json()["job_id"], timeout_s=30)
        assert parent["status"] == "failed"


def test_child_runner_exception_does_not_kill_parent(tmp_path: Path, monkeypatch) -> None:
    """If run_job itself raises (runner bug), the member is recorded as
    failed and the parent still finishes."""
    import fugu.server.composition_jobs as cj

    a, b = _two_local_dirs(tmp_path)

    async def boom(job, stages, store, **kwargs):
        raise RuntimeError("runner exploded")

    monkeypatch.setattr(cj, "run_job", boom)

    store = JobStore()
    parent = AuditJob(id="p5", source="composition:x, y")
    store.create(parent)
    asyncio.run(
        run_composition_job(
            parent,
            [{"ref": str(a), "label": "x"}, {"ref": str(b), "label": "y"}],
            [FakeMemberStage()],
            store,
        )
    )
    assert parent.status is JobStatus.failed  # every child "failed"
    snap = store.get("p5")
    assert snap is not None
    msgs = [e.data.get("message", "") for e in snap.events if e.type == "log"]
    assert any("runner error" in m for m in msgs)
    assert snap.events[-1].type == "error"


def test_member_results_injected_into_stage(tmp_path: Path, monkeypatch) -> None:
    """The runner injects `_member_results` (findings + tool_names +
    slug per member) into the composition stage before run() — patched
    at whichever module currently provides CompositionStage (W1's real
    module, or the in-module stub before it lands)."""
    import importlib

    from fugu.server import composition_jobs as cj

    a, b = _two_local_dirs(tmp_path)
    store = JobStore()
    parent = AuditJob(id="p6", source="composition:x, y")
    store.create(parent)

    captured: dict[str, Any] = {}

    class ProbeStage:
        name = "composition"

        def __init__(self) -> None:
            self._member_results = None

        async def run(self, job, target):
            captured["members"] = getattr(self, "_member_results", None)
            return StageResult(stage=self.name, ok=True, metrics={})

    try:
        comp_mod = importlib.import_module("fugu.pipeline.stages.composition")
        monkeypatch.setattr(comp_mod, "CompositionStage", ProbeStage, raising=False)
    except ImportError:  # stub path (W1 not landed)
        monkeypatch.setattr(cj, "_StubCompositionStage", ProbeStage, raising=False)

    asyncio.run(
        run_composition_job(
            parent,
            [{"ref": str(a), "label": "x"}, {"ref": str(b), "label": "y"}],
            [FakeMemberStage()],
            store,
        )
    )

    assert parent.status is JobStatus.done
    members = captured["members"]
    assert members is not None and len(members) == 2
    assert [m.label for m in members] == ["x", "y"]
    assert all(len(m.findings) == 1 for m in members)
    # tool names harvested from the fabricated manifests
    all_tools = {t for m in members for t in m.tool_names}
    assert {"web_fetch", "fs_read"} <= all_tools
    assert all(m.slug for m in members)


def test_fallback_stage_zero_findings(tmp_path: Path, monkeypatch) -> None:
    """With W1's module importable-forced-absent, the stub produces zero
    findings but the full event lifecycle still holds (contracts §3: W3
    must stay testable without W1)."""
    import sys

    a, b = _two_local_dirs(tmp_path)
    store = JobStore()
    parent = AuditJob(id="p7", source="composition:x, y")
    store.create(parent)

    # A None entry in sys.modules makes `from ... import ...` raise
    # ImportError inside run_composition_job → the stub fallback engages.
    saved = sys.modules.get("fugu.pipeline.stages.composition")
    monkeypatch.setitem(sys.modules, "fugu.pipeline.stages.composition", None)

    asyncio.run(
        run_composition_job(
            parent,
            [{"ref": str(a), "label": "x"}, {"ref": str(b), "label": "y"}],
            [FakeMemberStage()],
            store,
        )
    )
    monkeypatch.undo()
    if saved is not None:
        sys.modules["fugu.pipeline.stages.composition"] = saved

    snap = store.get("p7")
    assert snap is not None
    # stub → zero findings, but lifecycle events all present
    assert snap.findings == []
    assert parent.status is JobStatus.done
    stage_names = [r.stage for r in snap.stages]
    assert stage_names == ["composition"]
    types = [e.type for e in snap.events]
    assert "stage_started" in types and "stage_done" in types
    assert types[-1] == "verdict"


def test_api_prefix_multi_source(tmp_path: Path) -> None:
    """The /api mirror serves composition audits identically."""
    a, b = _two_local_dirs(tmp_path)
    with _client([FakeMemberStage()]) as client:
        resp = client.post(
            "/api/audits",
            json={"sources": [{"ref": str(a)}, {"ref": str(b)}]},
        )
        assert resp.status_code == 202
        assert resp.json()["events"].startswith("/api/audits/")
        body = _wait_done(client, resp.json()["job_id"])
        assert body["status"] == "done"
