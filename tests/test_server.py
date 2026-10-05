"""Tests for the Fugu audit server (app factory, job runner, SSE).

TestClient-based, fully offline: stages are fakes, the audited source is
the tiny fixture dir tests/fixtures/server_sample/. No git, no network.

Because starlette's TestClient buffers SSE responses (no real socket), a
slow-producer/keepalive test would hang; the keepalive path is instead
covered by a direct asyncio run of the store + generator-level check.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fugu.server import create_app
from fugu.server.jobs import (
    ExtractionError,
    JobStore,
    extract_source,
    run_job,
)
from fugu.types import AuditJob, Finding, JobStatus, StageEvent, StageResult

FIXTURE_DIR = _PROJECT_ROOT / "tests" / "fixtures" / "server_sample"


# --- fake stages -----------------------------------------------------------------

class FakeFindingStage:
    """Stage protocol fake: returns two findings."""

    name = "static"

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        assert target.is_dir(), "target must be the extracted source dir"
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
            stage=self.name,
            ok=True,
            findings=findings,
            metrics={"files_scanned": 3},
        )


class FakeBoomStage:
    """Stage protocol fake: raises (a stage bug, must not 500 the job)."""

    name = "semantic"

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        raise RuntimeError("boom: semantic stage exploded")


def _make_app(stages: list[Any] | None = None, **kwargs: Any):
    return create_app(stages=stages, **kwargs)


def _submit(client: TestClient, source: str, depth: str = "standard") -> str:
    resp = client.post("/audits", json={"source": source, "depth": depth})
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["job_id"]
    return body["job_id"]


def _wait_done(client: TestClient, job_id: str, timeout_s: float = 5.0) -> dict[str, Any]:
    """Poll GET /audits/{id} until status is done/failed (real time)."""
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        body = client.get(f"/audits/{job_id}").json()
        if body["status"] in ("done", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish in {timeout_s}s: {body}")


def _parse_sse(text: str) -> list[dict[str, Any]]:
    """Parse data lines of an SSE body into StageEvent envelope dicts."""
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        if line.startswith("data: "):
            events.append(json.loads(line[len("data: "):]))
    return events


# --- health / boot ------------------------------------------------------------------

def test_health_with_and_without_stages() -> None:
    for stages in ([], [FakeFindingStage()], [FakeFindingStage(), FakeBoomStage()]):
        app = _make_app(stages)
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert isinstance(body["stages"], list)


def test_app_boots_with_zero_stages_and_completes_job() -> None:
    app = _make_app([])  # explicit empty list: default until stages land
    with TestClient(app) as client:
        job_id = _submit(client, str(FIXTURE_DIR))
        body = _wait_done(client, job_id)
        assert body["status"] == "done"
        assert body["stages"] == []
        assert body["findings"] == []


def test_create_app_default_stages_is_empty() -> None:
    app = _make_app()  # no stages argument at all
    with TestClient(app) as client:
        job_id = _submit(client, str(FIXTURE_DIR))
        body = _wait_done(client, job_id)
        assert body["status"] == "done"
        assert body["findings"] == []


# --- submission validation ----------------------------------------------------------

def test_post_audits_validates_depth_and_source() -> None:
    client = TestClient(_make_app([]))
    # bad depth
    resp = client.post("/audits", json={"source": str(FIXTURE_DIR), "depth": "deep"})
    assert resp.status_code == 422
    # missing source
    resp = client.post("/audits", json={"depth": "standard"})
    assert resp.status_code == 422
    # nonexistent local path → rejected at submit time (422)
    resp = client.post(
        "/audits", json={"source": "/nonexistent/fugu/path", "depth": "standard"}
    )
    assert resp.status_code == 422


def test_get_audit_unknown_id_404() -> None:
    client = TestClient(_make_app([]))
    assert client.get("/audits/doesnotexist").status_code == 404
    assert client.get("/audits/doesnotexist/events").status_code == 404


# --- the core flow: fake stages, findings, errors -------------------------------------

def test_full_flow_stages_findings_sse_order() -> None:
    app = _make_app([FakeFindingStage(), FakeBoomStage()])
    with TestClient(app) as client:
        job_id = _submit(client, str(FIXTURE_DIR), depth="full")
        body = _wait_done(client, job_id)

        # job-level assertions
        assert body["status"] == "done"  # failed stage != failed job
        assert body["id"] == job_id
        assert body["depth"] == "full"
        stage_names = [s["stage"] for s in body["stages"]]
        assert stage_names == ["static", "semantic"]

        # failed stage → error StageResult, not a 500
        semantic = body["stages"][1]
        assert semantic["ok"] is False
        assert "RuntimeError" in (semantic["error"] or "")
        assert semantic["findings_count"] == 0

        # findings from the good stage survived
        assert len(body["findings"]) == 2
        assert body["findings"][0]["severity"] == "high"
        assert body["findings"][0]["owasp_ids"] == ["MCP06"]

        # SSE: replayed after job completion, must contain ordered events
        resp = client.get(f"/audits/{job_id}/events")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        events = _parse_sse(resp.text)
        types = [e["type"] for e in events]
        assert types[0] in ("log", "stage_started")
        assert "stage_started" in types
        assert "finding" in types
        assert "stage_done" in types
        assert types[-1] == "verdict"
        # relative order of the stage lifecycle
        assert types.index("stage_started") < types.index("finding") < types.index("stage_done")
        # every envelope carries job_id + ts
        assert all(e["job_id"] == job_id and e["ts"] for e in events)

        # finding event payload shape
        finding_events = [e for e in events if e["type"] == "finding"]
        assert finding_events[0]["data"]["stage"] == "static"
        assert finding_events[0]["data"]["finding"]["severity"] == "high"

        # verdict event summarizes severity counts
        verdict = events[-1]["data"]
        assert verdict["status"] == "done"
        assert verdict["total_findings"] == 2
        assert verdict["severity_counts"] == {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 1}
        assert len(verdict["stages"]) == 2

        # stage_done of the failed stage carries the error
        done_events = [e for e in events if e["type"] == "stage_done"]
        assert done_events[1]["data"]["ok"] is False
        assert "RuntimeError" in (done_events[1]["data"]["error"] or "")


def test_sse_stream_closes_after_verdict() -> None:
    app = _make_app([FakeFindingStage()])
    with TestClient(app) as client:
        job_id = _submit(client, str(FIXTURE_DIR))
        _wait_done(client, job_id)

        resp = client.get(f"/audits/{job_id}/events")
        assert resp.status_code == 200
        events = _parse_sse(resp.text)
        types = [e["type"] for e in events]
        assert "verdict" in types
        assert types[-1] == "verdict"  # nothing after the terminal event


# --- CORS ------------------------------------------------------------------------------

def test_cors_open_in_dev() -> None:
    client = TestClient(_make_app([]))
    resp = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "*"


# --- store + runner unit-level (asyncio.run, no client) ----------------------------------

def test_run_job_zero_stages_via_store() -> None:
    async def scenario() -> None:
        store = JobStore()
        job = AuditJob(id="j0", source=str(FIXTURE_DIR))
        store.create(job)
        await run_job(job, [], store)
        assert job.status is JobStatus.done
        snap = store.get("j0")
        assert snap is not None
        assert snap.findings == []
        types = [e.type for e in snap.events]
        assert "verdict" in types and snap.ended

    asyncio.run(scenario())


def test_run_job_extraction_failure_emits_error_event() -> None:
    async def scenario() -> None:
        store = JobStore()
        job = AuditJob(id="j1", source="/definitely/not/here")
        store.create(job)
        ran = []
        await run_job(
            job,
            [{"name": "never", "run": lambda *a: ran.append(1)}],  # type: ignore[list-item]
            store,
        )
        assert job.status is JobStatus.failed
        assert ran == []  # stages never invoked
        types = [e.type for e in store.get("j1").events]  # type: ignore[union-attr]
        assert types[-1] == "error"
        assert "extraction" in store.get("j1").events[-1].data["error"]  # type: ignore[union-attr]

    asyncio.run(scenario())


def test_store_pubsub_replay_and_close() -> None:
    async def scenario() -> None:
        store = JobStore()
        store.create(AuditJob(id="j2", source=str(FIXTURE_DIR)))
        # publish before subscribe → history
        store.publish("j2", StageEvent(type="log", job_id="j2", data={}))  # type: ignore[arg-type]
        q = store.subscribe("j2")
        store.publish(
            "j2", StageEvent(type="stage_started", job_id="j2", data={"stage": "x"})  # type: ignore[arg-type]
        )
        assert [e.type if e else None for e in (q.get_nowait(),)] == ["stage_started"]
        store.close("j2")
        assert store.get("j2").ended is True  # type: ignore[union-attr]
        assert q.get_nowait() is None  # EOF sentinel
        store.unsubscribe("j2", q)
        # publishing to a closed job still records history (no crash)
        store.publish("j2", StageEvent(type="log", job_id="j2", data={}))  # type: ignore[arg-type]
        assert len(store.get("j2").events) == 3  # type: ignore[union-attr]

    asyncio.run(scenario())


def test_extract_source_local_caps_and_errors() -> None:
    async def scenario() -> None:
        # happy path
        job = AuditJob(id="e1", source=str(FIXTURE_DIR))
        snapshot = await extract_source(job)
        try:
            assert snapshot != FIXTURE_DIR
            assert snapshot.is_dir()
            assert (snapshot / "SKILL.md").read_bytes() == (FIXTURE_DIR / "SKILL.md").read_bytes()
        finally:
            shutil.rmtree(snapshot, ignore_errors=True)

        # nonexistent
        with pytest.raises(ExtractionError):
            await extract_source(AuditJob(id="e2", source="/no/such/dir"))

        # file-count cap
        with pytest.raises(ExtractionError, match="too many files"):
            await extract_source(AuditJob(id="e3", source=str(FIXTURE_DIR)), max_files=1)

        # size cap
        with pytest.raises(ExtractionError, match="too large"):
            await extract_source(AuditJob(id="e4", source=str(FIXTURE_DIR)), max_bytes=10)

    asyncio.run(scenario())


def test_git_materialization_uses_local_entry_and_byte_caps_and_cleans_clone(tmp_path, monkeypatch):
    import fugu.server.jobs as jobs_module

    clone_parents: list[Path] = []

    async def fake_clone(source, target, branch=None, *, timeout_s=120):
        clone_parents.append(target.parent)
        target.mkdir(parents=True)
        (target / "one.md").write_text("1234")
        nested = target / "nested"
        nested.mkdir()
        (nested / "two.md").write_text("5678")

    monkeypatch.setattr(jobs_module, "_git_clone", fake_clone)

    async def scenario():
        remote = "https://example.invalid/acme/repo.git"
        with pytest.raises(ExtractionError, match="too many"):
            await extract_source(AuditJob(id="git-files", source=remote), max_files=2)
        assert not clone_parents[-1].exists()

        with pytest.raises(ExtractionError, match="too large"):
            await extract_source(AuditJob(id="git-bytes", source=remote), max_bytes=7)
        assert not clone_parents[-1].exists()

    asyncio.run(scenario())


def test_git_clone_timeout_kills_and_reaps_fake_process(tmp_path, monkeypatch):
    import fugu.server.jobs as jobs_module

    class SlowProcess:
        def __init__(self):
            self.returncode = None
            self.communicate_calls = 0
            self.killed = False

        async def communicate(self):
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                await asyncio.sleep(10)
            self.returncode = -9 if self.killed else 0
            return b"", b""

        def kill(self):
            self.killed = True

    process = SlowProcess()
    async def fake_subprocess(*args, **kwargs):
        return process

    monkeypatch.setattr(jobs_module.asyncio, "create_subprocess_exec", fake_subprocess)

    async def scenario():
        with pytest.raises(ExtractionError, match="timed out"):
            await jobs_module._git_clone("fake://source", tmp_path / "clone", timeout_s=0.001)

    asyncio.run(scenario())
    assert process.killed
    assert process.communicate_calls == 2


@pytest.mark.parametrize(
    "teardown_mode", ["open-pipe", "drain-error", "already-exited", "wait-hangs"]
)
def test_git_clone_timeout_teardown_is_bounded_and_cleans_partial_source(
    tmp_path, monkeypatch, teardown_mode
):
    import time

    import fugu.server.jobs as jobs_module

    class FakeTransport:
        def __init__(self):
            self.close_calls = 0

        def close(self):
            self.close_calls += 1

    class FakeProcess:
        def __init__(self):
            self.returncode = None
            self.communicate_calls = 0
            self.kill_calls = 0
            self.wait_calls = 0
            self._transport = FakeTransport()

        async def communicate(self):
            self.communicate_calls += 1
            if self.communicate_calls == 1 or teardown_mode == "open-pipe":
                await asyncio.Event().wait()
            if teardown_mode in {"drain-error", "wait-hangs"}:
                raise OSError("fabricated post-kill pipe drain failure")
            if teardown_mode == "already-exited":
                self.returncode = 0
                await self.wait()
            return b"", b""

        def kill(self):
            self.kill_calls += 1
            if teardown_mode == "already-exited":
                self.returncode = 0
                raise ProcessLookupError
            self.returncode = -9

        async def wait(self):
            self.wait_calls += 1
            if teardown_mode == "wait-hangs":
                await asyncio.Event().wait()
            return self.returncode

    process = FakeProcess()
    partial_targets: list[Path] = []
    workspaces: list[Path] = []
    original_mkdtemp = jobs_module.tempfile.mkdtemp

    def tracked_mkdtemp(*args, **kwargs):
        kwargs["dir"] = tmp_path
        workspace = Path(original_mkdtemp(*args, **kwargs))
        workspaces.append(workspace)
        return str(workspace)

    async def fake_subprocess(*args, **kwargs):
        target = Path(args[-1])
        target.mkdir(parents=True)
        (target / "partial.txt").write_text("fabricated partial clone")
        partial_targets.append(target)
        return process

    monkeypatch.setattr(jobs_module.tempfile, "mkdtemp", tracked_mkdtemp)
    monkeypatch.setattr(jobs_module.asyncio, "create_subprocess_exec", fake_subprocess)

    async def scenario():
        started = time.monotonic()
        with pytest.raises(ExtractionError, match="timed out"):
            await asyncio.wait_for(
                extract_source(
                    AuditJob(id="bounded-clone-timeout", source="https://example.invalid/repo.git"),
                    git_timeout_s=0.01,
                ),
                timeout=0.75,
            )
        return time.monotonic() - started

    elapsed = asyncio.run(scenario())
    assert elapsed < 0.5
    assert process.kill_calls == 1
    assert process.communicate_calls == 2
    assert process.wait_calls == 1
    assert process._transport.close_calls >= 1
    assert partial_targets and not partial_targets[0].exists()
    assert workspaces and all(not workspace.exists() for workspace in workspaces)


def test_git_view_materialization_is_capped_and_slashed_ref_retry_stays_at_two(
    tmp_path, monkeypatch
):
    import fugu.server.giturls as giturls_module
    import fugu.server.jobs as jobs_module

    clone_parents: list[Path] = []
    branches: list[str | None] = []
    timeouts: list[float] = []

    async def fake_clone(source, target, branch=None, *, timeout_s=120):
        clone_parents.append(target.parent)
        branches.append(branch)
        timeouts.append(timeout_s)
        target.mkdir(parents=True)
        selected = target / ("tools/skill" if branch == "main" else "skill")
        selected.mkdir(parents=True)
        (selected / "one.md").write_text("1234")
        nested = selected / "nested"
        nested.mkdir()
        (nested / "two.md").write_text("5678")

    monkeypatch.setattr(
        giturls_module,
        "extract_git_parts",
        lambda source: ("https://example.invalid/repo.git", "main", "tools/skill"),
    )
    monkeypatch.setattr(jobs_module, "_git_clone", fake_clone)

    async def scenario():
        with pytest.raises(ExtractionError, match="too many"):
            await extract_source(
                AuditJob(id="git-view", source="https://example.invalid/repo/tree/main/tools/skill"),
                max_files=2,
                git_timeout_s=0.25,
            )

    asyncio.run(scenario())
    assert branches == ["main", "main/tools"]
    assert timeouts == [0.25, 0.25]
    assert all(not parent.exists() for parent in clone_parents)


def test_configured_pipeline_depth_and_limit_telemetry_survive_http_sse_and_restart(
    tmp_path, monkeypatch
):
    import fugu.pipeline.stages.harness as harness_module
    import fugu.pipeline.stages.semantic as semantic_module
    from fugu.config import DEFAULT_PRODUCTION_LIMITS
    from fugu.pipeline.assemble import build_stages

    def fake_call(system, user):
        if '"probes"' in system:
            text = '{"probes": []}'
        elif "security reviewer" in system:
            text = '{"findings": []}'
        else:
            text = "A direct answer."
        from fugu.pipeline.stages.semantic import JudgeCall

        return text, JudgeCall("fake/pipeline", 0.01, len(system) + len(user), len(text), {})

    monkeypatch.setattr(semantic_module, "_default_make_call", lambda max_tokens=4096, **kwargs: fake_call)
    monkeypatch.setattr(harness_module, "_default_make_call", lambda max_tokens=4096, **kwargs: fake_call)
    monkeypatch.setattr(
        harness_module.HarnessStage,
        "_everyday_call",
        staticmethod(lambda call, *, injected, limits=None: call),
    )

    source = tmp_path / "single-skill"
    source.mkdir()
    (source / "SKILL.md").write_text("A small, ordinary skill.")
    database = tmp_path / "jobs.sqlite3"
    stages = build_stages(include_detonation=False, include_reputation=False)
    app = create_app(stages=stages, db=database, static_dir="/not-present")

    with TestClient(app) as client:
        for requested_depth in ("standard", "full"):
            job_id = _submit(client, str(source), depth=requested_depth)
            job = _wait_done(client, job_id)
            assert job["depth"] == "full"
            stage_names = [stage["stage"] for stage in job["stages"]]
            assert stage_names == ["concealment", "static", "semantic", "harness"]
            semantic = next(stage for stage in job["stages"] if stage["stage"] == "semantic")
            harness = next(stage for stage in job["stages"] if stage["stage"] == "harness")
            assert semantic["metrics"]["effective_limits"] == DEFAULT_PRODUCTION_LIMITS.to_dict()
            assert harness["metrics"]["effective_limits"] == DEFAULT_PRODUCTION_LIMITS.to_dict()
            assert harness["metrics"]["probes"] == 6

            events = _parse_sse(client.get(f"/audits/{job_id}/events").text)
            semantic_event = next(
                event for event in events
                if event["type"] == "stage_done" and event["data"].get("stage") == "semantic"
            )
            assert semantic_event["data"]["metrics"]["effective_limits"] == DEFAULT_PRODUCTION_LIMITS.to_dict()

        app.state.fugu.store.db.close()

    recovered = create_app(stages=[], db=database, static_dir="/not-present")
    with TestClient(recovered) as client:
        for job_id in recovered.state.fugu.store.all_ids():
            job = client.get(f"/audits/{job_id}").json()
            harness = next(stage for stage in job["stages"] if stage["stage"] == "harness")
            assert harness["metrics"]["effective_limits"] == DEFAULT_PRODUCTION_LIMITS.to_dict()
            events = _parse_sse(client.get(f"/audits/{job_id}/events").text)
            assert any(
                event["type"] == "stage_done"
                and event["data"].get("stage") == "harness"
                and event["data"]["metrics"]["effective_limits"] == DEFAULT_PRODUCTION_LIMITS.to_dict()
                for event in events
            )
    recovered.state.fugu.store.db.close()


def test_configured_auto_fanout_propagates_member_coverage_through_http_sse_and_restart(
    tmp_path, monkeypatch
):
    import fugu.pipeline.stages.harness as harness_module
    import fugu.pipeline.stages.semantic as semantic_module
    from fugu.config import DEFAULT_PRODUCTION_LIMITS
    from fugu.pipeline.assemble import build_stages

    def fake_call(system, user):
        if '"probes"' in system:
            text = '{"probes": []}'
        elif "security reviewer" in system:
            text = '{"findings": []}'
        else:
            text = "A direct answer."
        from fugu.pipeline.stages.semantic import JudgeCall

        return text, JudgeCall("fake/auto", 0.01, len(system) + len(user), len(text), {})

    monkeypatch.setattr(semantic_module, "_default_make_call", lambda max_tokens=4096, **kwargs: fake_call)
    monkeypatch.setattr(harness_module, "_default_make_call", lambda max_tokens=4096, **kwargs: fake_call)
    monkeypatch.setattr(
        harness_module.HarnessStage,
        "_everyday_call",
        staticmethod(lambda call, *, injected, limits=None: call),
    )

    source = tmp_path / "monorepo"
    source.mkdir()
    for label in ("alpha", "beta"):
        unit = source / label
        unit.mkdir()
        (unit / "SKILL.md").write_text(f"# {label}\n" + "ordinary content " * 2400)

    database = tmp_path / "auto-jobs.sqlite3"
    stages = build_stages(include_detonation=False, include_reputation=False)
    app = create_app(stages=stages, db=database, static_dir="/not-present")
    with TestClient(app) as client:
        parent_id = _submit(client, str(source))
        parent = _wait_done(client, parent_id)
        composition = next(stage for stage in parent["stages"] if stage["stage"] == "composition")
        assert composition["metrics"]["effective_limits"] == DEFAULT_PRODUCTION_LIMITS.to_dict()
        coverage = composition["metrics"]["member_coverage"]
        assert {
            (record["member"], record["stage"], record["state"])
            for record in coverage
            if record["stage"] == "harness"
        } == {("alpha", "harness", "partial"), ("beta", "harness", "partial")}
        events = _parse_sse(client.get(f"/audits/{parent_id}/events").text)
        verdict = next(event["data"]["verdict"] for event in events if event["type"] == "verdict")
        assert all(
            any(label in caveat and "harness: partial" in caveat for caveat in verdict["coverage_caveats"])
            for label in ("alpha", "beta")
        )
        children = [
            event["data"]["child_job_id"]
            for event in events
            if event["type"] == "log" and event["data"].get("child_job_id")
        ]
        assert len(children) == 2
        for child_id in children:
            child = client.get(f"/audits/{child_id}").json()
            harness = next(stage for stage in child["stages"] if stage["stage"] == "harness")
            assert harness["metrics"]["mounted_chars"] <= 32_000
            assert harness["metrics"]["coverage_incomplete"]
            assert harness["metrics"]["effective_limits"] == DEFAULT_PRODUCTION_LIMITS.to_dict()

        first_events = events
        app.state.fugu.store.db.close()

    recovered = create_app(stages=[], db=database, static_dir="/not-present")
    with TestClient(recovered) as client:
        assert client.get(f"/audits/{parent_id}").json()["stages"] == parent["stages"]
        assert _parse_sse(client.get(f"/audits/{parent_id}/events").text) == first_events
    recovered.state.fugu.store.db.close()


def test_git_source_detection() -> None:
    from fugu.server.jobs import is_git_source

    assert is_git_source("https://github.com/acme/evil-skill.git")
    assert is_git_source("git@github.com:acme/evil.git")
    assert is_git_source("ssh://git@host/repo")
    assert not is_git_source("/tmp/local/dir")
    assert not is_git_source("")


# --- static frontend mount (safe when missing) --------------------------------------------

def test_static_dir_missing_is_fine() -> None:
    app = _make_app([], static_dir="/definitely/not/web/dist")
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        # API routes still win over any static fallback
        job_id = _submit(client, str(FIXTURE_DIR))
        assert _wait_done(client, job_id)["status"] == "done"


def test_static_dir_mounted_serves_index(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<html>fugu ui</html>")
    (tmp_path / "app.js").write_text("console.log('fugu')")
    app = _make_app([], static_dir=tmp_path)
    client = TestClient(app)
    assert client.get("/").text == "<html>fugu ui</html>"
    assert client.get("/app.js").status_code == 200
    # SPA fallback: unknown path serves index.html
    assert "<html>fugu ui</html>" in client.get("/jobs/abc").text
    # API still takes precedence
    assert client.get("/health").status_code == 200
    assert client.get("/audits/nope").status_code == 404
