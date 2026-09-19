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
    client = TestClient(app)
    job_id = _submit(client, str(FIXTURE_DIR))
    body = _wait_done(client, job_id)
    assert body["status"] == "done"
    assert body["stages"] == []
    assert body["findings"] == []


def test_create_app_default_stages_is_empty() -> None:
    app = _make_app()  # no stages argument at all
    client = TestClient(app)
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
    client = TestClient(app)

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
    assert verdict["severity_counts"] == {"high": 1, "info": 1}
    assert len(verdict["stages"]) == 2

    # stage_done of the failed stage carries the error
    done_events = [e for e in events if e["type"] == "stage_done"]
    assert done_events[1]["data"]["ok"] is False
    assert "RuntimeError" in (done_events[1]["data"]["error"] or "")


def test_sse_stream_closes_after_verdict() -> None:
    app = _make_app([FakeFindingStage()])
    client = TestClient(app)
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
        assert await extract_source(job) == FIXTURE_DIR

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
    client = TestClient(app)
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
