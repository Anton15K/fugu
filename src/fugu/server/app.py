"""FastAPI application factory for the Fugu audit server.

    create_app(stages=None) -> FastAPI

Routes:
    POST /audits                  submit an audit (202 + job_id)
    GET  /audits/{job_id}         job fields + stages + findings
    GET  /audits/{job_id}/events  SSE stream of StageEvent envelopes
    GET  /health                  liveness probe
    /                             static frontend (web/dist, if built)

The app boots and serves jobs with zero stages (jobs finish instantly
with empty findings) so the server lands before the pipeline stages do.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Iterable

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Mount

from fugu.server.jobs import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    JobStore,
    finding_public,
    is_git_source,
    new_job_id,
    run_job,
    stage_public,
)
from fugu.types import AuditJob

__all__ = ["create_app", "AppState"]

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_STATIC_DIR = PROJECT_ROOT / "web" / "dist"

# Events that terminate the SSE stream (after being delivered).
TERMINAL_EVENT_TYPES = ("verdict", "error")

SSE_KEEPALIVE_S = 15.0


def _sse_line(event: Any) -> str:
    """Format one StageEvent as an SSE `data:` line."""
    payload = json.dumps(
        {
            "type": event.type,
            "job_id": event.job_id,
            "ts": event.ts,
            "data": event.data,
        },
        default=str,
    )
    return f"data: {payload}\n\n"


class AuditCreateRequest(BaseModel):
    source: str = Field(..., min_length=1, description="local dir path or git URL")
    depth: str = Field("standard", description="'standard' or 'full'")


class AuditCreateResponse(BaseModel):
    job_id: str
    status: str
    events: str


class AppState:
    """Server singletons attached to app.state.fugu."""

    def __init__(
        self,
        stages: Iterable[Any],
        static_dir: Path | None,
        db: str | Path | None = None,
    ) -> None:
        # Full-pipeline list; depth=standard filters the harness (A/B) stage
        # out per job — "fastest path to verdict" must actually skip it.
        self._stages_all: list[Any] = list(stages)
        self.stages: list[Any] = self._stages_all
        store: JobStore | None = None
        if db is not None:
            from fugu.store.sqlite import SqliteJobStore

            store = JobStore(store=SqliteJobStore(db))
        self.store = store if store is not None else JobStore()
        self.static_dir = static_dir

    def stages_for(self, depth: str) -> list[Any]:
        """Per-depth stage list: standard skips the harness A/B stage."""
        if depth == "full":
            return self._stages_all
        return [s for s in self._stages_all if "harness" not in type(s).__name__.lower()]


def create_app(
    stages: Iterable[Any] | None = None,
    static_dir: str | Path | None = None,
    cors_origins: list[str] | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    db: str | Path | None = None,
) -> FastAPI:
    """Build the Fugu audit server.

    stages: injected pipeline stages (Stage protocol). Defaults to an
    empty list until the real stages land; jobs then complete with no
    findings. static_dir: web/dist location (default <repo>/web/dist);
    a missing dir is fine — no static routes are mounted. cors_origins
    defaults to wide-open (dev). db: SQLite path for job persistence
    (restart-safe GET /audits/<id>); None keeps the store in-memory.
    """
    resolved_static = Path(static_dir) if static_dir is not None else DEFAULT_STATIC_DIR
    app = FastAPI(
        title="Fugu Audit Server",
        description="Agentic security auditor for third-party agent extensions.",
        version="0.1.0",
    )
    state = AppState(stages or [], resolved_static, db=db)
    app.state.fugu = state

    if cors_origins is None:
        cors_origins = ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- routes (registered BEFORE the static mount) --------------------------
    # Routes are defined once on a router and mounted TWICE: at "/" (curl,
    # tests) and at "/api" (the SPA's API_BASE both in dev - the vite proxy
    # forwards /api/* verbatim - and in production same-origin).
    api = APIRouter()

    @api.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "fugu-audit-server",
            "stages": [getattr(s, "name", type(s).__name__) for s in state.stages],
            "jobs": len(state.store.all_ids()),
        }

    @api.post("/audits", status_code=202, response_model=AuditCreateResponse)
    async def create_audit(req: AuditCreateRequest) -> AuditCreateResponse:
        if req.depth not in ("standard", "full"):
            raise HTTPException(
                status_code=422,
                detail=f"depth must be 'standard' or 'full', got {req.depth!r}",
            )
        source = req.source.strip()
        if not source:
            raise HTTPException(status_code=422, detail="source must not be empty")

        # Source validation at submit time: local paths must exist and be
        # directories. Git URLs cannot be validated offline — they are
        # accepted now and cloned at runtime; clone failures surface as an
        # `error` SSE event + failed job status.
        if not is_git_source(source):
            local = Path(source).expanduser()
            if not local.exists():
                raise HTTPException(
                    status_code=422,
                    detail=f"local source path does not exist: {source}",
                )
            if not local.is_dir():
                raise HTTPException(
                    status_code=422,
                    detail=f"local source path is not a directory: {source}",
                )

        job = AuditJob(id=new_job_id(), source=source, depth=req.depth)  # type: ignore[arg-type]
        state.store.create(job)
        asyncio.create_task(
            run_job(
                job,
                state.stages_for(req.depth),
                state.store,
                max_files=max_files,
                max_bytes=max_bytes,
            )
        )
        return AuditCreateResponse(
            job_id=job.id,
            status=job.status.value,
            events=f"/api/audits/{job.id}/events",
        )

    @api.get("/audits/{job_id}")
    async def get_audit(job_id: str) -> dict[str, Any]:
        snap = state.store.get(job_id)
        if snap is None:
            raise HTTPException(status_code=404, detail=f"unknown job {job_id!r}")
        return {
            "id": snap.job.id,
            "source": snap.job.source,
            "depth": snap.job.depth,
            "status": snap.job.status.value,
            "created_at": snap.job.created_at,
            "stages": [stage_public(r) for r in snap.stages],
            "findings": [finding_public(f) for f in snap.findings],
        }

    @api.get("/audits/{job_id}/events")
    async def audit_events(job_id: str, request: Request) -> StreamingResponse:
        snap = state.store.get(job_id)
        if snap is None:
            raise HTTPException(status_code=404, detail=f"unknown job {job_id!r}")

        queue = state.store.subscribe(job_id)

        async def gen() -> Any:
            try:
                # Replay event history first (client may connect after the
                # job finished), then live-tail until a terminal event or the
                # store's EOF sentinel. (History lives in memory; the SQLite
                # pass will persist it properly.)
                replayed: set[int] = set()
                for event in list(snap.events):
                    replayed.add(id(event))
                    yield _sse_line(event)
                    if event.type in TERMINAL_EVENT_TYPES:
                        return
                if snap.ended:
                    return
                while True:
                    try:
                        event = await asyncio.wait_for(
                            queue.get(), timeout=SSE_KEEPALIVE_S
                        )
                    except asyncio.TimeoutError:
                        if await request.is_disconnected():
                            break
                        yield ": keepalive\n\n"
                        continue
                    if event is None:  # EOF sentinel from store.close()
                        break
                    if id(event) in replayed:  # already sent via history
                        continue
                    yield _sse_line(event)
                    if event.type in TERMINAL_EVENT_TYPES:
                        break
                while not queue.empty():  # drain residue → clean unsubscribe
                    queue.get_nowait()
            finally:
                state.store.unsubscribe(job_id, queue)

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    app.include_router(api)
    app.include_router(api, prefix="/api")

    # --- static frontend (optional, LAST so /audits wins) ----------------------

    if resolved_static is not None and resolved_static.is_dir():
        class SPAStaticFiles(StaticFiles):
            """Serve index.html for unknown paths (history-mode router).

            StaticFiles raises HTTPException(404) on missing files (and
            older versions return a 404 response); handle both shapes.
            """

            async def get_response(self, path: str, scope: Any) -> Any:
                try:
                    response = await super().get_response(path, scope)
                except StarletteHTTPException as exc:
                    if exc.status_code != 404:
                        raise
                    return await super().get_response("./index.html", scope)
                if response.status_code == 404:
                    response = await super().get_response("./index.html", scope)
                return response

        app.router.routes.append(
            Mount("/", app=SPAStaticFiles(directory=resolved_static, html=True), name="spa")
        )

    return app


# Dev entrypoint: python -m fugu.server.app
if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        create_app(),
        host=os.environ.get("FUGU_HOST", "127.0.0.1"),
        port=int(os.environ.get("FUGU_PORT", "8000")),
    )
