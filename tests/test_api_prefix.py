"""Repro: /api/* routes are shadowed by the SPA static mount.

FastAPI matches routes in order; the SPA Mount at "/" is appended to
app.router.routes AFTER include_router - but include_router(api, prefix='/api')
may register on the app BEFORE the mount... this test pins the correct
behavior: POST /api/audits must reach the API, not the static handler.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from fugu.server.app import create_app  # noqa: E402


def test_api_prefix_routes_win_over_spa_mount(tmp_path):
    static_dir = tmp_path / "dist"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<html>spa</html>")
    app = create_app(stages=[], static_dir=static_dir)
    client = TestClient(app)

    # POST /api/audits must NOT be swallowed by the SPA static mount (405)
    r = client.post(
        "/api/audits",
        json={"source": "corpus/07-clean-skill", "depth": "standard"},
    )
    assert r.status_code == 202, f"expected 202, got {r.status_code}: {r.text[:200]}"

    # GET /api/health must be JSON, not the SPA fallback
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json"), r.headers["content-type"]

    # SSE endpoint under /api must stream, not return html
    r = client.get("/api/audits/does-not-exist/events")
    assert r.status_code != 200 or "text/event-stream" in r.headers.get("content-type", "")
