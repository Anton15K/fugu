"""Integration probe: submit a real audit over HTTP and inspect the result.

Run: uv run --no-sync python scripts/integration_probe.py
Requires the server on :8000 (uv run python -m fugu.server).
"""
import json
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8000"


def req(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.loads(resp.read())


def main() -> int:
    print("health:", req("GET", "/health"))
    t0 = time.time()
    sub = req("POST", "/audits", {"source": "corpus/03-env-harvest-installer", "depth": "standard"})
    print(f"POST /audits -> {sub} ({time.time()-t0:.1f}s)")
    jid = sub["job_id"]

    for _ in range(40):
        time.sleep(3)
        d = req("GET", f"/audits/{jid}")
        if d.get("status") in ("done", "failed"):
            break
    print(f"final status: {d.get('status')} after {time.time()-t0:.1f}s")
    print("stages:")
    for s in d.get("stages", []):
        print(f"  - {s.get('stage')} ok={s.get('ok')} {s.get('error') or ''}")
    fs = d.get("findings", [])
    print(f"findings: {len(fs)}")
    for f in fs[:10]:
        print(f"  * {f.get('severity'):9} {f.get('owasp_ids')} {f.get('confidence'):13} {(f.get('title') or '')[:60]}")
    return 0 if d.get("status") == "done" else 1


if __name__ == "__main__":
    sys.exit(main())
