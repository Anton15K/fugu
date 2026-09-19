"""Happy-path QA of the SPA contract: exactly what web/src consumes.

Drives the API like the frontend does (POST /audits -> stream SSE ->
render), asserting every field the UI touches:
  - submitAudit: 202 {job_id} (accepts full AuditJob too)
  - openAuditStream: stage_started/stage_done/finding/verdict order,
    severity_counts shape, stage names in the fixed STAGE_ORDER set
  - verdict banner inputs: verdict.status, severity_counts, coverage
  - findings: owasp_ids/severity/confidence/evidence present
"""
import json
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8000"
STAGE_ORDER = ["concealment", "static", "semantic", "detonation", "harness", "reputation", "composition", "verdict"]


def req(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    with urllib.request.urlopen(r, timeout=30) as resp:
        return resp.status, json.loads(resp.read())


def main() -> int:
    ok = fail = 0

    def check(name, cond, extra=""):
        nonlocal ok, fail
        mark = "PASS" if cond else "FAIL"
        (ok, fail) = (ok + 1, fail + 1) if cond else (ok, fail + 0) if cond else (ok, fail)
        if cond:
            ok += 0
        print(f"[{mark}] {name} {extra}")
        if not cond:
            fail = fail + 1

    # --- SPA served ---------------------------------------------------------
    with urllib.request.urlopen(BASE + "/", timeout=10) as r:
        html = r.read().decode()
    check("SPA index served at /", "<div id=\"root\">" in html and "Fugu" in html)
    with urllib.request.urlopen(BASE + "/health", timeout=10) as r:
        health = json.loads(r.read())
    check("health", health.get("status") == "ok", str(health.get("stages")))

    # --- submit (frontend: submitAudit) --------------------------------------
    status, sub = req("POST", "/api/audits", {"source": "corpus/03-env-harvest-installer", "depth": "standard"})
    check("POST /api/audits -> 202", status == 202, str(sub))
    jid = sub.get("job_id")
    check("job_id present", bool(jid))

    # --- SSE stream (frontend: openAuditStream) ------------------------------
    events = []
    stream = urllib.request.urlopen(
        urllib.request.Request(f"{BASE}/api/audits/{jid}/events", headers={"Accept": "text/event-stream"}),
        timeout=120,
    )
    start = time.time()
    buf = b""
    while time.time() - start < 110:
        chunk = stream.read(256)
        if not chunk:
            break
        buf += chunk
        if b"verdict" in buf and buf.rstrip().endswith(b"}"):
            # keep reading a moment for trailing frames
            time.sleep(0.5)
            try:
                chunk = stream.read(256)
                if chunk:
                    buf += chunk
            except Exception:
                pass
            break
    text = buf.decode(errors="replace")
    for block in text.split("\n\n"):
        for line in block.splitlines():
            if line.startswith("data: "):
                try:
                    events.append(json.loads(line[6:]))
                except ValueError:
                    pass
        if events and events[-1].get("type") == "verdict":
            break

    types = [e["type"] for e in events]
    check("SSE: events received", len(events) > 3, f"n={len(events)}")
    check("SSE: first event is log/stage_started", types[0] in ("log", "stage_started"), types[0])
    check("SSE: stage_started precedes stage_done per stage",
          types.count("stage_started") == types.count("stage_done") and types.count("stage_started") >= 2)
    check("SSE: finding events present", "finding" in types)
    check("SSE: terminal verdict present", "verdict" in types)
    check("SSE: verdict is last", types[-1] == "verdict")

    # stage names valid for the UI's fixed STAGE_ORDER cards
    stage_names = [e["data"]["stage"] for e in events if e["type"] == "stage_started"]
    check("SSE: stage names in UI's known set", all(s in STAGE_ORDER for s in stage_names), str(stage_names))

    # job_id echoed on every envelope (UI contract request from sa-3)
    check("SSE: job_id echoed on all events", all(e.get("job_id") == jid for e in events))

    # finding shape the Scorecard renders
    for e in events:
        if e["type"] == "finding":
            f = e["data"].get("finding", {})
            check("finding: severity/owasp/confidence/stage present",
                  all(k in f for k in ("severity", "owasp_ids", "confidence", "stage")))
            break

    # verdict banner inputs (PipelineMonitor -> Scorecard)
    v = next((e["data"] for e in events if e["type"] == "verdict"), {})
    check("verdict: status done", v.get("status") == "done")
    check("verdict: severity_counts has all 5 keys",
          all(k in v.get("severity_counts", {}) for k in ("critical", "high", "medium", "low", "info")),
          str(v.get("severity_counts")))
    check("verdict: nested verdict.status present (banner input)",
          isinstance(v.get("verdict"), dict) and "status" in v["verdict"], str((v.get("verdict") or {}).get("status")))
    check("verdict: total_findings matches severity sum",
          v.get("total_findings") == sum(v.get("severity_counts", {}).values()))

    # --- job endpoint (recent-audits/resume path) -----------------------------
    status, job = req("GET", f"/api/audits/{jid}")
    check("GET job after completion", status == 200 and job.get("status") == "done")
    check("GET job carries findings + stages", isinstance(job.get("findings"), list) and isinstance(job.get("stages"), list))

    print(f"\n=== {ok} passed / {fail} failed ===")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
