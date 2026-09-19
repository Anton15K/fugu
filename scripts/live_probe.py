"""Full-pipeline live probe: submit an audit, poll to completion, print the verdict."""
import json
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8000"
SAMPLE = sys.argv[1] if len(sys.argv) > 1 else "corpus/03-env-harvest-installer"


def req(method, path, body=None):
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, timeout=60) as resp:
        return json.loads(resp.read())


t0 = time.time()
sub = req("POST", "/audits", {"source": SAMPLE, "depth": "standard"})
jid = sub["job_id"]
print(f"submitted {jid} for {SAMPLE}")

while True:
    time.sleep(4)
    d = req("GET", f"/audits/{jid}")
    if d.get("status") in ("done", "failed"):
        break
    print(f"  ...{time.time()-t0:.0f}s {d.get('status')}")

print(f"final: {d.get('status')} in {time.time()-t0:.1f}s\n")
for s in d.get("stages", []):
    note = s.get("error") or ("skipped" if "skipped" in (s.get("metrics") or {}) else "ok")
    print(f"  {s.get('stage'):12} {note}")

print(f"\nfindings ({len(d.get('findings', []))}):")
for f in d.get("findings", []):
    print(f"  [{f['severity']:8}] {','.join(f['owasp_ids']):16} {f['confidence']:13} {f['stage']:10} {f['title'][:58]}")
