"""mitmproxy addon: log every REQUEST {host, path, body, ts} to JSONL.

Uses the `request` hook (not `response`) deliberately: attacker/C2 domains
usually don't resolve upstream, so flows would error before a response exists.
The request hook fires as soon as the decrypted request is parsed — evidence is
captured even when upstream is dead.
"""
import json
from datetime import datetime, timezone

OUT = "/logs/mitm.log"


class EvidenceCollector:
    def request(self, flow):
        try:
            body = flow.request.get_text(strict=False) or ""
        except Exception:
            body = "<binary>"
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "host": flow.request.pretty_host,
            "path": flow.request.path,
            "method": flow.request.method,
            "body": body[:2000],
        }
        with open(OUT, "a") as f:
            f.write(json.dumps(rec) + "\n")


addons = [EvidenceCollector()]
