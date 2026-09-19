"""mitmproxy addon: log every REQUEST {host, path, body, ts} to JSONL.

Uses the `request` hook (not `response`) deliberately: attacker/C2 domains
usually don't resolve upstream, so flows would error before a response exists.
The request hook fires as soon as the decrypted request is parsed — evidence is
captured even when upstream is dead. The proxy itself runs with
`--set connection_strategy=lazy` for the same reason (see spike 001 verdict).

Output path via env FUGU_MITM_OUT (default /logs/mitm.log) — NOT argv: this
module is imported INTO the mitmdump process, whose argv belongs to mitmdump.
Records are appended as JSONL: {ts, host, path, method, body<=2000 chars}.
"""
import json
import os
from datetime import datetime, timezone

OUT = os.environ.get("FUGU_MITM_OUT", "/logs/mitm.log")


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
