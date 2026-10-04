import ast
import asyncio
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from fugu.pipeline.stages.static_scan import StaticScanStage
from fugu.types import AuditJob
from fugu.verdict import aggregate_verdict

ROOT = Path(__file__).parent


class OfflineScanner:
    def scan(self, *args):
        return [], {"enabled": False}


rows = []
for name, (filename, text, expected) in json.loads(
    (ROOT / "fixtures.json").read_text()
).items():
    target = ROOT / "fixtures" / name
    target.mkdir(parents=True, exist_ok=True)
    path = target / filename
    path.write_text(text)
    if filename.endswith(".py"):
        ast.parse(text)
        syntax = {"parser": "ast.parse", "ok": True}
    else:
        node = shutil.which("node")
        if node:
            p = subprocess.run(
                [node, "--check", str(path)], capture_output=True, text=True, timeout=10
            )
            syntax = {"parser": "node --check", "ok": p.returncode == 0}
        else:
            syntax = {"parser": "node --check", "ok": None}
    result = asyncio.run(
        StaticScanStage(surface_scanner=OfflineScanner()).run(
            AuditJob(id=name, source=str(target)), target
        )
    )
    verdict = aggregate_verdict(result.findings, [result])
    rows.append(
        {
            "case": name,
            "expected_status": expected,
            "fixture_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "syntax": syntax,
            "ok": result.ok,
            "verdict": verdict,
            "findings": [
                {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "contexts": [e.meta.get("source_context") for e in f.evidence],
                    "rules": [e.meta.get("rule") for e in f.evidence],
                }
                for f in result.findings
            ],
        }
    )
value = {
    "scope": "Trusted static parser and fake scanner on inert source text; fixtures are never executed; no provider/target/container calls",
    "source_hashes": {
        p.as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [
            Path("src/fugu/pipeline/stages/static_context.py"),
            Path("src/fugu/pipeline/stages/static_scan.py"),
        ]
    },
    "rows": rows,
}
(ROOT / "context-probes.json").write_text(json.dumps(value, indent=2) + "\n")
fail = [r["case"] for r in rows if r["verdict"]["status"] != r["expected_status"]]
print(json.dumps({"rows": len(rows), "unexpected": fail}))
if fail:
    sys.exit(1)
