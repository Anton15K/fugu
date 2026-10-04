import asyncio
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time

from fugu.pipeline.stages.static_context import source_context
from fugu.pipeline.stages.static_scan import StaticScanStage
from fugu.types import AuditJob

PACKAGE = Path(
    "/var/folders/c7/_wznbvx501d1n5562y9w3l8c0000gn/T/fugu-workflow-integration-g_m1668u"
)
OUT = Path("/tmp/fugu-workflow-context-correction-lead")


def signature(findings):
    return sorted(
        (
            f["title"],
            f["severity"],
            f["confidence"],
            tuple(f["owasp_ids"]),
            tuple(e["source"] for e in f["evidence"]),
        )
        for f in findings
    )


async def main():
    indexed = {}
    for path in (PACKAGE / "measurement/audits").glob("*.json"):
        audit = json.loads(path.read_text())
        indexed[json.dumps(audit["input_sha256"], sort_keys=True)] = audit
    cases = json.loads((PACKAGE / "measurement/cases.json").read_text())["cases"]
    stage = StaticScanStage()
    stage.surface_scanner = None
    seen = set()
    checks = []
    for case in cases:
        target = Path(case["target"])
        for member in case.get("members") or [{"dir": None}]:
            directory = target / member["dir"] if member["dir"] else target
            hashes = {
                p.relative_to(directory).as_posix(): hashlib.sha256(
                    p.read_bytes()
                ).hexdigest()
                for p in sorted(directory.rglob("*"))
                if p.is_file()
            }
            key = json.dumps(hashes, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            old = next(s for s in indexed[key]["baseline"] if s["stage"] == "static")
            result = await stage.run(
                AuditJob(id="lead-source-check", source=str(directory)), directory
            )
            same = (
                signature(old["findings"])
                == signature([asdict(f) for f in result.findings])
                and old["ok"] == result.ok
            )
            checks.append(
                {
                    "input_hashes": hashes,
                    "findings": len(result.findings),
                    "decision_signature_and_ok_match": same,
                }
            )
    assert len(checks) == 45
    scaling = []
    for count in (600, 1200, 6000):
        source = "".join(f'paths_{i} = [".env"]\n' for i in range(count))
        start = time.perf_counter()
        context = source_context(source, "synthetic.py")
        elapsed = time.perf_counter() - start
        scaling.append(
            {
                "lists": count,
                "bytes": len(source.encode()),
                "seconds": elapsed,
                "mapped_lines": len(context),
            }
        )
    value = {
        "scope": "Static source parsing only; no provider, chamber, audited command or target execution",
        "baseline_inputs": 45,
        "all_baseline_static_decision_signatures_and_ok_match": all(
            c["decision_signature_and_ok_match"] for c in checks
        ),
        "checks": checks,
        "final_context_scaling": scaling,
        "current_source_hashes": {
            str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path("src/fugu").rglob("*.py"))
        },
    }
    (OUT / "source-only-verification.json").write_text(
        json.dumps(value, indent=2) + "\n"
    )
    print(
        json.dumps(
            {
                "baseline_inputs": 45,
                "same_decisions": all(
                    c["decision_signature_and_ok_match"] for c in checks
                ),
                "scaling": scaling,
            }
        ),
        flush=True,
    )


asyncio.run(main())
