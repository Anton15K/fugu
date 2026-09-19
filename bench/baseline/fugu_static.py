"""Fugu static-tier baseline (S0 concealment + S1 static) over the corpus.

Writes bench/baseline/fugu_static.json:
  {sample: {"kind": ..., "owasp_ids": [...], "n_findings": N,
            "findings": [{stage, rule, confidence, owasp_ids}...]}}
Run with NEBIUS_API_KEY unset so only deterministic stages produce output.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "corpus"
OUT = ROOT / "bench" / "baseline" / "fugu_static.json"

from fugu.pipeline import run_audit  # noqa: E402

rows: dict[str, dict] = {}
for d in sorted(CORPUS.iterdir()):
    if not (d / "manifest.json").is_file():
        continue
    manifest = json.loads((d / "manifest.json").read_text())
    findings = run_audit(
        d,
        include_detonation=False,
        include_semantic=False,
        include_harness=False,
        include_reputation=False,
    )
    ids: list[str] = []
    slim = []
    for f in findings or []:
        fids = list(getattr(f, "owasp_ids", []) or [])
        ids.extend(fids)
        slim.append(
            {
                "stage": getattr(f, "stage", None),
                "rule": getattr(f, "rule", None) or getattr(f, "check_id", None),
                "confidence": getattr(f, "confidence", None),
                "owasp_ids": fids,
            }
        )
    rows[d.name] = {
        "kind": manifest.get("kind"),
        "expected": manifest.get("expected_owasp_ids", []),
        "n_findings": len(findings or []),
        "owasp_ids": list(dict.fromkeys(ids)),
        "findings": slim,
    }

OUT.write_text(json.dumps(rows, indent=2))
print(json.dumps({k: {"kind": v["kind"], "ids": v["owasp_ids"], "n": v["n_findings"]} for k, v in rows.items()}, indent=2))
