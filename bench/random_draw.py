"""TRUE random-draw evaluation from the public skills.sh registry.

MCPZoo-comparable methodology: draw a random (not curated, not
popularity-ordered) sample of registry skills, audit them, report the FLAG
RATE and manually adjudicate every flag. No ground truth exists for a
random draw - that is the point.

Draw policy (documented for reproducibility):
  - catalog: /api/v1/skills requires auth (401 anonymous); PUBLIC surface is
    GET /api/search?q=<term>&limit=100 (fuzzy). We query 30 random common
    English words (fixed list below, rng-seeded order), union + dedupe ids.
    This is a random-draw OVER THE UNION of common-word query results - not
    a full census draw; skills not matching any word are excluded (bias
    documented).
  - sample:  random.Random(seed=20260920).sample(ids, n)  -- fixed seed
  - files:   GET /api/download/{owner}/{repo}/{slug} -> {files:[{path,contents}]}
  - label:   kind="unknown" (random draw; may contain anything)

Usage:
  python -m bench.random_draw --fetch-only   # download skills, no LLM
  python -m bench.random_draw                # fetch if needed + audit (S0+S1+S2)
Writes bench/results/random-draw.md + .json, skills under bench/real/random-draw-samples/.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

RESULTS = ROOT / "bench" / "results"
SAMPLES = ROOT / "bench" / "real" / "random-draw-samples"
SEED = 20260920
N_DRAW = 25

_UA = {"User-Agent": "fugu-benchmark/0.1 (hackathon eval; contact via repo)"}


def _get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


_WORDS = [
    "data", "time", "work", "code", "test", "text", "file", "task", "help",
    "write", "build", "make", "check", "chart", "email", "cloud", "sql",
    "api", "web", "docs", "pdf", "css", "game", "music", "video", "image",
    "budget", "plan", "travel", "health",
]


def catalog_ids(max_pages: int = 20, per_page: int = 100) -> list[str]:
    """Union of public search results over random common words."""
    rng = random.Random(SEED)
    words = _WORDS[:]
    rng.shuffle(words)
    ids: list[str] = []
    seen: set[str] = set()
    for w in words:
        try:
            payload = json.loads(_get(f"https://skills.sh/api/search?q={w}&limit=100"))
        except Exception as exc:
            print(f"search '{w}' failed: {exc}", file=sys.stderr)
            continue
        for row in payload.get("skills") or []:
            rid = str(row.get("id") or "").strip()
            if rid and rid not in seen:
                seen.add(rid)
                ids.append(rid)
        time.sleep(0.4)  # polite
    return ids


def _safe_relpath(path: str) -> Path | None:
    p = Path(path.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or not p.parts:
        return None
    return p


def fetch_sample(rid: str) -> Path | None:
    """Download one skill's files into a sample dir; None on failure."""
    parts = rid.split("/")
    if len(parts) < 3:
        return None
    owner, repo, slug = parts[0], "/".join(parts[1:-1]), parts[-1]
    dest = SAMPLES / rid.replace("/", "__")
    if (dest / "manifest.fugu.json").is_file():
        return dest
    try:
        payload = json.loads(_get(f"https://skills.sh/api/download/{owner}/{repo}/{slug}"))
    except Exception:
        return None
    files = payload.get("files") or []
    dest.mkdir(parents=True, exist_ok=True)
    wrote = 0
    for f in files:
        rel = _safe_relpath(str(f.get("path") or ""))
        content = str(f.get("contents") or "")
        if rel is None or len(content.encode()) > 1_000_000:
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", errors="replace")
        wrote += 1
    if wrote == 0:
        return None
    (dest / "manifest.fugu.json").write_text(
        json.dumps(
            {
                "name": f"random-{slug}"[:80],
                "kind": "unknown",
                "expected_owasp_ids": [],
                "description": f"Random draw from skills.sh registry (id {rid})",
                "provenance": "random-draw",
            },
            indent=2,
        )
        + "\n"
    )
    return dest


def do_fetch(n: int) -> list[Path]:
    ids = catalog_ids()
    print(f"catalog: {len(ids)} unique skill ids")
    rng = random.Random(SEED)
    draw = rng.sample(ids, min(n, len(ids)))
    SAMPLES.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    for i, rid in enumerate(draw):
        got = fetch_sample(rid)
        print(f"{i+1}/{len(draw)} {rid}: {'ok' if got else 'FAILED'}", flush=True)
        if got:
            out.append(got)
        time.sleep(0.3)
    (ROOT / "bench" / "real" / "random-draw-ids.json").write_text(
        json.dumps({"seed": SEED, "drawn": draw, "fetched": len(out)}, indent=1)
    )
    return out


async def do_audit(sample_dirs: list[Path]) -> int:
    from fugu.pipeline import build_stages, run_stages
    from fugu.types import AuditJob, JobStatus

    stages = build_stages(include_detonation=False, include_harness=False, include_reputation=False)
    rows = []
    flagged = []
    t0 = time.time()
    for i, d in enumerate(sample_dirs):
        job = AuditJob(id=f"rd-{i}", source=str(d), status=JobStatus.running)
        results = await run_stages(job, d, stages)
        findings = [f for r in results for f in r.findings]
        med = [f for f in findings if f.severity in ("critical", "high", "medium")]
        rows.append(
            {
                "dir": d.name,
                "findings": len(findings),
                "med_plus": len(med),
                "med": [
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "excerpt": (f.evidence[0].excerpt[:200] if f.evidence else ""),
                    }
                    for f in med
                ],
            }
        )
        if med:
            flagged.append(d.name)
        if (i + 1) % 5 == 0:
            print(f"{i+1}/{len(sample_dirs)} flagged={len(flagged)} {time.time()-t0:.0f}s", flush=True)

    n = len(sample_dirs)
    lines = [
        "# Random-draw audit - skills.sh registry",
        "",
        f"n={n} (seed={SEED}, view=all-time catalog, uniform sample) · mode: S0+S1+S2 · {time.strftime('%Y-%m-%d %H:%M')}",
        "",
        f"**FLAGGED (medium+): {len(flagged)}/{n} ({len(flagged)/n:.0%})** - MCPZoo-comparable flag rate (no ground truth; every flag adjudicated manually below)",
        "",
    ]
    for r in rows:
        if r["med_plus"]:
            lines.append(f"## {r['dir']}")
            for m in r["med"]:
                lines.append(f"- [{m['severity']}/{m['confidence']}] {m['title']}")
                lines.append(f"  > {m['excerpt'][:180]}")
            lines.append("")
    text = "\n".join(lines)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "random-draw.md").write_text(text + "\n")
    (RESULTS / "random-draw.json").write_text(json.dumps(rows, indent=1))
    print(text)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=N_DRAW)
    p.add_argument("--fetch-only", action="store_true")
    args = p.parse_args()

    existing = sorted(SAMPLES.glob("*")) if SAMPLES.is_dir() else []
    existing = [d for d in existing if (d / "manifest.fugu.json").is_file()]
    if args.fetch_only or not existing:
        dirs = do_fetch(args.n)
        if args.fetch_only:
            print(f"fetched {len(dirs)} skills (audit skipped)")
            return 0
    else:
        dirs = existing
        print(f"using {len(dirs)} previously fetched skills")
    return asyncio.run(do_audit(dirs))


if __name__ == "__main__":
    sys.exit(main())
