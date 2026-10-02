"""Reproducible label-free S0/S1 and bounded S2 evaluation; never executes targets.

Offline: python -m bench.fresh_benchmark --out bench/results/<new-directory>
Live: add --semantic (at most 210 attempts, no SDK retries, 90s timeout/call).
Uses cached public corpora; no automatic downloads or shared dependency changes.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SEED = "20261002"
MEDPLUS = {"medium", "high", "critical"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def aggregate(rows: list[dict]) -> dict:
    completed = [r for r in rows if r["complete"]]
    flagged = sum(r["flagged"] is True for r in completed)
    return {"attempted": len(rows), "completed": len(completed),
            "incomplete": len(rows) - len(completed), "flagged": flagged,
            "rate": flagged / len(completed) if completed else None}


def select_balanced(rows: list[dict], group: str, identity: str,
                    per_group: int, seed: str) -> list[dict]:
    groups = defaultdict(list)
    for row in rows:
        groups[row[group]].append(row)
    selected = []
    for name in sorted(groups):
        members = sorted(groups[name], key=lambda r: digest((seed + ':' + r[identity]).encode()))
        if len(members) < per_group:
            raise ValueError(f"Insufficient cases in {name}")
        selected.extend(members[:per_group])
    return selected


def clean_tool_document(case: dict) -> dict:
    # Identical wrapper for malicious and benign descriptions. No provenance,
    # labels, category, attack hints, or raw case file reach either scanner.
    return {"tools": [{"name": case["poisoned_tool_name"],
                       "description": case["poisoned_description"],
                       "inputSchema": {"type": "object", "properties": {}},
                       "annotations": {"readOnlyHint": True, "destructiveHint": False,
                                       "idempotentHint": True, "openWorldHint": False}}]}


def source_hashes() -> dict:
    paths = sorted((ROOT / 'src/fugu').rglob('*.py')) + [Path(__file__)]
    return {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in paths}


class BudgetedJudge:
    """Existing config/client/router, explicit budget, fail-closed circuit breaker."""

    def __init__(self, limit: int = 210):
        from fugu.config import get_settings
        from fugu.client import make_client
        from fugu.model_router import pick_model
        settings = get_settings()
        self.stop_reason = None if settings.has_api_key else "missing_api_key"
        self.client = make_client(settings).with_options(max_retries=0, timeout=90) if settings.has_api_key else None
        self.model = pick_model("audit semantic security analysis")
        self.limit = limit
        self.attempts = 0
        self.calls = []

    def __call__(self, system: str, user: str):
        from fugu.pipeline.stages.semantic import JudgeCall
        if self.stop_reason or self.attempts >= self.limit:
            self.stop_reason = self.stop_reason or "call_budget_exhausted"
            raise RuntimeError(self.stop_reason)
        self.attempts += 1
        start = time.perf_counter()
        try:
            response = self.client.chat.completions.create(
                model=self.model, messages=[{"role": "system", "content": system},
                                            {"role": "user", "content": user}],
                temperature=0.1, max_tokens=1600)
        except Exception as exc:
            # Inspect locally for classification; never retain headers, credentials,
            # request bodies or raw provider error text.
            message = str(exc).lower()
            status = getattr(exc, "status_code", None)
            if any(s in message for s in ("insufficient_quota", "quota exceeded", "quota exhausted", "insufficient balance", "credit balance")) or status == 402:
                self.stop_reason = "provider_quota_exhausted"
            elif status == 429:
                self.stop_reason = "rate_limited_not_proven_quota_exhaustion"
            elif status in (401, 403):
                self.stop_reason = "provider_auth_failure"
            else:
                self.stop_reason = f"provider_error_{type(exc).__name__}_{status}"
            raise RuntimeError(self.stop_reason) from None
        text = (response.choices[0].message.content or "").strip()
        usage = response.usage
        rec = JudgeCall(model=self.model, latency_s=round(time.perf_counter() - start, 3),
                        prompt_chars=len(system) + len(user), completion_chars=len(text),
                        usage={"prompt_tokens": getattr(usage, "prompt_tokens", None),
                               "completion_tokens": getattr(usage, "completion_tokens", None)})
        self.calls.append(asdict(rec))
        return text, rec


def discover() -> tuple[list[dict], list[dict]]:
    from bench.mcptox.run_puretool import load_pure_tool
    from bench.mcptox.fetch import load_cases, SHA256
    datasets = []
    samples = []
    for name, file, loader in [
        ("mcptox_pure", ROOT / "bench/mcptox/data/pure_tool.json", load_pure_tool),
        ("mcptox_full", ROOT / "bench/mcptox/data/response_all.json", load_cases),
    ]:
        content = file.read_bytes()
        if name == "mcptox_full" and digest(content) != SHA256:
            raise ValueError("Full MCPTox source hash mismatch")
        cases = loader(file)
        datasets.append({"name": name, "path": str(file.relative_to(ROOT)),
                         "sha256": digest(content), "n": len(cases)})
        for case in cases:
            samples.append({"id": name + '/' + case['case_id'], "set": name,
                            "kind": "malicious", "group": case['paradigm'],
                            "category": case['category'], "tool": case})
    clean_path = ROOT / 'bench/results/2026-10-02/sources/fuzzd-bench_clean_tools.json'
    clean = json.loads(clean_path.read_text())
    datasets.append({"name": "fuzzd_clean", "path": str(clean_path.relative_to(ROOT)),
                     "sha256": digest(clean_path.read_bytes()), "n": len(clean)})
    for tool in clean:
        samples.append({"id": 'fuzzd_clean/' + tool['name'], "set": "fuzzd_clean",
                        "kind": "benign", "group": "constructed clean tools",
                        "tool": {"poisoned_tool_name": tool['name'],
                                 "poisoned_description": tool['description']}})
    bases = [(ROOT / 'corpus', 'manifest.json', 'crafted')] + [
        (p, 'manifest.fugu.json', 'public_skills') for p in sorted((ROOT / 'bench/real').glob('*-samples'))]
    for base, manifest, name in bases:
        for directory in sorted(base.iterdir()):
            path = directory / manifest
            if not path.is_file():
                continue
            meta = json.loads(path.read_text())
            samples.append({"id": name + '/' + base.name + '/' + directory.name,
                            "set": name, "kind": meta['kind'], "group": base.name,
                            "path": str(directory.relative_to(ROOT))})
    if len({s['id'] for s in samples}) != len(samples):
        raise ValueError("Duplicate sample identity")
    return samples, datasets


async def audit(sample: dict, semantic: bool, judge: BudgetedJudge | None) -> dict:
    from fugu.pipeline import build_stages
    from fugu.pipeline.stages.semantic import SemanticStage
    from fugu.pipeline.stages.concealment import collect_text_files
    from fugu.types import AuditJob, JobStatus
    start = time.perf_counter()
    stages = [s for s in build_stages(include_semantic=False, include_harness=False,
              include_detonation=False, include_reputation=False) if s.name in ('concealment', 'static')]
    if semantic:
        stages.append(SemanticStage(make_call=judge))
    row = {k: v for k, v in sample.items() if k != 'tool'}
    row['mode'] = 'S0+S1+S2' if semantic else 'S0+S1'
    with tempfile.TemporaryDirectory(prefix='fugu-benchmark-') as temp:
        target = Path(temp)
        if 'tool' in sample:
            (target / 'tools.json').write_text(json.dumps(clean_tool_document(sample['tool']), indent=2) + '\n')
        else:
            # Scan public extension content only, with evaluation manifests excluded
            # uniformly from BOTH static and semantic inputs.
            original = ROOT / sample['path']
            if original.is_symlink() or any(p.is_symlink() for p in original.rglob('*')):
                raise ValueError(f"Symlink rejected in curated input: {sample['id']}")
            files, _ = collect_text_files(original, 2_000_000, 2000)
            for file in files:
                if Path(file.rel).name.lower() in ('manifest.json', 'manifest.fugu.json', 'case.json'):
                    continue
                out = target / file.rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(file.text)
        inputs = {str(p.relative_to(target)): digest(p.read_bytes()) for p in sorted(target.rglob('*')) if p.is_file()}
        row['input_sha256'] = inputs
        job = AuditJob(id='fresh-benchmark', source=str(target), status=JobStatus.running)
        results = [await stage.run(job, target) for stage in stages]
        row['stages'] = [asdict(r) for r in results]
        complete = bool(inputs) and all(r.ok and not r.metrics.get('skipped') and not r.metrics.get('call_errors')
                                       and not r.metrics.get('parse_errors') for r in results)
        if semantic:
            complete = complete and bool(results[-1].metrics.get('llm_calls'))
        row['complete'] = complete
        row['flagged'] = any(f.severity in MEDPLUS for r in results for f in r.findings) if complete else None
        row['elapsed_s'] = round(time.perf_counter() - start, 3)
    return row


def summarize(rows: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for r in rows:
        groups[(r['set'], r['kind'], r['mode'])].append(r)
    return [dict(zip(('set', 'kind', 'mode'), group), **aggregate(members))
            for group, members in sorted(groups.items())]


async def run(args) -> int:
    args.out.mkdir(parents=True, exist_ok=True)
    result_path = args.out / ('semantic.json' if args.semantic else 'static.json')
    if result_path.exists():
        raise SystemExit(f"Refusing to overwrite {result_path}; choose a new directory")
    samples, datasets = discover()
    if args.semantic:
        attack = select_balanced([s for s in samples if s['set'] == 'mcptox_pure'], 'group', 'id', 10, SEED)
        skills = select_balanced([s for s in samples if s['set'] == 'public_skills'], 'group', 'id', 5, SEED)
        clean = [s for s in samples if s['set'] == 'fuzzd_clean']
        # Interleave classes so interrupted paid work is visible across cohorts.
        samples = [items[i] for i in range(max(map(len, (attack, clean, skills))))
                   for items in (attack, clean, skills) if i < len(items)]
    judge = BudgetedJudge() if args.semantic else None
    source_before = source_hashes()
    result = {"started_utc": datetime.now(timezone.utc).isoformat(),
              "protocol": "label-free-v1", "threshold": "any finding >= medium",
              "seed": SEED, "datasets": datasets,
              "versions": {"python": platform.python_version(),
                           **{p: importlib.metadata.version(p) for p in ('openai', 'pydantic')}},
              "source_hashes_before": source_before,
              "selected_ids": [s['id'] for s in samples],
              "remaining_provider_quota": "unknown; no quota endpoint queried",
              "scope": "S0/S1 and optional S2 only; no target execution; no detector tuning",
              "rows": []}
    start = time.perf_counter()
    for i, sample in enumerate(samples):
        if judge and judge.stop_reason:
            break
        row = await audit(sample, args.semantic, judge)
        result['rows'].append(row)
        result['summary'] = summarize(result['rows'])
        result['elapsed_s'] = round(time.perf_counter() - start, 3)
        if judge:
            result['live'] = {"model": judge.model, "attempts": judge.attempts, "limit": judge.limit,
                              "stop_reason": judge.stop_reason, "calls": judge.calls,
                              "max_retries": 0, "timeout_s": 90, "temperature": 0.1, "max_output_tokens": 1600}
        result_path.write_text(json.dumps(result, indent=2) + '\n')
        if args.semantic or (i + 1) % 100 == 0:
            print(f"{i+1}/{len(samples)} {sample['set']} complete={row['complete']} flagged={row['flagged']}", flush=True)
    result['source_hashes_after'] = source_hashes()
    result['source_changed_during_run'] = source_before != result['source_hashes_after']
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    result['unattempted_ids'] = [s['id'] for s in samples[len(result['rows']):]]
    result_path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result.get('summary', []), indent=2), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--semantic', action='store_true')
    return asyncio.run(run(parser.parse_args()))


if __name__ == '__main__':
    raise SystemExit(main())
