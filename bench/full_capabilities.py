"""Bounded full-capability evaluation; target code runs only in the chamber.

python -m bench.full_capabilities --prepare
python -m bench.full_capabilities --run
No product prompts, detection rules, shared dependencies or old results change.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "bench/results/2026-10-02-full"
SEED = "20261002-full"
MEDPLUS = {"medium", "high", "critical"}
EXCLUDED_FILES = {"manifest.json", "manifest.fugu.json", "case.json", "set.json"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recover_json(text: str) -> tuple[str | None, str | None]:
    """Extract one complete object; remove only commas outside string literals.

    Never complete truncated structures, invent findings, or modify quoted text.
    """
    start = text.find("{")
    if start < 0:
        return None, None
    candidate = text[start:]
    decoder = json.JSONDecoder()
    try:
        value, _ = decoder.raw_decode(candidate)
        if isinstance(value, dict):
            return json.dumps(value, ensure_ascii=False), "json_extract"
    except ValueError:
        pass
    out: list[str] = []
    in_string = escaped = False
    for index, char in enumerate(candidate):
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            out.append(char)
        elif char == "," and candidate[index + 1:].lstrip().startswith(("}", "]")):
            continue
        else:
            out.append(char)
    try:
        value, _ = decoder.raw_decode("".join(out))
        if isinstance(value, dict):
            return json.dumps(value, ensure_ascii=False), "trailing_comma_reparse"
    except ValueError:
        pass
    return None, None


def cohort_score(rows: list[dict]) -> dict:
    completed = [r for r in rows if r["complete"]]
    flagged = sum(bool(r["detected"]) for r in completed)
    return {"attempted": len(rows), "completed": len(completed),
            "excluded": len(rows) - len(completed), "flagged": flagged,
            "completed_rate": flagged / len(completed) if completed else None,
            "attempted_yield": flagged / len(rows) if rows else None}


def stage_state(result: dict) -> str:
    metrics = result.get("metrics") or {}
    if not result["ok"]:
        return "failed"
    if metrics.get("skipped"):
        reason = str(metrics["skipped"])
        if any(s in reason for s in ("no runnable triggers", "no searchable identifiers", "single-source job")):
            return "not_applicable"
        return "unavailable"
    if any(metrics.get(k) for k in ("coverage_incomplete", "call_errors", "parse_errors")):
        return "partial"
    return "completed"


def composition_score(findings: list[dict], expected: dict) -> dict:
    comp = [f for f in findings if f.get("stage") == "composition"]
    trifecta = any("trifecta" in f["title"].lower() for f in comp)
    shadowing = any("shadowing" in f["title"].lower() for f in comp)
    return {"trifecta": trifecta, "shadowing": shadowing,
            "matches_expected": (trifecta == expected["trifecta"] and shadowing == expected["shadowing"]),
            "detected": trifecta or shadowing}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def engine_hashes() -> dict:
    return {str(p.relative_to(ROOT)): digest(p.read_bytes())
            for p in sorted((ROOT / "src/fugu").rglob("*.py"))}


def copy_input(original: Path, target: Path) -> dict:
    from fugu.source_safety import validate_source_tree
    from fugu.pipeline.stages.concealment import collect_text_files
    validate_source_tree(original)
    files, stats = collect_text_files(original, 2_000_000, 2000)
    for file in files:
        if Path(file.rel).name.lower() in EXCLUDED_FILES:
            continue
        path = target / file.rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(file.text)
    return stats


def input_hashes(target: Path) -> dict:
    return {str(p.relative_to(target)): digest(p.read_bytes())
            for p in sorted(target.rglob("*")) if p.is_file()}


def prepare(out: Path) -> dict:
    """Freeze before any live call; labels stay outside opaque target directories."""
    if (out / "cases.json").exists():
        manifest = json.loads((out / "cases.json").read_text())
        for case in manifest["cases"]:
            assert input_hashes(ROOT / case["target"]) == case["input_sha256"]
        return manifest
    from bench.mcptox.run_puretool import load_pure_tool
    source = ROOT / "bench/mcptox/data/pure_tool.json"
    attacks = load_pure_tool(source)
    selected = []
    for group in sorted({r["paradigm"] for r in attacks}):
        members = [r for r in attacks if r["paradigm"] == group]
        selected.extend(sorted(members, key=lambda r: digest((SEED + ':' + r['case_id']).encode()))[:5])
    clean_source = ROOT / "bench/real/fuzzd-cache/clean_tools.json"
    if not clean_source.exists():
        clean_source = ROOT / "bench/results/2026-10-02/sources/fuzzd-bench_clean_tools.json"
    assert digest(clean_source.read_bytes()) == "38b8fbf265e49147a6865836d1eff3796278625599ee47f3ffb2eb7b5f037348"
    clean = sorted(json.loads(clean_source.read_text()), key=lambda r: digest((SEED + ':' + r['name']).encode()))[:5]
    cases = []
    def add(case: dict) -> Path:
        target = out / "targets" / f"{len(cases):04d}"
        target.mkdir(parents=True, exist_ok=True)
        case["target"] = str(target.relative_to(ROOT))
        cases.append(case)
        return target
    for attack in selected:
        target = add({"id": 'mcptox/' + attack['case_id'], "cohort": "mcptox",
                      "kind": "malicious", "paradigm": attack['paradigm'],
                      "source": str(source.relative_to(ROOT))})
        write_json(target / "tools.json", {"tools": [{"name": attack['poisoned_tool_name'],
                   "description": attack['poisoned_description'], "inputSchema": {}}]})
    for tool in clean:
        target = add({"id": 'clean/' + tool['name'], "cohort": "clean_descriptions", "kind": "benign",
                      "source": str(clean_source.relative_to(ROOT))})
        write_json(target / "tools.json", {"tools": [{"name": tool['name'], "description": tool['description'], "inputSchema": {}}]})
    for path in sorted((ROOT / "corpus").glob('*/manifest.json')):
        metadata = json.loads(path.read_text())
        case = {"id": 'crafted/' + path.parent.name, "cohort": "crafted", "kind": metadata['kind'],
                "source": str(path.parent.relative_to(ROOT))}
        target = add(case)
        case["collection"] = copy_input(path.parent, target)
    for path in sorted((ROOT / "corpus/composition").glob('*/set.json')):
        metadata = json.loads(path.read_text())
        case = {"id": 'composition/' + path.parent.name, "cohort": "composition",
                "kind": "malicious" if metadata['kind'] == 'attack' else "benign",
                "source": str(path.parent.relative_to(ROOT)), "members": metadata['members'],
                "expected": metadata['expected']}
        target = add(case)
        case["collection"] = copy_input(path.parent, target)
    for version, kind in (("2.19.1", "vulnerable_dependency"), ("2.32.5", "dependency_control")):
        target = add({"id": 'reputation/requests-' + version, "cohort": "reputation",
                      "kind": kind, "source": "constructed exact-version PyPI dependency probe"})
        (target / "pyproject.toml").write_text('[project]\nname = "dependency-review-fixture"\nversion = "0.0.0"\ndependencies = ["requests==' + version + '"]\n')
    assert len(cases) == 40
    for case in cases:
        case['input_sha256'] = input_hashes(ROOT / case['target'])
    manifest = {"created_utc": datetime.now(timezone.utc).isoformat(), "seed": SEED,
                "threshold": "any finding >= medium; composition uses its own expected rules",
                "schema_adapter": "uniform inputSchema={} required by comparator MCP parsers; no annotations or invented parameters",
                "source_hashes": {str(source.relative_to(ROOT)): digest(source.read_bytes()),
                                  str(clean_source.relative_to(ROOT)): digest(clean_source.read_bytes())},
                "engine_hashes": engine_hashes(), "cases": cases}
    write_json(out / "cases.json", manifest)
    return manifest


class InferenceBudget:
    """Live calls through project client, bounded and sanitized; no target execution."""
    def __init__(self, out: Path, limit: int = 1800):
        from fugu.client import make_client
        from fugu.config import get_settings
        settings = get_settings()
        if not settings.has_api_key:
            raise RuntimeError("missing_nebius_api_key")
        self.client = make_client(settings).with_options(max_retries=0, timeout=90)
        self.out, self.limit = out, limit
        self.lock = threading.Lock()
        self.calls: list[dict] = []
        self.attempts = 0
        self.stop_reason = None
        self.context = ""
        self.stage = ""

    def request(self, model: str, system: str, user: str, maximum: int) -> tuple[str, dict]:
        with self.lock:
            if self.stop_reason or self.attempts >= self.limit:
                self.stop_reason = self.stop_reason or "inference_attempt_budget_exhausted"
                raise RuntimeError(self.stop_reason)
            self.attempts += 1
            number = self.attempts
        start = time.perf_counter()
        record = {"number": number, "context": self.context, "stage": self.stage, "requested_model": model,
                  "max_tokens": maximum, "prompt_sha256": digest((system + '\n' + user).encode())}
        try:
            response = self.client.chat.completions.create(model=model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                temperature=0.1, max_tokens=maximum)
        except Exception as exc:
            message = str(exc).lower()
            status = getattr(exc, "status_code", None)
            if status == 402 or any(s in message for s in ('insufficient_quota','quota exceeded','quota exhausted','insufficient balance','credit balance')):
                self.stop_reason = "provider_quota_exhausted"
            elif status in (401,403):
                self.stop_reason = "provider_auth_failure"
            elif status == 429:
                self.stop_reason = "provider_rate_limit_not_proven_exhaustion"
            error = self.stop_reason or f"provider_error_{type(exc).__name__}_{status}"
            record.update(error=error, duration_s=round(time.perf_counter()-start,3))
            self.calls.append(record)
            write_json(self.out / 'calls' / f'{number:05d}.json', record)
            raise RuntimeError(error) from None
        choice = response.choices[0]
        raw = (choice.message.content or '').strip()
        usage = response.usage
        record.update(model=response.model, duration_s=round(time.perf_counter()-start,3),
                      finish_reason=choice.finish_reason, raw_response=raw,
                      usage={"prompt_tokens": getattr(usage,'prompt_tokens',None),
                             "completion_tokens": getattr(usage,'completion_tokens',None)})
        self.calls.append(record)
        write_json(self.out / 'calls' / f'{number:05d}.json', record)
        return raw, record

    def caller(self, model: str):
        from fugu.pipeline.stages.semantic import JudgeCall, SemanticStage
        def call(system: str, user: str):
            expected = 'findings' if 'quality_summary' in system else ('probes' if '"probes"' in system else None)
            records = []
            raw = ''
            for attempt in range(2):
                # First request matches product 1600 budget; one retry gets 4096.
                maximum = (1600 if attempt == 0 else 4096) if expected else (600 if model.endswith('a12b') else 1600)
                raw, record = self.request(model,system,user,maximum)
                records.append(record)
                if expected is None:
                    break
                recovered, method = recover_json(raw)
                doc = json.loads(recovered) if recovered else None
                valid = isinstance(doc,dict) and isinstance(doc.get(expected),list)
                if valid and expected == 'findings':
                    try:
                        valid = all(SemanticStage._to_finding(f,'benchmark') is not None for f in doc['findings'])
                    except (ValueError, TypeError):
                        valid = False
                record['parse_valid'] = valid
                record['reparse_method'] = method
                record['structured_retry_index'] = attempt
                write_json(self.out / 'calls' / f"{record['number']:05d}.json",record)
                if valid:
                    raw = recovered
                    break
            total_usage = {k: sum(r.get('usage',{}).get(k) or 0 for r in records)
                           for k in ('prompt_tokens','completion_tokens')}
            return raw, JudgeCall(model=model,latency_s=sum(r['duration_s'] for r in records),
                                 prompt_chars=len(system)+len(user),completion_chars=len(raw),usage=total_usage)
        return call


class SearchBudget:
    def __init__(self, out: Path, limit: int = 180):
        self.out, self.limit = out, limit
        self.calls = []
        self.stop_reason = None
    def __call__(self, key: str, query: str):
        from fugu.pipeline.stages.reputation import _default_search
        if not key:
            raise RuntimeError('missing_tavily_api_key')
        if self.stop_reason or len(self.calls) >= self.limit:
            raise RuntimeError(self.stop_reason or 'research_search_budget_exhausted')
        record = {'query': query, 'number': len(self.calls)+1}
        self.calls.append(record)
        try:
            response = _default_search(key,query)
        except Exception as exc:
            status = getattr(exc,'code',None)
            # Tavily uses HTTP432 for plan usage limit; no raw errors retained.
            if status in (402,432,433):
                self.stop_reason = 'tavily_quota_exhausted'
            elif status in (401,403):
                self.stop_reason = 'tavily_auth_failure'
            record['error'] = self.stop_reason or f'search_error_{type(exc).__name__}_{status}'
            write_json(self.out / 'searches' / f"{record['number']:04d}.json",record)
            raise RuntimeError(record['error']) from None
        record['response'] = response
        write_json(self.out / 'searches' / f"{record['number']:04d}.json",record)
        return response


async def run(out: Path) -> None:
    from fugu.config import ULTRA_MODEL, SUPER_MODEL
    from fugu.dedupe import dedupe_findings
    from fugu.pipeline import build_stages, run_stages
    from fugu.pipeline.stages.semantic import SemanticStage
    from fugu.pipeline.stages.harness import HarnessStage
    from fugu.pipeline.stages.reputation import ReputationStage
    from fugu.pipeline.stages.composition import CompositionStage, MemberResult
    from fugu.server.composition_jobs import harvest_tool_names
    from fugu.types import AuditJob, JobStatus, StageResult
    from fugu.verdict import aggregate_verdict
    manifest = prepare(out)
    assert engine_hashes() == manifest['engine_hashes'], 'engine changed after freeze'
    budget = InferenceBudget(out)
    search = SearchBudget(out)
    ultra, everyday = budget.caller(ULTRA_MODEL), budget.caller(SUPER_MODEL)
    class TwoModelHarness(HarnessStage):
        def _everyday_call(self, call, *, injected):
            return everyday
    stages = build_stages(include_semantic=False,include_harness=False,include_reputation=False)
    if not any(s.name=='detonation' for s in stages):
        raise RuntimeError('detonation_driver_unavailable')
    stages[2:2] = [SemanticStage(make_call=ultra),TwoModelHarness(make_call=ultra),ReputationStage(search_fn=search)]
    stage_cache: dict[str,list] = {}
    rows = []
    started = datetime.now(timezone.utc).isoformat()
    async def audit_target(target: Path, context: str):
        fingerprint = digest(json.dumps(input_hashes(target),sort_keys=True).encode())
        if fingerprint in stage_cache:
            return stage_cache[fingerprint], True
        job = AuditJob(id='full-benchmark',source=str(target),status=JobStatus.running,depth='full')
        results = []
        budget.context = context
        for stage in stages:
            budget.stage = stage.name
            print(f'  {context} {stage.name}',flush=True)
            result = (await run_stages(job,target,[stage]))[0]
            results.append(result)
        # Every capability represented, including explicit single-source N/A.
        results.append(await CompositionStage().run(job,target))
        stage_cache[fingerprint] = results
        write_json(out / 'audits' / (fingerprint + '.json'), {'context': context,
                   'input_sha256': input_hashes(target), 'stages': [asdict(r) for r in results]})
        return results, False
    def serialized(results):
        output = []
        for result in results:
            value = asdict(result)
            value['state'] = stage_state(value)
            output.append(value)
        return output
    for number, case in enumerate(manifest['cases'],1):
        start = time.perf_counter()
        print(f"CASE {number}/40 {case['id']}",flush=True)
        target = ROOT / case['target']
        assert input_hashes(target) == case['input_sha256']
        row = dict(case)
        if case['cohort'] == 'composition':
            member_results, children, all_results, all_findings = [], [], [], []
            for member in case['members']:
                directory = target / member['dir']
                results, cached = await audit_target(directory,case['id']+'/'+member['dir'])
                findings = dedupe_findings([f for r in results for f in r.findings])
                children.append({'member': member['dir'],'cached_identical_input':cached,
                                 'stages':serialized(results)})
                all_results.extend(results)
                all_findings.extend(findings)
                member_results.append(MemberResult(label=member.get('label') or member['dir'],
                    slug=member['dir'],findings=findings,tool_names=harvest_tool_names(directory),target_dir=directory))
            composition = CompositionStage()
            composition._member_results = member_results
            job = AuditJob(id='full-composition',source=str(target),status=JobStatus.running,depth='full')
            comp = await composition.run(job,target)
            all_results.append(comp)
            all_findings.extend(comp.findings)
            row['members_results'] = children
            results, findings = all_results, dedupe_findings(all_findings)
            row['composition_score'] = composition_score([asdict(f) for f in findings],case['expected'])
            row['detected'] = row['composition_score']['detected']
        else:
            results, _ = await audit_target(target,case['id'])
            findings = dedupe_findings([f for r in results for f in r.findings])
            row['detected'] = any(f.severity in MEDPLUS for f in findings)
        row['stages'] = serialized(results)
        row['findings'] = [asdict(f) for f in findings]
        row['verdict'] = aggregate_verdict(findings,results)
        row['exclusions'] = [{'stage':r['stage'],'state':r['state'],'error':r.get('error'),
                              'reason':r.get('metrics',{}).get('coverage_incomplete')}
                             for r in row['stages'] if r['state'] not in ('completed','not_applicable')]
        row['complete'] = not row['exclusions']
        # Partial results remain visible; they do not enter completed denominators.
        row['elapsed_s'] = round(time.perf_counter()-start,3)
        rows.append(row)
        write_json(out / 'rows' / f'{number:02d}.json',row)
        print(f"  RESULT complete={row['complete']} detected={row['detected']} verdict={row['verdict']['status']}",flush=True)
        write_json(out / 'fugu.json', {'started_utc': started, 'rows': rows,'attempts':budget.attempts,
                                     'stop_reason':budget.stop_reason,'search_stop_reason':search.stop_reason})
        if budget.stop_reason:
            break
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row['cohort'],row['kind'])].append(row)
    summary = [{'cohort':cohort,'kind':kind,**cohort_score(items)} for (cohort,kind),items in sorted(grouped.items())]
    after = engine_hashes()
    write_json(out / 'fugu.json', {'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),
        'protocol':'full-capabilities-v1','threshold':'any finding >= medium; composition rule outcome separate',
        'rows':rows,'summary':summary,'planned':len(manifest['cases']),
        'unattempted_ids':[c['id'] for c in manifest['cases'] if c['id'] not in {r['id'] for r in rows}],
        'unique_audits':len(stage_cache),'attempts':budget.attempts,'searches':len(search.calls),
        'inference_stop_reason':budget.stop_reason,'search_stop_reason':search.stop_reason,
        'usage':{k:sum(c.get('usage',{}).get(k) or 0 for c in budget.calls) for k in ('prompt_tokens','completion_tokens')},
        'parsing':{'structured_retries':sum(c.get('structured_retry_index',0)>0 for c in budget.calls),
                   'trailing_comma_reparses':sum(c.get('reparse_method')=='trailing_comma_reparse' for c in budget.calls)},
        'models':sorted({c['requested_model'] for c in budget.calls}),
        'engine_hashes_after':after,'engine_unchanged':after==manifest['engine_hashes'],
        'monetary_cost':None,'remaining_quota':None})
    assert after == manifest['engine_hashes'], 'engine changed during evaluation'
    print(json.dumps(summary,indent=2),flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare',action='store_true')
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--out',type=Path,default=OUT)
    args = parser.parse_args()
    if args.prepare:
        manifest = prepare(args.out)
        print('Frozen',len(manifest['cases']),'cases')
    if args.run:
        asyncio.run(run(args.out))


if __name__ == '__main__':
    main()
