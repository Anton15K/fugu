"""New 40-case full-workflow measurement of the S1 integration.

Other stages consume only source, never S1 findings. Run them once and share
their exact results between the paired variants to isolate the S1 change.
Composition and final verdicts are recomputed independently for each variant.
No old release, result, budget or approval row is reused or modified.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from bench.current_limits import RequestJournal, observe_sdk, hash_json, write_json
from bench.full_capabilities import input_hashes, SearchBudget

MEDIUM = {'critical', 'high', 'medium'}


def state(row):
    metrics = row.get('metrics', {})
    if metrics.get('unattempted'):
        return 'unattempted'
    if not row.get('ok'):
        return 'failed'
    if metrics.get('skipped'):
        reason = str(metrics['skipped'])
        return ('not_applicable' if any(x in reason for x in (
            'no runnable triggers', 'no searchable identifiers', 'single-source job',
            'no eligible text units', 'no supported tool')) else 'unavailable')
    if any(metrics.get(k) for k in ('coverage_incomplete', 'call_errors', 'parse_errors', 'omitted_units')):
        return 'partial'
    return 'completed'


def public(result):
    doc = asdict(result)
    doc['state'] = state(doc)
    return doc


def summary(rows):
    groups = defaultdict(list)
    for row in rows:
        for variant in ('baseline', 'integrated'):
            groups[(variant, row['cohort'], row['kind'])].append(row[variant])
    result = []
    for (variant, cohort, kind), items in sorted(groups.items()):
        complete = [r for r in items if r['complete']]
        result.append({'variant': variant, 'cohort': cohort, 'kind': kind,
                       'attempted': len(items), 'complete': len(complete),
                       'excluded': len(items) - len(complete),
                       'flagged_complete': sum(bool(r['detected']) for r in complete),
                       'flagged_partial': sum(bool(r['detected']) for r in items if not r['complete'])})
    return result


def engine_hashes():
    root = Path(__file__).resolve().parents[1]
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((root / 'src/fugu').rglob('*.py'))}


def plan(out, binary, image):
    from fugu.config import get_production_limits, SUPER_MODEL, ULTRA_MODEL
    cases = json.loads((out / 'cases.json').read_text())
    assert len(cases['cases']) == 40
    for c in cases['cases']:
        assert input_hashes(Path(c['target'])) == c['input_sha256']
    value = {'protocol': 'paired-full-workflow-integration-v1',
             'cases_sha256': hash_json(cases), 'engine': engine_hashes(),
             'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'image': image,
             'limits': get_production_limits().to_dict(), 'models': [SUPER_MODEL, ULTRA_MODEL],
             'maximum_sdk_attempts': 1900, 'maximum_requested_output_tokens': 1900 * 4096,
             'maximum_searches': 180,
             'shared_evidence': 'Identical S0/S2/S3/S4/S5 source-only inputs; native stages run once per unique source.',
             'scoring': 'Complete cases only; any medium+ finding. Composition uses its expected rule outcome.',
             'live_authority': 'User request on 2026-10-04 for new integration and whole-workflow benchmark; rig/CULTURE.md existing quota authorization.',
             'remaining_quota': None, 'dollar_cost': None}
    write_json(out / 'plan.json', value)
    return value


async def run(out, binary, image, credential_project):
    from dotenv import load_dotenv
    load_dotenv(credential_project / '.env', override=False)
    from fugu.config import SUPER_MODEL, ULTRA_MODEL, get_settings
    from fugu.pipeline import build_stages, run_stages
    from fugu.pipeline.stages.static_scan import StaticScanStage
    from fugu.pipeline.stages.tool_surface import ToolSurfaceScanner
    from fugu.pipeline.stages.composition import CompositionStage, MemberResult
    from fugu.server.composition_jobs import harvest_tool_names
    from fugu.dedupe import dedupe_findings
    from fugu.types import AuditJob, StageResult
    from fugu.verdict import aggregate_verdict
    approved_plan = plan(out, binary, image)
    cases = json.loads((out / 'cases.json').read_text())['cases']
    search = SearchBudget(out, limit=180)
    # Use available, hash-verified collectors without rebuilding owner tags.
    stages = build_stages()
    for stage in stages:
        if stage.name == 'reputation':
            stage._search_fn = search
        if stage.name == 'detonation':
            stage._driver._dns_img_built = True
            stage._driver._mitm_img_built = True
    if not any(s.name == 'detonation' for s in stages):
        stages.append(type('UnavailableChamber', (), {
            'name': 'detonation', 'run': unavailable_chamber})())
    integrated_static = StaticScanStage(surface_scanner=ToolSurfaceScanner(
        binary=binary, image=image, expected_sha256=approved_plan['binary_sha256']))
    baseline_static = StaticScanStage()
    baseline_static.surface_scanner = None
    for index, stage in enumerate(stages):
        if stage.name == 'static':
            stages[index] = baseline_static
    cache = {}
    rows = []
    started = datetime.now(timezone.utc).isoformat()
    with RequestJournal(out / 'inference', limit=1900, binding=hash_json(approved_plan),
                        expected_output_tokens=4096,
                        expected_models=[SUPER_MODEL, ULTRA_MODEL]) as journal:
        def publish():
            coverage = {variant: dict(Counter((s['stage'], s['state']) for r in rows
                for s in r[variant]['stages'])) for variant in ('baseline', 'integrated')}
            coverage = {v: [{'stage': k[0], 'state': k[1], 'count': n} for k, n in counts.items()]
                        for v, counts in coverage.items()}
            value = {'started_utc': started, 'measured_utc': datetime.now(timezone.utc).isoformat(),
                     'plan_sha256': hash_json(approved_plan), 'rows': rows,
                     'summary': summary(rows), 'coverage': coverage, 'planned': 40,
                     'unattempted_case_ids': [c['id'] for c in cases if c['id'] not in {r['id'] for r in rows}],
                     'inference': journal.summary(), 'searches': len(search.calls),
                     'search_stop_reason': search.stop_reason, 'unique_inputs': len(cache),
                     'profile': approved_plan['limits'], 'shared_nonstatic_evidence': True,
                     'remaining_quota': None, 'dollar_cost': None}
            write_json(out / 'fugu.json', value)
            return value

        async def audit(directory, context):
            key = hash_json(input_hashes(directory))
            if key in cache:
                return cache[key]
            job = AuditJob(id=key, source=str(directory), depth='full')
            baseline = []
            new_static = None
            for stage in stages:
                assert engine_hashes() == approved_plan['engine'], 'engine changed'
                print(f'  {context} {stage.name}', flush=True)
                if stage.name in ('semantic', 'harness') and (journal.stop_reason or not get_settings().has_api_key):
                    r = StageResult(stage=stage.name, ok=False,
                                    metrics={'unattempted': journal.stop_reason or 'missing_nebius_api_key'})
                else:
                    with journal.context(key, stage.name, 'full-workflow'):
                        r = (await run_stages(job, directory, [stage]))[0]
                baseline.append(r)
                if stage.name == 'static':
                    new_static = (await run_stages(job, directory, [integrated_static]))[0]
            integrated = [new_static if r.stage == 'static' else r for r in baseline]
            cache[key] = (baseline, integrated)
            write_json(out / 'audits' / f'{key}.json', {'context': context,
                'input_sha256': input_hashes(directory), 'baseline': [public(r) for r in baseline],
                'integrated': [public(r) for r in integrated]})
            publish()
            return baseline, integrated

        with observe_sdk(journal):
            for number, case in enumerate(cases, 1):
                target = Path(case['target'])
                assert input_hashes(target) == case['input_sha256']
                print(f"CASE {number}/40 {case['id']}", flush=True)
                started_case = time.perf_counter()
                variants = {'baseline': [], 'integrated': []}
                members = {'baseline': [], 'integrated': []}
                for member in case.get('members') or [{'dir': None, 'label': case['id']}]:
                    directory = target / member['dir'] if member['dir'] else target
                    baseline, integrated = await audit(directory, case['id'] + '/' + str(member['dir']))
                    for variant, results in (('baseline', baseline), ('integrated', integrated)):
                        variants[variant].extend(results)
                        if case.get('members'):
                            findings = dedupe_findings([f for r in results for f in r.findings])
                            members[variant].append(MemberResult(
                                label=member.get('label') or member['dir'], slug=member['dir'],
                                findings=findings, tool_names=harvest_tool_names(directory), target_dir=directory))
                row = dict(case, elapsed_s=round(time.perf_counter() - started_case, 3))
                for variant, results in variants.items():
                    comp = CompositionStage()
                    if members[variant]:
                        comp._member_results = members[variant]
                    results.append(await comp.run(AuditJob(id=case['id'], source=str(target), depth='full'), target))
                    findings = dedupe_findings([f for r in results for f in r.findings])
                    stage_rows = [public(r) for r in results]
                    complete = all(r['state'] in ('completed', 'not_applicable') for r in stage_rows)
                    raw_alert = any(f.severity in MEDIUM for f in findings)
                    score = None
                    detected = raw_alert
                    if case['cohort'] == 'composition':
                        titles = [f.title.lower() for f in results[-1].findings]
                        score = {k: any(k in t for t in titles) for k in ('trifecta', 'shadowing')}
                        score['matches_expected'] = all(score[k] == case['expected'][k] for k in ('trifecta', 'shadowing'))
                        detected = score['trifecta'] or score['shadowing']
                    elif case['cohort'] == 'reputation':
                        detected = any(f.stage == 'reputation' and f.confidence == 'measured' for f in findings)
                    row[variant] = {'complete': complete, 'detected': detected, 'raw_medium_alert': raw_alert,
                        'stages': stage_rows, 'findings': [asdict(f) for f in findings],
                        'composition_score': score, 'verdict': aggregate_verdict(findings, results)}
                rows.append(row)
                write_json(out / 'rows' / f'{number:02d}.json', row)
                publish()
                print(f"  RESULT baseline={row['baseline']['complete']}/{row['baseline']['detected']} integrated={row['integrated']['complete']}/{row['integrated']['detected']} attempts={len(journal.records)}", flush=True)
    write_json(out / 'engine-after.json', {'unchanged': engine_hashes() == approved_plan['engine']})


async def unavailable_chamber(self, job, target):
    from fugu.types import StageResult
    return StageResult(stage='detonation', ok=False, error='Docker chamber unavailable')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--credential-project', type=Path, required=True)
    parser.add_argument('--prepare', action='store_true')
    args = parser.parse_args()
    if args.prepare:
        value = plan(args.out, args.binary, args.image)
        print(json.dumps({'cases': 40, 'plan_sha256': hash_json(value), 'sdk_attempt_limit': 1900}))
    else:
        asyncio.run(run(args.out, args.binary, args.image, args.credential_project))


if __name__ == '__main__':
    main()
