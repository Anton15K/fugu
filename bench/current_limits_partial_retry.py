"""One frozen case, a fresh existing SDK journal, and whole-row aggregation."""
from __future__ import annotations

import argparse
import asyncio
import copy
from dataclasses import asdict
from pathlib import Path
import re
from types import SimpleNamespace

from bench import current_limits as base
from bench import current_limits_continuation as history

CASE_ID = 'mcptox/AlphaVantage_4'
LIMIT = 80
PROTOCOL = 'current-production-source-inference-partial-retry-v1'
RELEASE_PROTOCOL = 'fugu-partial-retry-data-release-v1'
DEFAULT_OUTPUT = base.DEFAULT_OUTPUT / 'partial-retry-cc58a58'
PREVIOUS = history.DEFAULT_CHILD
COMBINED_SHA256 = '436b0bd1e0e2bb4504ef82612dc2a5be175731a28718e851a5a29f2b1b05ffc7'
INVENTORY_SHA256 = 'a92f16dce0c1c9df95f44d574aacb37c547b152562f527d3915a192d57298d30'
ADJUDICATION = Path('/tmp/fugu-quality-continuation-final/benign-adjudication.json')
ADJUDICATION_SHA256 = 'e714ec567dedd96c78cbf5ef7c292e9713dfc5f71223c4414a5c18da4b4cc94b'
ADJUDICATION_REVIEW = 'qitem-20261003100222-9c2b92be'
BOOTSTRAP = '''"""Exact-root bootstrap for the separately reviewed partial-case data grant."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path({root!r})
ENGINE = Path({engine!r})
OUTPUT = Path({output!r})

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-release-ref', required=True)
    parser.add_argument('--approved-plan-sha256', required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    from bench import current_limits_partial_retry as mod
    plan = mod.base.read_json(OUTPUT / 'plan.json')
    mod.authenticate_release(args.data_release_ref, plan, args.approved_plan_sha256)
    common = ['--engine-root', str(ENGINE), '--output', str(OUTPUT),
              '--approved-plan-sha256', args.approved_plan_sha256,
              '--data-release-ref', args.data_release_ref]
    subprocess.run([sys.executable, '-B', '-m', 'bench.current_limits_partial_retry',
                    'preflight', *common], cwd=ROOT, check=True, timeout=90,
                   env=dict(os.environ, PYTHON_DOTENV_DISABLED='1', NEBIUS_API_KEY=''))
    from dotenv import load_dotenv
    load_dotenv(ROOT / '.env', override=False)
    return mod.main(['run', *common])

if __name__ == '__main__':
    raise SystemExit(main())
'''


def require(value, message):
    if not value:
        raise base.EvidenceError(message)


def select_partial(combined: dict, original: dict) -> dict:
    cases, rows = original['cases'], combined['rows']
    require(len(cases) == len(rows) == 40 and [r['id'] for r in rows] == [c['id'] for c in cases],
            'original40 order changed')
    require([r['id'] for r in rows if not r['complete']] == [CASE_ID], 'sole assigned partial changed')
    case = next((c for c in cases if c['id'] == CASE_ID), None)
    require(case is not None and case['cohort'] == 'mcptox' and case['kind'] == 'malicious'
            and not case.get('members'), 'assigned case contract changed')
    row = next(r for r in rows if r['id'] == CASE_ID)
    require(row['status'] == 'partial' and all(row.get(k) == v for k, v in case.items() if k != 'target'),
            'original partial labels/input/grouping changed')
    return {k: copy.deepcopy(v) for k, v in original.items() if k != 'cases'} | {'cases': [copy.deepcopy(case)]}


def load_baseline():
    require(base.sha((PREVIOUS / 'artifact-manifest.json').read_bytes()) == INVENTORY_SHA256,
            'sealed continuation inventory changed')
    for item in base.read_json(PREVIOUS / 'artifact-manifest.json')['sha256']:
        path = base.ROOT / item['path']
        require(not path.is_symlink() and base.sha(path.read_bytes()) == item['sha256'], 'sealed continuation changed')
    parent = history.load_parent()
    require(base.sha((PREVIOUS / 'combined.json').read_bytes()) == COMBINED_SHA256, 'original combined changed')
    combined = base.read_json(PREVIOUS / 'combined.json')
    selected = select_partial(combined, parent.original)
    ledger = history.read_ledger(PREVIOUS)
    require(len(parent.records) == 359 and len(ledger.records) == 919, 'old SDK history changed')
    return SimpleNamespace(parent=parent, combined=combined, original=parent.original,
                           selected=selected, records=parent.records + ledger.records)


def _namespace(output: Path, engine_root: Path):
    require(not any(p.is_symlink() for p in (output, *output.parents)), 'symlink retry namespace')
    resolved = output.resolve()
    scratch = resolved.is_relative_to(Path('/tmp').resolve()) and any(
        p.name.startswith('fugu-partial-retry-') for p in (resolved, *resolved.parents))
    require(resolved == DEFAULT_OUTPUT.resolve() or scratch, 'outside assigned new retry namespace')
    require(not resolved.is_relative_to(engine_root.resolve()), 'retry namespace overlaps engine')


def _bindings(engine, baseline):
    base.verify_engine(engine)
    history._bindings(engine, baseline.parent)
    return dict(engine=engine.manifest, profile=base.engine_profile(engine),
                profile_sha256=base.hash_json(base.engine_profile(engine)), runtime=base.runtime_versions(),
                provider_base_url=engine.modules['config'].DEFAULT_BASE_URL,
                text_contracts=base.text_contracts(engine), requested_models=baseline.parent.plan['requested_models'],
                runner_sha256=base.sha(Path(base.__file__).read_bytes()),
                history_helper_sha256=base.sha(Path(history.__file__).read_bytes()),
                wrapper_sha256=base.sha(Path(__file__).read_bytes()),
                original_case_manifest_sha256=base.FIXED_CASE_MANIFEST_SHA256,
                original_combined_sha256=COMBINED_SHA256, original_inventory_sha256=INVENTORY_SHA256,
                original_partial_row_sha256=base.hash_json(next(r for r in baseline.combined['rows'] if r['id'] == CASE_ID)),
                prior_adjudication_sha256=ADJUDICATION_SHA256, prior_adjudication_review=ADJUDICATION_REVIEW)


def prepare(engine, output: Path) -> dict:
    _namespace(output, engine.root)
    require(not (output / 'plan.json').exists() and not (output / 'measurement').exists(), 'preserve existing retry plan/history')
    baseline = load_baseline()
    bindings = _bindings(engine, baseline)
    bootstrap = BOOTSTRAP.format(root=str(base.ROOT.resolve()), engine=str(engine.root.resolve()),
                                 output=str(output.resolve())).encode()
    copied = base.prepare_inputs(baseline.selected, output / 'prepared', base.ROOT)
    inspected = base.preflight(engine, copied)
    require((inspected['context_count'], inspected['unique_audit_count'], inspected['semantic_primary_units']) == (1, 1, 1),
            'one-case unit/input contract changed')
    require(base.sha(ADJUDICATION.read_bytes()) == ADJUDICATION_SHA256, 'accepted prior adjudication changed')
    (output / 'prior-benign-adjudication.json').write_bytes(ADJUDICATION.read_bytes())
    plan = dict(schema=1, protocol=PROTOCOL, created_utc=base.utc(), **bindings,
                engine_root=str(engine.root.resolve()), namespace=str(output.resolve()),
                measurement_directory=str((output / 'measurement').resolve()),
                bootstrap_sha256=base.sha(bootstrap),
                selected_case_ids=[CASE_ID], cases_sha256=base.hash_json(copied), preflight=inspected,
                context=inspected['contexts'][0]['fingerprint'], attempt_limit=LIMIT,
                temperature=0.1, sdk_retries=0, timeout_s=90, http_error_retries=0,
                primary_maximum=29, native_repair_maximum=11, mounted_comparisons_expected=18,
                previous_attempts=1278, worst_cumulative_attempts=1278 + LIMIT,
                provider_requests=0, execution_authorized=False,
                capabilities_excluded=['detonation', 'target execution', 'reputation', 'fresh competitors'])
    base.write_json(output / 'cases.json', copied)
    (output / 'bootstrap.py').write_bytes(bootstrap)
    base.write_json(output / 'plan.json', plan)
    base.write_json(output / 'plan-hash.json', {'plan_sha256': base.hash_json(plan)})
    base.write_json(output / 'release-template.json', release_template(plan))
    return plan


def validate_plan(engine, plan: dict, output: Path) -> dict:
    _namespace(output, engine.root)
    baseline = load_baseline()
    require(all(plan.get(k) == v for k, v in _bindings(engine, baseline).items()), 'frozen retry plan binding changed')
    require(plan.get('schema') == 1 and plan.get('protocol') == PROTOCOL and plan.get('attempt_limit') == LIMIT
            and plan.get('temperature') == 0.1 and plan.get('sdk_retries') == 0 and plan.get('timeout_s') == 90
            and plan.get('http_error_retries') == 0 and plan.get('selected_case_ids') == [CASE_ID]
            and plan.get('namespace') == str(output.resolve())
            and plan.get('measurement_directory') == str((output / 'measurement').resolve())
            and plan.get('engine_root') == str(engine.root.resolve()), 'retry selection/profile/namespace changed')
    cases = base.read_json(output / 'cases.json')
    require(base.hash_json(cases) == plan['cases_sha256'] and len(cases['cases']) == 1, 'selected manifest changed')
    restored = copy.deepcopy(cases)
    for case in restored['cases']:
        require(base.input_hashes(base.case_target(case)) == case['input_sha256'], 'copied input changed')
        case['target'] = case.pop('original_target')
    require(restored == baseline.selected and base.preflight(engine, cases) == plan['preflight'], 'case contract/preflight changed')
    require(base.sha((output / 'prior-benign-adjudication.json').read_bytes()) == ADJUDICATION_SHA256, 'prior adjudication copy changed')
    require(base.sha((output / 'bootstrap.py').read_bytes()) == plan.get('bootstrap_sha256'), 'reviewed bootstrap changed')
    return cases


def journal_settings(plan: dict) -> dict:
    require(plan.get('attempt_limit') == LIMIT, 'fixed80 request limit changed')
    return dict(limit=LIMIT, binding=base.hash_json(plan), phase_limits={'common20': LIMIT},
                expected_output_tokens=4096, expected_models=plan['requested_models'])


def complete_case(row):
    stages = row.get('stages', [])
    if [s.get('stage') for s in stages] != ['concealment', 'static', 'semantic', 'harness']:
        return False
    metrics = stages[-1].get('metrics', {})
    return (all(base.stage_state(s) == 'completed' for s in stages)
            and metrics.get('comparisons_expected') == metrics.get('comparisons_completed') == 18)


def finish_case(result, journal, output):
    row = result['rows'][0]
    changed = row['complete'] and not complete_case(row)
    if changed:
        row['native_complete'] = True
        row.update(complete=False, status='partial',
                   unavailable_reason='required18 mounted comparisons not completed')
        journal._stop('required_comparison_coverage_incomplete')
    current = journal.summary()
    if current != result['usage'] or changed:
        result['usage'] = current
        result['summary'] = base.summarize_rows(result['rows'])
        result['accounted_utc'] = base.utc()
        base.write_json(output / 'fugu.json', result)
    return result


async def evaluate_retry(engine, manifest, output, journal, *, sdk_factory=None):
    saved = output / 'fugu.json'
    if saved.exists():
        result = base.read_json(saved)
        require(result['binding'] == journal.binding and result['cases_sha256'] == base.hash_json(manifest), 'saved retry contract changed')
        require([r['id'] for r in result['rows']] == [CASE_ID], 'saved retry selection changed')
        if journal.stop_reason or result['rows'][0]['status'] != 'unattempted':
            current = journal.summary()
            if current != result['usage']:
                result['usage'] = current
                result['accounted_utc'] = base.utc()
                base.write_json(saved, result)
            return finish_case(result, journal, output)
    # The native evaluator normally continues to the next stage after failure.
    # Stop the existing SDK journal once an unresolved stage result returns.
    original = engine.pipeline.run_stages
    async def stop_failed_stage(*args, **kwargs):
        results = await original(*args, **kwargs)
        if any(base.stage_state(asdict(r)) != 'completed' for r in results):
            journal._stop('native_analysis_failure')
        return results
    engine.pipeline.run_stages = stop_failed_stage
    try:
        result = await base.evaluate_cases(engine, manifest, output, journal, sdk_factory=sdk_factory)
        return finish_case(result, journal, output)
    finally:
        engine.pipeline.run_stages = original


def release_template(plan):
    return dict(schema=1, protocol=RELEASE_PROTOCOL, execution_authorized=False,
                owner='research-security@fugu', reviewed_commit=None, review_queue_ref=None,
                plan_sha256=base.hash_json(plan), original_combined_sha256=COMBINED_SHA256,
                namespace=plan['namespace'], attempt_limit=LIMIT, sdk_retries=0, http_error_retries=0)


def authenticate_release(queue_ref, plan, approved):
    require(base.hash_json(plan) == approved, 'exact accepted plan digest required')
    identity = history._rig_json(['whoami', '--json'])['identity']
    require(identity.get('rigName') == 'fugu' and identity.get('sessionName') == 'research-security@fugu'
            and identity.get('logicalId') == 'research.security', 'wrong authenticated retry owner')
    row = history._rig_json(['queue', 'show', queue_ref, '--full', '--json'])
    require(row.get('qitemId') == queue_ref and row.get('sourceSession') == 'control-lead@fugu'
            and row.get('destinationSession') == 'research-security@fugu'
            and row.get('state') == 'in-progress' and row.get('claimedAt'), 'claimed separate lead data row required')
    body = history._parse_json(row.get('body', ''))
    expected = release_template(plan)
    require(isinstance(body, dict) and set(body) == set(expected) and body.get('execution_authorized') is True
            and re.fullmatch(r'[0-9a-f]{40}', body.get('reviewed_commit') or '')
            and re.fullmatch(r'qitem-[0-9]{14}-[0-9a-f]{8}', body.get('review_queue_ref') or '')
            and all(body[k] == v for k, v in expected.items() if k not in {'execution_authorized', 'reviewed_commit', 'review_queue_ref'}),
            'exact independent-review/data release required')
    return {'queue_ref': queue_ref, 'contract': body,
            'binding': base.hash_json({k: row[k] for k in ('qitemId', 'sourceSession', 'destinationSession', 'body')})}


def aggregate(engine, output):
    plan = base.read_json(output / 'plan.json')
    manifest = validate_plan(engine, plan, output)
    baseline = load_baseline()
    directory = output / 'measurement'
    child = base.read_json(directory / 'fugu.json')
    ledger = history.read_ledger(directory, allow_orphans=True)
    require(ledger.state['binding'] == base.hash_json(plan) and ledger.state['limit'] == LIMIT
            and child['binding'] == base.hash_json(plan) and child['cases_sha256'] == base.hash_json(manifest)
            and child['planned'] == 1 and len(child['rows']) == 1 and child['engine'] == plan['engine']
            and child['limits'] == plan['profile'] and child['scope'] == baseline.combined['scope'], 'new retry result contract changed')
    saved_usage = dict(child['usage'])
    replayed = saved_usage.pop('replayed_requests_this_process', None)
    current_usage = dict(ledger.usage)
    current_usage.pop('replayed_requests_this_process')
    require(type(replayed) is int and replayed >= 0 and saved_usage == current_usage, 'saved retry accounting changed')
    row = child['rows'][0]
    require(all(row.get(k) == v for k, v in manifest['cases'][0].items()), 'retry row case contract changed')
    require(row['complete'] == complete_case(row), 'retry completion contradicts native coverage/full18 contract')
    rows = [copy.deepcopy(row if r['id'] == CASE_ID else r) for r in baseline.combined['rows']]
    combined = copy.deepcopy(baseline.combined)
    digest = base.sha((directory / 'fugu.json').read_bytes())
    interval = dict(id='retry', started_utc=child['started_utc'], measured_utc=child['measured_utc'],
                    result_sha256=digest, usage=copy.deepcopy(child['usage']))
    records = baseline.records + ledger.records
    usage = base.RequestJournal.summary(SimpleNamespace(state={'attempts': len(records)}, records=records,
                                                       replayed=0, stop_reason=ledger.usage['stop_reason']))
    usage['interval_stop_reasons'] = dict(baseline.combined['usage']['interval_stop_reasons'], retry=ledger.usage['stop_reason'])
    intervals = copy.deepcopy(baseline.combined['intervals']) + [interval]
    lineage = {'previous_combined_sha256': COMBINED_SHA256, 'previous_inventory_sha256': INVENTORY_SHA256,
               'previous_lineage': copy.deepcopy(baseline.combined['lineage']),
               'retry_plan_sha256': base.hash_json(plan), 'retry_result_sha256': digest}
    combined.update(schema=2, protocol=PROTOCOL, rows=rows, summary=base.summarize_rows(rows),
                    coverage=base.coverage_data(rows), usage=usage, intervals=intervals,
                    measured_utc=child['measured_utc'], lineage=lineage, binding=base.hash_json(lineage))
    combined['row_interval'][CASE_ID] = 'retry'
    combined['prior_benign_adjudication'] = {'path': str((output / 'prior-benign-adjudication.json').relative_to(base.ROOT))
        if output.is_relative_to(base.ROOT) else str(output / 'prior-benign-adjudication.json'),
        'sha256': ADJUDICATION_SHA256, 'review_queue_ref': ADJUDICATION_REVIEW, 'raw_fields_preserved': True}
    for alignment in combined['coverage']['attempt_alignment']:
        fingerprint = alignment['fingerprint']
        origin = 'retry' if fingerprint == plan['context'] else next(
            a['interval_id'] for a in baseline.combined['coverage']['attempt_alignment'] if a['fingerprint'] == fingerprint)
        alignment['interval_id'] = origin
        alignment['audit_directory'] = str(directory / 'audits') if origin == 'retry' else next(
            a['audit_directory'] for a in baseline.combined['coverage']['attempt_alignment'] if a['fingerprint'] == fingerprint)
    provenance = base.read_json(PREVIOUS / 'provenance.json')
    provenance.update(protocol=PROTOCOL, lineage=lineage, row_interval=copy.deepcopy(combined['row_interval']),
                      native_attempt_alignment=copy.deepcopy(combined['coverage']['attempt_alignment']))
    provenance['sdk_requests'] += [dict(interval_id='retry', number=r['number'], state=r['state'], context=r.get('context'),
        stage=r.get('stage'), phase=r.get('phase'), request_sha256=r.get('request_sha256'), response_sha256=r.get('response_sha256'))
        for r in ledger.records]
    base.write_json(directory / 'combined.json', combined)
    base.write_json(directory / 'provenance.json', provenance)
    return combined


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'preflight', 'run', 'aggregate'])
    parser.add_argument('--engine-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--approved-plan-sha256')
    parser.add_argument('--data-release-ref')
    args = parser.parse_args(argv)
    release = None
    if args.command in {'run', 'preflight'}:
        require(args.approved_plan_sha256 and args.data_release_ref, 'separate accepted data release required')
        plan = base.read_json(args.output / 'plan.json')
        release = authenticate_release(args.data_release_ref, plan, args.approved_plan_sha256)
    engine = base.load_engine(args.engine_root)
    if args.command == 'prepare':
        plan = prepare(engine, args.output)
        print(base.hash_json(plan))
        return 0
    plan = base.read_json(args.output / 'plan.json')
    manifest = validate_plan(engine, plan, args.output)
    if args.command == 'preflight':
        print(base.hash_json(plan))
        return 0
    if args.command == 'aggregate':
        aggregate(engine, args.output)
        return 0
    directory = args.output / 'measurement'
    cfg = engine.modules['config']
    settings = cfg.get_settings()
    require(settings.has_api_key and settings.base_url == plan['provider_base_url'] == cfg.DEFAULT_BASE_URL,
            'approved provider credentials/default endpoint unavailable')
    if directory.exists() and any(directory.iterdir()):
        require((directory / 'budget.json').exists() and (directory / 'data-release.json').exists(), 'do not reset existing retry history')
        require(base.read_json(directory / 'data-release.json') == release, 'retry data release changed')
    with base.RequestJournal(directory, **journal_settings(plan)) as journal:
        base.write_json(directory / 'data-release.json', release)
        result = asyncio.run(evaluate_retry(engine, manifest, directory, journal))
    print({'attempts': result['usage']['attempts'], 'complete': result['rows'][0]['complete'],
           'stop_reason': result['usage']['stop_reason']})
    return 0 if result['rows'][0]['complete'] and not result['usage']['stop_reason'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
