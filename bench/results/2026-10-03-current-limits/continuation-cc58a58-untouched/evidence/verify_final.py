"""Check completed continuation bytes and counts offline before sealing."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import math
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[5]
CHILD = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bench import current_limits as base
from bench import current_limits_continuation as continuation
from bench import current_limits_continuation_charts as charts


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    preflight = base.read_json(CHILD / 'evidence/preflight.json')
    for item in preflight['protected']:
        path = Path(item['path'])
        require(path.is_file() and not path.is_symlink(), 'Protected file missing or symlink: ' + str(path))
        require(digest(path) == item['sha256'], 'Protected file changed: ' + str(path))
    for item in preflight['owner']:
        require(digest(ROOT / item['path']) == item['sha256'], 'Owner file changed: ' + item['path'])
    require(len(preflight['protected']) == 2348, 'Protected inventory changed')
    parent = continuation.load_parent()
    child = base.read_json(CHILD / 'fugu.json')
    combined = base.read_json(CHILD / 'combined.json')
    provenance = base.read_json(CHILD / 'provenance.json')
    plan = base.read_json(CHILD / 'plan.json')
    release = base.read_json(CHILD / 'data-release.json')
    ledger = continuation.read_ledger(CHILD, allow_orphans=True)
    registry_path = continuation.DEFAULT_REGISTRY
    registry = base.read_json(registry_path)
    continuation.validate_registry_ledger(registry, ledger, CHILD,
        binding=base.hash_json(plan), parent_usage=parent.usage)

    require(base.hash_json(plan) == 'ea8cff37184b4dd7efe06d3494643462298b398bebcb471d50ce0d6d76f32835', 'Plan changed')
    require(release['queue_ref'] == 'qitem-20261003080043-770294f3', 'Release changed')
    require(release['binding'] == preflight['release_binding'], 'Release binding changed')
    require(digest(CHILD / 'evidence/reviewed-bootstrap-v2.py') == preflight['bootstrap_sha256'], 'Bootstrap changed')
    require(len(child['rows']) == 27 and all(r['complete'] and r['status'] == 'completed' for r in child['rows']), 'Child completion differs')
    require(combined['rows'][:13] == parent.result['rows'][:13], 'Carried rows changed')
    require(combined['rows'][13:] == child['rows'], 'Child rows changed in combined result')
    require([r['id'] for r in combined['rows']] == [c['id'] for c in parent.original['cases']], 'Original order changed')
    require(Counter(r['status'] for r in combined['rows']) == {'completed': 39, 'partial': 1}, 'Combined status differs')

    # Independently count numbered SDK records, rather than trusting summary fields.
    records = [base.read_json(p) for p in sorted((CHILD / 'calls').glob('*.json'))]
    require([r['number'] for r in records] == list(range(1, 920)), 'Request numbering differs')
    require(all(r['state'] == 'returned' and r['output_error'] is None for r in records), 'Child request incomplete/error')
    require(all(r['max_tokens'] == 4096 and r['temperature'] == 0.1 and r['finish_reason'] == 'stop' for r in records), 'Profile or finish differs')
    require(all(r['requested_model'] == r['served_model'] for r in records), 'Served identity differs')
    models = dict(Counter(r['served_model'] for r in records))
    require(models == {'nvidia/Nemotron-3-Ultra-550b-a55b': 640,
                      'nvidia/nemotron-3-super-120b-a12b': 279}, 'Model counts differ')
    phases = dict(Counter(r['phase'] for r in records))
    require(phases == {'common20': 194, 'remainder': 725}, 'Phase counts differ')
    require(dict(Counter(r['stage'] for r in records)) == {'semantic': 50, 'harness': 869}, 'Stage counts differ')
    prompt = sum(r['usage']['prompt_tokens'] for r in records)
    completion = sum(r['usage']['completion_tokens'] for r in records)
    duration = sum(r['duration_s'] for r in records)
    require((prompt, completion) == (498335, 307652), 'Child token totals differ')
    require(math.isclose(duration, 1689.373336299759, rel_tol=0, abs_tol=1e-8), 'Child duration differs')
    require(child['usage']['prompt_tokens_total'] == prompt and child['usage']['completion_tokens_total'] == completion, 'Saved child tokens disagree')
    require(child['usage']['phase_attempts'] == phases and child['usage']['served_models'] == sorted(models), 'Saved phases/model identities disagree')
    require(math.isclose(child['usage']['sum_request_duration_s'], duration, rel_tol=0, abs_tol=1e-8), 'Saved child duration disagrees')
    for field in ('provider_errors', 'orphan_attempts', 'output_errors', 'unknown_usage_calls', 'unknown_duration_calls', 'replayed_requests_this_process'):
        require(child['usage'][field] == 0, 'Unexpected child accounting field: ' + field)
    require(child['usage']['attempts'] == registry['attempts'] == ledger.state['attempts'] == 919, 'Attempt records disagree')
    require(registry['session_open'] is False and registry['stop_reason'] is None, 'Ownership not cleanly closed')
    guard = registry_path.with_suffix('.guard.json')
    seal = registry_path.with_suffix('.lock')
    require(not guard.exists() and seal.is_file(), 'Ownership guard/seal differs')
    require((CHILD / '.journal.lock').read_bytes() == b'', 'Journal bookkeeping changed')
    require(combined['usage']['attempts'] == 1278, 'Cumulative attempts differ')
    require(combined['usage']['prompt_tokens_known_subtotal'] == 583411, 'Prompt subtotal differs')
    require(combined['usage']['completion_tokens_known_subtotal'] == 420289, 'Completion subtotal differs')
    require(combined['usage']['prompt_tokens_total'] is None and combined['usage']['completion_tokens_total'] is None, 'Unknown parent usage lost')
    require(len(provenance['sdk_requests']) == 1278, 'SDK provenance count differs')
    require(len({(r['interval_id'], r['number']) for r in provenance['sdk_requests']}) == 1278, 'SDK references not interval-qualified')
    require(combined['child_result_sha256'] == digest(CHILD / 'fugu.json'), 'Child result lineage hash differs')
    require(combined['parent_result_sha256'] == digest(parent.directory / 'fugu.json'), 'Parent result lineage hash differs')

    competitors = charts.load_competitors(parent.original, base.FROZEN / 'competitors')
    charts.verify_manifest_packets(parent.original)
    rebuilt = charts.chart_data(combined, parent.original, competitors, comparator_snapshot='2026-10-02-full')
    require(rebuilt == base.read_json(CHILD / 'charts/chart-data.json'), 'Numerical chart data differs from source')
    qa = base.read_json(CHILD / 'evidence/qa.json')
    for item in qa['visual_inspection']:
        require(item['viewed'] and digest(ROOT / item['path']) == item['sha256'], 'Viewed PNG changed')
    svg = sorted((CHILD / 'charts').glob('*.svg'))
    require(len(svg) == 3, 'SVG count differs')
    for path in svg:
        ET.parse(path)
    require(not any(p.is_symlink() for p in CHILD.rglob('*')), 'Child contains symlink')
    report = ROOT / 'docs/benchmark-current-limits-continuation.md'
    report_text = report.read_text()
    require(not any(line.rstrip() != line for line in report_text.splitlines()), 'Report trailing whitespace')
    links = re.findall(r'\]\(([^)]+)\)', report_text)
    for link in links:
        if '://' not in link and not link.startswith('#'):
            target = (report.parent / link.split('#')[0]).resolve()
            # These two outputs are checked after their writes to avoid circular hashes.
            if target in (CHILD / 'artifact-manifest.json', CHILD / 'evidence/final-check.json'):
                continue
            require(target.exists(), 'Report link missing: ' + link)
    result = {
        'schema': 2, 'checked_utc': datetime.now(timezone.utc).isoformat(),
        'data_release_queue_ref': release['queue_ref'], 'provider_requests': 0,
        'target_executions': 0, 'protected_files_preserved': 2348,
        'owner_files_preserved': 3, 'parent_files_preserved': 403,
        'carried_rows_preserved': 13, 'child_rows_preserved': 27,
        'child_requests': 919, 'cumulative_requests': 1278, 'phase_requests': phases,
        'models': models, 'child_prompt_tokens': prompt, 'child_completion_tokens': completion,
        'child_sdk_duration_s': duration, 'whole_tokens_unknown': True,
        'registry_session_open': False, 'registry_stop_reason': None,
        'registry_guard_present': False, 'registry_seal_present': True,
        'numerical_chart_data_recomputed': True, 'viewed_png_hashes_preserved': 3,
        'svg_parsed': 3, 'report_links_checked': len(links),
        'script_sha256': digest(Path(__file__)), 'report_sha256': digest(report),
        'artifact_inventory_pending': True,
    }
    base.write_json(CHILD / 'evidence/final-check.json', result)
    require((CHILD / 'evidence/final-check.json').is_file(), 'Final check output missing')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
