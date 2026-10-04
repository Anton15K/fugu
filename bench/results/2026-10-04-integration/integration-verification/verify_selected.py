"""Offline selected-evidence recount; no SDK, search, scanner or target execution.

--package verifies original bytes and writes allowlisted metadata to --output.
Without --package, recount the selected export and check its retained chart data.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':')).encode())


def load(path):
    return json.loads(path.read_text())


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def write_call_records(root, calls, budget):
    def compact(value):
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    path = root / 'selected/sdk-calls.json'
    path.write_text('{"rows":[\n' + ',\n'.join(compact(row) for row in calls) +
                    '\n],"budget":' + compact(budget) + '}\n')


def tree_hashes(root):
    result = {}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(), 'symlink in retained inputs'
        if path.is_file():
            assert path.name.lower() not in {'.env', '.netrc', 'credentials'}, 'credential path'
            result[path.relative_to(root).as_posix()] = sha(path.read_bytes())
    return result


def aggregate(rows):
    groups = defaultdict(list)
    for row in rows:
        for variant in ('baseline', 'integrated'):
            groups[(variant, row['cohort'], row['kind'])].append(row[variant])
    return [{'variant': v, 'cohort': c, 'kind': k, 'attempted': len(items),
             'complete': sum(r['complete'] for r in items),
             'excluded': sum(not r['complete'] for r in items),
             'flagged_complete': sum(r['complete'] and r['detected'] for r in items),
             'flagged_partial': sum(not r['complete'] and r['detected'] for r in items)}
            for (v, c, k), items in sorted(groups.items())]


def usage(calls):
    value = {'attempts': len(calls), 'orphan_attempts': sum(r['state'] == 'reserved' for r in calls),
             'provider_errors': sum(r['state'] == 'error' for r in calls),
             'output_errors': sum(bool(r.get('output_error')) for r in calls),
             'finish_reasons': dict(Counter(r.get('finish_reason') or 'unknown' for r in calls)),
             'requested_models': sorted({r['requested_model'] for r in calls}),
             'served_models': sorted({r['served_model'] for r in calls if r.get('served_model')}),
             'phase_attempts': dict(Counter(r.get('phase') or 'unknown' for r in calls)),
             'sum_request_duration_s': sum(r.get('duration_s', 0) for r in calls),
             'unknown_duration_calls': sum('duration_s' not in r for r in calls),
             'unknown_usage_calls': sum(any(r['usage'][k] is None
                 for k in ('prompt_tokens', 'completion_tokens')) for r in calls)}
    for field in ('prompt_tokens', 'completion_tokens'):
        unknown = sum(r['usage'][field] is None for r in calls)
        subtotal = sum(r['usage'][field] for r in calls if r['usage'][field] is not None)
        value[field + '_known_subtotal'] = subtotal
        value[field + '_unknown_calls'] = unknown
        value[field + '_total'] = subtotal if not unknown else None
    return value


def coverage(rows, variant):
    return Counter((s['stage'], s['state']) for r in rows for s in r[variant]['stages'])


def selected_stage(stage):
    return {k: stage[k] for k in ('stage', 'state', 'ok')} | {
        'raw_stage_sha256': canonical(stage),
        'error': None if stage['error'] is None else {'sha256': canonical(stage['error'])},
        'metrics': {k: v for k, v in stage['metrics'].items()
                    if v is None or isinstance(v, (bool, int, float))},
        'coverage_markers': {k: bool(stage['metrics'].get(k)) for k in (
            'skipped', 'unattempted', 'coverage_incomplete', 'call_errors', 'parse_errors', 'omitted_units')},
        'findings': [{k: f[k] for k in ('stage', 'severity', 'confidence')}
                     for f in stage['findings']]}


def selected_variant(value):
    return {k: value[k] for k in ('complete', 'detected', 'raw_medium_alert', 'composition_score')} | {
        'stages': [selected_stage(s) for s in value['stages']],
        'raw_variant_sha256': canonical(value)}


def export(package, repo, output):
    manifest_bytes = (package / 'delivery-manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    assert len(manifest) == 1572
    secret_patterns = {
        'aws_access_key': re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
        'github_token': re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})'),
        'slack_token': re.compile(rb'\bxox[baprs]-[A-Za-z0-9-]{20,}'),
        'private_key_header': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        'bearer_token': re.compile(rb'(?i)Bearer\s+[A-Za-z0-9_.-]{20,}'),
    }
    scan = Counter()
    github_candidates = set()
    for name, expected in manifest.items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts
        path = package / rel
        assert path.is_file() and not path.is_symlink()
        assert path.resolve().is_relative_to(package.resolve())
        assert path.name.lower() not in {'.env', '.netrc', 'credentials'}
        raw = path.read_bytes()
        assert sha(raw) == expected['sha256'] and len(raw) == expected['bytes'], 'original package hash changed'
        # Counts only. Archive/binary bytes are hashed, never unpacked or executed.
        if path.suffix in {'.json', '.jsonl', '.log', '.md', '.py', '.patch'}:
            for key, pattern in secret_patterns.items():
                scan[key] += len(pattern.findall(raw))
            github_candidates.update(secret_patterns['github_token'].findall(raw))
    m = package / 'measurement'
    data, cases, plan = (load(m / n) for n in ('fugu.json', 'cases.json', 'plan.json'))
    assert canonical(plan) == data['plan_sha256']
    assert canonical(cases) == plan['cases_sha256']
    assert data['profile'] == plan['limits'] and data['profile']['llm_max_output_tokens'] == 4096
    assert len(cases['cases']) == data['planned'] == len(data['rows']) == 40
    assert [r['id'] for r in data['rows']] == [c['id'] for c in cases['cases']]
    frozen = load(package / 'measured-engine/manifest.json')['hashes']
    assert frozen == plan['engine']
    assert len(frozen) == 39
    for name, expected in frozen.items():
        assert sha((package / 'measured-engine' / name).read_bytes()) == expected
    audits = {}
    audit_refs = []
    for path in sorted((m / 'audits').glob('*.json')):
        audit = load(path)
        key = canonical(audit['input_sha256'])
        assert path.stem == key and key not in audits
        assert [s for s in audit['baseline'] if s['stage'] != 'static'] == [
            s for s in audit['integrated'] if s['stage'] != 'static']
        audits[key] = audit
        audit_refs.append({'id': key, 'path': path.relative_to(package).as_posix(),
                           'sha256': sha(path.read_bytes()), 'input_sha256': audit['input_sha256'],
                           'nonstatic_sha256': canonical([s for s in audit['baseline'] if s['stage'] != 'static']),
                           'baseline_static_sha256': canonical(next(s for s in audit['baseline'] if s['stage'] == 'static')),
                           'integrated_static_sha256': canonical(next(s for s in audit['integrated'] if s['stage'] == 'static'))})
    assert len(audits) == data['unique_inputs'] == 45
    local = load(repo / '.fugu-private/workflow-integration-20261004/preservation.json')
    local_by_hash = defaultdict(list)
    for name, digest in local['immutable_benchmark_files'].items():
        local_by_hash[digest].append(name)
    restoration, unique = [], set()
    for index, (case, row) in enumerate(zip(cases['cases'], data['rows']), 1):
        assert load(m / 'rows' / f'{index:02d}.json') == row
        assert {k: row[k] for k in case} == case
        target = Path(case['target'])
        assert target.resolve().is_relative_to((m / 'targets').resolve())
        assert tree_hashes(target) == case['input_sha256']
        for member in case.get('members') or [{'dir': None}]:
            directory = target / member['dir'] if member['dir'] else target
            key = canonical(tree_hashes(directory))
            assert key in audits
            unique.add(key)
        for variant in ('baseline', 'integrated'):
            expected_stages = []
            for member in case.get('members') or [{'dir': None}]:
                directory = target / member['dir'] if member['dir'] else target
                expected_stages.extend(audits[canonical(tree_hashes(directory))][variant])
            assert row[variant]['stages'][:-1] == expected_stages
            assert row[variant]['stages'][-1]['stage'] == 'composition'
            assert row[variant]['complete'] == all(s['state'] in ('completed', 'not_applicable')
                                                  for s in row[variant]['stages'])
            alert = any(f['severity'] in ('medium', 'high', 'critical') for f in row[variant]['findings'])
            assert row[variant]['raw_medium_alert'] == alert
            if case['cohort'] == 'composition':
                score = row[variant]['composition_score']
                assert score['matches_expected'] == all(score[k] == case['expected'][k]
                                                        for k in ('trifecta', 'shadowing'))
                detected = score['trifecta'] or score['shadowing']
            elif case['cohort'] == 'reputation':
                detected = any(f['stage'] == 'reputation' and f['confidence'] == 'measured'
                               for f in row[variant]['findings'])
            else:
                detected = alert
            assert row[variant]['detected'] == detected
        assert [s for s in row['baseline']['stages'] if s['stage'] not in ('static', 'composition')] == [
            s for s in row['integrated']['stages'] if s['stage'] not in ('static', 'composition')]
        restoration.append({'id': case['id'], 'raw_target': target.relative_to(package).as_posix(),
            'member_dirs': [member['dir'] for member in case.get('members', [])],
            'files': [{'path': name, 'sha256': digest, 'existing_matches': sorted(local_by_hash[digest])}
                      for name, digest in case['input_sha256'].items()]})
    assert len(unique) == 45
    assert aggregate(data['rows']) == data['summary']
    for variant in ('baseline', 'integrated'):
        assert coverage(data['rows'], variant) == Counter({(s['stage'], s['state']): s['count']
                                                          for s in data['coverage'][variant]})
    calls = []
    allowed = ('number', 'ordinal', 'context', 'stage', 'phase', 'state', 'reserved_utc',
               'requested_model', 'served_model', 'max_tokens', 'temperature', 'finish_reason',
               'choice_present', 'usage_object_present', 'usage', 'duration_s', 'output_error',
               'messages_sha256', 'request_sha256', 'response_sha256', 'error')
    for path in sorted((m / 'inference/calls').glob('*.json')):
        row = load(path)
        assert row['context'] in audits
        assert row['messages_sha256'] == canonical(row['messages'])
        assert row['request_sha256'] == canonical({'model': row['requested_model'],
            'messages': row['messages'], 'temperature': row['temperature'], 'max_tokens': row['max_tokens']})
        assert row['response_sha256'] == sha(row['raw_response'].encode())
        assert row['max_tokens'] == 4096 and row['requested_model'] in plan['models']
        safe = {k: row[k] for k in allowed if k in row}
        safe['response_chars'] = len(row['raw_response'])
        assert not safe.get('error') and not safe.get('output_error')
        safe['raw_record'] = {'path': path.relative_to(package).as_posix(), 'sha256': sha(path.read_bytes())}
        calls.append(safe)
    assert [r['number'] for r in calls] == list(range(1, 1297))
    measured_usage = usage(calls)
    for key, value in measured_usage.items():
        assert data['inference'][key] == value, 'usage recount mismatch'
    budget = load(m / 'inference/budget.json')
    assert budget['attempts'] == len(calls) and budget['binding'] == canonical(plan)
    assert budget['expected_output_tokens'] == 4096 and budget['limit'] == 1900
    searches = []
    for path in sorted((m / 'searches').glob('*.json')):
        row = load(path)
        searches.append({'number': row['number'], 'error': row.get('error'),
                         'query_sha256': canonical(row['query']),
                         'response_sha256': canonical(row['response']) if 'response' in row else None,
                         'raw_record': {'path': path.relative_to(package).as_posix(), 'sha256': sha(path.read_bytes())}})
    assert [r['number'] for r in searches] == list(range(1, 17))
    assert len(searches) == data['searches'] and not any(r['error'] for r in searches)
    cmp, common = load(m / 'mcp-sec-audit.json'), load(m / 'common.json')['common']
    common_cases = [c for c in cases['cases'] if c['cohort'] in ('mcptox', 'clean_descriptions')]
    assert [r['id'] for r in cmp['results']] == [c['id'] for c in common_cases] == [c['id'] for c in common]
    assert len(common) == 20
    assert cmp['source_commit'] == '457057a7dfda6b81622a12ee68b74f76f3fbde85'
    assert cmp['rules_sha256'] == 'c7529b02d5ae056f67c6b46eb75616b897107044d1b6bf4a1c38af823fcce1b4'
    for row, case, binding in zip(cmp['results'], common_cases, common):
        assert row['packet_sha256'] == binding['packet_sha256'] == case['input_sha256']['tools.json']
        tool = load(Path(case['target']) / 'tools.json')['tools'][0]
        assert set(tool) == {'name', 'description', 'inputSchema'} and tool['inputSchema'] == {}
        assert row['risk_score'] == row['raw']['total_score']
        assert row['flagged'] == (row['risk_score'] >= 25)
        assert row['native_flag'] == bool(row['raw']['findings'])
        assert row['complete'] is True
    extended = load(m / 'extended-static.json')
    assert len(extended['rows']) == 140
    hardening = load(m / 'hardening-equivalence.json')
    final_engine = {k: sha((package / 'work' / k).read_bytes()) for k in frozen}
    assert final_engine == hardening['engine_after']
    assert [k for k in frozen if frozen[k] != final_engine[k]] == hardening['changed_engine_files'] == [
        'src/fugu/pipeline/stages/tool_surface.py']
    assert hardening['unique_inputs'] == len(hardening['checks']) == 45
    assert hardening['all_decision_signatures_unchanged'] and all(r['decision_signature_unchanged'] for r in hardening['checks'])
    assert {canonical(tree_hashes(Path(r['target']))) for r in hardening['checks']} == unique
    current_differences = [{'path': k, 'delivered_sha256': final_engine[k],
                            'current_sha256': sha((repo / k).read_bytes())}
                           for k in final_engine if sha((repo / k).read_bytes()) != final_engine[k]]
    output.mkdir(parents=True, exist_ok=True)
    (output / 'raw-delivery-manifest.json').write_bytes(manifest_bytes)
    write(output, 'frozen-plan.json', plan)
    safe_data = {k: v for k, v in data.items() if k != 'rows'}
    safe_data['export_contract'] = 'Selected metadata; raw details omitted and linked by SHA256. No new measurement.'
    safe_data['rows'] = [{k: row[k] for k in ('id', 'cohort', 'kind', 'input_sha256')} | {
        'baseline': selected_variant(row['baseline']), 'integrated': selected_variant(row['integrated'])}
                        for row in data['rows']]
    write(output, 'selected/fugu.json', safe_data)
    write(output, 'selected/mcp-sec-audit.json', {k: v for k, v in cmp.items() if k != 'results'} | {
        'results': [{k: v for k, v in r.items() if k != 'raw'} | {'raw_result_sha256': canonical(r['raw'])}
                    for r in cmp['results']]})
    write(output, 'selected/extended-static.json', {k: v for k, v in extended.items() if k != 'rows'} | {
        'rows': [{k: r[k] for k in ('id', 'cohort', 'label', 'complete', 'flagged')} | {
            'raw_static_sha256': canonical(r['static'])} for r in extended['rows']]})
    write_call_records(output, calls, budget)
    write(output, 'selected/searches.json', {'rows': searches, 'persistent_search_budget_file_present':
        (m / 'searches/budget.json').exists(), 'recorded_stop_reason': data['search_stop_reason']})
    write(output, 'audit-bindings.json', {'rows': audit_refs})
    write(output, 'input-restoration-map.json', {'cases': restoration, 'source_hashes': cases['source_hashes'],
        'boundary': 'Existing paths are candidate byte sources only. Verify each SHA256 before copying regular files into new opaque directories. Never write old targets or execute inputs.'})
    source_reasons = {
        'src/fugu/pipeline/stages/static_context.py': 'Backend one-pass AST pre-indexing; separate differential parser check reported for 45 inputs.',
        'src/fugu/pipeline/stages/static_scan.py': 'Backend bounded npm-hook fix: echo/exit exemptions exclude shell control, substitution and newlines.',
    }
    for difference in current_differences:
        difference['reason'] = source_reasons.get(difference['path'], 'Unadjudicated source difference; independent verification required.')
    write(output, 'source-binding.json', {'frozen_engine': frozen, 'delivered_engine': final_engine,
        'recorded_hardening_path': 'measurement/hardening-equivalence.json',
        'recorded_hardening_sha256': sha((m / 'hardening-equivalence.json').read_bytes()),
        'recorded_checks': 45, 'fresh_scanner_run': False, 'current_differences': current_differences,
        'current_engine_equivalence': 'Separate backend/lead classification checks required for listed differences; no inference/chamber rerun.'})
    write(output, 'export-verification.json', {'checked_utc': datetime.now(timezone.utc).isoformat(),
        'raw_manifest_sha256': sha(manifest_bytes), 'raw_manifest_entries_verified': 1572,
        'case_order_and_40_row_files_match': True, 'unique_audits_verified': 45,
        'raw_nonstatic_pairing_equal': True, 'recorded_masking_only_source_change': True,
        'sdk_message_request_response_hashes_verified': 1296, 'comparator_packets_verified': 20,
        'credential_pattern_candidate_counts': dict(scan),
        'github_candidate_review': {'unique_values': len(github_candidates),
            'all_match_authored_fake_fixture_or_synthetic_redaction_test': github_candidates <=
                set(secret_patterns['github_token'].findall((repo / 'corpus/04-credential-reader/skill.py').read_bytes())) |
                {b'ghp_' + b'a1' * 18}},
        'credential_scan_limit': 'Pattern candidate counts only, not proof of absence. No matched values exported or printed. Selected export excludes content payloads.',
        'new_inference_search_chamber_target_calls': 0})


def restore_inputs(root, repo, scratch):
    """Copy existing regular bytes to new scratch targets; never execute them."""
    scratch = scratch.resolve()
    assert scratch.parent == Path('/tmp').resolve() and scratch.name.startswith('fugu-workflow-evidence-')
    assert not scratch.exists() or not any(scratch.iterdir()), 'scratch output must be absent or empty'
    cases = load(root / 'input-restoration-map.json')['cases']
    expected_ids = {r['id'] for r in load(root / 'audit-bindings.json')['rows']}
    unique = set()
    files = 0
    for index, case in enumerate(cases):
        target = scratch / 'targets' / f'{index:04d}'
        for file in case['files']:
            relative = Path(file['path'])
            assert not relative.is_absolute() and '..' not in relative.parts
            source = None
            for name in file['existing_matches']:
                candidate = repo / name
                if candidate.is_file() and not candidate.is_symlink() and candidate.resolve().is_relative_to(repo.resolve()):
                    if sha(candidate.read_bytes()) == file['sha256']:
                        source = candidate
                        break
            assert source is not None, 'matching regular input bytes unavailable'
            output = target / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(source.read_bytes())
            files += 1
        assert tree_hashes(target) == {f['path']: f['sha256'] for f in case['files']}
        for member in case['member_dirs'] or [None]:
            unique.add(canonical(tree_hashes(target / member if member else target)))
    assert unique == expected_ids and len(cases) == 40 and files == 81
    result = {'restored_cases': 40, 'restored_regular_files': files, 'unique_inputs': len(unique),
              'all_input_and_audit_hashes_match': True, 'target_execution': False}
    write(scratch, 'restoration-verification.json', result)
    return result


def recount(root):
    selected = root / 'selected'
    data, cmp, extended = (load(selected / n) for n in ('fugu.json', 'mcp-sec-audit.json', 'extended-static.json'))
    calls, searches = load(selected / 'sdk-calls.json'), load(selected / 'searches.json')
    assert len(data['rows']) == data['planned'] == 40
    assert aggregate(data['rows']) == data['summary']
    recounted_usage = usage(calls['rows'])
    for key, value in recounted_usage.items():
        assert value == data['inference'][key]
    assert len(searches['rows']) == data['searches'] == 16
    assert len(cmp['results']) == 20 and all(r['complete'] for r in cmp['results'])
    partial = [r['id'] for r in data['rows'] if not r['integrated']['complete']]
    assert len(partial) == 4 and sum(r['integrated']['complete'] for r in data['rows']) == 36
    result = {'planned': 40, 'unique_inputs': data['unique_inputs'], 'complete': 36, 'partial_ids': partial,
              'unattempted': data['unattempted_case_ids'], 'cohorts': aggregate(data['rows']),
              'sdk_usage': recounted_usage, 'searches': len(searches['rows']),
              'comparator': {label: {'planned': len(group), 'complete': sum(r['complete'] for r in group),
                  'risk_ge_25': sum(r['flagged'] for r in group), 'native_any_finding': sum(r['native_flag'] for r in group)}
                  for label in ('attack', 'benign') for group in [[r for r in cmp['results'] if r['label'] == label]]},
              'separate_static': {label: {'planned': len(group), 'complete': sum(r['complete'] for r in group),
                  'flagged': sum(r['complete'] and r['flagged'] for r in group)}
                  for label in ('attack', 'benign') for group in [[r for r in extended['rows'] if r['label'] == label]]}}
    chart_path = root / 'charts/chart-data.json'
    if chart_path.exists():
        charts = load(chart_path)
        by_id = {r['id']: r for r in cmp['results']}
        common = [r for r in data['rows'] if r['id'] in by_id and r['baseline']['complete']
                  and r['integrated']['complete'] and by_id[r['id']]['complete']]
        assert charts['common_complete_ids'] == [r['id'] for r in common]
        assert charts['common_planned'] == 20
        for kind, prefix in [('malicious', 'attack'), ('benign', 'clean')]:
            group = [r for r in common if r['kind'] == kind]
            static_counts = [sum(any(f['severity'] in ('medium', 'high', 'critical')
                for s in r[v]['stages'] if s['stage'] in ('static', 'concealment') for f in s['findings'])
                for r in group) for v in ('baseline', 'integrated')]
            counts = static_counts + [sum(r[v]['detected'] for r in group) for v in ('baseline', 'integrated')]
            counts += [sum(by_id[r['id']][key] for r in group) for key in ('flagged', 'native_flag')]
            assert charts[prefix + '_counts'] == counts
            assert charts[prefix + '_denominator'] == len(group)
        assert charts['coverage'] == [[coverage(data['rows'], 'integrated')[(s, state)]
                                      for state in charts['states']] for s in charts['stage_names']]
        result['chart_counts_verified'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--repo', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--restore-scratch', type=Path)
    args = parser.parse_args()
    if args.restore_scratch:
        assert args.repo and not args.package
        print(json.dumps(restore_inputs(args.output, args.repo, args.restore_scratch)))
        return
    if args.package:
        assert args.repo, '--repo is required for package export'
        export(args.package, args.repo, args.output)
    result = recount(args.output)
    write(args.output, 'recount.json', result)
    print(json.dumps({'planned': result['planned'], 'complete': result['complete'],
                      'sdk_attempts': result['sdk_usage']['attempts'], 'searches': result['searches'],
                      'chart_counts_verified': result.get('chart_counts_verified', False)}))


if __name__ == '__main__':
    main()
