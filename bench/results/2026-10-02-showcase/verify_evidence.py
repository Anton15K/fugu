"""Verify showcase integrity, coverage, telemetry and source adjudication.

Default mode uses only the standard library and retained evidence. Optional
cache/engine arguments inspect local bytes; they never run auditee code or APIs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DOCS = ROOT / 'docs/showcase/2026-10-02-active-repos'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(name: str):
    return json.loads((HERE / name).read_text())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--engine', type=Path)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--offline-result', type=Path)
    args = parser.parse_args()
    manifest = read('manifest.json')
    listed = set(manifest['files'])
    actual = {str(p.relative_to(ROOT)) for base in (HERE, DOCS)
              for p in base.rglob('*') if p.is_file() and p != HERE / 'manifest.json'
              and '__pycache__' not in p.parts}
    require(actual == listed, 'Deliverable inventory differs from manifest')
    patterns = [
        re.compile(rb'(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{24,}'),
        re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),
        re.compile(rb'github_pat_[A-Za-z0-9_]{40,}'),
        re.compile(rb'AKIA[0-9A-Z]{16}'),
        re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    ]
    require(bool(patterns[0].search(b' sk-' + b'A' * 32)), 'Synthetic credential shape missed')
    require(not patterns[0].search(b'disk-' + b'A' * 32), 'Word ending mistaken for credential prefix')
    for rel, entry in manifest['files'].items():
        path = ROOT / rel
        require(path.is_file() and not path.is_symlink(), 'Nonregular deliverable: ' + rel)
        data = path.read_bytes()
        require(sha(data) == entry['sha256'] and len(data) == entry['bytes'], 'Hash/size mismatch: ' + rel)
        for pattern in patterns:
            require(not pattern.search(data), 'Credential-like pattern in ' + rel)
        if path.suffix == '.json':
            json.loads(data)
    # Manifest is generated metadata, but still belongs in the credential scan.
    for pattern in patterns:
        require(not pattern.search((HERE / 'manifest.json').read_bytes()), 'Credential-like pattern in manifest')
    plan, measured, summary = read('measurement-plan.json'), read('measured.json'), read('summary.json')
    engine = read('engine-manifest.json')
    calls, responses, adjudication = read('call-ledger.json'), read('responses.json'), read('adjudication.json')
    acquisitions = {a['repository']: a for a in read('acquisition.json')['projects']}
    projects = {p['repository']: p for p in read('shortlist.json')['projects']}
    require(len(projects) == 8 and len(plan['artifacts']) == len(measured['rows']) == 5, 'Artifact bounds')
    require(measured['plan_sha256'] == sha((HERE / 'measurement-plan.json').read_bytes()), 'Measurement plan changed')
    require(not measured['engine_changed'] and measured['engine_hashes_before'] == measured['engine_hashes_after'] == engine['engine_source_hashes'], 'Mixed engine versions')
    require(measured['target_executions'] == 0 and not measured['unmeasured_semantic_artifacts'], 'Scope/coverage mismatch')
    require(sha((HERE / 'system-prompt.txt').read_bytes()) == plan['system_prompt_sha256'], 'System prompt mismatch')
    require(18 == len(calls) == len(responses) == read('budget-state.json')['attempts'] <= plan['calls_limit_total'] == 24, 'Cumulative request budget')
    require(calls == measured['live']['calls'] and measured['live']['stop_reason'] is None, 'Call ledger differs from raw stages')
    expected_units = []
    findings = []
    stage_counts = {'concealment': 0, 'static': 0, 'semantic': 0}
    for artifact, row in zip(plan['artifacts'], measured['rows']):
        require(row['id'] == artifact['id'] and row['commit'] == artifact['commit'] == projects[row['repository']]['commit'], 'Wrong pin/order')
        require(row['input_sha256'] == artifact['input_sha256'], 'Input packet changed')
        for rel, expected in artifact['input_sha256'].items():
            require(acquisitions[row['repository']]['files_sha256'][rel] == expected, 'Acquired input hash mismatch')
        expected_units.extend((artifact['id'], f"File: {u['file']} (part {u['part']})") for u in artifact['units'])
        require([s['stage'] for s in row['stages']] == ['concealment', 'static', 'semantic'], 'Unexpected stage coverage')
        for stage in row['stages']:
            m = stage['metrics']
            require(stage['ok'] and stage['error'] is None and m['files_scanned'] == len(artifact['files']), 'Failed/incomplete stage')
            require(not any(v for k, v in m.items() if k.startswith('skipped_')), 'Collector omission')
            if stage['stage'] == 'semantic':
                require(m['units_completed'] == m['units_total'] == len(artifact['units']), 'Unit denominator mismatch')
                require(not any(m[k] for k in ('units_partial', 'units_omitted', 'parse_errors', 'call_errors', 'response_recoveries')), 'Incomplete/repaired analysis')
            stage_counts[stage['stage']] += len(stage['findings'])
            findings.extend((row['id'], stage['stage'], i, f) for i, f in enumerate(stage['findings']))
    require(expected_units == [(c['artifact'], c['unit_label']) for c in calls], 'Missing/extra unit or retry')
    for i, (call, response) in enumerate(zip(calls, responses), 1):
        require(call['attempt'] == response['attempt'] == i and call['state'] == 'response_received', 'Attempt accounting')
        require(call['system_sha256'] == plan['system_prompt_sha256'] and call['system_chars'] == plan['system_prompt_chars'], 'Prompt contract')
        require(call['max_completion_tokens'] == 4096 and call['timeout_s'] == 90 and call['sdk_retries'] == 0, 'Request bound')
        require(call['model'] == summary['model'] and call['finish_reason'] == 'stop', 'Model/finish state')
        raw = response['raw_response']
        require(sha(raw.encode()) == response['response_sha256'] == call['response_sha256'], 'Response integrity')
        require(len(raw) == call['response_chars'] and isinstance(json.loads(raw)['findings'], list), 'Response parse state')
    require(summary['raw_alerts'] == stage_counts == {'concealment': 0, 'static': 1, 'semantic': 7}, 'Alert counts')
    require(summary['prompt_tokens'] == sum(c['usage']['prompt_tokens'] for c in calls) == 31329, 'Prompt token tally')
    require(summary['completion_tokens'] == sum(c['usage']['completion_tokens'] for c in calls) == 15430, 'Completion token tally')
    require(summary['prompt_chars'] == sum(c['system_chars'] + c['user_chars'] for c in calls), 'Prompt size tally')
    require(summary['sum_request_latency_s'] == round(sum(c['latency_s'] for c in calls), 3), 'Latency tally')
    require(len(adjudication['alerts']) == len(findings) == 8, 'Missing adjudication')
    for (artifact, stage, index, finding), note in zip(findings, adjudication['alerts']):
        require((artifact, stage, index) == (note['artifact'], note['stage'], note['finding_index']), 'Adjudication locator')
        require(sha(json.dumps(finding, sort_keys=True, separators=(',', ':')).encode()) == note['finding_sha256'], 'Alert altered')
        require(not note['confirmed_vulnerability'], 'Unreviewed vulnerability claim')
    cached_files, actual_engine, historical, reconstructed_prompts = 0, 0, 0, 0
    guards = 'not rerun; requires --engine and project Python dependencies'
    if args.cache:
        for repo, acquisition in acquisitions.items():
            root = args.cache / repo.replace('/', '--')
            require(root.is_dir() and not root.is_symlink(), 'Unsafe cache root')
            for rel, expected in acquisition['files_sha256'].items():
                path = root / rel
                components = [root]
                for part in Path(rel).parts:
                    components.append(components[-1] / part)
                require(not any(p.is_symlink() for p in components), 'Cache symlink')
                require(path.is_file() and sha(path.read_bytes()) == expected, 'Pinned cache mismatch: ' + repo + '/' + rel)
                cached_files += 1
        for entry in adjudication['manual_unmeasured_sources']:
            path = args.cache / entry['repository'].replace('/', '--') / entry['path']
            require(sha(path.read_bytes()) == entry['sha256'], 'Manual review source changed')
    if args.engine:
        hashes = {'src/' + str(p.relative_to(args.engine)): sha(p.read_bytes()) for p in (args.engine / 'fugu').rglob('*.py')}
        require(hashes == engine['engine_source_hashes'], 'Execution engine mismatch')
        actual_engine = len(hashes)
        sys.path.insert(0, str(args.engine))
        from fugu.pipeline.stages.semantic import _chunks, _JUDGE_SYSTEM
        require(_JUDGE_SYSTEM == (HERE / 'system-prompt.txt').read_text(), 'Frozen rubric differs')
        if args.cache:
            unit_index = 0
            for artifact in plan['artifacts']:
                units = []
                for rel in artifact['files']:
                    source = (args.cache / artifact['repository'].replace('/', '--') / rel).read_text()
                    for part, chunk in enumerate(_chunks(source), 1):
                        units.append({'file': rel, 'part': part, 'content_chars': len(chunk), 'content_sha256': sha(chunk.encode())})
                        user = f'File: {rel} (part {part})\n<content>\n{chunk}\n</content>\n\nAudit this content per the system instructions. JSON only.'
                        call = calls[unit_index]
                        require(sha(user.encode()) == call['user_sha256'] and len(user) == call['user_chars'], 'User prompt reconstruction differs')
                        unit_index += 1
                require(units == artifact['units'], 'Frozen chunk plan differs')
            reconstructed_prompts = unit_index
        spec = importlib.util.spec_from_file_location('showcase_runner', HERE / 'run_showcase.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for attempts, reason in [(24, None), (18, 'provider_quota_exhausted'), (18, 'provider_auth_error')]:
            caller = module.BudgetedCaller.__new__(module.BudgetedCaller)
            caller.attempts, caller.limit, caller.stop_reason = attempts, 24, reason
            # No SDK/client is assigned: getting past the stop gate would fail.
            try:
                caller('', '')
                raise ValueError('Stop guard allowed a request')
            except RuntimeError as exc:
                require(str(exc).startswith('Paid requests stopped:'), 'Unexpected guard failure')
            require(caller.attempts == attempts, 'Guard incremented/networked after stop')
        guards = 'hard24, quota and auth gates refused before counter/client access'
    if args.baseline:
        baseline = json.loads(args.baseline.read_text())
        for rel, expected in baseline['immutable_source_hashes'].items():
            require(sha((ROOT / rel).read_bytes()) == expected, 'Historical evidence changed: ' + rel)
            historical += 1
        require(historical == 1672, 'Unexpected historical inventory')
    if args.offline_result:
        replay = json.loads(args.offline_result.read_text())
        require(replay['engine_hashes_before'] == replay['engine_hashes_after'] == engine['engine_source_hashes'], 'Replay engine changed')
        require(replay['target_executions'] == 0 and len(replay['rows']) == 5 and 'live' not in replay, 'Offline replay scope')
        for original, repeated in zip(measured['rows'], replay['rows']):
            require(original['input_sha256'] == repeated['input_sha256'], 'Replay packet changed')
            require([s['stage'] for s in repeated['stages']] == ['concealment', 'static'], 'Offline replay executed extra stages')
            for left, right in zip(original['stages'][:2], repeated['stages']):
                require(left['findings'] == right['findings'] and right['ok'], 'Offline alerts differ')
    print(json.dumps({'status': 'pass', 'deliverables_hashed': len(listed),
        'credential_pattern_scan': {'files': len(listed) + 1, 'patterns': len(patterns), 'matches': 0,
            'limit': 'Common credential-like formats only; does not prove absence of every secret'},
        'real_world_packets': 5, 'completed_semantic_units': 18, 'requests': 18,
        'source_adjudications': 8, 'cached_regular_files_verified': cached_files,
        'user_prompts_reconstructed': reconstructed_prompts,
        'engine_files_verified': actual_engine, 'historical_files_preserved': historical,
        'request_stop_guards': guards, 'offline_replay_compared': bool(args.offline_result)}, indent=2))


if __name__ == '__main__':
    main()
