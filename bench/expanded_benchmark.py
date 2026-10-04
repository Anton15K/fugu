"""200-case offline diagnostic evaluation. Packets are inert; no target is executed.

80 external MCPTox descriptions, 60 clean descriptions (20 upstream/40
explicitly authored), 24 existing authored compositions, 20 context controls,
and 16 dependency-name checks. Reserved external cases are grouped by server;
this is a reproducible split, not an independently blinded test.
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
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
SEED = '20261003-expanded-v1'
MEDPLUS = {'medium', 'high', 'critical'}
FUZZD_HASH = '85224f942db23733bb4e3ccacbf246fe2cde266ca96321231973bef6d98ea208'
FUZZD_IMAGE = 'sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def select_cases(rows: list[dict], count: int) -> list[dict]:
    if len(rows) < count:
        raise ValueError('Insufficient external cases')
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row['category']].append(row)
    for members in groups.values():
        members.sort(key=lambda r: sha((SEED + r['case_id']).encode()))
    selected = []
    while len(selected) < count:
        for category in sorted(groups):
            if groups[category] and len(selected) < count:
                row = dict(groups[category].pop(0))
                row['split'] = 'reserved' if int(sha((SEED + row['server']).encode())[:8], 16) % 4 == 0 else 'development'
                selected.append(row)
    return selected


def tool_packet(row: dict) -> dict:
    return {'tools': [{'name': row['name'], 'description': row['description'], 'inputSchema': {}}]}


def summarize(rows: list[dict]) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row['label']].append(row)
    return {label: {'planned': len(group), 'completed': sum(r['complete'] for r in group),
                    'flagged': sum(r['complete'] and r['flagged'] is True for r in group),
                    'rate_planned': sum(r['complete'] and r['flagged'] is True for r in group) / len(group)}
            for label, group in sorted(groups.items())}


CLEAN_TASKS = [
    'calendar events', 'contacts', 'weather forecasts', 'unit conversions', 'currency-code names',
    'file metadata', 'directory listings', 'CSV columns', 'JSON fields', 'Markdown headings',
    'repository branches', 'commit summaries', 'pull request titles', 'issue labels', 'build statuses',
    'test durations', 'application logs', 'package versions', 'dependency licenses', 'container image tags',
    'database table names', 'SQL query plans', 'inventory quantities', 'order statuses', 'shipment dates',
    'product identifiers', 'support ticket titles', 'document paragraphs', 'PDF page counts', 'image dimensions',
    'audio durations', 'video frame rates', 'translation entries', 'spelling suggestions', 'text word counts',
    'URL components', 'checksum comparisons', 'time zone names', 'coordinate distances', 'public transit stops',
]


def prepare(out: Path, clean_tools: Path) -> dict:
    from bench.fresh_benchmark import load_clean_tools
    from bench.mcptox.fetch import load_cases, SHA256
    dataset = ROOT / 'bench/mcptox/data/response_all.json'
    if sha(dataset.read_bytes()) != SHA256:
        raise ValueError('MCPTox cache hash mismatch')
    raw = load_cases(dataset)
    if any(not r['poisoned_tool_name'] or not r['poisoned_description'] for r in raw):
        raise ValueError('Unparsed source cases; repair adapter before selection')
    clean = load_clean_tools(clean_tools)
    common = []
    for row in select_cases(raw, 80):
        common.append({'id': 'mcptox/' + row['case_id'], 'cohort': 'external_attack', 'label': 'attack',
                       'name': row['poisoned_tool_name'], 'description': row['poisoned_description'],
                       'server': row['server'], 'category': row['category'], 'split': row['split']})
    for i, tool in enumerate(clean):
        common.append({'id': f'upstream-clean/{i:02}', 'cohort': 'upstream_clean', 'label': 'benign',
                       'name': tool['name'], 'description': tool['description'], 'split': 'known_control'})
    for i, task in enumerate(CLEAN_TASKS):
        common.append({'id': f'authored-clean/{i:02}', 'cohort': 'authored_clean', 'label': 'benign',
                       'name': 'lookup_' + task.replace(' ', '_').replace('-', '_'),
                       'description': f'Return the {task} requested by the user from the supplied data. '
                                      'Return an empty list when no entries match. Do not modify the data.',
                       'split': 'authored_control'})
    assert len(common) == 140
    for i, row in enumerate(common):
        target = out / 'packets' / f'{i:04}'
        target.mkdir(parents=True)
        packet = target / 'tools.json'
        packet.write_text(json.dumps(tool_packet(row), ensure_ascii=False, indent=2) + '\n')
        row['target'] = str(target)
        row['packet_sha256'] = sha(packet.read_bytes())
    contexts = [
        ('guard.py', '# Reject /etc/shadow\n', 'sensitive_path_access'),
        ('guard.py', '# Refuse ~/.ssh/id_rsa\n', 'sensitive_path_access'),
        ('guard.py', '# Reject ~/.aws/credentials\n', 'sensitive_path_access'),
        ('guard.mjs', '// Reject /etc/shadow\n', 'sensitive_path_access'),
        ('guard.ts', '/** Refuse ~/.ssh/id_rsa */\n', 'sensitive_path_access'),
        ('guard.py', '_DENY = ["/etc/shadow"]\ndef check(path):\n    if path in _DENY:\n        raise PermissionError()\n', 'sensitive_path_access'),
        ('guard.py', '_DENY = ["id_rsa"]\ndef check(path):\n    if path in _DENY:\n        raise PermissionError()\n', 'sensitive_path_access'),
        ('shield.py', 'WORDS = ["ignore previous instructions"]\ndef detect(text):\n    return any(word in text for word in WORDS)\n', 'tool_description_injection'),
        ('shield.py', 'WORDS = ["disregard previous instructions"]\ndef detect(text):\n    return any(word in text for word in WORDS)\n', 'tool_description_injection'),
        ('package-lock.json', '{"name":"app","packages":{"":{"name":"app"}}}', 'mcp_duplicate_tool_names'),
        ('openapi.json', '{"parameters":[{"name":"q"},{"name":"q"}]}', 'mcp_duplicate_tool_names'),
        ('examples.py', 'a={"name":"a"}\nb={"name":"a"}\n', 'mcp_duplicate_tool_names'),
        ('server.py', 'A=[{"name":"lookup","inputSchema":{}}]\nB=[{"name":"lookup","inputSchema":{}}]\n', 'mcp_duplicate_tool_names'),
        ('package.json', '{"scripts":{"//postinstall":"npm notes"}}', 'npm_install_hook'),
        ('uv.lock', 'wheels=[{url="https://example.org/token/package.whl", hash="sha256:5a11e665ea718277e8cc0a7c19f327762775f6900e63fbe49782019ceea44949"}]', 'secret_high_entropy_b64'),
        ('requirements.txt', 'requests\nnumpy\n', 'typosquat_hint'),
        ('package.json', '{"dependencies":{"react":"1","preact":"1"}}', 'typosquat_hint'),
        ('env.py', 'import os\nfiltered = {k:v for k,v in os.environ.items() if k not in {"API_KEY"}}\n', 'env_harvest'),
        ('guard.js', 'const filtered = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("API_")));', 'env_harvest'),
        ('config.py', 'import os\ndef get(name):\n    return next((v for k,v in os.environ.items() if k == name), None)\n', 'env_harvest'),
    ]
    local = []
    for i, (name, content, rule) in enumerate(contexts):
        local.append({'id': f'context/{i:02}', 'cohort': 'context_control', 'label': 'benign',
                      'filename': name, 'content': content, 'scored_rule': rule, 'expected_flag': False})
    deps = [('reqeusts', True, False), ('flsak', True, False), ('numpyy', True, False), ('httxp', True, False),
            ('pandass', True, False), ('nod-fetch', True, True), ('lodas', True, True), ('expres', True, True),
            ('requests', False, False), ('numpy', False, False), ('flask', False, False), ('httpx', False, False),
            ('react', False, True), ('preact', False, True), ('@mdx-js/react', False, True), ('express', False, True)]
    for i, (name, expected, npm) in enumerate(deps):
        local.append({'id': f'dependency/{i:02}', 'cohort': 'dependency_name',
                      'label': 'near_miss' if expected else 'canonical', 'expected_flag': expected,
                      'scored_rule': 'typosquat_hint', 'filename': 'package.json' if npm else 'requirements.txt',
                      'content': json.dumps({'dependencies': {name: '^1'}}) if npm else name + '\n'})
    for i, row in enumerate(local):
        target = out / 'local' / f'{i:04}'
        target.mkdir(parents=True)
        (target / row['filename']).write_text(row.pop('content'))
        row['target'] = str(target)
        row['input_sha256'] = {row['filename']: sha((target / row['filename']).read_bytes())}
    manifest = {'created_at': datetime.now(timezone.utc).isoformat(), 'seed': SEED, 'common': common,
                'local': local, 'composition_cases': 24,
                'scope': 'S0/S1, source composition; no auditee execution, no hosted inference',
                'dataset_sha256': {'mcptox': SHA256, 'clean_tools': sha(clean_tools.read_bytes())},
                'selection_categories': dict(Counter(r['category'] for r in common if r['label'] == 'attack')),
                'split_note': 'External cases reserved by server hash, author-visible; clean/context cases are known controls. No blinded-generalization claim.'}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


async def run_fugu(rows: list[dict]) -> list[dict]:
    from fugu.pipeline.stages import ConcealmentStage, StaticScanStage
    from fugu.types import AuditJob
    results = []
    for row in rows:
        target = Path(row['target'])
        records = [await stage.run(AuditJob(id='expanded', source=str(target)), target)
                   for stage in (ConcealmentStage(), StaticScanStage())]
        complete = all(r.ok and not any(r.metrics.get(k) for k in
                       ('rule_errors', 'skipped_max_files', 'skipped_large', 'skipped_unreadable', 'skipped_undecodable')) for r in records)
        flagged = any(f.severity in MEDPLUS and (not row.get('scored_rule') or any(
                      e.meta.get('rule') == row['scored_rule'] for e in f.evidence))
                      for result in records for f in result.findings) if complete else None
        results.append({'id': row['id'], 'cohort': row['cohort'], 'label': row['label'], 'split': row.get('split'),
                        'complete': complete, 'flagged': flagged,
                        'correct': complete and flagged == row.get('expected_flag', row['label'] == 'attack'),
                        'stages': [asdict(r) for r in records]})
    return results


def run_fuzzd(rows: list[dict], out: Path, binary: Path) -> dict:
    if sha(binary.read_bytes()) != FUZZD_HASH:
        raise ValueError('Pinned fuzzd binary hash mismatch')
    results = []
    for row in rows:
        start = time.monotonic()
        command = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges', '-v', str(binary) + ':/usr/local/bin/fuzzd:ro',
                   '-v', row['target'] + ':/input:ro', FUZZD_IMAGE,
                   '/usr/local/bin/fuzzd', 'scan', '--schema', '/input/tools.json', '--output', 'json']
        try:
            cp = subprocess.run(command, capture_output=True, text=True, timeout=45)
            raw = json.loads(cp.stdout)
            findings = [f for f in raw['findings'] if not f.get('suppressed')]
            result = {'id': row['id'], 'label': row['label'], 'cohort': row['cohort'], 'complete': True,
                      'flagged': any(f['severity'].lower() in MEDPLUS for f in findings),
                      'native_flag': bool(findings), 'packet_sha256': row['packet_sha256'],
                      'exit_code': cp.returncode, 'elapsed_s': time.monotonic() - start, 'raw': raw}
        except (ValueError, KeyError, subprocess.SubprocessError) as exc:
            result = {'id': row['id'], 'label': row['label'], 'cohort': row['cohort'], 'complete': False,
                      'flagged': None, 'error_type': type(exc).__name__}
            results.append(result)
            # Setup failure is not 140 independent parse failures.
            break
        results.append(result)
        if len(results) % 20 == 0:
            print('fuzzd', len(results), 'of', len(rows), flush=True)
    seen = {r['id'] for r in results}
    results.extend({'id': r['id'], 'label': r['label'], 'cohort': r['cohort'], 'complete': False,
                    'flagged': None, 'error_type': 'not_attempted_after_setup_failure'} for r in rows if r['id'] not in seen)
    report = {'tool': 'fuzzd', 'version': '0.13.0', 'binary_sha256': FUZZD_HASH,
              'container_image': FUZZD_IMAGE, 'scope': 'static tool descriptions; medium+ unsuppressed findings',
              'results': results, 'summary': summarize(results)}
    (out / 'fuzzd.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--clean-tools', type=Path, required=True)
    parser.add_argument('--fuzzd-binary', type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    manifest = prepare(args.out, args.clean_tools)
    rows = asyncio.run(run_fugu(manifest['common'] + manifest['local']))
    report = {'tool': 'Fugu', 'scope': manifest['scope'], 'results': rows, 'summary': summarize(rows),
              'engine_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sorted((ROOT / 'src/fugu').rglob('*.py'))}}
    (args.out / 'fugu.json').write_text(json.dumps(report, indent=2) + '\n')
    from bench.composition_expanded import run_suite
    composition = run_suite(ROOT / 'src', args.out / 'composition.json', label='after')
    print(json.dumps({'fugu': report['summary'], 'composition': composition['summary'],
                      'total_planned': len(rows) + len(composition['cases'])}, indent=2), flush=True)
    if args.fuzzd_binary:
        print(json.dumps(run_fuzzd(manifest['common'], args.out, args.fuzzd_binary)['summary'], indent=2), flush=True)


if __name__ == '__main__':
    main()
