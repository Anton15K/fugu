"""Pinned mcp-sec-audit adapter: JSON description data only; never target code."""
from __future__ import annotations
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rulebook = args.source / 'detection/rules/keywords.toml'
    expected = 'c7529b02d5ae056f67c6b46eb75616b897107044d1b6bf4a1c38af823fcce1b4'
    if hashlib.sha256(rulebook.read_bytes()).hexdigest() != expected:
        raise ValueError('Pinned competitor rulebook changed')
    sys.path.insert(0, str(args.source))
    from detection.cli import _load_builtin_plugins
    from detection.core.registry import DetectorRegistry
    from detection.rules import load_rulebook
    from detection.pipelines import run_static_pipeline
    registry = DetectorRegistry()
    _load_builtin_plugins(registry, load_rulebook(rulebook))
    rows = []
    for case in json.loads(args.manifest.read_text())['common']:
        packet = Path(case['target']) / 'tools.json'
        if hashlib.sha256(packet.read_bytes()).hexdigest() != case['packet_sha256']:
            raise ValueError('Frozen packet changed')
        tool = json.loads(packet.read_text())['tools'][0]
        wrapper = {'tool_name': tool['name'], 'tool_content': tool['description']}
        started = time.monotonic()
        try:
            with tempfile.TemporaryDirectory(prefix='fugu-expanded-competitor-') as folder:
                (Path(folder) / 'tool.json').write_text(json.dumps(wrapper, ensure_ascii=False))
                result = run_static_pipeline(Path(folder), registry, args.source / 'detection/mitigation/policy_templates')
            row = {'id': case['id'], 'label': case['label'], 'cohort': case['cohort'], 'complete': True,
                   'flagged': result.total_score >= 25, 'native_flag': bool(result.findings),
                   'packet_sha256': case['packet_sha256'], 'risk_score': result.total_score,
                   'raw': asdict(result), 'elapsed_s': time.monotonic() - started}
        except Exception as exc:
            row = {'id': case['id'], 'label': case['label'], 'cohort': case['cohort'], 'complete': False,
                   'flagged': None, 'error_type': type(exc).__name__}
        rows.append(row)
    summary = {}
    for label in ('attack', 'benign'):
        group = [row for row in rows if row['label'] == label]
        summary[label] = {'planned': len(group), 'completed': sum(row['complete'] for row in group),
                          'flagged': sum(row['complete'] and row['flagged'] is True for row in group)}
    args.output.write_text(json.dumps({'tool': 'mcp-sec-audit', 'version': '0.1.0',
        'source_commit': '457057a7dfda6b81622a12ee68b74f76f3fbde85', 'rules_sha256': expected,
        'source_sha256': {str(p.relative_to(args.source)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(args.source.rglob('*.py')) if '.venv' not in p.parts},
        'scope': 'Same original names/descriptions mapped to tool_name/tool_content; aggregate risk >=25. '
                 'Native any-capability findings are also retained. No model inference or target execution.',
        'summary': summary, 'results': rows}, indent=2, default=str) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
