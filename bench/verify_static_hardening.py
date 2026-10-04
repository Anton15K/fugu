"""Verify the delivered masking-only snapshot against measured unique inputs.

The accepted change vector is tool_surface.py only. Later classifier changes
require a separate verification and are rejected by this helper.
"""
from __future__ import annotations
import asyncio
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from fugu.pipeline.stages.static_scan import StaticScanStage
from fugu.pipeline.stages.tool_surface import ToolSurfaceScanner
from fugu.types import AuditJob


def signature(findings):
    return sorted((f['title'], f['severity'], f['confidence'], tuple(f['owasp_ids']),
                   tuple(e['source'] for e in f['evidence'])) for f in findings)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path, help='Retained delivery package root.')
    parser.add_argument('--source-root', type=Path,
                        help='Source to verify; defaults to PACKAGE/work. Run with its src on PYTHONPATH.')
    parser.add_argument('--output', type=Path, required=True,
                        help='New equivalence report path; original measurement is read-only.')
    args = parser.parse_args(argv)
    root = args.package
    work = args.source_root or root / 'work'
    measurement = root / 'measurement'
    if args.output.resolve().is_relative_to(measurement.resolve()):
        parser.error('--output must be outside the retained measurement')
    plan = json.loads((measurement / 'plan.json').read_text())
    now = {p.relative_to(work).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
           for p in sorted((work / 'src/fugu').rglob('*.py'))}
    changed = [k for k, v in plan['engine'].items() if now[k] != v]
    assert changed == ['src/fugu/pipeline/stages/tool_surface.py']
    indexed = {}
    for path in (measurement / 'audits').glob('*.json'):
        audit = json.loads(path.read_text())
        indexed[json.dumps(audit['input_sha256'], sort_keys=True)] = audit
    cases = json.loads((measurement / 'cases.json').read_text())['cases']
    if cases:
        import fugu
        assert Path(fugu.__file__).resolve().parents[2] == work.resolve(), (
            'loaded engine does not match --source-root; set PYTHONPATH to SOURCE_ROOT/src')
    stage = StaticScanStage(surface_scanner=ToolSurfaceScanner(
        binary=root / 'build-artifact/static-rules', image=plan['image'],
        expected_sha256=plan['binary_sha256']))
    results = []
    seen = set()
    for case in cases:
        target = Path(case['target'])
        for member in case.get('members') or [{'dir': None}]:
            directory = target / member['dir'] if member['dir'] else target
            hashes = {p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in sorted(directory.rglob('*')) if p.is_file()}
            key = json.dumps(hashes, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            audit = indexed[key]
            result = asyncio.run(stage.run(AuditJob(id='hardening-check', source=str(directory)), directory))
            old = next(s for s in audit['integrated'] if s['stage'] == 'static')
            assert signature(old['findings']) == signature([asdict(f) for f in result.findings]), str(directory)
            assert old['ok'] == result.ok
            results.append({'target': str(directory), 'findings': len(result.findings),
                            'decision_signature_unchanged': True})
    value = {'changed_engine_files': changed,
             'reason': 'Evidence credential masking only; all nonstatic engine files unchanged.',
             'unique_inputs': len(results), 'all_decision_signatures_unchanged': True,
             'engine_after': now, 'checks': results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, indent=2))
    print(json.dumps({'unique_inputs': len(results), 'decision_signatures_unchanged': True}))


if __name__ == '__main__':
    main()
