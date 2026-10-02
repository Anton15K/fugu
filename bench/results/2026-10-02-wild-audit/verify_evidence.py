"""Check the bounded audit's pins, performed scope, coverage and artifact hashes."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name):
    return json.loads((HERE / name).read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    inventory = load('source-inventory.json')['projects']
    assert len(inventory) == 6 and len({p['repository'] for p in inventory}) == 6
    acquired = {p['repository']: p for p in load('acquisition.json')['projects']}
    scope = load('scope.json')['files']
    raw = load('static.json')
    assert len(raw['rows']) == 6 and raw['engine_hashes_verified']
    assert raw['paid_model_calls'] == 0
    assert sum(len(paths) for paths in scope.values()) == 44
    for project in inventory:
        repo = project['repository']
        assert not project['archived'] and len(project['commit']) == 40
        assert acquired[repo]['commit'] == project['commit']
        row = next(r for r in raw['rows'] if r['repository'] == repo)
        assert row['commit'] == project['commit']
        assert set(row['input_sha256']) == set(scope[repo])
        for rel, expected in row['input_sha256'].items():
            assert expected == acquired[repo]['files_sha256'][rel]
            if args.cache:
                path = args.cache / repo.replace('/', '--') / rel
                assert not path.is_symlink() and path.is_file()
                assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
        assert {s['stage'] for s in row['stages']} == {'concealment', 'static'}
        for stage in row['stages']:
            assert stage['ok'] and not stage['findings']
            assert not stage.get('error')
            metrics = stage['metrics']
            assert metrics['files_seen'] == metrics['files_scanned'] == len(scope[repo])
            assert all(not v for k, v in metrics.items() if k.startswith('skipped_'))
            assert not metrics.get('coverage_incomplete')
    limits = load('limits-and-usage.json')
    assert limits['chamber_preparation']['auditee_executions'] == 0
    assert limits['chamber_preparation']['auditee_dependency_installations'] == 0
    assert all(limits['usage'][k] == 0 for k in ('nebius_semantic_attempts', 'nebius_tokens', 'tavily_calls', 'snyk_calls'))
    manifest = HERE / 'artifact-manifest.json'
    if manifest.exists():
        for entry in json.loads(manifest.read_text())['files']:
            path = ROOT / entry['path']
            data = path.read_bytes()
            assert len(data) == entry['bytes']
            assert hashlib.sha256(data).hexdigest() == entry['sha256']
            assert b'\r' not in data
    print('PASS: six pinned projects; 44 selected inputs hash-matched; 12 S0/S1 runs complete with zero alerts; zero auditee executions/paid audit calls; artifact integrity verified when manifest present.')


if __name__ == '__main__':
    main()
