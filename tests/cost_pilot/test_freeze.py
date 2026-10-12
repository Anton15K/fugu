import hashlib
import os
from pathlib import Path
import pytest
from bench.cost_pilot.contracts import SafetyStop
from bench.cost_pilot.freeze import canonical, tree_manifest, pair_order, freeze_run, load_frozen, verify_frozen


def test_source_hash_preserves_unicode_crlf_long_lines(tmp_path):
    path = tmp_path / 'a.txt'
    path.write_bytes('α\r\n'.encode() + b'x' * 17000)
    first = tree_manifest(tmp_path)
    assert first['files'][0]['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
    path.write_bytes('α\n'.encode() + b'x' * 17000)
    assert tree_manifest(tmp_path)['sha256'] != first['sha256']
    assert canonical({'x': 'α'}) == b'{"x":"\xce\xb1"}'


def test_inventory_rejects_symlink_without_reading_secret(tmp_path):
    source = tmp_path / 'source'; source.mkdir()
    (source / 'escape').symlink_to(tmp_path / 'missing-secret')
    with pytest.raises(SafetyStop, match='source_symlink'):
        tree_manifest(source)


def test_order_smoke_prefix_and_counterbalanced_functional_suffix():
    cases = [{'id': f'c{i}', 'lane': 'functional' if i > 3 else 'security',
              'smoke': ['benign', 'adverse', 'other', 'other', 'other', 'other'][i]} for i in range(6)]
    order = pair_order(cases, 20261012)
    assert [r['id'] for r in order[:2]] == ['c0', 'c1']
    assert [r['lane'] for r in order[-2:]] == ['functional', 'functional']
    assert len({tuple(r['arms']) for r in order}) == 2
    assert order == pair_order(list(reversed(cases)), 20261012)
    with pytest.raises(SafetyStop, match='smoke'):
        pair_order(cases[1:], 1)


@pytest.mark.parametrize('kind', ['source', 'pricing', 'prompt', 'truth', 'approval'])
def test_freeze_drift_and_immutable_bytes(tmp_path, kind):
    source = tmp_path / 'source'; source.mkdir()
    file = source / 'a.txt'; file.write_text('original')
    ref = tmp_path / 'reference.json'; ref.write_bytes(b'{"verified":true}')
    doc = {'schema_version': 1, 'kind': 'frozen_run', 'cap_micro': 10000000,
           'arm_cap_micro': 2000000, 'pair_cap_micro': 4000000,
           'sources': [{'root': str(source), 'manifest': tree_manifest(source)}],
           'references': [{'kind': kind, 'path': str(ref), 'sha256': hashlib.sha256(ref.read_bytes()).hexdigest()}]}
    path = tmp_path / 'run-plan.json'
    run = freeze_run(path, doc)
    original = path.read_bytes()
    verify_frozen(load_frozen(path))
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(SafetyStop, match='exists'):
        freeze_run(path, doc)
    if kind == 'source': file.write_text('changed')
    else: ref.write_bytes(b'changed')
    with pytest.raises(SafetyStop, match=kind + '_drift'):
        verify_frozen(run)
    assert path.read_bytes() == original


def test_freeze_rejects_fake_authority_and_wrong_cap(tmp_path):
    doc = {'schema_version': 1, 'kind': 'frozen_run', 'cap_micro': 10000000,
           'arm_cap_micro': 2000000, 'pair_cap_micro': 4000000, 'sources': [], 'references': [],
           'tariffs': {'account_verified': False}}
    with pytest.raises(SafetyStop, match='tariff_authority'):
        freeze_run(tmp_path / 'run.json', doc)
    doc.pop('tariffs'); doc['cap_micro'] = 11000000
    with pytest.raises(SafetyStop, match='cap'):
        freeze_run(tmp_path / 'run.json', doc)
