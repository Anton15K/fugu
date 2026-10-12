"""Complete review regressions: authored sources and fake observations only."""
import copy
import json
from dataclasses import asdict
from pathlib import Path

import pytest
from bench.cost_pilot import adjudication, freeze, report
from bench.cost_pilot.contracts import ArmResult, Match, SafetyStop


def approved_export(root):
    source = root / 'sources/c00'; source.mkdir(parents=True)
    (source / 'main.py').write_text('print("inert source data")\n')
    manifest = freeze.tree_manifest(source)
    truth = {'cases': [{'id': 'c00', 'source_hash': manifest['sha256'],
        'expected_action': 'reject', 'issues': [{'id': 't1', 'severity': 'high',
        'proof': 'source_allowed'}]}]}
    freeze.immutable_json(root/'private/truth.json', truth)
    case = {'id': 'c00', 'lane': 'security', 'root': str(source), 'manifest': manifest}
    doc = {'schema_version': 1, 'kind': 'frozen_run', 'cap_micro': 10000000,
        'arm_cap_micro': 2000000, 'pair_cap_micro': 4000000,
        'sources': [case], 'cases': [case], 'seed': 1,
        'references': [{'kind': 'truth', 'path': str(root/'private/truth.json'),
                        'sha256': freeze.byte_hash(root/'private/truth.json')}]}
    run = freeze.freeze_run(root/'run-plan.json', doc)
    rows = [ArmResult('c00', 'fugu', 'complete', {'verdict': {'status': 'fail'},
        'findings': [{'id': 'f1', 'severity': 'high', 'stage': 'semantic'}]}, {}, root/'arms/c00/fugu'),
        ArmResult('c00', 'agent', 'unattempted', {}, {}, root/'arms/c00/agent')]
    measurement = {'run_sha256': freeze.byte_hash(run.path),
                   'rows': [{**asdict(x), 'evidence_path': str(x.evidence_path)} for x in rows]}
    freeze.immutable_json(root/'measurement.json', measurement)
    masked = adjudication.prepare_masked(run, root/'measurement.json')
    mapping = json.loads((root/'private/mask-map.json').read_bytes())
    mask = next(k for k,v in mapping['c00'].items() if v == 'fugu')
    review = {'reviewer': 'fugu-codex-reviewer', 'verdict': 'APPROVE',
        'matches': [asdict(Match('c00', mask, 'f1', 't1', 'fp',
            'PRIVATE_REASON /private/canary SENTINEL', 'fugu-codex-reviewer'))],
        'masked_outputs_sha256': freeze.byte_hash(root/'masked/outputs.json'),
        'truth_sha256': freeze.byte_hash(root/'private/truth.json'),
        'measurement_sha256': freeze.byte_hash(root/'measurement.json'),
        'mask_map_sha256': freeze.byte_hash(root/'private/mask-map.json'),
        'run_sha256': freeze.byte_hash(run.path)}
    freeze.immutable_json(root/'private/approved-review.json', review)
    adj = adjudication.load_adjudication(root/'private/approved-review.json', masked, run)
    freeze.immutable_json(root/'adjudicated.json', adj)
    return run, measurement, adj


def test_actual_approved_export_success(tmp_path):
    approved_export(tmp_path)
    bundle = report.export_report(tmp_path, tmp_path/'publishable')
    assert bundle.results['lanes']['security']['fugu']['tp'] == 0
    assert bundle.results['lanes']['security']['fugu']['fp'] == 1


@pytest.mark.parametrize('mutation', ['copy_matches','copy_truth','copy_mapping','copy_time',
    'measurement','masked','map','truth','run_binding','review','source'])
def test_export_rejects_changed_approved_inputs(tmp_path, mutation):
    run, measurement, adj = approved_export(tmp_path)
    target = tmp_path/'adjudicated.json'
    if mutation == 'copy_matches': adj['matches'][0]['state'] = 'tp'
    elif mutation == 'copy_truth': adj['truth']['cases'][0]['expected_action'] = 'accept'
    elif mutation == 'copy_mapping': adj['mapping']['c00'] = {k:('agent' if v=='fugu' else 'fugu') for k,v in adj['mapping']['c00'].items()}
    elif mutation == 'copy_time': adj['human_time'] = {'seconds': 999}
    elif mutation in {'measurement','run_binding'}:
        target = tmp_path/'measurement.json'; adj = measurement
        if mutation == 'measurement': adj['rows'][0]['raw']['verdict']['status'] = 'pass'
        else: adj['run_sha256'] = '0'*64
    elif mutation == 'masked':
        target = tmp_path/'masked/outputs.json'; adj=json.loads(target.read_bytes())
        adj['cases']['c00']['A']['action'] = 'accept'
    elif mutation == 'map':
        target=tmp_path/'private/mask-map.json'; adj=json.loads(target.read_bytes()); adj['c00']={k:('agent' if v=='fugu' else 'fugu') for k,v in adj['c00'].items()}
    elif mutation == 'truth':
        target=tmp_path/'private/truth.json'; adj=json.loads(target.read_bytes()); adj['cases'][0]['issues']=[]
    elif mutation == 'review':
        target=tmp_path/'private/approved-review.json'; adj=json.loads(target.read_bytes()); adj['matches'][0]['state']='tp'
    else:
        (tmp_path/'sources/c00/main.py').write_text('changed source\n')
        target=None
    if target: target.write_bytes(freeze.canonical(adj))
    with pytest.raises(SafetyStop): report.export_report(tmp_path, tmp_path/'publishable')
    assert not (tmp_path/'publishable').exists()


def test_mask_preparation_refuses_stale_existing_outputs(tmp_path):
    run, measurement, adj=approved_export(tmp_path)
    measurement['rows'][0]['raw']['findings']=[]
    (tmp_path/'measurement.json').write_bytes(freeze.canonical(measurement))
    with pytest.raises(SafetyStop): adjudication.prepare_masked(run,tmp_path/'measurement.json')
