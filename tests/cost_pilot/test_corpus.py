import json
from pathlib import Path
import pytest
from bench.cost_pilot.corpus import prepare_corpus,validate_corpus,truth_template,FIX_PINS
from bench.cost_pilot.freeze import tree_manifest
from bench.cost_pilot.contracts import SafetyStop


def exports(root):
    result={}
    for n in range(8,12):
        id=f'c{n:02}';p=root/id;s=p/'source';s.mkdir(parents=True);(s/'README.md').write_text('full export\n');(s/'main.txt').write_text('public source\n')
        fix=FIX_PINS[0 if n<10 else 1];parent=('a' if n<10 else 'b')*40
        (p/'export.json').write_text(json.dumps({'schema_version':1,'commit':parent if n%2==0 else fix,'tree':'c'*40,'first_parent':parent,'fix_commit':fix,'complete':True,'tracked_manifest':tree_manifest(s),'source_rel':'source','original_validated':True,'provenance':'FAKE-EXPORT-UNIT-TEST'}))
        result[id]=p
    return result


def test_fresh_sources_and_truth_separation(tmp_path):
    m=prepare_corpus(tmp_path/'run',{});fresh=[c for c in m['cases'] if c['origin']=='fresh']
    assert len(fresh)==8;assert m['status']=='awaiting_exports'
    for c in fresh:
        s=Path(c['root']);assert (s/'README.md').is_file()
        assert (s/'SKILL.md').is_file() or (s/'a/SKILL.md').is_file()
        assert not (s/'truth.json').exists();assert c['id'].startswith('c')
    p=m['private_preparation'];assert p['adverse_count']==p['control_count']==4;assert p['runtime_required_count']>=2
    validate_corpus(m)
    t=truth_template(m);assert t['status']=='proposal_pending_independent_truth_review'
    assert all(x['reviewer'] is None for x in t['cases'])
    content=''.join(p.read_text() for c in fresh for p in Path(c['root']).rglob('*') if p.is_file())
    assert 'NEBIUS_API_KEY' not in content and 'PRIVATE-LABEL' not in content


def test_complete_exports_byte_exact_and_separate_functional(tmp_path):
    e=exports(tmp_path/'exports');m=prepare_corpus(tmp_path/'run',e);validate_corpus(m)
    assert m['status']=='sources_prepared_pending_truth';assert len(m['cases'])==12
    assert sum(c['lane']=='functional' for c in m['cases'])==4
    for c in m['cases'][8:]:assert tree_manifest(Path(c['root']))==c['manifest']


@pytest.mark.parametrize('damage',['missing','source','pin','symlink'])
def test_incomplete_or_unsafe_export_rejected(tmp_path,damage):
    e=exports(tmp_path/'exports');p=e['c09']
    if damage=='missing':(p/'source/main.txt').unlink()
    elif damage=='source':(p/'source/main.txt').write_text('changed')
    elif damage=='pin':
        d=json.loads((p/'export.json').read_text());d['commit']='d'*40;(p/'export.json').write_text(json.dumps(d))
    else:(p/'source/link').symlink_to(tmp_path/'secret')
    with pytest.raises(SafetyStop):prepare_corpus(tmp_path/'run',e)
