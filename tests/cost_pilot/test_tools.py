import json
import pytest
from bench.cost_pilot.tools import ToolRegistry,validate_arguments
from bench.cost_pilot.freeze import tree_manifest
from bench.cost_pilot.contracts import SafetyStop


def registry(tmp_path,text='ordinary\r\n'):
    s=tmp_path/'source';s.mkdir();(s/'main.txt').write_bytes(text.encode())
    return s,ToolRegistry(s,'c0',tree_manifest(s)['sha256'],tmp_path/'journal',lambda q:{'results':[{'title':'advisory','url':'https://example.org'}]})


def test_long_line_lossless_cursor(tmp_path):
    text='α"\\😀'*9000+'\r\n'+'tail\r\n';s,t=registry(tmp_path,text)
    args={'path':'main.txt','start_line':1,'end_line':2,'cursor':None};pages=[]
    while True:
        r=t.dispatch('read_file',args);assert len(r.text)<=8192;pages.append(r.payload)
        assert r==t.dispatch('read_file',args)
        c=r.payload['next_cursor']
        if c is None:assert r.payload['range_complete'];break
        assert any(x['char_end']>x['char_start'] for x in r.payload['segments'])
        args={**args,'cursor':c}
    assert ''.join(x['text'] for p in pages for x in p['segments'])==text
    assert t.coverage()['fully_read_paths']==['main.txt']
    with pytest.raises(SafetyStop,match='cursor'):t.dispatch('read_file',{**args,'cursor':'forged'})
    with pytest.raises(SafetyStop):t.dispatch('read_file',{**args,'end_line':3})


def test_drift_and_private_escape(tmp_path):
    s,t=registry(tmp_path,'x'*17000)
    r=t.dispatch('read_file',{'path':'main.txt'})
    (tmp_path/'truth.json').write_text('PRIVATE-LABEL')
    for p in ('../truth.json',str(tmp_path/'truth.json')):
        with pytest.raises(SafetyStop):t.dispatch('read_file',{'path':p})
    (s/'link').symlink_to(tmp_path/'truth.json')
    with pytest.raises(SafetyStop):t.dispatch('read_file',{'path':'link'})
    (s/'link').unlink();(s/'main.txt').write_text('changed')
    with pytest.raises(SafetyStop,match='drift'):t.dispatch('read_file',{'path':'main.txt','cursor':r.payload['next_cursor']})
    assert 'PRIVATE-LABEL' not in ''.join(p.read_text() for p in (tmp_path/'journal').rglob('*.json'))


@pytest.mark.parametrize('args',[{'path':'main.txt','start_line':True},{'path':'main.txt','end_line':201},{'path':'main.txt','evil':1},{'path':'/tmp/x'}])
def test_strict_args(tmp_path,args):
    s,t=registry(tmp_path)
    with pytest.raises(SafetyStop):t.dispatch('read_file',args)


def test_four_tools_only_and_web(tmp_path):
    s,t=registry(tmp_path)
    assert [x['function']['name'] for x in t.schemas()]==['list_files','read_file','search_files','search_web']
    for n in ('query_osv','run_sandbox','shell','http_get'):
        with pytest.raises(SafetyStop):t.dispatch(n,{})
    for q in ('%61pi%2eosv%2edev','{"run_sandbox":true}'):
        with pytest.raises(SafetyStop):t.dispatch('search_web',{'query':q})
    assert t.dispatch('search_web',{'query':'ordinary advisory'}).payload['results']


def test_listing_search_pagination_and_not_read_coverage(tmp_path):
    s,t=registry(tmp_path)
    # New inventory created before constructing the final registry.
    for i in range(260):(s/f'{i:03}.txt').write_text('literal needle\n')
    t=ToolRegistry(s,'c0',tree_manifest(s)['sha256'],tmp_path/'other',lambda q:{})
    args={};paths=[]
    while True:
        r=t.dispatch('list_files',args);assert len(r.text)<=8192;paths+=r.payload['files']
        if not r.payload['next_cursor']:break
        args={'cursor':r.payload['next_cursor']}
    assert len(paths)==261
    args={'query':'needle'};matches=[]
    while True:
        r=t.dispatch('search_files',args);assert len(r.text)<=8192;matches+=r.payload['matches']
        if not r.payload['next_cursor']:break
        args={**args,'cursor':r.payload['next_cursor']}
    assert len(matches)==260;assert not t.coverage()['fully_read_paths']


def test_empty_undecodable_and_range_limit(tmp_path):
    s,t=registry(tmp_path,'')
    assert t.dispatch('read_file',{'path':'main.txt'}).payload['eof']
    assert t.coverage()['fully_read_paths']==['main.txt']
    (s/'bad').write_bytes(b'\xff')
    t=ToolRegistry(s,'c0',tree_manifest(s)['sha256'],tmp_path/'other',lambda q:{})
    with pytest.raises(SafetyStop,match='undecodable'):t.dispatch('read_file',{'path':'bad'})
    assert t.coverage()['omissions']


def test_visible_evidence_identifier(tmp_path):
    s,t=registry(tmp_path)
    r=t.dispatch('read_file',{'path':'main.txt'})
    assert r.payload['evidence_id']==r.evidence_id
    assert json.loads(r.text)['evidence_id']==r.evidence_id


def test_binary_omission_not_claimed_read(tmp_path):
    s,t=registry(tmp_path,'text\x00binary')
    with pytest.raises(SafetyStop,match='binary'):t.dispatch('read_file',{'path':'main.txt'})
    assert not t.coverage()['fully_read_paths'];assert t.coverage()['omissions'][0]['reason']=='binary'
