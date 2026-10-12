import copy,json,re,hashlib
from pathlib import Path
from types import SimpleNamespace
import pytest
from openai.types.chat import ChatCompletion
from fugu.credentials import CredentialSet
from bench.cost_pilot.agent import run_agent,validate_final
from bench.cost_pilot.prompts import extract_prompts,prompt_hashes
from bench.cost_pilot.tools import ToolRegistry
from bench.cost_pilot.freeze import tree_manifest
from bench.cost_pilot.ledger import Ledger
from bench.cost_pilot.pricing import Pricing
from bench.cost_pilot.transport import GuardedTransport
from bench.cost_pilot.contracts import ULTRA,SUPER,SafetyStop
from tests.cost_pilot.support import fake_tariffs
SPEC=Path('docs/superpowers/specs/2026-10-12-whole-system-cost-benchmark-design.md')


def final():return {'snapshot_id':'c0','lane':'security','action':'accept','reasons':['No supported issue'],'findings':[],'unknowns':[],'coverage':{'inventoried_files':1,'read_paths':['a.py'],'searched_paths':[],'omitted_paths':[],'tool_errors':[],'truncations':[]},'review_resolutions':[]}


def setup(tmp_path,mode='normal'):
    s=tmp_path/'source';s.mkdir();(s/'a.py').write_text('value=1\n');calls=[]
    def create(**kw):
        calls.append(copy.deepcopy(kw));n=len(calls);message={'role':'assistant','content':json.dumps(final())};finish='stop'
        if n==1 or mode=='endless' or (mode=='no-draft' and n<=24):
            finish='tool_calls';message={'role':'assistant','content':None,'reasoning_content':'inspect source','tool_calls':[{'id':f'call-{n}','type':'function','function':{'name':'read_file','arguments':'{"path":"a.py"}'}}]}
        elif kw['model']==SUPER:message['content']=json.dumps({'critiques':[],'additional_candidates':[],'unknowns':[],'coverage':{}}) if mode!='bad-review' else '{}'
        elif mode=='bad-final' and n>=4:message['content']='not JSON'
        return ChatCompletion.model_validate({'id':f'r{n}','object':'chat.completion','created':1,'model':kw['model'],'choices':[{'index':0,'finish_reason':finish,'message':message}],'usage':{'prompt_tokens':100,'completion_tokens':20,'total_tokens':120}})
    client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    tools=ToolRegistry(s,'c0',tree_manifest(s)['sha256'],tmp_path/'tools',lambda q:{'results':[]})
    return client,tools,calls


def test_loop_keeps_tool_ids_and_exact_registry(tmp_path):
    c,t,calls=setup(tmp_path)
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');transport=GuardedTransport(l,Pricing(fake_tariffs(),test_only=True),tmp_path/'events',CredentialSet('FAKE-N','FAKE-T'),lambda:{'status':'admitted'})
        r=run_agent('c0','security',t,transport,c,extract_prompts(SPEC),tmp_path/'agent')
        assert r.workflow=='complete';assert len(calls)==4
        assert calls[2]['model']==SUPER and calls[3]['model']==ULTRA
        a=next(m for m in calls[1]['messages'] if m.get('tool_calls'));tool=next(m for m in calls[1]['messages'] if m['role']=='tool')
        assert a['tool_calls'][0]['id']==tool['tool_call_id']=='call-1';assert a['reasoning_content']=='inspect source'
        for call in calls:
            assert call['max_tokens']==4096 and call['temperature']==.1
            assert len(call['tools'])==4
        assert len([e for e in l.events() if e['kind']=='earmark'])==2


@pytest.mark.parametrize('mode',['endless','bad-review','bad-final'])
def test_incomplete_never_upgraded_or_more_than_32(tmp_path,mode):
    c,t,calls=setup(tmp_path,mode)
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');tr=GuardedTransport(l,Pricing(fake_tariffs(),test_only=True),tmp_path/'e',CredentialSet(),lambda:{'status':'admitted'})
        r=run_agent('c0','security',t,tr,c,extract_prompts(SPEC),tmp_path/'a')
        assert r.workflow=='partial';assert len(calls)<=32
        if mode=='endless':assert len(calls)==32 and calls[-1]['model']==ULTRA


def test_prompts_exact_and_drift(tmp_path):
    p=extract_prompts(SPEC);blocks=re.findall(rb'```text\n(.*?)\n```',SPEC.read_bytes(),re.S)
    assert list(p.values())==[b.decode() for b in blocks]
    assert list(prompt_hashes(p).values())==[hashlib.sha256(b).hexdigest() for b in blocks]
    altered=tmp_path/'spec';altered.write_bytes(SPEC.read_bytes()+b' ')
    with pytest.raises(SafetyStop):extract_prompts(altered)


def test_final_denies_runtime_and_forged_evidence():
    f=final();f['findings']=[{'id':'f1','title':'x','severity':'high','location':{'path':'a.py','start_line':1,'end_line':1},'mechanism':'x','evidence':['forged'],'evidence_strength':'source_deduction','observed_runtime':False}]
    with pytest.raises(SafetyStop):validate_final(f,'c0','security',set(),set())
    f['findings'][0]['evidence']=['e1'];f['findings'][0]['observed_runtime']=True
    with pytest.raises(SafetyStop):validate_final(f,'c0','security',{'e1'},set())


def test_budget_preflight_leaves_zero_paid_attempts(tmp_path):
    c,t,calls=setup(tmp_path);tariffs=fake_tariffs()
    for m in tariffs['models'].values():m['output_micro_per_million']=180000000
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');tr=GuardedTransport(l,Pricing(tariffs,test_only=True),tmp_path/'e',CredentialSet(),lambda:{'status':'admitted'})
        r=run_agent('c0','security',t,tr,c,extract_prompts(SPEC),tmp_path/'a')
        assert r.workflow=='partial' and not calls
        assert not [e for e in l.events() if e['kind']=='dispatch']


def test_no_draft_after_investigation_cannot_complete(tmp_path):
    c,t,calls=setup(tmp_path,'no-draft')
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');tr=GuardedTransport(l,Pricing(fake_tariffs(),test_only=True),tmp_path/'e',CredentialSet(),lambda:{'status':'admitted'})
        result=run_agent('c0','security',t,tr,c,extract_prompts(SPEC),tmp_path/'a')
        assert len(calls)==26
        assert result.raw['draft'] is None
        assert result.workflow=='partial'
