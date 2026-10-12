import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from bench.cost_pilot.native import run_native,reconcile_native
from bench.cost_pilot.contracts import ULTRA
from bench.cost_pilot.ledger import Ledger
from bench.cost_pilot.pricing import Pricing
from bench.cost_pilot.transport import GuardedTransport
from fugu.credentials import CredentialSet
from tests.cost_pilot.support import fake_tariffs


def test_native_omissions_not_upgraded():
    report={'audit_status':'done','verdict':'PASS','exit_code':3,'coverage':{'incomplete':True},'children':[]}
    expected={'files':['root.py','a/SKILL.md','b/SKILL.md'],'units':['a','b'],'triggers':{'a':['import a'],'b':['import b']}}
    observed={'units':['a','b'],'selected_paths':['a/SKILL.md','b/SKILL.md'],'triggers':{'a':['import a'],'b':[]},'stage_records':[]}
    c=reconcile_native(report,observed,expected)
    assert c['incomplete'];assert c['unconsumed_root_paths']==['root.py']
    assert c['missing_trigger_occurrences']==[{'member':'b','trigger':'import b','occurrence':1}]
    assert report['verdict']=='PASS' and report['exit_code']==3


def test_exact_native_invocation_and_unchanged_report(tmp_path,monkeypatch):
    import fugu.cli_audit
    source=tmp_path/'s';source.mkdir();(source/'a.py').write_text('x=1')
    raw={'audit_status':'done','verdict':'PASS','exit_code':3,'coverage':{'incomplete':True},'children':[]};calls=[]
    monkeypatch.setattr(fugu.cli_audit,'run_cli_audit',lambda *a,**kw:(calls.append((a,kw)),raw)[1])
    keys=CredentialSet('FAKE-N','FAKE-T')
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=GuardedTransport(l,Pricing(fake_tariffs(),test_only=True),tmp_path/'e',keys,lambda:{'status':'admitted'})
        r=run_native(source,'c0',keys,t,tmp_path/'native',{'files':['a.py'],'units':['root'],'triggers':{}})
    assert calls==[((str(source.resolve()),'full',keys),{'detonate':True})]
    assert r.raw is raw;assert r.workflow=='partial'


@pytest.mark.parametrize('units',[1,2])
def test_actual_canonical_fake_boundary_full_depth_six_probes(tmp_path,monkeypatch,units):
    from openai.types.chat import ChatCompletion
    import fugu.client
    from fugu.pipeline.stages.tool_surface import ToolSurfaceScanner
    from fugu.detonation.docker_driver import DockerDriver
    import fugu.detonation.triggers
    from fugu.types import DetonationEvidence
    import urllib.request,io,socket,subprocess
    def deny(*a,**kw):raise AssertionError('external boundary attempted')
    monkeypatch.setattr(socket.socket,'connect',deny);monkeypatch.setattr(subprocess,'Popen',deny)
    monkeypatch.setattr(ToolSurfaceScanner,'from_environment',classmethod(lambda cls:None))
    monkeypatch.setattr(fugu.detonation.triggers,'derive_triggers',lambda *a,**kw:['owned inert command'])
    calls=[];cleanup=[]
    async def detonate(self,target,triggers,**kw):
        try:return [DetonationEvidence(trigger=t,exit_code=0,duration_s=.01) for t in triggers]
        finally:cleanup.append(str(target))
    monkeypatch.setattr(DockerDriver,'detonate',detonate)
    monkeypatch.setattr(urllib.request,'urlopen',lambda *a,**kw:io.BytesIO(b'{"results":[],"credits":1}'))
    def create(**kw):
        calls.append(kw);system=kw['messages'][0]['content']
        text='{"findings":[]}' if 'security auditor' in system.lower() or 'findings' in system else ('{"probes":[]}' if 'probes' in system else 'Direct answer. PLAN: answer task')
        return ChatCompletion.model_validate({'id':f'r{len(calls)}','object':'chat.completion','created':1,'model':kw['model'],'choices':[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':text}}],'usage':{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}})
    client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setattr(fugu.client,'make_client',lambda *a,**kw:client)
    source=tmp_path/'source';source.mkdir();files=[];members=[]
    for n in range(units):
        d=source if units==1 else source/str(n);d.mkdir(exist_ok=True);(d/'SKILL.md').write_text('# Formatter\nFormats ordinary tables.');members.append('root' if units==1 else str(n));files.append('SKILL.md' if units==1 else str(n)+'/SKILL.md')
    keys=CredentialSet('FAKE-N','FAKE-T')
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=GuardedTransport(l,Pricing(fake_tariffs(),test_only=True),tmp_path/'e',keys,lambda:{'status':'admitted'})
        r=run_native(source,'c0',keys,t,tmp_path/'native',{'files':files,'units':members,'triggers':{m:['owned inert command'] for m in members},'required_stages':['concealment','static','semantic','harness','reputation','detonation']})
        leaves=r.raw['children'] or [r.raw]
        assert all(next(s for s in leaf['stages'] if s['stage']=='harness')['metrics']['static_probes']==6 for leaf in leaves)
        assert len(cleanup)==units;assert all(x['depth']=='full' for x in r.coverage['stage_records'])
        assert len([e for e in l.events() if e['kind']=='dispatch'])==len(calls)
        assert len(calls)>12*units
        assert 'FAKE-N' not in json.dumps(r.raw)
        assert all(e['attribution']['member'] in members for e in l.events() if e['kind']=='reserve')


def test_missing_delivered_occurrence_is_not_derived_coverage():
    raw={'audit_status':'done','exit_code':0,'coverage':{'incomplete':False}}
    expected={'files':[],'units':['root'],'triggers':{'root':['inert','inert']}}
    observed={'units':['root'],'selected_paths':[],'triggers':{'root':['inert','inert']},'stage_records':[],'docker_results':[{'member':'root','selected_triggers':['inert','inert'],'results':[{'trigger':'inert','exit_code':0}]}]}
    c=reconcile_native(raw,observed,expected)
    assert c['incomplete'];assert c['missing_trigger_occurrences']==[{'member':'root','trigger':'inert','occurrence':2}]
