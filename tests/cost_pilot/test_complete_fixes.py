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


def test_public_export_withholds_private_prose_paths_canaries_and_keys(tmp_path):
    run, measurement, adj=approved_export(tmp_path)
    private='PRIVATE_TRUTH_CANARY /private/owner-secret'
    adj['matches'][0]['reason']=private
    adj['matches'][0]['truth_id']=private
    adj['truth']['cases'][0]['issues'][0]['id']=private
    adj['truth']['cases'][0]['issues'][0]['severity']='critical'
    adj['human_time']={'seconds':2, 'notes':private}
    rows=measurement['rows'];rows[0]['coverage']={'incomplete':False,
        'selected_paths':[private], 'triggers':{'root':[private]}, 'tool_errors':[private]}
    from bench.cost_pilot import runner
    from fugu.credentials import CredentialSet
    keys=CredentialSet('AUTHORED_OWNER_KEY_N','AUTHORED_OWNER_KEY_T')
    with runner._owner_environment(keys,{'scanner_binary_path':'/FAKE/NOT_EXECUTED','scanner_binary_sha256':'a'*64,'scanner_image_digest':'fake@sha256:'+'b'*64}):
        rows[0]['coverage']['owner_note']=keys.nebius
        b=report.build_report(run,{'known_micro':0,'unknown_upper_micro':0},rows,
            {**adj,'known_cost_by_arm':{'agent':0,'fugu':0},'unknown_by_arm':{'agent':0,'fugu':0}},tmp_path/'publishable')
    for p in b.root.iterdir():
        text=p.read_text()
        assert private not in text and '/private/' not in text
        assert 'AUTHORED_OWNER_KEY' not in text and 'PRIVATE_REASON' not in text
    assert b.results['rows'][1]['coverage']['selected_paths_count']==1
    assert b.results['human_time']=={'seconds':2}
    reasons=json.loads((b.root/'adjudication-reasons.json').read_bytes())
    assert reasons[0]['reason']=='Private adjudication explanation withheld.'
    assert adj['matches'][0]['reason']==private


def test_default_public_export_has_safe_reason_placeholder(tmp_path):
    approved_export(tmp_path)
    b=report.export_report(tmp_path,tmp_path/'publishable')
    assert all('PRIVATE_REASON' not in p.read_text() for p in b.root.iterdir())
    assert json.loads((b.root/'adjudication-reasons.json').read_bytes())[0]['reason']=='Private adjudication explanation withheld.'


def native_runtime_fixture(root, *, vector='http', children=False):
    from fugu.types import DetonationEvidence, EvidenceSnippet, FlowRecord, DnsRecord
    from fugu.detonation.docker_driver import evidence_to_findings
    arm=root/'arms/c00/fugu';arm.mkdir(parents=True)
    hit=EvidenceSnippet('mitm.flow[0].path' if vector=='http' else 'dns.query[0]',
        'OWNED_CANARY_EXCERPT', {'vector':vector,'canary':'github_token','field':'path'} if vector=='http' else {'vector':vector,'canary':'github_token'})
    ev=DetonationEvidence('owned-inert-trigger',0,.1,
        flows=[FlowRecord('collector.pilot.invalid','GET','/observe?canary=OWNED_CANARY')]
            if vector=='http' else [],
        dns=[DnsRecord('encoded.collector.pilot.invalid')] if vector=='dns' else [],canary_hits=[hit])
    f=asdict(evidence_to_findings(ev)[0]); f['id']='f1'
    member='child' if children else 'root'
    source=root/'sources/c00';source.mkdir(parents=True);(source/'main.py').write_text('owned inert source data\n')
    source_hash=freeze.tree_manifest(source)['sha256']
    record={'schema_version':1,'kind':'measured_native_observation','snapshot_id':'c00',
        'arm':'fugu','source_sha256':source_hash,'member':member,
        'selected_triggers':[ev.trigger], 'occurrences':[1],
        'results':[asdict(ev)], 'collector_scope':'cumulative_per_chamber'}
    path=arm/'docker-result-fixture.json';freeze.immutable_json(path,record)
    coverage={'source_sha256':source_hash,'runtime_journals':[{'path':str(path),'sha256':freeze.byte_hash(path)}]}
    raw={'verdict':{'status':'fail'},'findings':[] if children else [f],
        'children':[{'label':'child','findings':[f]}] if children else []}
    result=ArmResult('c00','fugu','complete',raw,coverage,arm)
    requirement={'member':member,'trigger':ev.trigger,'occurrence':1,
        'mechanism':'credential_network_attempt',
        'collector':{'kind':'canary_http_attempt' if vector=='http' else 'canary_dns_attempt',
                     'source':hit.source,'canary':'github_token',
                     **({'host':'collector.pilot.invalid','method':'GET','path_prefix':'/observe?'} if vector=='http' else {'query':'encoded.collector.pilot.invalid'})}}
    truth={'id':'c00','source_hash':source_hash,'expected_action':'reject',
        'issues':[{'id':'t1','severity':'critical','proof':'runtime_required',
                   'mechanism':'credential_network_attempt','runtime_requirement':requirement}]}
    return result,truth,path,record


@pytest.mark.parametrize('vector',['http','dns'])
@pytest.mark.parametrize('children',[False,True])
def test_actual_native_runtime_normalization_mask_score_and_report(tmp_path,vector,children):
    result,t,path,record=native_runtime_fixture(tmp_path,vector=vector,children=children)
    n=adjudication.normalized(result)
    assert n['findings'][0]['evidence_strength']=='runtime_observation'
    assert n['findings'][0]['observed_runtime'] is True
    masked=adjudication.mask_outputs(tmp_path,[result],1)
    mapping=json.loads((tmp_path/'private/mask-map.json').read_bytes())
    mask=next(k for k,v in mapping['c00'].items() if v=='fugu')
    match=Match('c00',mask,'f1','t1','tp','Private exact collector match','fugu-codex-reviewer')
    assert adjudication.validate_matches({'cases':[t]},masked,[match])['status']=='validated'
    score=adjudication.score_case(t,n,[match]);assert score['tp']==1 and score['critical_misses']==[]
    assert score['observed_runtime_count']==1
    from bench.cost_pilot.contracts import FrozenRun
    bundle=report.build_report(FrozenRun(tmp_path/'plan',{'cases':[{'id':'c00','lane':'security'}]}),
        {'known_micro':0,'unknown_upper_micro':0},[result],{'status':'APPROVE',
        'reviewer':'fugu-codex-reviewer','truth':{'cases':[t]},'matches':[asdict(match)],
        'mapping':mapping},tmp_path/'publishable')
    assert bundle.results['lanes']['security']['fugu']['tp']==1


@pytest.mark.parametrize('bad',['missing','other_member','other_case','other_source','other_arm',
    'wrong_trigger','wrong_occurrence','wrong_collector','wrong_canary','wrong_host','wrong_method',
    'wrong_path','wrong_dns','http_success','file_content','path_only','truth_owner','tampered',
    'rehash_tampered','outside','symlink','irrelevant_finding','cumulative_later','failed_cumulative_later','missing_requirement'])
def test_runtime_proof_must_match_frozen_finding_and_collector(tmp_path,bad):
    result,t,path,record=native_runtime_fixture(tmp_path)
    req=t['issues'][0]['runtime_requirement']
    if bad=='missing':path.unlink();result.coverage['runtime_journals']=[]
    elif bad=='other_member':record['member']='unrelated-child'
    elif bad=='other_case':record['snapshot_id']='c01'
    elif bad=='other_source':record['source_sha256']='0'*64
    elif bad=='other_arm':record['arm']='agent'
    elif bad=='wrong_trigger':req['trigger']='benign-setup'
    elif bad=='wrong_occurrence':req['occurrence']=2
    elif bad=='wrong_collector':req['collector']['source']='mitm.flow[99].body'
    elif bad=='wrong_canary':req['collector']['canary']='aws_secret'
    elif bad=='wrong_host':req['collector']['host']='unrelated.invalid'
    elif bad=='wrong_method':req['collector']['method']='POST'
    elif bad=='wrong_path':req['collector']['path_prefix']='/other/'
    elif bad=='wrong_dns':req['collector']={'kind':'canary_dns_attempt','source':'dns.query[0]','canary':'github_token','query':'wrong.invalid'}
    elif bad in {'http_success','file_content'}:req['collector']['kind']=bad
    elif bad=='path_only':record['results'][0].update(canary_hits=[],flows=[],fs_changes=['A cache.tmp'])
    elif bad=='truth_owner':record['kind']='truth_owner_reproduction'
    elif bad in {'tampered','rehash_tampered'}:record['results'][0]['canary_hits'][0]['excerpt']='FORGED_CANARY'
    elif bad in {'outside','symlink'}:
        outside=tmp_path/'truth-owner-proof.json';outside.write_bytes(path.read_bytes());path.unlink()
        if bad=='symlink':path.symlink_to(outside)
        else:result.coverage['runtime_journals'][0]['path']=str(outside)
    elif bad=='irrelevant_finding':result.raw['findings'][0]['evidence'][0]['excerpt']='DIFFERENT_CANARY'
    elif bad in {'cumulative_later','failed_cumulative_later'}:
        prior=copy.deepcopy(record['results'][0]);prior['trigger']='earlier-trigger'
        if bad=='failed_cumulative_later':prior['exit_code']=1
        record['results'].insert(0,prior);record['selected_triggers'].insert(0,'earlier-trigger');record['occurrences'].insert(0,1)
    elif bad=='missing_requirement':del t['issues'][0]['runtime_requirement']
    if bad not in {'missing','outside','symlink'}:
        path.write_bytes(freeze.canonical(record))
        if bad not in {'tampered','rehash_tampered'}:result.coverage['runtime_journals'][0]['sha256']=freeze.byte_hash(path)
    try:n=adjudication.normalized(result)
    except SafetyStop:
        assert bad=='symlink'
        return
    # Hostile claimed strength must never bypass relevant-proof validation.
    n['findings'][0].update(evidence_strength='runtime_observation',observed_runtime=True,mechanism='credential_network_attempt')
    if bad=='rehash_tampered':
        for p in n['findings'][0].get('runtime_proofs',[]):p['sha256']=freeze.byte_hash(path)
    match=Match('c00','B','f1','t1','tp','Invalid collector claim','fugu-codex-reviewer')
    with pytest.raises(SafetyStop):adjudication.score_case(t,n,[match])
    unresolved=Match('c00','B','f1','t1','unresolved','Missing relevant proof','fugu-codex-reviewer')
    score=adjudication.score_case(t,n,[unresolved])
    assert score['tp']==0 and score['fn']==1 and score['critical_misses']==['t1']


def test_unrelated_chamber_does_not_upgrade_native_finding(tmp_path):
    r,t,path,rec=native_runtime_fixture(tmp_path)
    rec['member']='unrelated-child';path.write_bytes(freeze.canonical(rec))
    r.coverage['runtime_journals'][0]['sha256']=freeze.byte_hash(path)
    f=adjudication.normalized(r)['findings'][0]
    assert f['observed_runtime'] is False and f['evidence_strength']=='unresolved'
    assert not f.get('runtime_proofs')


def test_fs_canary_path_is_observation_not_file_content(tmp_path):
    from fugu.types import DetonationEvidence,EvidenceSnippet
    from fugu.detonation.docker_driver import evidence_to_findings
    r,t,path,record=native_runtime_fixture(tmp_path)
    ev=DetonationEvidence('owned-inert-trigger',0,.1,fs_changes=['A /opt/target/OWNED_CANARY'],
        canary_hits=[EvidenceSnippet('fs.change[0]','A /opt/target/OWNED_CANARY',
                                    {'vector':'fs','canary':'github_token'})])
    f=asdict(evidence_to_findings(ev)[0]);f['id']='f1';r.raw['findings']=[f]
    record['results']=[asdict(ev)];path.write_bytes(freeze.canonical(record))
    r.coverage['runtime_journals'][0]['sha256']=freeze.byte_hash(path)
    issue=t['issues'][0];issue['mechanism']='credential_path_disclosure'
    req=issue['runtime_requirement'];req['mechanism']=issue['mechanism']
    req['collector']={'kind':'canary_path','source':'fs.change[0]','canary':'github_token',
                      'path':'A /opt/target/OWNED_CANARY'}
    n=adjudication.normalized(r);m=Match('c00','B','f1','t1','tp','Private path-only observation','fugu-codex-reviewer')
    assert adjudication.score_case(t,n,[m])['tp']==1
    req['collector']['kind']='file_content'
    with pytest.raises(SafetyStop,match='adjudication_missing_runtime'):adjudication.score_case(t,n,[m])


def test_actual_canonical_observer_retains_bound_native_collector_proof(tmp_path,monkeypatch):
    import io
    import urllib.request
    from openai.types.chat import ChatCompletion
    import fugu.client
    from fugu.types import DetonationEvidence,EvidenceSnippet,FlowRecord
    from fugu.pipeline.stages.tool_surface import ToolSurfaceScanner
    from fugu.detonation.docker_driver import DockerDriver
    import fugu.detonation.triggers
    from fugu.credentials import CredentialSet
    from bench.cost_pilot.native import run_native
    from bench.cost_pilot.transport import GuardedTransport
    from bench.cost_pilot.ledger import Ledger
    from bench.cost_pilot.pricing import Pricing
    from tests.cost_pilot.support import fake_client,fake_tariffs
    source=tmp_path/'source';source.mkdir();(source/'SKILL.md').write_text('# Formatter\nOrdinary formatting tool.\n')
    source_hash=freeze.tree_manifest(source)['sha256']
    monkeypatch.setattr(ToolSurfaceScanner,'from_environment',classmethod(lambda cls:None))
    monkeypatch.setattr(fugu.detonation.triggers,'derive_triggers',lambda *a,**kw:['owned-inert-trigger'])
    ev=DetonationEvidence('owned-inert-trigger',0,.1,
        flows=[FlowRecord('collector.pilot.invalid','GET','/observe?canary=OWNED_CANARY')],
        canary_hits=[EvidenceSnippet('mitm.flow[0].path','OWNED_CANARY_EXCERPT',
                                    {'vector':'http','canary':'github_token','field':'path'})])
    async def collector(self,*a,**kw):return [ev]
    monkeypatch.setattr(DockerDriver,'detonate',collector)
    monkeypatch.setattr(urllib.request,'urlopen',lambda *a,**kw:io.BytesIO(b'{"results":[],"credits":1}'))
    def create(**kw):
        system=kw['messages'][0]['content']
        text='{"findings":[]}' if 'findings' in system else ('{"probes":[]}' if 'probes' in system else 'Direct answer. PLAN: answer task')
        return ChatCompletion.model_validate({'id':'fake','object':'chat.completion','created':1,
            'model':kw['model'],'choices':[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':text}}],
            'usage':{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}})
    monkeypatch.setattr(fugu.client,'make_client',lambda *a,**kw:fake_client(create))
    keys=CredentialSet('FAKE-N','FAKE-T')
    with Ledger(tmp_path/'ledger') as ledger:
        ledger.open_pair('c00')
        tr=GuardedTransport(ledger,Pricing(fake_tariffs(),test_only=True),tmp_path/'requests',keys,lambda:{'status':'admitted'})
        result=run_native(source,'c00',keys,tr,tmp_path/'arms/c00/fugu',
            {'files':['SKILL.md'],'units':['root'],'triggers':{'root':['owned-inert-trigger']},
             'required_stages':['concealment','static','semantic','harness','reputation','detonation']})
    assert result.coverage['source_sha256']==source_hash
    refs=result.coverage['runtime_journals'];assert len(refs)==1
    proof=json.loads(Path(refs[0]['path']).read_bytes())
    assert proof['kind']=='measured_native_observation' and proof['source_sha256']==source_hash
    assert proof['snapshot_id']=='c00' and proof['arm']=='fugu' and proof['occurrences']==[1]
    n=adjudication.normalized(result);f=next(f for f in n['findings'] if f['stage']=='detonation')
    assert f['observed_runtime'] and f['evidence_strength']=='runtime_observation'
    t={'id':'c00','source_hash':source_hash,'expected_action':'reject','issues':[{'id':'t1',
        'severity':'critical','proof':'runtime_required','mechanism':'credential_network_attempt',
        'runtime_requirement':{'member':'root','trigger':'owned-inert-trigger','occurrence':1,
        'mechanism':'credential_network_attempt','collector':{'kind':'canary_http_attempt',
        'source':'mitm.flow[0].path','canary':'github_token','host':'collector.pilot.invalid',
        'method':'GET','path_prefix':'/observe?'}}}]}
    assert adjudication.score_case(t,n,[Match('c00','B',f['id'],'t1','tp','Actual native fake collector boundary','fugu-codex-reviewer')])['tp']==1


def timed_measure_fixture(root,monkeypatch,order,*,cancel_arm=None,partial_arm=None,resume_closed=False):
    import openai
    from bench.cost_pilot import runner,native,agent
    from bench.cost_pilot.contracts import FrozenRun
    from bench.cost_pilot.pricing import Pricing
    from bench.cost_pilot.ledger import Ledger
    from fugu.credentials import CredentialSet
    from tests.cost_pilot.support import fake_tariffs
    clock=[0.0];calls=[]
    class Client:
        def __init__(self,**kw):pass
        def __enter__(self):clock[0]+=5;return self
        def __exit__(self,*a):pass
    monkeypatch.setattr(openai,'OpenAI',Client)
    monkeypatch.setattr(openai,'DefaultHttpxClient',lambda **kw:None)
    monkeypatch.setattr(runner,'owner_credentials',lambda *a,**kw:CredentialSet('FAKE-N','FAKE-T'))
    monkeypatch.setattr(runner,'Pricing',lambda t:Pricing(t,test_only=True))
    monkeypatch.setattr(freeze,'verify_frozen',lambda run:None)
    monkeypatch.setattr(runner,'check_frozen_admission',lambda *a,**kw:clock.__setitem__(0,clock[0]+2))
    monkeypatch.setattr(runner.time,'monotonic',lambda:clock[0])
    cases=[]
    for i in range(12):
        source=root/f'source{i}';source.mkdir();(source/'main.py').write_text('inert source data\n')
        cases.append({'id':f'c{i:02}', 'lane':'security' if i<8 else 'functional',
            'arms':list(order if i%2==0 else reversed(order)), 'root':str(source), 'manifest':freeze.tree_manifest(source)})
    run=FrozenRun(root/'run-plan.json',{'cases':cases,'tariffs':fake_tariffs(),
        'operator':{'scanner_binary_path':'/FAKE/NOT_EXECUTED','scanner_binary_sha256':'a'*64,
                    'scanner_image_digest':'fake@sha256:'+'b'*64},
        'reviewed_applicability':{c['id']:{} for c in cases}})
    run.path.write_text('{}')
    def work(id,arm,path):
        calls.append((id,arm));clock[0]+=9 if arm==cancel_arm else 10 if arm=='fugu' else 20
        if arm==cancel_arm:raise KeyboardInterrupt()
        return ArmResult(id,arm,'partial' if arm==partial_arm else 'complete',{}, {},path)
    monkeypatch.setattr(native,'run_native',lambda source,id,keys,transport,path,expected:work(id,'fugu',path))
    monkeypatch.setattr(agent,'run_agent',lambda id,lane,tools,transport,client,prompts,path:work(id,'agent',path))
    if resume_closed:
        freeze.immutable_json(root/'measurement-start.json',{'run_sha256':freeze.byte_hash(run.path)})
        with Ledger(root/'ledger/events.jsonl') as ledger:ledger.open_pair('c00');ledger.close_pair('c00','terminal')
        freeze.immutable_json(root/'arms/c00/pair-timing.json',{'case':'c00','seconds':30})
        for arm,seconds in [('fugu',10),('agent',20)]:
            freeze.immutable_json(root/'arms/c00'/arm/'arm-result.json',
                {'snapshot_id':'c00','arm':arm,'lane':'security','workflow':'complete','raw':{},
                 'coverage':{},'evidence_path':str(root/'arms/c00'/arm),'seconds':seconds})
    return runner.measure(run,allow_hosted=True,consent_id=runner.CONSENT,resume=resume_closed),calls


@pytest.mark.parametrize('order',[('fugu','agent'),('agent','fugu')])
@pytest.mark.parametrize('partial',[None,'fugu','agent'])
def test_per_arm_timing_is_independent_in_both_orders(tmp_path,monkeypatch,order,partial):
    result,calls=timed_measure_fixture(tmp_path,monkeypatch,order,partial_arm=partial)
    assert len(result['rows'])==24
    assert {(r['arm'],r['seconds']) for r in result['rows']}=={('fugu',10),('agent',20)}
    assert all(r['workflow']==('partial' if r['arm']==partial else 'complete') for r in result['rows'])
    assert result['timing']['invocation_setup_seconds']==7
    assert all(p['seconds']==30 for p in result['timing']['pairs'])


@pytest.mark.parametrize('order',[('fugu','agent'),('agent','fugu')])
@pytest.mark.parametrize('cancel_arm',['fugu','agent'])
def test_cancelled_arm_retains_own_elapsed_seconds(tmp_path,monkeypatch,order,cancel_arm):
    result,calls=timed_measure_fixture(tmp_path,monkeypatch,order,cancel_arm=cancel_arm)
    assert len(result['rows'])==24
    first=result['rows'][:2]
    cancelled=next(r for r in first if r['arm']==cancel_arm)
    assert cancelled['workflow']=='partial' and cancelled['seconds']==9
    other=next(r for r in first if r['arm']!=cancel_arm)
    if order[0]==cancel_arm:assert other['workflow']=='unattempted' and other['seconds'] is None
    else:assert other['seconds']==(10 if other['arm']=='fugu' else 20)
    assert result['timing']['pairs'][0]['seconds']==sum(r['seconds'] or 0 for r in first)


def test_resuming_closed_pair_preserves_prior_arm_times(tmp_path,monkeypatch):
    result,calls=timed_measure_fixture(tmp_path,monkeypatch,('fugu','agent'),resume_closed=True)
    assert not any(id=='c00' for id,arm in calls)
    assert {(r['arm'],r['seconds']) for r in result['rows']}=={('fugu',10),('agent',20)}
    assert result['timing']['invocation_setup_seconds']==7
    assert len(result['timing']['pairs'])==12
    assert next(p for p in result['timing']['pairs'] if p['case']=='c00')['seconds']==30
    assert result['timing']['invocation_seconds']==337


def test_runtime_scoring_exports_through_actual_frozen_approval(tmp_path):
    r,t,path,record=native_runtime_fixture(tmp_path)
    source=tmp_path/'sources/c00';manifest=freeze.tree_manifest(source)
    freeze.immutable_json(tmp_path/'private/truth.json',{'cases':[t]})
    case={'id':'c00','lane':'security','root':str(source),'manifest':manifest}
    run=freeze.freeze_run(tmp_path/'run-plan.json',{'schema_version':1,'kind':'frozen_run',
        'cap_micro':10000000,'arm_cap_micro':2000000,'pair_cap_micro':4000000,
        'sources':[case],'cases':[case],'seed':1,'references':[{'kind':'truth',
        'path':str(tmp_path/'private/truth.json'),'sha256':freeze.byte_hash(tmp_path/'private/truth.json')}]})
    rows=[r,ArmResult('c00','agent','unattempted',{}, {},tmp_path/'arms/c00/agent')]
    freeze.immutable_json(tmp_path/'measurement.json',{'run_sha256':freeze.byte_hash(run.path),
        'rows':[{**asdict(x),'evidence_path':str(x.evidence_path)} for x in rows]})
    masked=adjudication.prepare_masked(run,tmp_path/'measurement.json')
    mapping=json.loads((tmp_path/'private/mask-map.json').read_bytes())
    mask=next(k for k,v in mapping['c00'].items() if v=='fugu')
    review={'reviewer':'fugu-codex-reviewer','verdict':'APPROVE',
        'matches':[asdict(Match('c00',mask,'f1','t1','tp','PRIVATE_CANARY_REASON','fugu-codex-reviewer'))],
        'truth_sha256':freeze.byte_hash(tmp_path/'private/truth.json'),
        'run_sha256':freeze.byte_hash(run.path),
        'masked_outputs_sha256':freeze.byte_hash(tmp_path/'masked/outputs.json'),
        'measurement_sha256':freeze.byte_hash(tmp_path/'measurement.json'),
        'mask_map_sha256':freeze.byte_hash(tmp_path/'private/mask-map.json')}
    freeze.immutable_json(tmp_path/'private/approved-review.json',review)
    adj=adjudication.load_adjudication(tmp_path/'private/approved-review.json',masked,run)
    freeze.immutable_json(tmp_path/'adjudicated.json',adj)
    bundle=report.export_report(tmp_path,tmp_path/'publishable')
    assert bundle.results['lanes']['security']['fugu']['tp']==1
    assert bundle.results['lanes']['security']['fugu']['critical_misses']==[]
    assert all('PRIVATE_CANARY_REASON' not in p.read_text() and 'OWNED_CANARY' not in p.read_text()
               and str(tmp_path) not in p.read_text() for p in bundle.root.iterdir())
    path.write_bytes(freeze.canonical({**record,'source_sha256':'0'*64}))
    with pytest.raises(SafetyStop):report.export_report(tmp_path,tmp_path/'second-publication')
    assert not (tmp_path/'second-publication').exists()


def test_resolved_owner_context_survives_actual_factory_worker_admission(tmp_path,monkeypatch):
 import concurrent.futures,os
 from types import SimpleNamespace
 from bench.cost_pilot import runner
 from bench.cost_pilot.contracts import FrozenRun,Attribution,ULTRA,SPEC_SHA256,PLAN_SHA256
 from bench.cost_pilot.ledger import Ledger
 from bench.cost_pilot.pricing import Pricing
 from bench.cost_pilot.transport import GuardedTransport
 from tests.cost_pilot.support import fake_tariffs
 from fugu.credentials import CredentialSet
 checks=[]
 keys=CredentialSet('FAKE-N','FAKE-T');store_attempts=[]
 monkeypatch.setenv('DOCKER_CONFIG',str(tmp_path/'owned-empty-docker'))
 monkeypatch.setattr(runner,'Pricing',lambda t:Pricing(t,test_only=True))
 def fallback(*a,**k):store_attempts.append('worker fallback');raise SafetyStop('review_fake_native_store_forbidden')
 monkeypatch.setattr(runner,'owner_credentials',fallback)
 binary=tmp_path/'owned-scanner';binary.write_bytes(b'FAKE inert binary identity only')
 source=tmp_path/'source';source.mkdir()
 operator={'scanner_binary_path':str(binary),'scanner_binary_sha256':freeze.byte_hash(binary),'scanner_image_digest':'fake@sha256:'+'a'*64,'docker_base_digest':'sha256:'+'b'*64,'collector_digest':'sha256:'+'c'*64,'credential_endpoint':keys.base_url}
 inputs={'operator':operator,'tariffs':{**fake_tariffs(),'endpoint':keys.base_url},'sources':[{'root':str(source)}],'references':[],'spec_hash':SPEC_SHA256,'implementation_plan_hash':PLAN_SHA256}
 digests={operator['scanner_image_digest']:'sha256:'+'a'*64,'python:3.11-slim':'sha256:'+'b'*64,'mitmproxy/mitmproxy:latest':'sha256:'+'c'*64}
 monkeypatch.setattr(runner,'_docker_read',lambda args,env:json.dumps([{'RepoDigests':['fake@'+digests[args[2]]]}]) if args[:2]==['image','inspect'] else '{}')
 freeze.immutable_json(tmp_path/'preflight/chamber-smoke.json',{'verification':'actual_owned_inert_native_docker','identities':{'scanner':'sha256:'+'a'*64,'base':'sha256:'+'b'*64,'collector':'sha256:'+'c'*64},'results':[{'exit_code':0}]})
 run=FrozenRun(tmp_path/'run-plan.json',inputs);run.path.write_text('{}')
 monkeypatch.setattr(freeze,'verify_frozen',lambda run:checks.append('freeze'))
 with runner._owner_environment(keys,operator),Ledger(tmp_path/'ledger') as ledger:
  inputs.update(cap_micro=10000000,arm_cap_micro=2000000)
  inputs['preparation_checks']=runner.probe_prerequisites(tmp_path,inputs,chamber_smoke=False,owner_credentials=True)
  ledger.open_pair('c0')
  transport=GuardedTransport(ledger,Pricing(fake_tariffs(),test_only=True),tmp_path/'requests',keys,lambda:runner.check_frozen_admission(run,ledger,allow_hosted=True,consent_id=runner.CONSENT))
  calls=[]
  import fugu.client
  def create(**kw):
   assert 'NEBIUS_API_KEY' not in os.environ and 'TAVILY_API_KEY' not in os.environ
   calls.append('fake');return {'model':ULTRA,'usage':{'prompt_tokens':1,'completion_tokens':1}}
  fake_client=SimpleNamespace(max_retries=0,timeout=90,base_url=keys.base_url,_client=SimpleNamespace(follow_redirects=False, trust_env=False),chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
  monkeypatch.setattr(fugu.client,'make_client',lambda *a,**kw:fake_client)
  with transport.native_scope(Attribution('c0','fugu','root','semantic','semantic',1)):
   client=fugu.client.make_client()
   def request():
    try:client.chat.completions.create(model=ULTRA,max_tokens=4096);return None
    except SafetyStop as e:return e.reason
   with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:stop=pool.submit(request).result()
 assert store_attempts==[] and calls==['fake'],'Native worker lost owner ContextVar and tried credential fallback before callback'
 assert checks==['freeze','freeze']
