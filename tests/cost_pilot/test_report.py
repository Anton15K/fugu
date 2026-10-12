import json,csv
from pathlib import Path
import pytest
from bench.cost_pilot.adjudication import score_case,validate_matches,mask_outputs
from bench.cost_pilot.report import build_report
from bench.cost_pilot.contracts import Match,ArmResult,FrozenRun,SafetyStop


def truth(id='c02',lane='security'):
    return {'id':id,'lane':lane,'expected_action':'reject','issues':[{'id':'t1','severity':'high','proof':'source_allowed'},{'id':'t2','severity':'critical','proof':'runtime_required'}]}


def test_source_match_and_required_observation():
    t=truth();r={'case':'c02','arm':'agent','workflow':'complete','action':'investigate','findings':[{'id':'f1','severity':'high','evidence_strength':'source_deduction','observed_runtime':False},{'id':'f2','evidence_strength':'unresolved','observed_runtime':False}]}
    ms=[Match('c02','A','f1','t1','tp','source standard met','fugu-codex-reviewer'),Match('c02','A','f2','t2','unresolved','missing observation','fugu-codex-reviewer')]
    s=score_case(t,r,ms);assert s['tp']==1 and s['fn']==1 and s['unresolved']==1
    assert s['workflow']=='complete';assert s['critical_misses']==['t2'];assert s['observed_runtime_count']==0
    assert s['decision_correct'] is False and s['triage_correct'] is True
    with pytest.raises(SafetyStop):score_case(t,r,[ms[0],Match('c02','A','f2','t2','tp','claimed runtime','fugu-codex-reviewer')])


@pytest.mark.parametrize('workflow,action,fn,decision',[('unattempted','accept',None,None),('partial','accept',2,None),('complete','abstain',2,None)])
def test_denominators(workflow,action,fn,decision):
    s=score_case(truth(),{'case':'c02','workflow':workflow,'action':action,'findings':[]},[])
    assert s['fn']==fn and s['decision_correct'] is decision


def test_duplicate_no_extra_tp_and_warning_not_tp():
    r={'case':'c02','workflow':'complete','action':'investigate','findings':[{'id':'f1','evidence_strength':'source_deduction'},{'id':'f2','evidence_strength':'source_deduction'}]}
    ms=[Match('c02','A','f1','t1','tp','valid','fugu-codex-reviewer'),Match('c02','A','f2','t1','duplicate','same issue','fugu-codex-reviewer')]
    s=score_case(truth(),r,ms);assert s['tp']==1 and s['duplicate']==1 and s['fn']==1
    assert score_case(truth(),r,[])['tp']==0


def test_report_all_planned_rows_and_inclusive_unknown_costs(tmp_path):
    cases=[{'id':f'c{n:02}','lane':'security' if n<8 else 'functional'} for n in range(12)]
    truths=[{'id':c['id'],'lane':c['lane'],'expected_action':'accept','issues':[]} for c in cases]
    results=[]
    for n,c in enumerate(cases):
        for arm in ('agent','fugu'):
            workflow='complete' if n==0 else 'partial' if n==1 else 'unattempted'
            raw={'final':{'action':'accept','findings':[]}} if arm=='agent' else {'verdict':{'status':'pass'},'findings':[]}
            results.append(ArmResult(c['id'],arm,workflow,raw,{},tmp_path/'local-private-evidence'))
    run=FrozenRun(tmp_path/'run-plan.json',{'cases':cases,'seed':1,'cap_micro':10000000,'baseline_capabilities':['list_files','read_file','search_files','search_web']})
    adjud={'status':'APPROVE','reviewer':'fugu-codex-reviewer','truth':{'cases':truths},'matches':[],'mapping':{c['id']:{'A':'agent','B':'fugu'} for c in cases},'known_cost_by_arm':{'agent':100000,'fugu':200000},'unknown_by_arm':{'agent':17000,'fugu':0}}
    ledger={'known_micro':300000,'unknown_upper_micro':17000}
    b=build_report(run,ledger,results,adjud,tmp_path/'out');data=json.loads(b.json_path.read_text())
    assert len(data['rows'])==24
    assert data['lanes']['security']['agent']['attempted']==2 and data['lanes']['security']['agent']['unattempted']==6
    assert data['cost']['lower_micro']==300000 and data['cost']['upper_micro']==317000
    assert data['cost']['per_arm']['agent']['cost_per_tp'] is None
    assert data['cost']['per_arm']['agent']['cost_per_correct_decision']=={'lower_micro':100000,'upper_micro':117000}
    assert len(list(csv.DictReader(b.csv_path.open())))==24
    assert 'local-private-evidence' not in b.markdown_path.read_text()


def test_export_refuses_unreviewed(tmp_path):
    with pytest.raises(SafetyStop):build_report(FrozenRun(tmp_path/'x',{'cases':[]}),{},[],{'status':'pending'},tmp_path/'out')
