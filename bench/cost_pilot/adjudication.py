"""Named human matching; source proof and measured runtime proof stay distinct."""
from __future__ import annotations
import copy
import json
import random
from dataclasses import asdict
from pathlib import Path
from .contracts import Match,ArmResult,SafetyStop
from .freeze import immutable_json,byte_hash,digest,verify_frozen


def normalized(result):
    if isinstance(result,ArmResult):r=asdict(result);r['evidence_path']=str(result.evidence_path)
    else:r=copy.deepcopy(result)
    raw=r.get('raw',{});arm=r.get('arm');final=raw.get('final') or {} if arm=='agent' else raw
    verdict=raw.get('verdict');status=verdict.get('status','') if isinstance(verdict,dict) else str(verdict or '')
    action=final.get('action') if arm=='agent' else {'fail':'reject','warn':'investigate','pass':'accept'}.get(status.lower())
    findings=copy.deepcopy(final.get('findings',[]))
    for child in raw.get('children',[]):findings.extend(copy.deepcopy(child.get('findings',[])))
    for i,f in enumerate(findings):
        f.setdefault('id',f'finding-{i+1}');f.setdefault('observed_runtime',False)
        f.setdefault('evidence_strength','source_deduction' if f.get('stage')!='detonation' else 'unresolved')
        if arm=='fugu' and f.get('stage')=='detonation' and r.get('evidence_path'):
            proofs=[]
            for p in sorted(Path(r['evidence_path']).glob('docker-result-*.json')):
                data=json.loads(p.read_bytes())
                if any(row.get('exit_code') is not None and (row.get('canary_hits') or row.get('flows') or row.get('dns') or row.get('fs_changes')) for row in data.get('results',[])):
                    proofs.append({'path':str(p),'sha256':byte_hash(p)})
            if proofs:f['runtime_proofs']=proofs;f['observed_runtime']=True
    return {'case':r.get('snapshot_id',r.get('case')),'arm':arm,'workflow':r['workflow'],'action':action,'findings':findings,'coverage':r.get('coverage',{}),'seconds':r.get('seconds'),'evidence_path':r.get('evidence_path'),'native_verdict':verdict}


def _runtime(f,result):
    if f.get('observed_runtime') is not True or result.get('arm')=='agent':return False
    root=Path(result.get('evidence_path','')).resolve();proofs=f.get('runtime_proofs',[])
    if not proofs:return False
    for proof in proofs:
        p=Path(proof['path'])
        if not p.resolve().is_relative_to(root) or byte_hash(p)!=proof['sha256']:return False
        record=json.loads(p.read_bytes())
        if not any(row.get('trigger') and (row.get('canary_hits') or row.get('flows') or row.get('dns') or row.get('fs_changes')) for row in record.get('results',[])):return False
    return True


def _validate_case_matches(truth,result,matches):
    findings={f['id']:f for f in result.get('findings',[])};issues={i['id']:i for i in truth['issues']};seen=set();tp=set()
    for m in matches:
        if m.reviewer!='fugu-codex-reviewer' or not m.reason.strip() or m.case!=truth['id'] or m.finding_id not in findings or m.finding_id in seen or m.state not in {'tp','fp','unresolved','duplicate'}:raise SafetyStop('adjudication_match')
        seen.add(m.finding_id)
        if m.truth_id is not None and m.truth_id not in issues:raise SafetyStop('adjudication_truth_id')
        if m.state=='tp':
            if not m.truth_id or m.truth_id in tp:raise SafetyStop('adjudication_duplicate_tp')
            f=findings[m.finding_id];issue=issues[m.truth_id]
            if issue['proof']=='runtime_required' and not _runtime(f,result):raise SafetyStop('adjudication_missing_runtime')
            if f.get('evidence_strength')=='unresolved':raise SafetyStop('adjudication_unresolved_tp')
            if issue.get('mechanism') and issue['mechanism'] not in f.get('mechanism',f.get('detail','')):raise SafetyStop('adjudication_mechanism')
            if issue.get('location'):
                a=f.get('location',{});b=issue['location']
                if a.get('path')!=b['path'] or a.get('end_line',0)<b['start_line'] or a.get('start_line',10**9)>b['end_line']:raise SafetyStop('adjudication_location')
            tp.add(m.truth_id)
    return findings,issues,tp


def score_case(truth,result,matches):
    if result['workflow']=='unattempted':return {'case':truth['id'],'workflow':'unattempted','tp':None,'fp':None,'fn':None,'unresolved':0,'duplicate':0,'precision':None,'recall':None,'f1':None,'decision_correct':None,'triage_correct':None,'critical_misses':[],'observed_runtime_count':0,'severity_accuracy':None,'localization_accuracy':None}
    findings,issues,matched=_validate_case_matches(truth,result,matches)
    tp=len(matched);fp=sum(m.state=='fp' for m in matches);fn=len(issues)-tp
    unresolved=sum(m.state=='unresolved' for m in matches)+len(set(findings)-{m.finding_id for m in matches})
    precision=tp/(tp+fp) if tp+fp else None;recall=tp/(tp+fn) if tp+fn else None
    action=result.get('action');completed=result['workflow']=='complete' and action in {'accept','investigate','reject'}
    truths={i['id']:i for i in truth['issues']};severity=[findings[m.finding_id].get('severity')==truths[m.truth_id]['severity'] for m in matches if m.state=='tp']
    localized=[findings[m.finding_id].get('location',{}).get('path')==truths[m.truth_id].get('location',{}).get('path') for m in matches if m.state=='tp' and truths[m.truth_id].get('location')]
    return {'case':truth['id'],'workflow':result['workflow'],'tp':tp,'fp':fp,'fn':fn,'unresolved':unresolved,'duplicate':sum(m.state=='duplicate' for m in matches),'precision':precision,'recall':recall,'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,'decision_correct':action==truth['expected_action'] if completed else None,'triage_correct':(action in {'reject','investigate'})==(truth['expected_action'] in {'reject','investigate'}) if completed else None,'critical_misses':[i['id'] for i in issues.values() if i['severity']=='critical' and i['id'] not in matched],'observed_runtime_count':sum(_runtime(f,result) for f in findings.values()),'severity_accuracy':sum(severity)/len(severity) if severity else None,'localization_accuracy':sum(localized)/len(localized) if localized else None}


def _masked_records(results,seed):
    rng=random.Random(seed);cases={};mapping={}
    for result in results:
        r=normalized(result);id=r['case']
        if id not in mapping:
            arms=['agent','fugu'];rng.shuffle(arms);mapping[id]=dict(zip(('A','B'),arms));cases[id]={}
        masked=next(k for k,v in mapping[id].items() if v==r['arm'])
        view=copy.deepcopy(r);view.pop('arm');cases[id][masked]=view
    record={'schema_version':1,'cases':cases,'masking':'identity masked; structural formatting may reveal systems'}
    return record,mapping


def mask_outputs(root,results,seed):
    root=Path(root);record,mapping=_masked_records(results,seed)
    immutable_json(root/'private/mask-map.json',mapping);immutable_json(root/'masked/outputs.json',record);return record


def validate_matches(truth,outputs,matches):
    truth_cases={c['id']:c for c in truth['cases']}
    for id,arms in outputs['cases'].items():
        if id not in truth_cases:raise SafetyStop('adjudication_case')
        for masked,result in arms.items():
            selected=[m for m in matches if m.case==id and m.masked_arm==masked]
            _validate_case_matches(truth_cases[id],result,selected)
            if result['workflow']!='unattempted' and {m.finding_id for m in selected}!={f['id'] for f in result.get('findings',[])}:raise SafetyStop('adjudication_unmatched_findings')
    if any(m.case not in outputs['cases'] or m.masked_arm not in outputs['cases'][m.case] for m in matches):raise SafetyStop('adjudication_unknown_output')
    return {'status':'validated','matches':[asdict(m) for m in matches]}


def prepare_masked(run,measurement_path):
    verify_frozen(run);data=json.loads(Path(measurement_path).read_bytes())
    if data['run_sha256']!=byte_hash(run.path):raise SafetyStop('measurement_run_mismatch')
    path=run.path.parent/'masked/outputs.json'
    if path.exists():
        expected,mapping=_masked_records(data['rows'],run.doc['seed'])
        if json.loads(path.read_bytes())!=expected or json.loads((run.path.parent/'private/mask-map.json').read_bytes())!=mapping:raise SafetyStop('masked_measurement_drift')
        return expected
    return mask_outputs(run.path.parent,data['rows'],run.doc['seed'])


def load_adjudication(path,masked,run):
    verify_frozen(run);root=run.path.parent;review=json.loads(Path(path).read_bytes())
    bindings={'run_sha256':byte_hash(run.path),'measurement_sha256':byte_hash(root/'measurement.json'),'mask_map_sha256':byte_hash(root/'private/mask-map.json'),'masked_outputs_sha256':byte_hash(root/'masked/outputs.json')}
    if any(review.get(k)!=v for k,v in bindings.items()):raise SafetyStop('adjudication_input_drift')
    if masked!=prepare_masked(run,root/'measurement.json'):raise SafetyStop('masked_measurement_drift')
    if review.get('reviewer')!='fugu-codex-reviewer' or review.get('verdict')!='APPROVE' or review.get('masked_outputs_sha256')!=byte_hash(run.path.parent/'masked/outputs.json'):raise SafetyStop('adjudication_not_approved')
    truth_ref=next(r for r in run.doc['references'] if r['kind']=='truth' and r['path'].endswith('truth.json'))
    if review.get('truth_sha256')!=truth_ref['sha256']:raise SafetyStop('adjudication_truth_drift')
    truth=json.loads(Path(truth_ref['path']).read_bytes());matches=[Match(**m) for m in review['matches']]
    validate_matches(truth,masked,matches)
    return {'schema_version':1,'status':'APPROVE','reviewer':review['reviewer'],'truth':truth,'matches':review['matches'],'mapping':json.loads((run.path.parent/'private/mask-map.json').read_bytes()),'review_path':str(path),'review_sha256':byte_hash(Path(path)),'human_time':review.get('human_time',{}),'bindings':bindings}
