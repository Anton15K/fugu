"""Named human matching; source proof and measured runtime proof stay distinct."""
from __future__ import annotations
import copy
import json
import random
import re
from collections import Counter
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
    if arm=='fugu':
        for f in findings:f['member']='root'
    for child in raw.get('children',[]):
        added=copy.deepcopy(child.get('findings',[]))
        for f in added:f['member']=child.get('label')
        findings.extend(added)
    view={'case':r.get('snapshot_id',r.get('case')),'arm':arm,'workflow':r['workflow'],
          'action':action,'findings':findings,'coverage':r.get('coverage',{}),
          'seconds':r.get('seconds'),'evidence_path':r.get('evidence_path'),
          'native_verdict':verdict,'runtime_capability':'native_docker' if arm=='fugu' else 'structurally_unavailable'}
    for i,f in enumerate(findings):
        f.setdefault('id',f'finding-{i+1}');f.setdefault('observed_runtime',False)
        f.setdefault('evidence_strength','source_deduction' if f.get('stage')!='detonation' else 'unresolved')
        if arm=='fugu' and f.get('stage')=='detonation':
            f['observed_runtime']=False;f['evidence_strength']='unresolved';f.pop('runtime_proofs',None)
            receipts=_receipts(f,view)
            if len(receipts)==1:
                proof,row,mechanism=receipts[0]
                f.update(runtime_proofs=[proof],observed_runtime=True,
                         evidence_strength='runtime_observation',mechanism=mechanism)
    return view


_NATIVE_FIELDS=('owasp_ids','title','detail','severity','confidence','stage','evidence')
_MECHANISMS={'Canary credential exfiltrated over the network':'credential_network_attempt',
             'Canary credential persisted to disk':'credential_path_disclosure',
             'Unexpected network egress during trigger execution':'network_attempt'}


def _native_findings(row):
    from fugu.types import DetonationEvidence,EvidenceSnippet,FlowRecord,DnsRecord
    from fugu.detonation.docker_driver import evidence_to_findings
    ev=DetonationEvidence(trigger=row['trigger'],exit_code=row['exit_code'],duration_s=row['duration_s'],
        flows=[FlowRecord(**v) for v in row.get('flows',[])],
        dns=[DnsRecord(**v) for v in row.get('dns',[])],fs_changes=row.get('fs_changes',[]),
        canary_hits=[EvidenceSnippet(**v) for v in row.get('canary_hits',[])],metrics=row.get('metrics',{}))
    return [asdict(f) for f in evidence_to_findings(ev)]


def _receipts(f,result):
    """Reconstruct native findings from hash-bound, same-arm collector records.

    Native collectors are cumulative within a chamber: a repeated observation
    cannot prove that a later trigger caused it. No HTTP response status or file
    content is collected; those stronger claims cannot be inferred here.
    """
    if result.get('arm')=='agent' or result.get('runtime_capability')!='native_docker':return []
    root=Path(result.get('evidence_path') or '').resolve();coverage=result.get('coverage',{})
    source=coverage.get('source_sha256')
    if not isinstance(source,str) or not re.fullmatch('[a-f0-9]{64}',source):return []
    receipts=[]
    for ref in coverage.get('runtime_journals',[]):
        try:
            p=Path(ref['path'])
            if not p.resolve().is_relative_to(root) or not p.name.startswith('docker-result-') or byte_hash(p)!=ref['sha256']:continue
            record=json.loads(p.read_bytes())
            if (record.get('schema_version')!=1 or record.get('kind')!='measured_native_observation'
                or record.get('arm')!='fugu' or record.get('snapshot_id')!=result['case']
                or record.get('source_sha256')!=source or record.get('member')!=f.get('member')
                or record.get('collector_scope')!='cumulative_per_chamber'):continue
            rows=record['results'];selected=record['selected_triggers'];occurrences=record['occurrences']
            if len(rows)!=len(selected) or len(rows)!=len(occurrences):continue
            counts=Counter();earlier=[]
            for index,row in enumerate(rows):
                trigger=row['trigger'];counts[trigger]+=1
                if (selected[index]!=trigger or type(occurrences[index]) is not int
                    or occurrences[index]!=counts[trigger]):continue
                generated=_native_findings(row)
                if type(row.get('exit_code')) is not int or row['exit_code']!=0:
                    earlier.extend(e for native in generated for e in native['evidence'])
                    continue
                for native in generated:
                    if any(native.get(k)!=f.get(k) for k in _NATIVE_FIELDS):continue
                    if any(e in earlier for e in native['evidence']):continue
                    mechanism=_MECHANISMS.get(native['title'])
                    if not mechanism:continue
                    proof={**ref,'row_index':index,'member':record['member'],'trigger':trigger,
                           'occurrence':occurrences[index],'source_sha256':source}
                    receipts.append((proof,row,mechanism))
                earlier.extend(e for native in generated for e in native['evidence'])
        except (OSError,ValueError,KeyError,TypeError,SafetyStop):continue
    return receipts


def _collector_matches(requirement,row,f):
    """Only native request/DNS/path observations; never delivery/content success."""
    if not isinstance(requirement,dict):return False
    kind=requirement.get('kind');source=requirement.get('source')
    if kind not in {'canary_http_attempt','canary_dns_attempt','canary_path','http_request','dns_attempt'}:return False
    pattern={'canary_http_attempt':r'mitm\.flow\[(\d+)\]\.(host|path|body)',
             'http_request':r'mitm\.flow\[(\d+)\]',
             'canary_dns_attempt':r'dns\.query\[(\d+)\]',
             'dns_attempt':r'dns\.query\[(\d+)\]',
             'canary_path':r'fs\.change\[(\d+)\]'}[kind]
    match=re.fullmatch(pattern,source or '')
    if not match or not any(e.get('source')==source for e in f.get('evidence',[])):return False
    index=int(match[1]);vector='http' if 'http' in kind else 'dns' if 'dns' in kind else 'fs'
    hits=[e for e in row.get('canary_hits',[]) if e.get('source')==source]
    if kind.startswith('canary_'):
        if not isinstance(requirement.get('canary'),str) or not any(
            e.get('meta',{}).get('vector')==vector and e.get('meta',{}).get('canary')==requirement['canary'] for e in hits):return False
    allowed={'kind','source','canary'}
    try:
        if vector=='http':
            allowed|={'host','method','path_prefix'};flow=row['flows'][index]
            if not all(isinstance(requirement.get(k),str) and requirement[k] for k in ('host','method','path_prefix')):return False
            if flow['host']!=requirement['host'] or flow['method']!=requirement['method'] or not flow['path'].startswith(requirement['path_prefix']):return False
        elif vector=='dns':
            allowed|={'query'}
            if not isinstance(requirement.get('query'),str) or not requirement['query'] or row['dns'][index]['query']!=requirement['query']:return False
        else:
            allowed|={'path'}
            if not isinstance(requirement.get('path'),str) or row['fs_changes'][index]!=requirement['path']:return False
    except (KeyError,IndexError,TypeError):return False
    return not (set(requirement)-allowed)


def _runtime(f,result,issue=None,truth=None):
    if f.get('observed_runtime') is not True:return False
    receipts=_receipts(f,result)
    if len(receipts)!=1 or f.get('runtime_proofs')!=[receipts[0][0]]:return False
    proof,row,mechanism=receipts[0]
    if f.get('mechanism')!=mechanism:return False
    if issue is None:return True
    req=issue.get('runtime_requirement')
    if (not isinstance(req,dict) or truth.get('source_hash')!=proof['source_sha256']
        or set(req)!={'member','trigger','occurrence','mechanism','collector'}
        or type(req.get('occurrence')) is not int
        or any(req.get(k)!=proof[k] for k in ('member','trigger','occurrence'))
        or req.get('mechanism')!=mechanism):return False
    return _collector_matches(req['collector'],row,f)


def _validate_case_matches(truth,result,matches):
    findings={f['id']:f for f in result.get('findings',[])};issues={i['id']:i for i in truth['issues']};seen=set();tp=set()
    for m in matches:
        if m.reviewer!='fugu-codex-reviewer' or not m.reason.strip() or m.case!=truth['id'] or m.finding_id not in findings or m.finding_id in seen or m.state not in {'tp','fp','unresolved','duplicate'}:raise SafetyStop('adjudication_match')
        seen.add(m.finding_id)
        if m.truth_id is not None and m.truth_id not in issues:raise SafetyStop('adjudication_truth_id')
        if m.state=='tp':
            if not m.truth_id or m.truth_id in tp:raise SafetyStop('adjudication_duplicate_tp')
            f=findings[m.finding_id];issue=issues[m.truth_id]
            if issue['proof']=='runtime_required' and not _runtime(f,result,issue,truth):raise SafetyStop('adjudication_missing_runtime')
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
