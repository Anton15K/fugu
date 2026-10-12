"""Evidence-qualified scores and estimated dollars, never invoice claims."""
from __future__ import annotations
import csv
import io
import json
import os
import statistics
from dataclasses import asdict
from pathlib import Path
from .contracts import Match,ReportBundle,SafetyStop
from .freeze import immutable_json,load_frozen,verify_frozen,byte_hash
from .adjudication import normalized,score_case


def safe_ratio(numerator,denominator):return None if not denominator else numerator/denominator


def _immutable_text(path,text):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.open('x',encoding='utf-8',newline='') as f:
        os.chmod(path,0o600);f.write(text);f.flush();os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def _interval(known,unknown,denominator):
    if not denominator:return None
    if unknown:return {'lower_micro':known/denominator,'upper_micro':(known+unknown)/denominator}
    return known/denominator


def build_report(run,ledger_summary,results,adjudication,output):
    if adjudication.get('status')!='APPROVE' or adjudication.get('reviewer')!='fugu-codex-reviewer':raise SafetyStop('report_unreviewed')
    output=Path(output);truths={t['id']:t for t in adjudication['truth']['cases']};matches=[m if isinstance(m,Match) else Match(**m) for m in adjudication['matches']];lookup={(r['case'],r['arm']):r for r in map(normalized,results)};rows=[];lanes={};mapping=adjudication['mapping']
    for c in run.doc['cases']:
        if c['id'] not in truths:raise SafetyStop('report_truth_missing')
        for arm in ('agent','fugu'):
            r=lookup.get((c['id'],arm),{'case':c['id'],'arm':arm,'workflow':'unattempted','action':None,'findings':[],'coverage':{}})
            mask=next(k for k,v in mapping[c['id']].items() if v==arm)
            score=score_case(truths[c['id']],r,[m for m in matches if m.case==c['id'] and m.masked_arm==mask])
            row={**score,'arm':arm,'lane':c['lane'],'action':r['action'],'coverage':r['coverage'],'runtime_capability':'structurally_unavailable' if arm=='agent' else 'native_docker','source_and_web_tools':['list_files','read_file','search_files','search_web'] if arm=='agent' else None,'seconds':r.get('seconds'),'cost':adjudication.get('cost_by_case',{}).get(c['id'],{}).get(arm,{'known_micro':0,'unknown_upper_micro':0})}
            rows.append(row)
    for lane in ('security','functional'):
        lanes[lane]={}
        for arm in ('agent','fugu'):
            subset=[r for r in rows if r['lane']==lane and r['arm']==arm];counts={w:sum(r['workflow']==w for r in subset) for w in ('complete','partial','failed','unattempted')};tp=sum(r['tp'] or 0 for r in subset);fp=sum(r['fp'] or 0 for r in subset);fn=sum(r['fn'] or 0 for r in subset);decisions=[r for r in subset if r['decision_correct'] is not None]
            table={}
            for r in decisions:
                key=truths[r['case']]['expected_action']+'->'+r['action'];table[key]=table.get(key,0)+1
            lanes[lane][arm]={**counts,'planned':len(subset),'attempted':len(subset)-counts['unattempted'],'tp':tp,'fp':fp,'fn':fn,'unresolved':sum(r['unresolved'] for r in subset),'precision':safe_ratio(tp,tp+fp),'recall':safe_ratio(tp,tp+fn),'f1':safe_ratio(2*tp,2*tp+fp+fn),'decision_n':len(decisions),'decision_accuracy':safe_ratio(sum(r['decision_correct'] for r in decisions),len(decisions)),'binary_triage_accuracy':safe_ratio(sum(r['triage_correct'] for r in decisions),len(decisions)),'three_action_table':table,'critical_misses':[{'case':r['case'],'truth_id':id} for r in subset for id in r['critical_misses']],'fixed_version_false_positives':sum(r['fp'] or 0 for r in subset if not truths[r['case']]['issues']) if lane=='functional' else None}
    known=ledger_summary['known_micro'];unknown=ledger_summary['unknown_upper_micro'];cost={'lower_micro':known,'upper_micro':known+unknown,'exact_estimate_micro':known if not unknown else None,'classification':'estimated tariff cost; not an owner invoice','per_arm':{}}
    for arm in ('agent','fugu'):
        ak=adjudication.get('known_cost_by_arm',{}).get(arm,0);au=adjudication.get('unknown_by_arm',{}).get(arm,0);rs=[r for r in rows if r['arm']==arm]
        cost['per_arm'][arm]={'known_micro':ak,'unknown_upper_micro':au,'cost_per_tp':_interval(ak,au,sum(r['tp'] or 0 for r in rs)),'cost_per_correct_decision':_interval(ak,au,sum(r['decision_correct'] is True for r in rs))}
    if sum(v['known_micro'] for v in cost['per_arm'].values())!=known or sum(v['unknown_upper_micro'] for v in cost['per_arm'].values())!=unknown:raise SafetyStop('report_cost_reconciliation')
    paired=[c['id'] for c in run.doc['cases'] if all(next(r for r in rows if r['case']==c['id'] and r['arm']==a)['workflow']=='complete' for a in ('agent','fugu'))]
    discordant=[c['id'] for c in run.doc['cases'] if len({next(r for r in rows if r['case']==c['id'] and r['arm']==a)['workflow'] for a in ('agent','fugu')})>1]
    pair_costs=[sum(r['cost']['known_micro'] for r in rows if r['case']==c) for c in paired if set(adjudication.get('cost_by_case',{}).get(c,{}))=={'agent','fugu'} and not any(r['cost']['unknown_upper_micro'] for r in rows if r['case']==c)]
    data={'schema_version':1,'planned_cases':len(run.doc['cases']),'rows':rows,'lanes':lanes,'cost':cost,'completed_matched_pairs':paired,'discordant_pairs':discordant,'median_known_completed_pair_micro':statistics.median(pair_costs) if pair_costs else None,'median_pair_n':len(pair_costs),'usage':adjudication.get('usage',{}),'human_time':adjudication.get('human_time',{}),'resources':'Docker CPU/memory/build/run metrics unpriced','limits':['Single frozen seed, small pilot; completed subset is not all planned cases.','Product-capability comparison: Fugu alone has OSV/Docker.','No equivalence, noninferiority, general superiority or equal-tool causal claim.','Upstream public familiarity and potential model contamination disclosed.','Agent target observations are structurally unavailable and zero.','Identity masking is imperfect due to structural output.'],'models':{'principal':'nvidia/Nemotron-3-Ultra-550b-a55b','reviewer':'nvidia/nemotron-3-super-120b-a12b','temperature':.1,'max_tokens':4096,'attempt_cap':32,'timeout':90,'sdk_retries':0},'reviewer':adjudication['reviewer']}
    immutable_json(output/'results.json',data)
    buffer=io.StringIO();fields=['case','arm','lane','workflow','tp','fp','fn','unresolved','decision_correct','triage_correct','observed_runtime_count'];writer=csv.DictWriter(buffer,fieldnames=fields,extrasaction='ignore');writer.writeheader();writer.writerows(rows);_immutable_text(output/'results.csv',buffer.getvalue())
    markdown='# Cost pilot results\n\nEstimated cost interval: '+str(known/1e6)+'–'+str((known+unknown)/1e6)+' USD. Includes failed attempts; reservations are liability bounds, not measured usage.\n\n'
    markdown+='Completed matched pairs: '+str(len(paired))+'. Planned cases: '+str(len(run.doc['cases']))+'.\n\n'
    for lane in ('security','functional'):
        markdown+='## '+lane.title()+' lane\n\n| Arm | Planned | Attempted | Complete | Partial | TP | FP | FN | Unresolved |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|\n'
        for arm in ('agent','fugu'):
            v=lanes[lane][arm];markdown+='| '+arm+' | '+' | '.join(str(v[k]) for k in ('planned','attempted','complete','partial','tp','fp','fn','unresolved'))+' |\n'
        markdown+='\n'
    markdown+='\n'.join('- '+s for s in data['limits'])+'\n\nIndependent adjudication and local raw evidence remain separately preserved. No measured outcome is invented by export.\n'
    _immutable_text(output/'report.md',markdown);immutable_json(output/'adjudication-reasons.json',[asdict(m) for m in matches])
    return ReportBundle(output,data,output/'results.json',output/'results.csv',output/'report.md')


def export_report(root,output):
    root=Path(root);run=load_frozen(root/'run-plan.json');verify_frozen(run)
    measurement=json.loads((root/'measurement.json').read_bytes());adjud=json.loads((root/'adjudicated.json').read_bytes())
    if byte_hash(Path(adjud['review_path']))!=adjud['review_sha256']:raise SafetyStop('adjudication_drift')
    from .ledger import Ledger
    with Ledger(root/'ledger/events.jsonl') as ledger:
        summary=ledger.summary();events=ledger.events()
    tickets={e['id']:e for e in events if e['kind']=='reserve'};costs={};known={'agent':0,'fugu':0};unknown={'agent':0,'fugu':0};usage={'models':{},'tavily':{'observed_credits':0,'contractual_credits':0}}
    for e in events:
        if e['kind'] not in {'settle','unknown'}:continue
        t=tickets[e['id']];a=t['attribution'];v=costs.setdefault(a['pair'],{}).setdefault(a['arm'],{'known_micro':0,'unknown_upper_micro':0})
        if e['kind']=='unknown':v['unknown_upper_micro']+=t['bound']['microdollars'];unknown[a['arm']]+=t['bound']['microdollars'];continue
        v['known_micro']+=e['actual'];known[a['arm']]+=e['actual'];u=e['usage']
        if t['bound']['service']=='tavily':usage['tavily']['contractual_credits' if u.get('credit_source')=='frozen_contract' else 'observed_credits']+=u['credits']
        else:
            m=usage['models'].setdefault(t['bound']['model'],{'input':0,'output':0,'cache':0,'reasoning':0,'calls':0});m['input']+=u['prompt_tokens'];m['output']+=u['completion_tokens'];m['cache']+=(u.get('prompt_tokens_details') or {}).get('cached_tokens',0);m['reasoning']+=(u.get('completion_tokens_details') or {}).get('reasoning_tokens',0);m['calls']+=1
    adjud.update(cost_by_case=costs,known_cost_by_arm=known,unknown_by_arm=unknown,usage=usage)
    return build_report(run,summary,measurement['rows'],adjud,Path(output))
