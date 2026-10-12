"""Ultra -> Super -> Ultra, preserving full SDK/tool conversation history."""
from __future__ import annotations
import copy
import json
from pathlib import Path,PurePosixPath
from .contracts import ULTRA,SUPER,Attribution,ArmResult,SafetyStop
from .freeze import immutable_json
from .transport import serialize_response,safe_artifact


def _location(loc):
    p=loc.get('path')
    if not isinstance(p,str) or not p or PurePosixPath(p).is_absolute() or '..' in PurePosixPath(p).parts:raise SafetyStop('final_location')
    if any(type(loc.get(k)) is not int for k in ('start_line','end_line')) or loc['start_line']<1 or loc['end_line']<loc['start_line']:raise SafetyStop('final_location')


def _evidence(items,known):
    if not isinstance(items,list) or any(not isinstance(i,str) or i not in known for i in items):raise SafetyStop('final_evidence')


def validate_final(value,snapshot_id,lane,evidence_ids,critique_ids):
    keys={'snapshot_id','lane','action','reasons','findings','unknowns','coverage','review_resolutions'}
    if not isinstance(value,dict) or set(value)!=keys or value['snapshot_id']!=snapshot_id or value['lane']!=lane or value['action'] not in {'accept','investigate','reject'}:raise SafetyStop('final_schema')
    if not isinstance(value['reasons'],list) or any(not isinstance(s,str) for s in value['reasons']):raise SafetyStop('final_schema')
    if not isinstance(value['unknowns'],list) or not isinstance(value['findings'],list):raise SafetyStop('final_schema')
    ids=set()
    for f in value['findings']:
        if set(f)!={'id','title','severity','location','mechanism','evidence','evidence_strength','observed_runtime'} or not isinstance(f['id'],str) or f['id'] in ids or f['severity'] not in {'critical','high','medium','low','info'} or f['evidence_strength'] not in {'source_deduction','web_supported','unresolved'} or f['observed_runtime'] is not False:raise SafetyStop('final_finding')
        if not all(isinstance(f[k],str) and f[k] for k in ('id','title','mechanism')):raise SafetyStop('final_finding')
        ids.add(f['id']);_location(f['location']);_evidence(f['evidence'],evidence_ids)
    for u in value['unknowns']:
        if not isinstance(u,dict) or not {'claim','available_evidence','missing_proof'}<=set(u):raise SafetyStop('final_unknown')
    coverage=value['coverage']
    if not isinstance(coverage,dict) or not {'inventoried_files','read_paths','searched_paths','omitted_paths','tool_errors','truncations'}<=set(coverage) or type(coverage['inventoried_files']) is not int:raise SafetyStop('final_coverage')
    for k in ('read_paths','searched_paths','omitted_paths','tool_errors','truncations'):
        if not isinstance(coverage[k],list):raise SafetyStop('final_coverage')
    resolved=set()
    if not isinstance(value['review_resolutions'],list):raise SafetyStop('final_resolution')
    for r in value['review_resolutions']:
        if set(r)!={'critique_id','disposition','reason','evidence'} or r['critique_id'] in resolved or r['disposition'] not in {'accepted','revised','rejected','unresolved'} or not isinstance(r['reason'],str):raise SafetyStop('final_resolution')
        resolved.add(r['critique_id']);_evidence(r['evidence'],evidence_ids)
    if resolved!=critique_ids:raise SafetyStop('final_resolution')


def _critique(value,evidence_ids):
    if not isinstance(value,dict) or set(value)!={'critiques','additional_candidates','unknowns','coverage'}:raise SafetyStop('critique_schema')
    ids=set()
    for k in ('critiques','additional_candidates'):
        if not isinstance(value[k],list):raise SafetyStop('critique_schema')
        for c in value[k]:
            if not {'id','location','mechanism','evidence','reason','resolution_suggestion'}<=set(c) or not isinstance(c['id'],str) or c['id'] in ids:raise SafetyStop('critique_schema')
            ids.add(c['id']);_location(c['location']);_evidence(c['evidence'],evidence_ids)
    if not isinstance(value['unknowns'],list) or not isinstance(value['coverage'],dict):raise SafetyStop('critique_schema')
    return ids


def run_agent(snapshot_id,lane,tools,transport,client,prompts,evidence:Path):
    evidence=Path(evidence);evidence_ids=set();critique_ids=set();attempts=0;errors=[];draft=None;critique=None;final=None
    task=prompts[lane+'_task'].replace('{snapshot_id}',snapshot_id).replace('{source_hash}',tools.hash)+'\n'+prompts['report_contract']
    history=[{'role':'system','content':prompts['principal']},{'role':'user','content':task}]
    def attr(role):return Attribution(snapshot_id,'agent','root','agent',role,attempts+1)
    def outbound(messages,model,role,earmark=None):
        nonlocal attempts
        if attempts>=32:raise SafetyStop('attempt_cap')
        request={'model':model,'messages':copy.deepcopy(messages),'tools':tools.schemas(),'max_tokens':4096,'temperature':.1}
        attempts+=1
        response=transport.sdk(request,lambda:client.chat.completions.create(**request),Attribution(snapshot_id,'agent','root','agent',role,attempts),earmark=earmark)
        data=serialize_response(response);message=data['choices'][0]['message']
        messages.append(message)
        immutable_json(evidence/f'transcript-{attempts:02d}.json',safe_artifact({'request':request,'response':data},[transport.keys.nebius,transport.keys.tavily]))
        if data['choices'][0].get('finish_reason') not in {'stop','tool_calls'}:raise SafetyStop('model_incomplete')
        calls=message.get('tool_calls') or []
        for call in calls:
            try:
                reply=tools.dispatch(call['function']['name'],json.loads(call['function']['arguments']))
                evidence_ids.add(reply.evidence_id);text=reply.text
            except (SafetyStop,ValueError,KeyError) as exc:
                reason=exc.reason if isinstance(exc,SafetyStop) else 'tool_schema';errors.append(reason);text=json.dumps({'error':reason})
            messages.append({'role':'tool','tool_call_id':call['id'],'content':text})
        if calls:return None
        try:return json.loads(message['content'])
        except (ValueError,TypeError):messages.append({'role':'user','content':'Output was invalid JSON. Return the requested JSON schema; retain all limitations.'});return None
    try:
        review_bound=transport.pricing.bound('nebius',SUPER);final_bound=transport.pricing.bound('nebius',ULTRA)
        transport.ledger.earmark(attr('reviewer'),'critique',review_bound)
        transport.ledger.earmark(attr('principal'),'final',final_bound)
        if sum((review_bound.microdollars,final_bound.microdollars,final_bound.microdollars))+transport.ledger.summary()['arm_outstanding_micro']['agent']-review_bound.microdollars-final_bound.microdollars>transport.ledger.arm_cap:raise SafetyStop('agent_preflight_budget')
        for _ in range(24):
            try:draft=outbound(history,ULTRA,'principal')
            except SafetyStop as exc:
                if exc.reason=='arm_cap':break
                raise
            if draft is not None:break
        review_history=[{'role':'system','content':prompts['reviewer']},{'role':'user','content':task},*copy.deepcopy(history[2:]),{'role':'user','content':json.dumps({'draft':draft,'computed_coverage':tools.coverage()})}]
        for n in range(6):
            value=outbound(review_history,SUPER,'reviewer','critique' if n==0 else None)
            if value is not None:
                try:critique_ids=_critique(value,evidence_ids);critique=value;break
                except SafetyStop:review_history.append({'role':'user','content':'Critique schema was invalid; use the required schema.'})
        history.extend(copy.deepcopy(review_history[2:]))
        history.append({'role':'user','content':json.dumps({'critique':critique,'computed_coverage':tools.coverage()})+'\n'+prompts['finalization']+'\n'+prompts['report_contract']})
        for n in range(min(2,32-attempts)):
            value=outbound(history,ULTRA,'principal','final' if n==0 else None)
            if value is not None:
                try:validate_final(value,snapshot_id,lane,evidence_ids,critique_ids);final=value;break
                except SafetyStop as exc:errors.append(exc.reason);history.append({'role':'user','content':'Final report schema/evidence validation failed. Resolve against the required contract.'})
    except (SafetyStop,Exception) as exc:
        errors.append(exc.reason if isinstance(exc,SafetyStop) else 'agent_failed')
    coverage=tools.coverage();complete=final is not None and critique is not None and not coverage['incomplete'] and not errors
    raw={'final':final,'draft':draft,'critique':critique,'attempts':attempts,'errors':errors,'evidence_ids':sorted(evidence_ids),'runtime_capability':'structurally_unavailable','observed_runtime_count':0}
    immutable_json(evidence/'result.json',safe_artifact(raw,[transport.keys.nebius,transport.keys.tavily]))
    return ArmResult(snapshot_id,'agent','complete' if complete else 'partial',raw,coverage,evidence)
