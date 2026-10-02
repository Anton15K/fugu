import json, hashlib
from pathlib import Path
from collections import Counter
out=Path(__file__).resolve().parents[1]
original=json.loads((out/'fugu.json').read_text());recovered=json.loads((out/'fugu-recovered.json').read_text())
evidence=recovered['recovery'];preserved=evidence['original_artifact_sha256']
assert all(hashlib.sha256((out/p).read_bytes()).hexdigest()==h for p,h in preserved.items())
oldcalls={x['number']:x for p in (out/'calls').glob('*.json') for x in [json.loads(p.read_text())]}
newcalls={x['number']:x for p in (out/'recovery/calls').glob('*.json') for x in [json.loads(p.read_text())]}
retried=[]
for audit in evidence['audits']:
 for retry in audit['retry_evidence']:
  if 'recovery_number' not in retry:continue
  new=newcalls[retry['recovery_number']]
  old=oldcalls[retry['original_numbers'][0]]
  assert not old.get('raw_response','').strip() and 'structured_retry_index' not in old
  assert new['requested_model']==old['requested_model'] and new['prompt_sha256']==old['prompt_sha256']
  assert new['max_tokens']==4096 and new['context']==old['context'] and new['stage']=='harness'
  retried.extend(retry['original_numbers'])
assert len(retried)==len(set(retried))
assert original['attempts']+len(newcalls)==recovered['attempts']<=1800
assert recovered['engine_hashes_after']==evidence['engine_hashes_before']
for row in recovered['rows']:
 old=next(x for x in original['rows'] if x['id']==row['id'])
 assert row['initial_exclusions']==old['exclusions']
result={'initial_attempts':original['attempts'],'recovery_attempts':len(newcalls),'combined_attempts':recovered['attempts'],
        'initial_complete':sum(x['complete'] for x in original['rows']),'recovered_complete':sum(x['complete'] for x in recovered['rows']),
        'replayed_audits':len(evidence['audits']),'completed_harness_audits':sum(x['replacement_state']=='completed' for x in evidence['audits']),
        'all_retry_prompts_models_exact':True,'only_empty_nonstructured_arms_retried':True,'no_original_call_retried_twice':True,
        'original_files_preserved':len(preserved),'frozen_engine_preserved':True,
        'nonempty_retries':sum(bool(x.get('raw_response','').strip()) for x in newcalls.values()),
        'retry_finish_reasons':dict(Counter(x.get('finish_reason') for x in newcalls.values())),
        'combined_usage':recovered['usage'],'recovery_usage':{k:sum(x.get('usage',{}).get(k) or 0 for x in newcalls.values()) for k in ['prompt_tokens','completion_tokens']},
        'unresolved':[{'id':r['id'],'exclusions':r['exclusions']} for r in recovered['rows'] if not r['complete']],
        'stop_reason':evidence['stop_reason'],'summary':recovered['summary']}
(out/'recovery/verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
