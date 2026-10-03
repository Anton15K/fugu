"""Validate final bounded continuation evidence without provider requests."""
from collections import Counter
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
ROOT=Path('/Users/antonkogun/dev/nebius_hack')
sys.path.insert(0,str(ROOT))
from bench import current_limits as base
from bench import current_limits_continuation as mod
SCRATCH=Path(__file__).parent
out=mod.DEFAULT_CHILD
prepared=base.DEFAULT_OUTPUT/'continuation-offline/prepared-v3'
parent=mod.load_parent()
plan=mod.read_json(prepared/'plan.json')
ledger=mod.read_ledger(out,allow_orphans=True)
registry=mod.read_json(mod.DEFAULT_REGISTRY)
mod.validate_registry_ledger(registry,ledger,out,binding=base.hash_json(plan),parent_usage=parent.usage)
child=mod.read_json(out/'fugu.json')
combined=mod.read_json(out/'combined.json')
provenance=mod.read_json(out/'provenance.json')
assert not combined.get('synthetic')
assert combined['planned']==40 and child['planned']==27
assert child['binding']==base.hash_json(plan)
assert combined['rows'][:13]==parent.result['rows'][:13]
assert combined['rows'][13:]==child['rows']
assert [r['id'] for r in combined['rows']]==[c['id'] for c in parent.original['cases']]
assert combined['usage']['attempts']==359+ledger.state['attempts']
assert ledger.state['attempts']<=1316 and combined['usage']['attempts']<=1900
assert combined['usage']['prompt_tokens_total'] is None and combined['usage']['completion_tokens_total'] is None
assert combined['intervals'][0]['usage']==parent.usage
assert combined['intervals'][1]['usage']==child['usage']
assert combined['usage']['interval_stop_reasons']=={'parent':'provider_error','child':child['usage']['stop_reason']}
assert len(provenance['sdk_requests'])==combined['usage']['attempts']
qualified={(r['interval_id'],r['number']) for r in provenance['sdk_requests']}
assert len(qualified)==len(provenance['sdk_requests'])
assert all(r['max_tokens']==4096 and r['temperature']==0.1 for r in ledger.records if 'max_tokens' in r)
assert dict(Counter(r.get('phase') or 'unknown' for r in ledger.records))==ledger.usage['phase_attempts']
protected=mod.read_json(SCRATCH/'preflight.json')
changed=[item['path'] for item in protected['protected'] if base.sha(Path(item['path']).read_bytes())!=item['sha256']]
assert not changed,changed
assert all(base.sha((base.ROOT/item['path']).read_bytes())==item['sha256'] for item in protected['owner'])
phases={key:parent.usage['phase_attempts'].get(key,0)+registry['phase_attempts'].get(key,0) for key in mod.PARENT_PHASE_LIMITS}
assert all(value<=mod.PARENT_PHASE_LIMITS[key] for key,value in phases.items())
cohorts=[]
for name in dict.fromkeys(r['cohort'] for r in combined['rows']):
 rows=[r for r in combined['rows'] if r['cohort']==name]
 attacks=[r for r in rows if r['kind']=='malicious'];benign=[r for r in rows if r['kind']=='benign']
 cohorts.append({'cohort':name,'planned':len(rows),'complete':sum(r['complete'] for r in rows),
  'row_statuses':dict(Counter(r['status'] for r in rows)),
  'planned_attacks':len(attacks),'complete_attack_detections':sum(r['complete'] and r.get('detected') is True for r in attacks),
  'complete_attack_misses':[r['id'] for r in attacks if r['complete'] and r.get('detected') is False],
  'incomplete_attack_ids':[r['id'] for r in attacks if not r['complete']],
  'planned_benign':len(benign),'complete_benign':sum(r['complete'] for r in benign),
  'benign_detection_flag_ids':[r['id'] for r in benign if r.get('detected') is True],
  'benign_medium_finding_ids':[r['id'] for r in benign if r.get('raw_medium_flag') is True],
  'unavailable_detection_ids':[r['id'] for r in rows if r.get('detected') is None]})
errors=[{'number':r['number'],'phase':r['phase'],'requested_model':r.get('requested_model'),
         'error':r.get('error'),'usage':r['usage']} for r in ledger.records if r['state']=='error']
result={'schema':2,'checked_utc':datetime.now(timezone.utc).isoformat(),'data_release':'qitem-20261003080043-770294f3',
 'reviewed_commit':'2b5e134f11ff4a1349d519dfaa2f0051c2012e1f','child_plan_sha256':base.hash_json(plan),
 'models_requested':dict(Counter(r.get('requested_model') or 'unknown' for r in ledger.records)),
 'models_served':dict(Counter(r.get('served_model') or 'unknown' for r in ledger.records)),
 'finish_reasons':dict(Counter(r.get('finish_reason') or 'unknown' for r in ledger.records)),
 'child_row_statuses':dict(Counter(r['status'] for r in child['rows'])),
 'combined_row_statuses':dict(Counter(r['status'] for r in combined['rows'])),
 'child_usage':child['usage'],'combined_usage':combined['usage'],'cumulative_phase_attempts':phases,
 'child_provider_errors':errors,'coverage':combined['coverage'],'cohorts':cohorts,
 'benign_adjudication':combined['benign_adjudication'],
 'flag_count_semantics':'Chart/adjudication case flags follow detected under each cohort contract. raw_medium_flag also retains member findings in composition controls; those do not imply the expected composition rule hit.',
 'carried_parent_rows_preserved':13,'child_rows_preserved':27,'parent_sealed_files_preserved':403,
 'protected_files_preserved':len(protected['protected']),'owner_files_preserved':3,
 'whole_token_totals_known':False,'quota_remaining':'Not queried; no balance endpoint call authorized or made',
 'target_executions':0,'fresh_comparator_requests':0,'detector_tuned':False,
 'sdk_request_refs_qualified':len(qualified),'intervals':combined['intervals'],
 'sha256':[{'path':str((out/name).relative_to(base.ROOT)),'sha256':base.sha((out/name).read_bytes())} for name in ['fugu.json','combined.json','provenance.json','budget.json']],
 'script_sha256':base.sha(Path(__file__).read_bytes())}
base.write_json(SCRATCH/'analysis.json',result)
print(json.dumps({k:result[k] for k in ['child_row_statuses','combined_row_statuses','cohorts','child_provider_errors','cumulative_phase_attempts','parent_sealed_files_preserved','protected_files_preserved','owner_files_preserved']},indent=2))
