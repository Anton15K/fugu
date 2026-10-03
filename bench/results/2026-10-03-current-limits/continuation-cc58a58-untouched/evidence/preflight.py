"""Authenticated zero-call source/input/preservation check before live bootstrap."""
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
ROOT = Path('/Users/antonkogun/dev/nebius_hack')
sys.path.insert(0,str(ROOT))
from bench import current_limits as base
from bench import current_limits_continuation as mod
SCRATCH=Path(__file__).parent
PREPARED=base.DEFAULT_OUTPUT/'continuation-offline/prepared-v3'
PLAN_HASH='ea8cff37184b4dd7efe06d3494643462298b398bebcb471d50ce0d6d76f32835'
BOOTSTRAP=Path('/tmp/fugu-current-limits-continuation-reviewed-bootstrap-v2.py')
assert base.sha(BOOTSTRAP.read_bytes())=='266592fe883c6a58c6671f9feff36b5a0be4d5ed4b680c494bfa58e6c2858cc6'
plan=mod.read_json(PREPARED/'plan.json')
release=mod.authenticate_release('qitem-20261003080043-770294f3',plan,PLAN_HASH)
review=mod.read_json(Path('/tmp/fugu-quality-continuation-binding-2b5e134.json'))
assert review['reviewed_commit']=='2b5e134f11ff4a1349d519dfaa2f0051c2012e1f'
assert len(review['paths'])==52
for item in review['paths']:
 p=base.ROOT/item['path'];mod._regular(p)
 assert base.sha(p.read_bytes())==item['sha256'],item['path']
engine=base.load_engine(Path('/tmp/fugu-continuation-engine-cc58a58'))
parent=mod.load_parent()
cases=mod.validate_plan(engine,plan,PREPARED,parent=parent)
assert (len(cases['cases']),len(engine.manifest['hashes']))==(27,37)
assert (plan['preflight']['context_count'],plan['preflight']['unique_audit_count'],plan['preflight']['semantic_primary_units'])==(41,32,50)
assert plan['worst_new_requests']==1316 and plan['worst_cumulative_requests']==1675
assert plan['phase_limits']=={'common20':280,'remainder':1036}
assert not mod.DEFAULT_CHILD.exists() or not any(mod.DEFAULT_CHILD.iterdir())
for p in [mod.DEFAULT_REGISTRY,mod.DEFAULT_REGISTRY.with_suffix('.lock'),mod.DEFAULT_REGISTRY.with_suffix('.guard.json')]:
 assert not p.exists() and not mod._has_symlink(p),'fresh ownership surface already exists'
original_count=copied_count=0
for entries,is_copy in [(parent.original['cases'],False),(cases['cases'],True)]:
 for c in entries:
  target=base.case_target(c) if is_copy else base.ROOT/c['target']
  assert base.input_hashes(target)==c['input_sha256']
  for p in target.rglob('*'):
   assert not p.is_symlink()
   if p.is_file():
    if is_copy:copied_count+=1
    else:original_count+=1
assert (original_count,copied_count)==(81,68)
for name,h in engine.manifest['hashes'].items():
 assert base.sha((base.ROOT/name).read_bytes())==h,name
prior=mod.read_json(Path('/tmp/fugu-r1-protected-before.json'))
paths={Path(item['path']) for item in prior['files']}
paths.update(base.ROOT/item['path'] for item in review['paths'] if item['path']!='docs/benchmark-current-limits-continuation.md')
paths.update(p for p in PREPARED.rglob('*') if p.is_file())
paths.update([BOOTSTRAP,Path('/tmp/fugu-current-limits-continuation-data-phase.md')])
owner=mod.read_json(Path('/tmp/fugu-current-limits-continuation-correction-preservation.json'))['owner']
assert len(owner)==3
for name,h in owner.items():
 assert base.sha((base.ROOT/name).read_bytes())==h,name
protected=[{'path':str(p),'sha256':base.sha(p.read_bytes())} for p in sorted(paths)]
result={'schema':2,'checked_utc':datetime.now(timezone.utc).isoformat(),'release_queue_ref':release.queue_ref,
 'release_binding':release.binding,'review_queue_ref':release.body['review_queue_ref'],'reviewed_commit':release.body['reviewed_commit'],
 'canonical_plan_sha256':PLAN_HASH,'plan_file_sha256':base.sha((PREPARED/'plan.json').read_bytes()),
 'bootstrap_sha256':base.sha(BOOTSTRAP.read_bytes()),'profile_sha256':plan['profile_sha256'],
 'reviewed_paths_verified':52,'parent_files_verified':403,'original_files_verified':81,'copied_files_verified':68,
 'engine_source_files_verified':37,'selected_case_ids':plan['selected_case_ids'],
 'context_count':41,'unique_audit_count':32,'semantic_units':50,'cache_reuses':9,
 'child_attempt_cap':1316,'cumulative_bound':1675,'cumulative_cap':1900,'child_phase_caps':plan['phase_limits'],
 'source_and_input_preflight_passed':True,'fresh_child_registry_lock_guard':True,
 'owner':[{'path':name,'sha256':h} for name,h in sorted(owner.items())],
 'protected':protected,'provider_requests':0,'credential_access':False,'target_executions':0,
 'script_sha256':base.sha(Path(__file__).read_bytes())}
base.write_json(SCRATCH/'preflight.json',result)
print(json.dumps({k:result[k] for k in result if k not in ['protected','owner','selected_case_ids']},indent=2))
