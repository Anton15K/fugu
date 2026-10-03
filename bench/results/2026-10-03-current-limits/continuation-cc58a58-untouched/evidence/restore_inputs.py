"""Restore original benchmark inputs into scratch without touching accepted inputs."""
import copy,json
from pathlib import Path
import sys
ROOT=Path('/Users/antonkogun/dev/nebius_hack')
sys.path.insert(0,str(ROOT))
from bench import current_limits as base
scratch=Path(__file__).parent
original=base.read_json(base.FROZEN/'cases.json')
assert base.sha((base.FROZEN/'cases.json').read_bytes())==base.FIXED_CASE_MANIFEST_SHA256
before=[]
for c in original['cases']:
 target=base.ROOT/c['target']
 assert base.input_hashes(target)==c['input_sha256']
 before.extend({'path':str(p),'sha256':base.sha(p.read_bytes())} for p in target.rglob('*') if p.is_file())
output=(scratch/'portable-inputs-v2').resolve()
assert not output.exists(), 'preserve previous restoration proof'
copied=base.prepare_inputs(original,output,base.ROOT)
restored=copy.deepcopy(copied)
for c in restored['cases']:c['target']=c.pop('original_target')
assert restored==original
files=[]
for c in copied['cases']:
 target=base.case_target(c)
 assert base.input_hashes(target)==c['input_sha256']
 for p in target.rglob('*'):
  assert not p.is_symlink()
  if p.is_file():files.append({'path':str(p.relative_to(output)),'sha256':base.sha(p.read_bytes())})
assert len(files)==81 and len(copied['cases'])==40
assert all(base.sha(Path(r['path']).read_bytes())==r['sha256'] for r in before)
result={'schema':2,'original_manifest_sha256':base.FIXED_CASE_MANIFEST_SHA256,
 'restored_cases':40,'restored_regular_files':81,'original_fields_order_and_hashes_preserved':True,
 'sealed_inputs_rewritten':False,'provider_requests':0,'target_executions':0,
 'sha256':files,'script_sha256':base.sha(Path(__file__).read_bytes())}
base.write_json(scratch/'input-restoration.json',result)
print(json.dumps({k:result[k] for k in result if k!='sha256'},indent=2))
