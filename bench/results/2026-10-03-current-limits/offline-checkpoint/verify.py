import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET
if __package__ in (None, ""):
    sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from bench.current_limits import (DEFAULT_OUTPUT, FROZEN, ROOT, read_json,
                                 sha, input_hashes, case_target, verify_inventory)
from bench.current_limits_charts import historical_telemetry, chart_data, load_competitors
root=DEFAULT_OUTPUT/'offline-checkpoint'
if not __debug__:
    raise SystemExit("Run this verifier without Python optimization")
plan=read_json(root/'plan-offline.json')
assert not plan['ready_for_live_review']
assert plan['runner_sha256']==sha((ROOT/'bench/current_limits.py').read_bytes())
assert plan['charts_sha256']==sha((ROOT/'bench/current_limits_charts.py').read_bytes())
engine_root=Path('/tmp/fugu-current-limits-base-engine')
engine_manifest=read_json(root/'engine-manifest.json')
assert engine_manifest==plan['engine']
assert len(engine_manifest['hashes'])==37
if engine_root.exists():
    verify_inventory(engine_root,engine_manifest)
assert [plan['preflight'][k] for k in ['context_count','unique_audit_count','semantic_primary_units']]==[54,45,63]
assert sha((FROZEN/'cases.json').read_bytes())==plan['frozen_case_manifest_sha256']
manifest=read_json(root/'synthetic-fixture/cases.json')
original=read_json(FROZEN/'cases.json')
assert manifest==original, 'portable fixture must keep the original fixed manifest'
assert len(manifest['cases'])==40
for case in manifest['cases']:
    assert input_hashes(case_target(case))==case['input_sha256']
hist=historical_telemetry()
assert hist==read_json(root/'historical-telemetry.json')
assert len(hist['source_sha256'])==1359
assert hist['usage']['attempts']==1355
assert hist['usage']['prompt_tokens_total']==611330
assert hist['usage']['completion_tokens_total']==437721
assert abs(hist['usage']['sum_request_duration_s']-2362.979)<1e-8
assert hist['exposure']['mount_omitted_unique_inputs']==5
assert hist['exposure']['red_truncated_unique_inputs']==10
fresh=read_json(root/'synthetic-fixture/fugu.json')
assert fresh['synthetic'] and fresh['measurement_status']=='NOT A BENCHMARK'
data=chart_data(fresh,manifest,load_competitors(manifest,FROZEN/'competitors'),historical_telemetry=hist)
assert data==read_json(root/'charts/chart-data.json')
assert data==read_json(root/'synthetic-chart-data.json')
fugu=data['comparison']['primary']['fugu']
assert [fugu[k] for k in ['attack_detected','attack_missed','attack_incomplete','attack_unattempted']]==[11,2,1,1]
assert fugu['attack_planned_rate']==11/15
assert fugu['pending_adjudication']==1 and fugu['confirmed_false_positives']==0
assert data['cost'] is None and data['usage']['prompt_tokens_total'] is None
assert data['coverage']['harness']['red_mounted_chars']['total'] is None
for name in ['common-results','cohort-coverage','call-telemetry','input-coverage']:
    svg=(root/'charts'/(name+'.svg')).read_text()
    ET.fromstring(svg)
    assert 'SYNTHETIC OFFLINE FIXTURE' in svg
    assert (root/'charts'/(name+'.png')).read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
assert not (DEFAULT_OUTPUT/'budget.json').exists()
# Documentation local links: ignore generated future-only filenames inside code blocks.
doc=(ROOT/'docs/benchmark-current-limits.md').read_text()
links=re.findall(r'\[[^\]]+\]\(([^)]+)\)',doc)
for link in links:
    if '://' not in link:
        assert (ROOT/'docs'/link).resolve().exists(), link
print(json.dumps({'artifact_checks':'pass','cases_checked':40,'preflight':[40,54,45,63],
    'frozen_python_hashes':37,'engine_bytes_checked':engine_root.exists(),
    'historical_source_hashes':1359,'plots_checked':4,
    'documentation_links_checked':len(links),'live_provider_requests':0,'target_executions':0}))
