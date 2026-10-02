"""Run pinned fuzzd binary isolated in Docker against frozen common packets."""
import json, subprocess, sys, hashlib, time
from pathlib import Path
ROOT=Path('/Users/antonkogun/dev/nebius_hack')
BIN=Path('/tmp/fugu-competitor-fuzzd/target/release/fuzzd')
IMAGE='rust:1-bookworm'

def main():
    manifest=json.loads(Path(sys.argv[1]).read_text())
    cases=manifest.get('cases',manifest) if isinstance(manifest,dict) else manifest
    output=Path(sys.argv[2]); rows=[]
    for case in cases:
        if 'description' not in case['cohort'] and 'mcptox' not in case['cohort'] and case['kind'] not in ['mcp','tool_description','description']:
            rows.append({'id':case['id'],'status':'unsupported','reason':'Static tool-description scanner does not support this cohort.'}); continue
        try:
            target=ROOT/case['target']
            files=list(target.rglob('*.json')) if target.is_dir() else [target]
            assert len(files)==1,('expected one frozen protocol packet',len(files))
            packet=files[0]; data=json.loads(packet.read_text())
            tools=data['tools'] if isinstance(data,dict) and 'tools' in data else data
            if isinstance(tools,dict): tools=[tools]
            assert len(tools)==1 and tools[0]['inputSchema']=={}, 'Expected frozen required empty schema'
            # Fuzzd accepts ListToolsResult or array; write unchanged original packet wrapped only if needed.
            bridge=Path('/tmp/fugu-competitor-fuzzd')/(case['id'].replace('/','_')+'.json')
            bridge.write_text(json.dumps({'tools':tools},ensure_ascii=False))
            command=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','-v',str(BIN)+':/usr/local/bin/fuzzd:ro','-v',str(bridge)+':/input/tools.json:ro',IMAGE,'/usr/local/bin/fuzzd','scan','--schema','/input/tools.json','--output','json']
            start=time.monotonic(); cp=subprocess.run(command,capture_output=True,text=True,timeout=60)
            raw=json.loads(cp.stdout)
            findings=[f for f in raw['findings'] if not f.get('suppressed')]
            row={'id':case['id'],'status':'completed','exit_code':cp.returncode,'flagged_medium':any(f['severity'].lower() in ['medium','high','critical'] for f in findings),'flagged_native':bool(findings),'elapsed_seconds':round(time.monotonic()-start,3),'packet_sha256':hashlib.sha256(packet.read_bytes()).hexdigest(),'result':raw,'stderr':cp.stderr}
        except Exception as exc:
            row={'id':case['id'],'status':'excluded_error','error':str(exc),'flagged_medium':None,'flagged_native':None}
        rows.append(row); print(case['id'],row['status'],flush=True)
        output.write_text(json.dumps({'tool':'fuzzd','source_commit':'f739e120cd7dc253fead2a1f13668f9535e4d8a5','version':'0.13.0','invocation':'fuzzd scan --schema /input/tools.json --output json; Docker network none, read-only, no privileges','adapter':'Original name/description with required uniform inputSchema={}; same frozen packet used by Fugu. Native any finding; common medium+ finding severity.','results':rows},indent=2))
    output.write_text(json.dumps({'tool':'fuzzd','source_commit':'f739e120cd7dc253fead2a1f13668f9535e4d8a5','version':'0.13.0','invocation':'fuzzd scan --schema /input/tools.json --output json; Docker network none, read-only, no privileges','adapter':'Original name/description with required uniform inputSchema={}; same frozen packet used by Fugu. Native any finding; common medium+ finding severity.','results':rows},indent=2))
if __name__=='__main__':main()
