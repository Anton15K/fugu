"""Run pinned mcp-sec-audit on uniform, label-free description wrappers."""
import sys, json, tempfile, dataclasses, hashlib, time
from pathlib import Path
SOURCE = Path('/tmp/fugu-competitor-mcp-sec/detection')
sys.path.insert(0, str(SOURCE))
from detection.cli import _load_builtin_plugins
from detection.core.registry import DetectorRegistry
from detection.rules import load_rulebook
from detection.pipelines import run_static_pipeline

def main():
    manifest = json.loads(Path(sys.argv[1]).read_text())
    cases = manifest.get('cases', manifest) if isinstance(manifest, dict) else manifest
    root = Path('/Users/antonkogun/dev/nebius_hack')
    output = Path(sys.argv[2])
    registry = DetectorRegistry()
    _load_builtin_plugins(registry, load_rulebook(SOURCE/'detection/rules/keywords.toml'))
    rows = []
    for case in cases:
        target = root/case['target']
        if case['kind'] not in ['mcp', 'mcp_server', 'tool_description', 'description'] and 'description' not in case['cohort'] and 'mcptox' not in case['cohort'] and 'clean' not in case['cohort']:
            rows.append({'id':case['id'],'status':'unsupported','reason':'Outside common tool-description cohort for this comparison.'})
            continue
        try:
            files = list(target.rglob('*.json')) if target.is_dir() else [target]
            tools = []
            for path in files:
                data = json.loads(path.read_text())
                if isinstance(data,list): tools.extend(data)
                elif 'tools' in data: tools.extend(data['tools'])
                elif 'description' in data: tools.append(data)
            assert len(tools) == 1, ('expected one original tool',len(tools))
            tool = tools[0]
            start = time.monotonic()
            with tempfile.TemporaryDirectory(prefix='fugu-competitor-case-') as folder:
                folder=Path(folder)
                # Match the upstream metadata scanner contract; no labels, annotations or code.
                wrapper = {'tool_name':tool['name'],'tool_content':tool['description']}
                (folder/'tool.json').write_text(json.dumps(wrapper,ensure_ascii=False))
                result = run_static_pipeline(folder,registry,SOURCE/'detection/mitigation/policy_templates')
                raw=dataclasses.asdict(result)
            for f in raw['findings']:
                f['sources']=[str(x.value) if hasattr(x,'value') else str(x) for x in f['sources']]
                f['metadata']={}
                f['evidence']=[x.split(':',1)[-1] for x in f['evidence']]
            row={'id':case['id'],'status':'completed','flagged_medium':result.risk_level in ['medium','high','critical'],'flagged_native':bool(result.findings),'elapsed_seconds':round(time.monotonic()-start,3),'wrapper_sha256':hashlib.sha256(json.dumps(wrapper,ensure_ascii=False).encode()).hexdigest(),'result':raw}
        except Exception as exc:
            row={'id':case['id'],'status':'excluded_error','error':str(exc),'flagged_medium':None,'flagged_native':None}
        rows.append(row)
        print(case['id'],row['status'],flush=True)
        output.write_text(json.dumps({'tool':'mcp-sec-audit','source_commit':'457057a7dfda6b81622a12ee68b74f76f3fbde85','version':'0.1.0','adapter':'Original name->tool_name and description->tool_content. Native threshold any capability; common medium+ uses aggregate risk. No source execution.','results':rows},indent=2))
    output.write_text(json.dumps({'tool':'mcp-sec-audit','source_commit':'457057a7dfda6b81622a12ee68b74f76f3fbde85','version':'0.1.0','adapter':'Original name->tool_name and description->tool_content. Native threshold any capability; common medium+ uses aggregate risk. No source execution.','results':rows},indent=2))
if __name__=='__main__':main()
