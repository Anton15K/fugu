"""Passive observations around the unchanged canonical full product adapter."""
from __future__ import annotations
import copy
import importlib
import threading
import uuid
from collections import Counter
from contextlib import contextmanager,ExitStack
from dataclasses import asdict
from pathlib import Path
from .contracts import Attribution,ArmResult
from .freeze import immutable_json
from .transport import safe_artifact


def reconcile_native(report,observations,expected):
    out=copy.deepcopy(observations);selected=set(out.get('selected_paths',[]));files=set(expected.get('files',[]))
    if out.get('docker_results'):
        out['derived_triggers']=out.get('triggers',{})
        out['triggers']={}
        for chamber in out['docker_results']:
            out['triggers'].setdefault(chamber['member'],[]).extend(r['trigger'] for r in chamber['results'])
    out['unconsumed_paths']=sorted(files-selected)
    out['unconsumed_root_paths']=[p for p in out['unconsumed_paths'] if not any(p.startswith(m+'/') for m in expected.get('units',[]) if m!='root')]
    out['missing_units']=sorted(set(expected.get('units',[]))-set(out.get('units',[])))
    missing=[];unexpected=[]
    for member,triggers in expected.get('triggers',{}).items():
        actual=Counter(out.get('triggers',{}).get(member,[]));counts=Counter()
        for trigger in triggers:
            counts[trigger]+=1
            if counts[trigger]>actual[trigger]:missing.append({'member':member,'trigger':trigger,'occurrence':counts[trigger]})
        for trigger,n in (actual-Counter(triggers)).items():unexpected.append({'member':member,'trigger':trigger,'count':n})
    out['missing_trigger_occurrences']=missing;out['unexpected_trigger_occurrences']=unexpected
    stage_records=out.get('stage_records',[]);out['missing_stages']=[]
    for member in expected.get('units',[]):
        present={s['stage'] for s in stage_records if s['member']==member}
        out['missing_stages'].extend({'member':member,'stage':s} for s in expected.get('required_stages',[]) if s not in present)
    bad=[]
    for s in stage_records:
        m=s.get('metrics',{})
        if s.get('error') or not s.get('ok',False) or any(m.get(k) for k in ('skipped','coverage_incomplete','call_errors','rule_errors','omitted_units','skipped_large','skipped_unreadable','skipped_undecodable','skipped_max_files','skipped_binary','red_probes_omitted','trigger_results_missing','trigger_results_unexpected')):bad.append({'member':s['member'],'stage':s['stage'],'reason':'native_partial_or_failed'})
        if s['stage']=='harness' and m.get('static_probes')!=6:bad.append({'member':s['member'],'stage':'harness','reason':'six_static_probes_missing'})
    out['stage_coverage_failures']=bad
    out['incomplete']=bool(report.get('coverage',{}).get('incomplete',True) or report.get('exit_code',3) in {2,3,130} or report.get('audit_status')!='done' or out['unconsumed_paths'] or out['missing_units'] or missing or unexpected or out['missing_stages'] or bad)
    out['native_limits']={'semantic_chars_per_unit':6000,'harness_mount_chars':32000};out['osv_capability']='fugu_only';out['runtime_capability']='native_docker'
    return out


@contextmanager
def observe_native(transport,expected,evidence):
    import fugu.cli_audit as cli
    from fugu.detonation.docker_driver import DockerDriver
    import fugu.detonation.triggers as triggers_module
    from fugu.server.jobs import stage_public
    observations={'units':[],'selected_paths':[],'triggers':{},'stage_records':[],'file_selections':[],'docker_results':[]};mutex=threading.RLock()
    snapshot_id=expected.get('snapshot_id',transport.ledger.summary()['active_pair'])
    def member(target):return target.name if target.name in expected.get('units',[]) else 'root'
    def journal(kind,value):
        immutable_json(Path(evidence)/(kind+'-'+uuid.uuid4().hex+'.json'),safe_artifact(value,[transport.keys.nebius,transport.keys.tavily]))
    with ExitStack() as stack:
        def patch(obj,name,value):
            original=getattr(obj,name);setattr(obj,name,value);stack.callback(setattr,obj,name,original);return original
        original_build=cli._build_stages
        class StageObserver:
            def __init__(self,stage):self.stage=stage;self.name=stage.name
            def __getattr__(self,name):return getattr(self.stage,name)
            async def run(self,job,target):
                label=member(target);record={'member':label,'stage':self.name,'depth':job.depth,'ok':False,'metrics':{}}
                attr=Attribution(snapshot_id,'fugu',label,self.name,self.name,0)
                with transport.bind(attr):
                    journal('stage-start',record)
                    try:
                        result=await self.stage.run(job,target);record.update(stage_public(result));return result
                    except BaseException as exc:record['error']=type(exc).__name__;raise
                    finally:
                        with mutex:
                            if label not in observations['units']:observations['units'].append(label)
                            observations['stage_records'].append(record)
                        journal('stage-result',record)
        patch(cli,'_build_stages',lambda *a,**kw:[StageObserver(s) for s in original_build(*a,**kw)])
        for name in ('concealment','static_scan','semantic','harness','tool_surface','reputation'):
            module=importlib.import_module('fugu.pipeline.stages.'+name)
            if not hasattr(module,'collect_text_files'):continue
            original=module.collect_text_files
            def collect(target,*a,_original=original,_stage=name,**kw):
                result=_original(target,*a,**kw);files,metrics=result;label=member(Path(target));prefix='' if label=='root' else label+'/'
                paths=[prefix+f.rel for f in files];row={'member':label,'stage':_stage,'selected_paths':paths,'metrics':metrics,'selected_chars':sum(len(f.text) for f in files)}
                with mutex:
                    observations['file_selections'].append(row);observations['selected_paths']=sorted(set(observations['selected_paths'])|set(paths))
                journal('selection',row);return result
            patch(module,'collect_text_files',collect)
        original_derive=triggers_module.derive_triggers
        def derive(target,*a,**kw):
            result=original_derive(target,*a,**kw)
            with mutex:observations['triggers'][member(Path(target))]=list(result)
            return result
        patch(triggers_module,'derive_triggers',derive)
        original_detonate=DockerDriver.detonate
        async def detonate(driver,target,triggers,*a,**kw):
            rows=await original_detonate(driver,target,triggers,*a,**kw)
            value={'member':member(Path(target)),'selected_triggers':list(triggers),'results':[asdict(r) for r in rows],'collector_scope':'cumulative_per_chamber','dns_reply':'NXDOMAIN; attempt evidence','fs_changes':'paths, not file contents'}
            observations['docker_results'].append(value);journal('docker-result',value);return rows
        patch(DockerDriver,'detonate',detonate)
        with transport.native_scope(Attribution(snapshot_id,'fugu','root','native','native',0)):yield observations


def run_native(snapshot,snapshot_id,keys,transport,evidence,expected):
    from fugu.cli_audit import run_cli_audit
    expected={**expected,'snapshot_id':snapshot_id}
    with observe_native(transport,expected,evidence) as observed:
        raw=run_cli_audit(str(snapshot.resolve()),'full',keys,detonate=True)
    coverage=reconcile_native(raw,observed,expected)
    immutable_json(Path(evidence)/'native-report.json',safe_artifact(raw,[keys.nebius,keys.tavily]))
    immutable_json(Path(evidence)/'coverage.json',safe_artifact(coverage,[keys.nebius,keys.tavily]))
    return ArmResult(snapshot_id,'fugu','partial' if coverage['incomplete'] else 'complete',raw,coverage,Path(evidence))
