"""One safe JSON object per invocation; no implicit admission or fake mode."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .contracts import SafetyStop
from . import runner,freeze


class Parser(argparse.ArgumentParser):
    def error(self,message):raise SafetyStop('command_usage')


def main(argv=None):
    try:
        parser=Parser(prog='cost-pilot');commands=parser.add_subparsers(dest='command',required=True,parser_class=Parser)
        prepare=commands.add_parser('prepare');prepare.add_argument('--root',required=True,type=Path);prepare.add_argument('--upstream-dir',required=True,type=Path);prepare.add_argument('--seed',required=True,type=int)
        pre=commands.add_parser('preflight');pre.add_argument('--root',required=True,type=Path);pre.add_argument('--mode',required=True,choices=['preparation','admission'])
        for name in ('pricing','truth-review','operator-config','plan','engine-root'):pre.add_argument('--'+name,type=Path)
        pre.add_argument('--chamber-smoke',action='store_true');pre.add_argument('--owner-credentials',action='store_true')
        frozen=commands.add_parser('freeze');frozen.add_argument('--root',required=True,type=Path)
        for name in ('preparation-report','truth-review','readiness-review'):frozen.add_argument('--'+name,required=True,type=Path)
        measure=commands.add_parser('measure');measure.add_argument('--root',required=True,type=Path);measure.add_argument('--cap-usd',required=True,type=int,choices=[10]);measure.add_argument('--resume',action='store_true')
        for p in (pre,measure):p.add_argument('--allow-hosted',action='store_true');p.add_argument('--consent-id',default='')
        adjudicate=commands.add_parser('adjudicate');adjudicate.add_argument('--root',required=True,type=Path);adjudicate.add_argument('--review',required=True,type=Path)
        export=commands.add_parser('export');export.add_argument('--root',required=True,type=Path);export.add_argument('--output',required=True,type=Path)
        a=parser.parse_args(argv)
        if a.command=='prepare':result=runner.prepare_run(a.root,a.upstream_dir,a.seed)
        elif a.command=='preflight' and a.mode=='preparation':
            if any(getattr(a,k) is None for k in ('pricing','truth_review','operator_config','plan','engine_root')):raise SafetyStop('command_usage')
            result=runner.preflight_preparation(a.root,pricing_path=a.pricing,truth_review_path=a.truth_review,operator_path=a.operator_config,plan_path=a.plan,engine_root=a.engine_root,chamber_smoke=a.chamber_smoke,owner_credentials=a.owner_credentials)
        elif a.command=='freeze':result=runner.freeze_prepared(a.root,preparation_report_path=a.preparation_report,truth_review_path=a.truth_review,readiness_review_path=a.readiness_review).doc
        elif a.command in {'measure','preflight'}:
            runner._consent(a.allow_hosted,a.consent_id)
            run=freeze.load_frozen(a.root/'run-plan.json')
            if a.command=='measure':result=runner.measure(run,allow_hosted=a.allow_hosted,consent_id=a.consent_id,resume=a.resume)
            else:
                if not a.owner_credentials or a.chamber_smoke:raise SafetyStop('admission_mode_arguments')
                with runner.Ledger(a.root/'ledger/events.jsonl') as ledger:result=runner.check_frozen_admission(run,ledger,allow_hosted=a.allow_hosted,consent_id=a.consent_id)
        elif a.command=='adjudicate':
            from .adjudication import prepare_masked,load_adjudication
            run=freeze.load_frozen(a.root/'run-plan.json');masked=prepare_masked(run,a.root/'measurement.json')
            result=load_adjudication(a.review,masked,run)
            freeze.immutable_json(a.root/'adjudicated.json',result)
        else:
            from .report import export_report
            result={'status':'exported','report':str(export_report(a.root,a.output).markdown_path)}
        print(json.dumps({'status':result.get('status','written'),'artifact_root':str(a.root)}));return 0
    except SafetyStop as exc:print(json.dumps({'status':'BLOCKED','reason':exc.reason}));return 2
    except Exception:print(json.dumps({'status':'BLOCKED','reason':'unverified_input_or_prerequisite'}));return 2
