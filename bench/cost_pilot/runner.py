"""Owner-only acyclic preparation, independent approval and bounded measurement."""
from __future__ import annotations
import asyncio
import contextvars
import copy
import json
import os
import re
import subprocess
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from . import freeze
from .contracts import SafetyStop,SPEC_SHA256,PLAN_SHA256,ArmResult
from .corpus import prepare_corpus
from .ledger import Ledger
from .prompts import extract_prompts,prompt_hashes
from .pricing import Pricing
CONSENT='fugu-cost-pilot-usd10-native-approved'
SPEC=Path(__file__).resolve().parents[2]/'docs/superpowers/specs/2026-10-12-whole-system-cost-benchmark-design.md'
_CREDENTIALS=contextvars.ContextVar('cost_pilot_owner_credentials',default=None)


def _read(path):
    try:return json.loads(Path(path).read_bytes())
    except (OSError,ValueError):raise SafetyStop('artifact_missing_or_invalid') from None


def _ref(kind,path):return {'kind':kind,'path':str(Path(path).resolve()),'sha256':freeze.byte_hash(Path(path))}


def _approval(path,kind,reviewer):
    record=_read(path)
    if record.get('schema_version')!=1 or record.get('kind')!=kind or record.get('verdict')!='APPROVE' or record.get('reviewer')!=reviewer:raise SafetyStop(kind+'_missing_or_changes')
    return record


def owner_credentials(environ,store=None):
    if environ.get('FUGU_NO_DOTENV')!='1':raise SafetyStop('dotenv_isolation')
    if any(k in environ and not environ[k].strip() for k in ('NEBIUS_API_KEY','TAVILY_API_KEY')):raise SafetyStop('credential_missing')
    from fugu.credentials import NativeSecretStore,resolve_credentials
    try:keys=resolve_credentials(environ,store if store is not None else NativeSecretStore(),use_stored_tavily=True)
    except Exception:raise SafetyStop('credential_storage_or_endpoint') from None
    if not keys.nebius or not keys.tavily:raise SafetyStop('credential_missing')
    return keys


def sanitize_owner_env(environ):
    allowed={'PATH','HOME','TMPDIR','LANG','LC_ALL','PYTHONPATH','DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG','SSL_CERT_FILE','SSL_CERT_DIR'}
    result={k:v for k,v in environ.items() if k in allowed};result['FUGU_NO_DOTENV']='1';return result


@contextmanager
def _owner_environment(keys,operator):
    original=dict(os.environ);clean=sanitize_owner_env(original)
    clean.update({'FUGU_STATIC_RULES_BINARY':operator['scanner_binary_path'],'FUGU_STATIC_RULES_SHA256':operator['scanner_binary_sha256'],'FUGU_STATIC_RULES_IMAGE':operator['scanner_image_digest']})
    token=_CREDENTIALS.set(keys);os.environ.clear();os.environ.update(clean)
    try:yield
    finally:os.environ.clear();os.environ.update(original);_CREDENTIALS.reset(token)


def prepare_run(root,upstream_dir,seed):
    root=Path(root);upstream_dir=Path(upstream_dir)
    mapping={f'c{n:02}':upstream_dir/f'c{n:02}' for n in range(8,12) if (upstream_dir/f'c{n:02}').exists()}
    corpus=prepare_corpus(root,mapping)
    cases=[{**c,'root':c.get('root',str((root/c['source_rel']).resolve())),'smoke':'benign' if c['id']=='c00' else 'adverse' if c['id']=='c01' else 'other'} for c in corpus['cases']]
    prepared={**corpus,'schema_version':1,'kind':'prepared_sources','seed':seed,'root':str(root.resolve()),'status':'prepared' if len(cases)==12 else 'awaiting_exports','cases':freeze.pair_order(cases,seed)}
    freeze.immutable_json(root/'prepared-sources.json',prepared);return prepared


def _verify_refs(inputs):
    doc={'sources':inputs['sources'],'references':inputs['references'],'engine':inputs['engine'],'harness':inputs['harness']}
    freeze._verify_inputs(doc)


def preflight_preparation(root,*,pricing_path,truth_review_path,operator_path,plan_path,engine_root,chamber_smoke,owner_credentials,store=None):
    root=Path(root);prepared_path=root/'prepared-sources.json';prepared=_read(prepared_path)
    if prepared.get('kind')!='prepared_sources' or prepared.get('status')!='prepared' or len(prepared['cases'])!=12:raise SafetyStop('sources_incomplete')
    tr=_approval(truth_review_path,'truth_approval','fugu-codex-reviewer')
    if tr.get('source_inventory_sha256')!=freeze.byte_hash(prepared_path):raise SafetyStop('truth_source_mismatch')
    truth=_read(tr['truth_path'])
    if tr.get('truth_sha256')!=freeze.byte_hash(Path(tr['truth_path'])):raise SafetyStop('truth_drift')
    cases=truth.get('cases',[])
    if {c['id'] for c in cases}!={c['id'] for c in prepared['cases']} or len(cases)!=12:raise SafetyStop('truth_incomplete')
    fresh=[c for c in cases if int(c['id'][1:])<8]
    if sum(c.get('expected_action')=='reject' for c in fresh)!=4 or sum(c.get('expected_action')=='accept' for c in fresh)!=4 or sum(any(i.get('proof')=='runtime_required' for i in c.get('issues',[])) for c in fresh)<2:raise SafetyStop('truth_balance_or_runtime_proof')
    proofs=tr.get('proofs',[])
    if any(p['sha256']!=freeze.byte_hash(Path(p['path'])) for p in proofs):raise SafetyStop('truth_proof_drift')
    required={c['id'] for c in cases if any(i.get('proof')=='runtime_required' for i in c.get('issues',[]))}
    if not required<={p['case'] for p in proofs}:raise SafetyStop('runtime_proof_missing')
    operator=_read(operator_path);code=_approval(operator['code_approval_path'],'code_approval','fugu-codex-reviewer')
    if freeze.byte_hash(Path(operator['code_approval_path']))!=operator['code_approval_sha256']:raise SafetyStop('code_approval_drift')
    identity=freeze.engine_identity(Path(engine_root))
    if code.get('candidate_head')!=identity['commit'] or code.get('candidate_tree')!=identity['tree_hash'] or code.get('findings'):raise SafetyStop('unreviewed_engine')
    prompts=extract_prompts(SPEC)
    refs=[_ref('source_inventory',prepared_path),_ref('pricing',pricing_path),_ref('truth',tr['truth_path']),_ref('approval',truth_review_path),_ref('operator',operator_path),_ref('approval',operator['code_approval_path']),_ref('spec',SPEC),_ref('plan',plan_path)]
    refs.extend(_ref('truth',p['path']) for p in proofs)
    sources=[{'root':c['root'],'manifest':c['manifest']} for c in prepared['cases']]
    # Registry schema is source-independent, but derive from an actual source.
    from .tools import ToolRegistry
    schema_tools=ToolRegistry(Path(sources[0]['root']),'schema',sources[0]['manifest']['sha256'],root/'schema-tools',lambda q:(_ for _ in ()).throw(SafetyStop('schema_web_forbidden')))
    inputs={'schema_version':1,'kind':'prepared_inputs','run_id':root.name,'root':str(root.resolve()),'seed':prepared['seed'],'cap_micro':10000000,'arm_cap_micro':2000000,'pair_cap_micro':4000000,'cases':prepared['cases'],'sources':sources,'references':refs,'pricing_path':str(Path(pricing_path).resolve()),'tariffs':_read(pricing_path),'operator':operator,'truth_review_path':str(Path(truth_review_path).resolve()),'truth_review_sha256':freeze.byte_hash(Path(truth_review_path)),'code_approval_sha256':operator['code_approval_sha256'],'engine':{'root':str(Path(engine_root).resolve()),'identity':identity},'harness':{'root':str(Path(engine_root).resolve()),'identity':identity},'spec_hash':freeze.byte_hash(SPEC),'implementation_plan_hash':freeze.byte_hash(Path(plan_path)),'prompt_hashes':prompt_hashes(prompts),'tool_schema_hash':freeze.digest(schema_tools.schemas()),'result_schema_hash':freeze.digest(prompts['report_contract']),'credential_endpoint':operator['credential_endpoint'],'reviewed_applicability':{c['id']:c.get('applicability',{}) for c in cases},'timing_policy':'monotonic arm walltime; shared preflight/setup separately','baseline_capabilities':['list_files','read_file','search_files','search_web']}
    _verify_refs(inputs)
    freeze.immutable_json(root/'prepared-inputs.json',inputs)
    checks=probe_prerequisites(root,inputs,chamber_smoke=chamber_smoke,owner_credentials=owner_credentials,store=store)
    report={'schema_version':1,'kind':'preparation_preflight','status':checks['status'],'prepared_inputs_path':str((root/'prepared-inputs.json').resolve()),'prepared_inputs_sha256':freeze.byte_hash(root/'prepared-inputs.json'),'checks':checks,'created_unix':time.time()}
    freeze.immutable_json(root/'preflight/preparation.json',report)
    return report


def freeze_prepared(root,*,preparation_report_path,truth_review_path,readiness_review_path):
    root=Path(root);report=_read(preparation_report_path)
    if report.get('kind')!='preparation_preflight' or report.get('status')!='ready':raise SafetyStop('preparation_not_ready')
    inputs=_read(report['prepared_inputs_path'])
    if report['prepared_inputs_sha256']!=freeze.byte_hash(Path(report['prepared_inputs_path'])):raise SafetyStop('prepared_inputs_drift')
    ready=_approval(readiness_review_path,'readiness_approval','fugu-codex-integrator')
    _approval(truth_review_path,'truth_approval','fugu-codex-reviewer')
    hashes={'prepared_inputs_sha256':report['prepared_inputs_sha256'],'preparation_report_sha256':freeze.byte_hash(Path(preparation_report_path)),'truth_review_sha256':freeze.byte_hash(Path(truth_review_path)),'code_approval_sha256':inputs['code_approval_sha256']}
    if any(ready.get(k)!=v for k,v in hashes.items()) or inputs['truth_review_sha256']!=hashes['truth_review_sha256']:raise SafetyStop('readiness_binding')
    _verify_refs(inputs)
    doc={**inputs,**hashes,'kind':'frozen_run','preparation_report_path':str(Path(preparation_report_path).resolve()),'preparation_checks':report['checks']}
    if report['checks'].get('smoke_sha256'):
        if freeze.byte_hash(root/'preflight/chamber-smoke.json')!=report['checks']['smoke_sha256']:raise SafetyStop('chamber_smoke_drift')
        inputs['references']=inputs['references']+[_ref('chamber_smoke',root/'preflight/chamber-smoke.json')]
    doc['references']=inputs['references']+[_ref('prepared_inputs',report['prepared_inputs_path']),_ref('preparation_report',preparation_report_path),_ref('approval',readiness_review_path)]
    return freeze.freeze_run(root/'run-plan.json',doc)


def _consent(allow_hosted,consent_id):
    if allow_hosted is not True or consent_id!=CONSENT:raise SafetyStop('hosted_consent_required')


def check_frozen_admission(run,ledger,*,allow_hosted,consent_id,store=None):
    _consent(allow_hosted,consent_id);ledger.assert_admitted();freeze.verify_frozen(run)
    if ledger.cap!=run.doc['cap_micro'] or ledger.arm_cap!=run.doc['arm_cap_micro']:raise SafetyStop('caps')
    checks=probe_prerequisites(run.path.parent,run.doc,chamber_smoke=False,owner_credentials=True,store=store)
    if checks.get('status')!='ready':raise SafetyStop('prerequisites_blocked')
    original=run.doc['preparation_checks']
    if any(checks.get(k)!=original.get(k) for k in ('scanner','chamber','credential_presence','smoke_sha256')):raise SafetyStop('prerequisite_identity_drift')
    record={'schema_version':1,'kind':'frozen_admission','status':'admitted','frozen_run_sha256':freeze.byte_hash(run.path),'checks':checks,'consent_id':consent_id,'owner':'exclusive-posix-ledger','created_unix':time.time()}
    freeze.immutable_json(run.path.parent/'admission'/(uuid.uuid4().hex+'.json'),record);return record


def _docker_read(args,environment):
    try:
        result=subprocess.run(['docker',*args],env=environment,capture_output=True,text=True,timeout=30,check=True)
        return result.stdout
    except Exception:raise SafetyStop('docker_prerequisite') from None


def probe_prerequisites(root,inputs,*,chamber_smoke,owner_credentials,store=None):
    """Real unpaid boundary; test fixtures replace this function, never its caller."""
    operator=inputs['operator'];tariffs=inputs['tariffs'];Pricing(tariffs)
    if inputs['spec_hash']!=SPEC_SHA256 or inputs['implementation_plan_hash']!=PLAN_SHA256:raise SafetyStop('approved_document_drift')
    for ref in inputs['references']:
        value=_read(ref['path']) if ref['kind'] in {'approval','truth','operator'} else {}
        if 'FAKE' in value.get('verification',''):raise SafetyStop('unverified_provenance')
    if not owner_credentials:raise SafetyStop('owner_credentials_not_authorized')
    keys=_CREDENTIALS.get() or globals()['owner_credentials'](os.environ,store)
    if keys.base_url!=operator['credential_endpoint'] or tariffs.get('endpoint')!=keys.base_url:raise SafetyStop('endpoint_mismatch')
    clean=sanitize_owner_env(os.environ)
    if clean.get('DOCKER_HOST','').startswith(('tcp:','ssh:')):raise SafetyStop('unreviewed_docker_host')
    config=Path(clean.get('DOCKER_CONFIG',str(Path(clean.get('HOME',''))/'.docker')))/'config.json'
    if config.exists():
        doc=_read(config)
        if any(doc.get(k) for k in ('credsStore','credHelpers','proxies','auths')):raise SafetyStop('docker_auth_or_proxy_route')
    binary=Path(operator.get('scanner_binary_path',''))
    if not binary.is_file() or any(binary.resolve().is_relative_to(Path(s['root']).resolve()) for s in inputs['sources']) or freeze.byte_hash(binary)!=operator['scanner_binary_sha256']:raise SafetyStop('scanner_identity')
    image=operator['scanner_image_digest']
    if not re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}',image):raise SafetyStop('scanner_image_unpinned')
    _docker_read(['version','--format','{{json .Server}}'],clean);_docker_read(['buildx','version'],clean)
    identities={}
    for label,tag,expected in [('scanner',image,image.split('@')[1]),('base','python:3.11-slim',operator['docker_base_digest']),('collector','mitmproxy/mitmproxy:latest',operator['collector_digest'])]:
        inspect=json.loads(_docker_read(['image','inspect',tag],clean))
        if len(inspect)!=1 or not any(d.endswith(expected) for d in inspect[0].get('RepoDigests',[])):raise SafetyStop('docker_image_drift')
        identities[label]=expected
    smoke_path=Path(root)/'preflight/chamber-smoke.json'
    if chamber_smoke:
        if operator.get('native_approval_state')!='human_resolved':raise SafetyStop('native_build_approval_unresolved')
        from fugu.detonation.docker_driver import DockerDriver
        source=Path(root)/'preflight/owned-smoke';source.mkdir(parents=True)
        (source/'main.py').write_text('print("owned inert smoke")\n')
        with _owner_environment(keys,operator):rows=asyncio.run(DockerDriver().detonate(source,['python main.py']))
        if len(rows)!=1 or rows[0].exit_code!=0:raise SafetyStop('native_chamber_smoke_failed')
        freeze.immutable_json(smoke_path,{'kind':'native_chamber_smoke','results':[asdict(r) for r in rows],'identities':identities,'cleanup':'native driver finally returned','verification':'actual_owned_inert_native_docker'})
    else:
        # Reuse smoke evidence; admission never builds or executes a target.
        smoke=_read(smoke_path)
        if smoke.get('verification')!='actual_owned_inert_native_docker' or smoke.get('identities')!=identities or not smoke.get('results') or smoke['results'][0]['exit_code']!=0:raise SafetyStop('chamber_smoke_missing_or_drift')
    return {'status':'ready','scanner':{'binary_sha256':operator['scanner_binary_sha256'],'image_digest':image},'chamber':{'ready':True,'base_digest':operator['docker_base_digest'],'collector_digest':operator['collector_digest']},'credential_presence':{'nebius':True,'tavily':True},'billing_bounds_verified':True,'smoke_sha256':freeze.byte_hash(smoke_path)}


def measure(run,*,allow_hosted,consent_id,resume=False):
    _consent(allow_hosted,consent_id);freeze.verify_frozen(run);root=run.path.parent
    if (root/'measurement.json').exists():raise SafetyStop('measurement_already_terminal')
    if (root/'measurement-start.json').exists() and not resume:raise SafetyStop('explicit_resume_required')
    keys=owner_credentials(os.environ);pricing=Pricing(run.doc['tariffs']);prompts=extract_prompts(SPEC);results=[];stop=None
    from .transport import GuardedTransport
    from .tools import ToolRegistry
    from .native import run_native
    from .agent import run_agent
    from openai import OpenAI,DefaultHttpxClient
    if not (root/'measurement-start.json').exists():freeze.immutable_json(root/'measurement-start.json',{'run_sha256':freeze.byte_hash(run.path),'started_unix':time.time()})
    with _owner_environment(keys,run.doc['operator']),Ledger(root/'ledger/events.jsonl') as ledger:
        try:
            check_frozen_admission(run,ledger,allow_hosted=allow_hosted,consent_id=consent_id)
            if resume and ledger.summary()['active_pair']:raise SafetyStop('unfinished_pair_no_redispatch')
            transport=GuardedTransport(ledger,pricing,root/'requests',keys,lambda:check_frozen_admission(run,ledger,allow_hosted=allow_hosted,consent_id=consent_id))
            with _resource_guards(run,ledger),OpenAI(api_key=keys.nebius,base_url=keys.base_url,max_retries=0,timeout=90,http_client=DefaultHttpxClient(timeout=90,follow_redirects=False,trust_env=False)) as client:
                closed={e['pair'] for e in ledger.events() if e['kind']=='close'}
                for case in run.doc['cases']:
                    if case['id'] in closed:continue
                    ledger.open_pair(case['id']);started=time.monotonic()
                    try:
                        for arm in case['arms']:
                            ledger.assert_admitted();path=root/'arms'/case['id']/arm
                            freeze.immutable_json(path/'attempt.json',{'case':case['id'],'arm':arm,'started_unix':time.time()})
                            if arm=='fugu':
                                expected={'files':[f['path'] for f in case['manifest']['files']],**run.doc['reviewed_applicability'][case['id']]}
                                result=run_native(Path(case['root']),case['id'],keys,transport,path,expected)
                            else:
                                tools=ToolRegistry(Path(case['root']),case['id'],case['manifest']['sha256'],path/'tools',lambda q:transport.tavily(q,__import__('bench.cost_pilot.contracts',fromlist=['Attribution']).Attribution(case['id'],'agent','root','web','agent',0)))
                                result=run_agent(case['id'],case['lane'],tools,transport,client,prompts,path)
                            record={**asdict(result),'evidence_path':str(result.evidence_path),'lane':case['lane'],'seconds':time.monotonic()-started}
                            freeze.immutable_json(path/'arm-result.json',record);results.append(record);ledger.assert_admitted()
                    finally:ledger.close_pair(case['id'],'terminal')
        except BaseException as exc:stop=exc.reason if isinstance(exc,SafetyStop) else 'measurement_interrupted_or_failed'
        summary=ledger.summary()
    existing=[]
    for case in run.doc['cases']:
        for arm in case['arms']:
            path=root/'arms'/case['id']/arm/'arm-result.json'
            if path.exists():existing.append(_read(path))
            else:
                attempted=(path.parent/'attempt.json').exists()
                existing.append({'snapshot_id':case['id'],'arm':arm,'lane':case['lane'],'workflow':'partial' if attempted else 'unattempted','raw':{'stop':stop} if attempted else {},'coverage':{'incomplete':True} if attempted else {},'evidence_path':str(path.parent) if attempted else None,'seconds':None})
    record={'schema_version':1,'kind':'measurement','status':'stopped' if stop else 'terminal','stop':stop,'rows':existing,'ledger':summary,'run_sha256':freeze.byte_hash(run.path),'label':'actual owner measurement; dollar estimates require validated usage','planned_cases':12}
    freeze.immutable_json(root/'measurement.json',record);return record


@contextmanager
def _resource_guards(run,ledger):
    """Recheck pinned native build/run inputs; cleanup remains unconditional."""
    from fugu.detonation.docker_driver import DockerDriver
    original=DockerDriver._run
    async def guarded(driver,args,*a,**kw):
        if args and args[0] in {'build','run'}:
            check_frozen_admission(run,ledger,allow_hosted=True,consent_id=CONSENT)
        return await original(driver,args,*a,**kw)
    DockerDriver._run=guarded
    try:yield
    finally:DockerDriver._run=original
