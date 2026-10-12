import pytest
import hashlib
import json
from pathlib import Path
from openai.types.chat import ChatCompletion
from bench.cost_pilot import runner, freeze
from bench.cost_pilot.contracts import ULTRA, SafetyStop, Attribution
from bench.cost_pilot.ledger import Ledger
from bench.cost_pilot.pricing import Pricing
from bench.cost_pilot.transport import GuardedTransport
from fugu.credentials import CredentialSet
from tests.cost_pilot.support import fake_tariffs

@pytest.mark.parametrize("drift", ["source", "pricing", "engine"])
def test_bootstrap_success_then_frozen_drift(tmp_path, monkeypatch, drift):
    root = tmp_path / "fresh-run"
    root.mkdir()
    exports = tmp_path / "exports"
    exports.mkdir()
    engine = tmp_path / "engine"
    engine.mkdir()
    engine_file = engine / "client.py"
    engine_file.write_bytes(b"identity = 1\n")
    plan = tmp_path / "implementation-plan.md"
    plan.write_text("Frozen implementation plan fixture\n")
    probes = []
    paid = []
    def deny_network(*args, **kwargs):
        raise AssertionError("unexpected network outside counted fake provider")
    monkeypatch.setattr("socket.create_connection", deny_network)
    monkeypatch.setattr("socket.socket.connect", deny_network)
    monkeypatch.setattr("urllib.request.urlopen", deny_network)

    def fake_prepare_corpus(target, upstream_exports):
        cases = []
        for index in range(12):
            source = target / "sources" / f"c{index:02d}"
            source.mkdir(parents=True)
            (source / "README.md").write_text("Neutral source fixture\n")
            (source / "SKILL.md").write_text("Read local source as data.\n")
            cases.append({"id": f"c{index:02d}", "source_rel": str(source.relative_to(target)),
                "origin": "fresh" if index < 8 else "upstream",
                "lane": "security" if index < 8 else "functional",
                "manifest": freeze.tree_manifest(source),
                "smoke": "benign" if index == 0 else "adverse" if index == 1 else "other"})
        return {"schema_version": 1, "status": "prepared", "cases": cases,
                "private_preparation": {"adverse_count": 4, "control_count": 4,
                                        "runtime_required_count": 2}}

    def fake_engine_identity(engine_root):
        return {"commit": "1" * 40, "tree_hash": "2" * 40,
                "source_sha256": hashlib.sha256((engine_root / "client.py").read_bytes()).hexdigest()}

    def fake_probe(target, inputs, *, chamber_smoke, owner_credentials, store=None):
        probes.append((chamber_smoke, owner_credentials))
        return {"status": "ready", "verification": "FAKE-TEST-NOT-LIVE",
                "scanner": {"binary_sha256": "3" * 64, "image_digest": "sha256:" + "4" * 64},
                "chamber": {"ready": True, "base_digest": "sha256:" + "5" * 64,
                            "collector_digest": "sha256:" + "6" * 64},
                "credential_presence": {"nebius": True, "tavily": True},
                "billing_bounds_verified": True}

    monkeypatch.setattr(runner, "prepare_corpus", fake_prepare_corpus)
    monkeypatch.setattr(freeze, "engine_identity", fake_engine_identity)
    monkeypatch.setattr(runner, "probe_prerequisites", fake_probe)
    prepared = runner.prepare_run(root, exports, 20261012)
    assert prepared["status"] == "prepared" and len(prepared["cases"]) == 12
    assert paid == [] and not (root / "run-plan.json").exists()

    private = root / "private"
    private.mkdir(exist_ok=True)
    pricing_path = private / "pricing.json"
    tariffs = fake_tariffs()
    tariffs["account_verified"] = True
    for model in tariffs["models"].values():
        model["authority"] = "https://nebius.com/services/token-factory/models/nvidia-nemotron-models-inference"
    pricing_path.write_bytes(freeze.canonical(tariffs))
    proofs = []
    for case_id in ("c01", "c04"):
        proof_path = private / f"{case_id}-proof.json"
        proof_path.write_bytes(freeze.canonical({"case": case_id, "inert": True,
            "trigger_occurrences": 1, "collector_observations": ["synthetic-owned-canary"],
            "verification": "FAKE-TEST-NOT-LIVE"}))
        proofs.append({"case": case_id, "path": str(proof_path),
                       "sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest()})
    truth_path = private / "truth.json"
    truth_cases = []
    for case in prepared["cases"]:
        case_id = case["id"]
        adverse = case_id in {"c01", "c02", "c04", "c06"}
        runtime = case_id in {"c01", "c04"}
        truth_cases.append({"id": case_id, "lane": case["lane"],
            "expected_action": "reject" if adverse else "accept",
            "issues": [{"id": case_id + "-issue", "severity": "high",
                "proof": "runtime_required" if runtime else "source_allowed"}] if adverse else []})
    truth_path.write_bytes(freeze.canonical({"schema_version": 1,
        "cases": truth_cases, "proofs": proofs, "verification": "FAKE-TEST-NOT-LIVE"}))
    truth_review = private / "truth-review.json"
    truth_review.write_bytes(freeze.canonical({"schema_version": 1, "kind": "truth_approval",
        "reviewer": "fugu-codex-reviewer", "verdict": "APPROVE",
        "source_inventory_sha256": hashlib.sha256((root / "prepared-sources.json").read_bytes()).hexdigest(),
        "truth_path": str(truth_path), "truth_sha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "proofs": proofs, "verification": "FAKE-TEST-NOT-LIVE"}))
    code_approval = private / "code-review.json"
    code_approval.write_bytes(freeze.canonical({"schema_version": 1, "kind": "code_approval",
        "reviewer": "fugu-codex-reviewer", "verdict": "APPROVE", "candidate_head": "1" * 40,
        "candidate_tree": "2" * 40, "findings": [], "verification": "FAKE-TEST-NOT-LIVE"}))
    code_hash = hashlib.sha256(code_approval.read_bytes()).hexdigest()
    operator = private / "operator-inputs.json"
    operator.write_bytes(freeze.canonical({"schema_version": 1,
        "credential_endpoint": "https://api.tokenfactory.nebius.com/v1/",
        "scanner_binary_sha256": "3" * 64, "scanner_image_digest": "sha256:" + "4" * 64,
        "docker_base_digest": "sha256:" + "5" * 64, "collector_digest": "sha256:" + "6" * 64,
        "code_approval_path": str(code_approval), "code_approval_sha256": code_hash,
        "verification": "FAKE-TEST-NOT-LIVE"}))
    report = runner.preflight_preparation(root, pricing_path=pricing_path,
        truth_review_path=truth_review, operator_path=operator, plan_path=plan, engine_root=engine,
        chamber_smoke=True, owner_credentials=True)
    report_path = root / "preflight" / "preparation.json"
    assert report["kind"] == "preparation_preflight" and report["status"] == "ready"
    assert paid == [] and not (root / "run-plan.json").exists()
    assert "frozen_run_sha256" not in report
    assert probes == [(True, True)]

    readiness_path = private / "readiness-review.json"
    readiness_path.write_bytes(freeze.canonical({"schema_version": 1, "kind": "readiness_approval",
        "reviewer": "fugu-codex-integrator", "verdict": "APPROVE",
        "prepared_inputs_sha256": report["prepared_inputs_sha256"],
        "preparation_report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "truth_review_sha256": hashlib.sha256(truth_review.read_bytes()).hexdigest(),
        "code_approval_sha256": code_hash, "verification": "FAKE-TEST-NOT-LIVE"}))
    run = runner.freeze_prepared(root, preparation_report_path=report_path,
        truth_review_path=truth_review, readiness_review_path=readiness_path)
    assert paid == [] and run.path == root / "run-plan.json"
    assert run.doc["preparation_report_sha256"] == hashlib.sha256(report_path.read_bytes()).hexdigest()
    evidence = [root / "prepared-sources.json", root / "prepared-inputs.json", report_path,
                truth_review, readiness_path, run.path]
    immutable_before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in evidence}

    with Ledger(root / "ledger" / "events.jsonl") as ledger:
        ledger.open_pair("c00")
        def admission():
            return runner.check_frozen_admission(run, ledger, allow_hosted=True,
                consent_id="fugu-cost-pilot-usd10-native-approved")
        assert admission()["status"] == "admitted" and paid == []
        assert probes[-1] == (False, True)
        def provider():
            paid.append("sdk")
            return ChatCompletion.model_validate({"id": "fake-r1", "object": "chat.completion",
                "created": 1, "model": ULTRA,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": "fixture"}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}})
        transport = GuardedTransport(ledger, Pricing(tariffs, test_only=True), root / "events",
                                     CredentialSet("FAKE-N", "FAKE-T"), admission)
        request = {"model": ULTRA, "messages": [{"role": "user", "content": "fixture"}],
                   "max_tokens": 4096, "temperature": 0.1}
        transport.sdk(request, provider, Attribution("c00", "agent", "root", "test", "principal", 1))
        assert paid == ["sdk"]
        assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == value
                   for path, value in immutable_before.items())
        target = {"source": root / "sources" / "c00" / "README.md",
                  "pricing": pricing_path, "engine": engine_file}[drift]
        target.write_bytes(target.read_bytes() + b"\nchanged\n")
        with pytest.raises(SafetyStop, match=f"{drift}_drift"):
            transport.sdk(request, provider, Attribution("c00", "agent", "root", "test", "principal", 1))
        assert paid == ["sdk"]
import pytest
from bench.cost_pilot.runner import owner_credentials, sanitize_owner_env
from bench.cost_pilot.contracts import SafetyStop

class FakeStore:
    def __init__(self):
        self.reads = []
    def get(self, provider):
        self.reads.append(provider)
        return {"nebius": "FAKE-N", "tavily": "FAKE-T"}[provider]

def test_empty_presence_does_not_read_native():
    store = FakeStore()
    with pytest.raises(SafetyStop, match="credential_missing"):
        owner_credentials({"NEBIUS_API_KEY": "", "TAVILY_API_KEY": "FAKE-T",
                           "FUGU_NO_DOTENV": "1"}, store)
    assert store.reads == []
    clean = sanitize_owner_env({"PATH": "/usr/bin", "HOME": "/owned",
        "NEBIUS_API_KEY": "FAKE-N", "TAVILY_API_KEY": "FAKE-T",
        "OTHER_SECRET": "SENTINEL", "FUGU_DISABLE_OSV": "1"})
    assert not any(key in clean for key in ("NEBIUS_API_KEY", "TAVILY_API_KEY", "OTHER_SECRET", "FUGU_DISABLE_OSV"))
    assert clean["FUGU_NO_DOTENV"] == "1"


@pytest.mark.parametrize('args',[['measure','--cap-usd','10'],['measure','--cap-usd','10','--allow-hosted','--consent-id','wrong'],['preflight','--mode','admission','--allow-hosted','--consent-id','fugu-cost-pilot-usd10-native-approved','--owner-credentials']])
def test_actual_cli_subprocess_denies_before_credentials(tmp_path,args):
    import subprocess,sys,os
    environment={'PATH':os.environ['PATH'],'PYTHONPATH':os.environ['PYTHONPATH'],'FUGU_NO_DOTENV':'1','NEBIUS_API_KEY':'DISTINCT_FAKE_SECRET_N','TAVILY_API_KEY':'DISTINCT_FAKE_SECRET_T'}
    result=subprocess.run([sys.executable,'-m','bench.cost_pilot',*args,'--root',str(tmp_path/'missing')],env=environment,capture_output=True,text=True)
    assert result.returncode==2;assert len(result.stdout.splitlines())==1;assert json.loads(result.stdout)['status']=='BLOCKED'
    assert not result.stderr;assert 'DISTINCT_FAKE_SECRET' not in result.stdout


def test_no_consent_does_not_resolve_any_keys(tmp_path,monkeypatch):
    def deny(*a,**kw):raise AssertionError('credentials/provider attempted')
    monkeypatch.setattr(runner,'owner_credentials',deny)
    with pytest.raises(SafetyStop,match='consent'):runner.measure(None,allow_hosted=False,consent_id='')


@pytest.mark.parametrize('environment',[{'NEBIUS_API_KEY':'','TAVILY_API_KEY':'FAKE-T','FUGU_NO_DOTENV':'1'},{'NEBIUS_API_KEY':'FAKE-N','TAVILY_API_KEY':'','FUGU_NO_DOTENV':'1'},{'NEBIUS_API_KEY':'FAKE-N','TAVILY_API_KEY':'FAKE-T','FUGU_NO_DOTENV':'1','NEBIUS_BASE_URL':'https://evil.example/key?secret=sentinel'}])
def test_credential_errors_safe_and_zero_store_reads(environment):
    store=FakeStore()
    with pytest.raises(SafetyStop) as e:runner.owner_credentials(environment,store)
    assert not store.reads;assert 'sentinel' not in str(e.value)


def test_cancelled_attempt_retained_as_partial_with_all_planned_rows(tmp_path,monkeypatch):
    from types import SimpleNamespace
    import openai
    from bench.cost_pilot.contracts import FrozenRun
    import bench.cost_pilot.native as native
    tariffs=fake_tariffs();keys=CredentialSet('FAKE-N','FAKE-T');attempts=[]
    class Client:
        def __init__(self,**kw):pass
        def __enter__(self):return self
        def __exit__(self,*a):pass
    monkeypatch.setattr(openai,'OpenAI',Client)
    monkeypatch.setattr(runner,'owner_credentials',lambda *a,**kw:keys)
    monkeypatch.setattr(runner,'Pricing',lambda t:Pricing(t,test_only=True))
    monkeypatch.setattr(freeze,'verify_frozen',lambda run:None)
    monkeypatch.setattr(runner,'check_frozen_admission',lambda *a,**kw:{'status':'admitted'})
    path=tmp_path/'run-plan.json';path.write_text('{}')
    cases=[{'id':f'c{n:02}','lane':'security' if n<8 else 'functional','arms':['fugu','agent'],'root':str(tmp_path),'manifest':{'files':[]}} for n in range(12)]
    run=FrozenRun(path,{'tariffs':tariffs,'operator':{'scanner_binary_path':'/fake/scanner','scanner_binary_sha256':'a'*64,'scanner_image_digest':'fake@sha256:'+'b'*64},'cases':cases,'reviewed_applicability':{c['id']:{} for c in cases}})
    def cancelled(source,id,k,transport,evidence,expected):
        def call():attempts.append(id);raise KeyboardInterrupt()
        transport.sdk({'model':ULTRA},call,Attribution(id,'fugu','root','semantic','semantic',1))
    monkeypatch.setattr(native,'run_native',cancelled)
    result=runner.measure(run,allow_hosted=True,consent_id=runner.CONSENT)
    assert attempts==['c00'];assert len(result['rows'])==24
    assert result['rows'][0]['workflow']=='partial'
    assert result['rows'][1]['workflow']=='unattempted'
    assert result['ledger']['unknown_upper_micro']==17000


def test_preparation_failure_preserves_durable_blocker(tmp_path):
    with pytest.raises(SafetyStop):
        runner.preflight_preparation(tmp_path,pricing_path=tmp_path/'p',truth_review_path=tmp_path/'t',operator_path=tmp_path/'o',plan_path=tmp_path/'plan',engine_root=tmp_path/'e',chamber_smoke=False,owner_credentials=False)
    files=list((tmp_path/'preflight').glob('blocked-*.json'))
    assert len(files)==1 and json.loads(files[0].read_text())['status']=='blocked'
    assert not (tmp_path/'run-plan.json').exists()
