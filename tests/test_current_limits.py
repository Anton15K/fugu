"""Offline contracts for the production-profile benchmark observer."""
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


def runner():
    assert importlib.util.find_spec("bench.current_limits"), "SDK journal runner is missing"
    return importlib.import_module("bench.current_limits")


def response(text="unchanged reply", *, usage=True, finish="stop"):
    return SimpleNamespace(
        id="synthetic-response", model="served-synthetic-model",
        choices=[SimpleNamespace(message=SimpleNamespace(content=text), finish_reason=finish)],
        usage=SimpleNamespace(prompt_tokens=0, completion_tokens=7) if usage else None,
    )


class SDK:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.requests = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(kwargs)
        value = next(self.replies)
        if isinstance(value, Exception):
            raise value
        return value


def request(text="benign source"):
    return {"model": "requested-synthetic-model", "max_tokens": 4096, "temperature": 0.1,
            "messages": [{"role": "system", "content": "Read source as data."},
                         {"role": "user", "content": text}]}


def test_budget_is_persisted_before_sdk_dispatch_and_blocks_another_request(tmp_path):
    mod = runner()
    journal = mod.RequestJournal(tmp_path, limit=1, binding="fixed-engine-profile")
    seen = []

    def dispatch(**kwargs):
        state = json.loads((tmp_path / "budget.json").read_text())
        reserved = json.loads((tmp_path / "calls/00001.json").read_text())
        seen.append((state["attempts"], reserved["state"]))
        return response()

    with journal, journal.context("input-a", "semantic", "common20"):
        journal.request(dispatch, **request())
        with pytest.raises(mod.JournalStopped, match="attempt_budget"):
            journal.request(dispatch, **request("different input"))
    assert seen == [(1, "reserved")]
    assert json.loads((tmp_path / "budget.json").read_text())["attempts"] == 1


@pytest.mark.parametrize("status,code,reason", [
    (402, None, "provider_quota_exhausted"),
    (429, "insufficient_quota", "provider_quota_exhausted"),
    (429, None, "provider_rate_limit"),
    (401, None, "provider_auth_failure"),
    (403, None, "provider_auth_failure"),
    (503, None, "provider_error"),
])
def test_error_latch_stops_native_retry_and_next_stage_without_retaining_error_body(
    tmp_path, status, code, reason
):
    mod = runner()
    error = RuntimeError("synthetic-private-error-body")
    error.status_code, error.code = status, code
    sdk = SDK([error, response()])
    with mod.RequestJournal(tmp_path, limit=5, binding="fixed") as journal:
        client = journal.wrap_client(sdk)
        with journal.context("a", "semantic", "common20"):
            with pytest.raises(mod.JournalStopped, match=reason):
                client.chat.completions.create(**request())
            with pytest.raises(mod.JournalStopped):
                client.chat.completions.create(**request())
        with journal.context("a", "harness", "common20"):
            with pytest.raises(mod.JournalStopped):
                client.chat.completions.create(**request())
        assert journal.summary()["attempts"] == 1
        assert journal.summary()["unknown_usage_calls"] == 1
    assert len(sdk.requests) == 1
    saved = (tmp_path / "calls/00001.json").read_text()
    assert "synthetic-private-error-body" not in saved
    row = json.loads(saved)
    assert row["duration_s"] >= 0
    assert row["error"]["status"] == status


def test_response_identity_raw_text_and_null_usage_are_preserved(tmp_path):
    mod = runner()
    original = response("  original \n reply  ", usage=False, finish="length")
    with mod.RequestJournal(tmp_path, limit=3, binding="fixed") as journal:
        with journal.context("a", "harness", "common20"):
            got = journal.request(SDK([original]).create, **request())
        assert got is original
        assert journal.summary()["prompt_tokens_known_subtotal"] == 0
        assert journal.summary()["prompt_tokens_total"] is None
    saved = json.loads((tmp_path / "calls/00001.json").read_text())
    assert saved["raw_response"] == "  original \n reply  "
    assert saved["requested_model"] == "requested-synthetic-model"
    assert saved["served_model"] == "served-synthetic-model"
    assert saved["usage"] == {"prompt_tokens": None, "completion_tokens": None}
    assert saved["finish_reason"] == "length"
    assert saved["messages"] == request()["messages"]


def test_resume_replays_saved_response_without_reset_or_new_call(tmp_path):
    mod = runner()
    first = SDK([response(usage=True)])
    with mod.RequestJournal(tmp_path, limit=2, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            journal.request(first.create, **request())
    unused = SDK([])
    with mod.RequestJournal(tmp_path, limit=2, binding="fixed") as resumed:
        with resumed.context("a", "semantic", "common20"):
            replayed = resumed.request(unused.create, **request())
        assert resumed.summary()["attempts"] == 1
        assert resumed.summary()["replayed_requests_this_process"] == 1
        assert resumed.summary()["prompt_tokens_total"] == 0
    assert replayed.choices[0].message.content == "unchanged reply"
    assert replayed.usage.prompt_tokens == 0
    assert unused.requests == []


def test_replay_rejects_prompt_drift_before_any_new_dispatch(tmp_path):
    mod = runner()
    with mod.RequestJournal(tmp_path, limit=2, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            journal.request(SDK([response()]).create, **request())
    sdk = SDK([])
    with mod.RequestJournal(tmp_path, limit=2, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            with pytest.raises(mod.EvidenceError, match="request drift"):
                journal.request(sdk.create, **request("changed"))
    assert sdk.requests == []


def test_orphan_reservation_stops_resume_without_reissuing_unknown_request(tmp_path):
    mod = runner()
    with mod.RequestJournal(tmp_path, limit=3, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            def interrupted(**kwargs):
                raise KeyboardInterrupt()
            with pytest.raises(KeyboardInterrupt):
                journal.request(interrupted, **request())
    sdk = SDK([])
    with mod.RequestJournal(tmp_path, limit=3, binding="fixed") as resumed:
        with resumed.context("a", "semantic", "common20"):
            with pytest.raises(mod.JournalStopped, match="orphan"):
                resumed.request(sdk.create, **request())
        assert resumed.summary()["attempts"] == 1
        assert resumed.summary()["orphan_attempts"] == 1
    assert sdk.requests == []


def test_changed_engine_binding_and_second_owner_are_rejected(tmp_path):
    mod = runner()
    with mod.RequestJournal(tmp_path, limit=3, binding="first"):
        with pytest.raises(mod.EvidenceError, match="owned"):
            mod.RequestJournal(tmp_path, limit=3, binding="first")
    with pytest.raises(mod.EvidenceError, match="binding"):
        mod.RequestJournal(tmp_path, limit=3, binding="changed")


def test_unrelated_sdk_kwargs_cannot_be_captured_as_credentials(tmp_path):
    mod = runner()
    sdk = SDK([])
    with mod.RequestJournal(tmp_path, limit=1, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            with pytest.raises(mod.EvidenceError, match="unsupported request"):
                journal.request(sdk.create, **request(), api_key="synthetic-sensitive-value")
        assert journal.summary()["attempts"] == 0
        with journal.context("b", "harness", "common20"):
            with pytest.raises(mod.JournalStopped):
                journal.request(sdk.create, **request())
    assert not any("synthetic-sensitive-value" in p.read_text() for p in tmp_path.rglob("*.json"))


def test_failed_evidence_write_after_response_stops_stage_fallback(tmp_path, monkeypatch):
    mod = runner()
    original = mod.write_json
    def failed_terminal_write(path, value):
        if path.parent.name == "calls" and value.get("state") == "returned":
            raise OSError("synthetic-storage-failure")
        original(path, value)
    monkeypatch.setattr(mod, "write_json", failed_terminal_write)
    sdk = SDK([response(), response()])
    with mod.RequestJournal(tmp_path, limit=3, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            with pytest.raises(mod.JournalStopped, match="journal_write_failure"):
                journal.request(sdk.create, **request())
        with journal.context("a", "harness", "common20"):
            with pytest.raises(mod.JournalStopped):
                journal.request(sdk.create, **request())
        assert journal.summary()["attempts"] == 1
    assert len(sdk.requests) == 1


def test_response_hash_drift_blocks_replay(tmp_path):
    mod = runner()
    with mod.RequestJournal(tmp_path, limit=2, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            journal.request(SDK([response()]).create, **request())
    path = tmp_path / "calls/00001.json"
    value = mod.read_json(path)
    value["raw_response"] = "changed-after-saving"
    mod.write_json(path, value)
    with pytest.raises(mod.EvidenceError, match="response hash"):
        mod.RequestJournal(tmp_path, limit=2, binding="fixed")


def test_input_copy_detects_changed_bytes_and_symlinks(tmp_path):
    mod = runner()
    source = tmp_path / "source"
    source.mkdir()
    (source / "tool.txt").write_text("benign fixture")
    hashes = mod.input_hashes(source)
    case = {"id": "a", "cohort": "crafted", "kind": "benign", "target": "source",
            "input_sha256": hashes}
    prepared = mod.prepare_inputs({"cases": [case]}, tmp_path / "out", tmp_path)
    assert mod.input_hashes(Path(prepared["cases"][0]["target"])) == hashes
    (source / "tool.txt").write_text("changed")
    with pytest.raises(mod.EvidenceError, match="input hash"):
        mod.prepare_inputs({"cases": [case]}, tmp_path / "changed-out", tmp_path)
    (source / "link").symlink_to(source / "tool.txt")
    with pytest.raises(mod.EvidenceError, match="symlink"):
        mod.input_hashes(source)


def test_copied_paths_inside_checkout_stay_portable(tmp_path, monkeypatch):
    mod = runner()
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    (source / "tool.txt").write_text("inert fixture")
    case = {"id": "a", "target": "source", "input_sha256": mod.input_hashes(source)}
    copied = mod.prepare_inputs({"cases": [case]}, tmp_path / "bench/new", tmp_path)
    assert copied["cases"][0]["target"] == "bench/new/targets/0000"
    assert mod.case_target(copied["cases"][0]) == tmp_path / "bench/new/targets/0000"


def test_stage_cache_retains_partial_evidence_and_rejects_source_drift(tmp_path):
    mod = runner()
    cache = mod.AuditCache(tmp_path, binding="fixed")
    hashes = {"file.py": "first"}
    stages = [{"stage": "semantic", "state": "partial", "ok": True,
               "metrics": {"coverage_incomplete": "one invalid sibling"},
               "findings": [{"severity": "critical", "title": "retained"}]}]
    cache.save("fingerprint", hashes, stages)
    assert cache.get("fingerprint", hashes)[0]["findings"][0]["severity"] == "critical"
    with pytest.raises(mod.EvidenceError, match="cache input"):
        cache.get("fingerprint", {"file.py": "changed"})


def test_incomplete_and_unattempted_cases_remain_in_planned_denominators():
    mod = runner()
    rows = [
        {"id": "a", "cohort": "mcptox", "kind": "malicious", "complete": True,
         "detected": True, "status": "completed"},
        {"id": "b", "cohort": "mcptox", "kind": "malicious", "complete": False,
         "detected": True, "status": "partial"},
        {"id": "c", "cohort": "mcptox", "kind": "malicious", "complete": False,
         "detected": None, "status": "unattempted"},
    ]
    group = mod.summarize_rows(rows)[0]
    assert group["planned"] == 3
    assert group["detected"] == 1
    assert group["incomplete"] == 1
    assert group["unattempted"] == 1
    assert group["planned_yield"] == 1 / 3
    assert group["raw_flags"] == 2


def test_profile_uses_settled_production_accessor_without_overrides():
    mod = runner()
    native = {"llm_max_output_tokens": 4096, "semantic_max_units": 24,
              "semantic_max_chars_per_unit": 6000, "harness_mount_char_budget": 32000}
    def old_call(max_tokens=1600):
        return None
    engine = SimpleNamespace(modules={
        "config": SimpleNamespace(get_production_limits=lambda: SimpleNamespace(to_dict=lambda: native)),
        "pipeline.stages.semantic": SimpleNamespace(_default_make_call=old_call, MAX_UNITS=8, MAX_CHARS_PER_UNIT=6000),
        "pipeline.stages.harness": SimpleNamespace(MOUNT_CHAR_BUDGET=4000, RED_PROBE_COUNT=3),
    })
    assert mod.engine_profile(engine) == native


def test_live_output_contract_denies_wrong_cap_before_network(tmp_path):
    mod = runner()
    sdk = SDK([])
    with mod.RequestJournal(tmp_path, limit=2, binding="fixed", expected_output_tokens=4096) as journal:
        with journal.context("a", "semantic", "common20"):
            with pytest.raises(mod.EvidenceError, match="output contract"):
                journal.request(sdk.create, **{**request(), "max_tokens": 1600})
        assert journal.summary()["attempts"] == 0
    assert sdk.requests == []


NATIVE_ENGINE = Path(os.environ.get("FUGU_BENCH_TEST_ENGINE", "/tmp/fugu-current-limits-base-engine"))


NATIVE_INTEGRATION = r'''
import asyncio, json
from pathlib import Path
from types import SimpleNamespace as N
from bench.current_limits import (load_engine, evaluate_cases, RequestJournal,
                                 input_hashes, fingerprint, read_json, write_json, engine_profile, profile_ready)
engine = load_engine(Path(__import__('os').environ.get('FUGU_BENCH_TEST_ENGINE', '/tmp/fugu-current-limits-base-engine')))
profile=engine_profile(engine)
engine.modules['config'].get_settings = lambda: N(has_api_key=True)
root = Path(__import__('sys').argv[1])
target = root/'target'; target.mkdir()
(target/'SKILL.md').write_text('Synthetic inert public documentation.')
case = {'id':'synthetic-a','cohort':'clean_descriptions','kind':'benign',
        'target':str(target),'input_sha256':input_hashes(target)}
manifest = {'cases':[case,dict(case,id='synthetic-duplicate')]}
class SDK:
    def __init__(self):
        self.requests=[]; self.semantic_first=True; self.super_first=True
        self.chat=N(completions=N(create=self.create))
    def create(self, **kwargs):
        self.requests.append(kwargs)
        system=kwargs['messages'][0]['content']; finish='stop'
        if 'quality_summary' in system:
            if self.semantic_first:
                self.semantic_first=False; raw='{"findings": ['; finish='length'
            else:
                raw=json.dumps({'findings':[{'title':'Synthetic retained severe finding',
                    'owasp_ids':['MCP03'],'severity':'high','detail':'Synthetic fixture only',
                    'element':{'kind':'instruction','line_hint':1,'locator':'SKILL.md'},
                    'excerpt':'Synthetic inert public documentation.'}], 'quality_summary':'Synthetic'})
        elif '"probes"' in system: raw='{"probes": []}'
        elif kwargs['model']==engine.modules['config'].SUPER_MODEL and self.super_first:
            self.super_first=False; raw=''; finish='length'
        else: raw='A harmless summary.'
        return N(id='synthetic-id',model='synthetic-served',
                 choices=[N(message=N(content=raw),finish_reason=finish)],
                 usage=N(prompt_tokens=0,completion_tokens=7))
sdk=SDK(); out=root/'out'
with RequestJournal(out,limit=50,binding='native-compatibility',
                    expected_output_tokens=4096 if profile_ready(profile) else None) as journal:
    result=asyncio.run(evaluate_cases(engine,manifest,out,journal,sdk_factory=lambda *a,**k:sdk))
assert len(sdk.requests)==22, len(sdk.requests)
if profile_ready(profile):
    assert all(r['max_tokens']==4096 for r in sdk.requests)
else:
    assert [r['max_tokens'] for r in sdk.requests[:2]]==[1600,4096]
    assert any(r['max_tokens']==600 for r in sdk.requests)
assert len(result['rows'])==2 and all(r['complete'] for r in result['rows'])
assert result['rows'][1]['reuse'][0]['cached_identical_input'] is True
key=fingerprint(input_hashes(target)); cache=out/'audits'/(key+'.json')
partial=read_json(cache); partial['stages']=partial['stages'][:1]; write_json(cache,partial)
unused=SDK()
with RequestJournal(out,limit=50,binding='native-compatibility',
                    expected_output_tokens=4096 if profile_ready(profile) else None) as resumed:
    replay=asyncio.run(evaluate_cases(engine,manifest,out,resumed,sdk_factory=lambda *a,**k:unused))
    assert all(len(r['stages'])==4 for r in replay['rows']), replay['rows']
    assert resumed.summary()['attempts']==22
    assert resumed.summary()['replayed_requests_this_process']==22
assert unused.requests==[]
print(json.dumps({'requests':22,'resume_requests':0,'rows':2,'scope':'legacy offline compatibility'}))
'''


def test_native_recovery_cache_and_interrupted_stage_resume(tmp_path):
    runner()
    baseline = (NATIVE_ENGINE / "manifest.json")
    if not baseline.exists():
        pytest.skip("Lead frozen legacy compatibility engine is not on this host")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1")
    result = subprocess.run([sys.executable, "-c", NATIVE_INTEGRATION, str(tmp_path)],
                            cwd=Path(__file__).resolve().parents[1], env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-6000:]
    assert json.loads(result.stdout)["resume_requests"] == 0


@pytest.mark.parametrize("mode", ["quota", "interrupt"])
def test_native_stop_preserves_all_planned_rows_before_dispatch(tmp_path, mode):
    runner()
    if not (NATIVE_ENGINE / "manifest.json").exists():
        pytest.skip("Lead frozen legacy compatibility engine is not on this host")
    script = NATIVE_INTEGRATION.split("sdk=SDK(); out=root/'out'")[0] + r'''
mode=__import__('sys').argv[2]
sdk=SDK(); out=root/'out'
def stopped(**kwargs):
    sdk.requests.append(kwargs)
    if mode=='interrupt': raise KeyboardInterrupt()
    error=RuntimeError('synthetic-private-provider-body'); error.status_code=402
    raise error
sdk.chat.completions.create=stopped
try:
    with RequestJournal(out,limit=50,binding='legacy-stop') as journal:
        asyncio.run(evaluate_cases(engine,manifest,out,journal,sdk_factory=lambda *a,**k:sdk))
except KeyboardInterrupt: pass
assert (out/'fugu.json').exists(), 'planned rows must persist before dispatch'
saved=read_json(out/'fugu.json')
assert len(saved['rows'])==2 and saved['planned']==2
assert saved['rows'][0]['complete'] is False
assert saved['rows'][1]['status']=='unattempted'
assert len(sdk.requests)==1
assert saved['usage']['attempts']==1
assert saved['usage']['orphan_attempts']==(1 if mode=='interrupt' else 0)
assert [s['stage'] for s in saved['rows'][0]['stages']][:2]==['concealment','static']
assert 'synthetic-private-provider-body' not in (out/'fugu.json').read_text()
print(json.dumps({'calls':1,'planned_rows':2,'mode':mode}))
'''
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1")
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path), mode],
                            cwd=Path(__file__).resolve().parents[1], env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-2000:]
    assert json.loads(result.stdout)["planned_rows"] == 2


def test_missing_choices_survive_replay_as_missing_choices(tmp_path):
    mod = runner()
    empty = SimpleNamespace(id="empty", model="served", choices=[], usage=None)
    with mod.RequestJournal(tmp_path, limit=2, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            assert journal.request(SDK([empty]).create, **request()).choices == []
    with mod.RequestJournal(tmp_path, limit=2, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            assert journal.request(SDK([]).create, **request()).choices == []
        assert journal.summary()["output_errors"] == 1


def test_phase_budget_stops_other_stages_and_survives_restart(tmp_path):
    mod = runner()
    sdk = SDK([response()])
    for restart in range(2):
        with mod.RequestJournal(tmp_path, limit=3, binding="fixed", phase_limits={"common20": 1}) as journal:
            if restart == 0:
                with journal.context("a", "semantic", "common20"):
                    journal.request(sdk.create, **request())
            with journal.context("b", "harness", "common20"):
                with pytest.raises(mod.JournalStopped, match="phase_attempt_budget"):
                    journal.request(sdk.create, **request())
            with journal.context("c", "semantic", "remainder"):
                with pytest.raises(mod.JournalStopped):
                    journal.request(sdk.create, **request())
            assert journal.summary()["attempts"] == 1
    assert len(sdk.requests) == 1


def test_engine_inventory_cannot_omit_or_add_unhashed_python(tmp_path):
    mod = runner()
    frozen = tmp_path / "engine"
    source = frozen / "src/fugu"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("# inert fixture")
    mod.write_json(frozen / "manifest.json", {"commit": "e" * 40, "hashes": {}})
    with pytest.raises(mod.EvidenceError, match="inventory"):
        mod.load_engine(frozen)


def test_historical_artifact_directory_is_never_a_runner_output():
    mod = runner()
    with pytest.raises(mod.EvidenceError, match="output"):
        mod.validate_output(mod.FROZEN)


def test_preparation_binds_full_fixed_case_source_and_engine(tmp_path):
    runner()
    if not (NATIVE_ENGINE / "manifest.json").exists():
        pytest.skip("Lead frozen legacy compatibility engine is not on this host")
    script = r'''
import json, sys
from pathlib import Path
from bench.current_limits import load_engine, prepare, validate_plan, EvidenceError
engine=load_engine(Path(__import__('os').environ.get('FUGU_BENCH_TEST_ENGINE', '/tmp/fugu-current-limits-base-engine')))
out=Path(sys.argv[1]); plan=prepare(engine,out)
assert plan['ready_for_live_review']==(__import__('bench.current_limits',fromlist=['profile_ready']).profile_ready(plan['profile']))
assert plan['preflight']['context_count']==54
assert plan['preflight']['unique_audit_count']==45
assert plan['preflight']['semantic_primary_units']==63
cases=validate_plan(engine,plan,out)
assert len(cases['cases'])==40
assert sum(c['cohort'] in {'mcptox','clean_descriptions'} for c in cases['cases'][:20])==20
try: prepare(engine,out)
except EvidenceError: pass
else: raise AssertionError('fixed plan was overwritten')
assert plan['text_contracts']['semantic_system_sha256']
assert len(plan['text_contracts']['static_probes_chars'])==6
assert plan['runtime']['dependencies']['openai']
import subprocess, os
denied=subprocess.run([sys.executable,'-m','bench.current_limits','run','--engine-root',str(engine.root),
                      '--output',str(out)],env=dict(os.environ,PYTHON_DOTENV_DISABLED='1'),
                      capture_output=True,text=True,timeout=10)
assert denied.returncode==2
assert 'approved pre-call plan hash' in denied.stderr, denied.stderr
assert not (out/'budget.json').exists()
print(json.dumps({'preflight':[40,54,45,63]}))
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path / "prepared")],
                            cwd=Path(__file__).resolve().parents[1],
                            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1"),
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-3000:]


def test_native_attempt_lineage_maps_ordered_request_rows_without_extra_calls(tmp_path):
    mod = runner()
    with mod.RequestJournal(tmp_path, limit=2, binding="fixed") as journal:
        with journal.context("a", "semantic", "common20"):
            journal.request(SDK([response("raw")]).create, **request())
        native = {"stage": "semantic", "metrics": {"request_attempts": [{
            "requested_model": "requested-synthetic-model", "served_model": "served-synthetic-model",
            "max_tokens": 4096, "finish_reason": "stop", "response_chars": 3,
            "response_sha256": mod.sha(b"raw"), "error": None,
            "usage": {"prompt_tokens": 0, "completion_tokens": 7}, "latency_s": 0.0}]}}
        linked = mod.link_native_attempts(native, journal, "a")
        assert linked["native_request_links"] == [{"native_index": 0, "journal_number": 1,
                                                   "identity_matches": True}]
        assert journal.summary()["attempts"] == 1
        native["metrics"]["request_attempts"][0]["response_sha256"] = "changed"
        assert mod.link_native_attempts(native, journal, "a")["native_request_links"][0]["identity_matches"] is False


def test_changed_copied_labels_are_rejected_by_plan_before_network(tmp_path):
    mod = runner()
    engine = SimpleNamespace(manifest={"commit": "e" * 40})
    cases = {"cases": [{"id": "a", "kind": "benign"}]}
    mod.write_json(tmp_path / "cases.json", cases)
    profile = {"llm_max_output_tokens": 4096}
    plan = {"engine": engine.manifest, "profile": profile,
            "runner_sha256": mod.sha(Path(mod.__file__).read_bytes()),
            "cases_sha256": mod.hash_json(cases)}
    mod.write_json(tmp_path / "cases.json", {"cases": [{"id": "a", "kind": "malicious"}]})
    with pytest.raises(mod.EvidenceError, match="case manifest"):
        mod.validate_plan(engine, plan, tmp_path, profile=profile)


def test_profile_validation_keeps_wrong_or_legacy_defaults_out_of_live_plan():
    mod = runner()
    profile = {"llm_max_output_tokens": 4096, "semantic_max_units": 24,
               "semantic_max_chars_per_unit": 6000, "harness_mount_char_budget": 32000,
               "red_probe_count": 3, "red_probe_max_chars": 200,
               "sdk_max_retries": 0, "request_timeout_seconds": 90,
               "source_max_entries": 20000, "source_max_bytes": 536870912,
               "git_clone_timeout_seconds": 120, "fanout_max_units": 24}
    assert mod.profile_ready(profile) is True
    assert mod.profile_ready({**profile, "llm_max_output_tokens": 600}) is False
    assert mod.profile_ready({"legacy_compatibility_only": True}) is False


def test_stopped_resume_does_not_erase_completed_rows(tmp_path):
    runner()
    if not (NATIVE_ENGINE / "manifest.json").exists():
        pytest.skip("Lead frozen legacy compatibility engine is not on this host")
    script = NATIVE_INTEGRATION.split("sdk=SDK(); out=root/'out'")[0] + r'''
second=root/'second'; second.mkdir()
(second/'SKILL.md').write_text('Synthetic quota-target documentation.')
manifest={'cases':[case,dict(case,id='synthetic-b',target=str(second),input_sha256=input_hashes(second))]}
sdk=SDK(); create=sdk.create
def with_quota(**kwargs):
    if 'quota-target' in kwargs['messages'][1]['content']:
        sdk.requests.append(kwargs)
        error=RuntimeError('synthetic-private-body'); error.status_code=402
        raise error
    return create(**kwargs)
sdk.chat.completions.create=with_quota; out=root/'out'
with RequestJournal(out,limit=50,binding='legacy-stop-resume') as journal:
    before=asyncio.run(evaluate_cases(engine,manifest,out,journal,sdk_factory=lambda *a,**k:sdk))
assert before['rows'][0]['complete'] is True
assert before['rows'][1]['complete'] is False
unused=SDK()
with RequestJournal(out,limit=50,binding='legacy-stop-resume') as resumed:
    after=asyncio.run(evaluate_cases(engine,manifest,out,resumed,sdk_factory=lambda *a,**k:unused))
assert after['rows'][0]['complete'] is True, 'completed output was erased on stopped resume'
assert after['rows'][0]['findings']==before['rows'][0]['findings']
assert unused.requests==[]
print(json.dumps({'preserved':True}))
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                            cwd=Path(__file__).resolve().parents[1],
                            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1"),
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-2000:]


def test_native_composition_uses_original_members_and_identical_input_cache(tmp_path):
    runner()
    if not (NATIVE_ENGINE / "manifest.json").exists():
        pytest.skip("Lead frozen legacy compatibility engine is not on this host")
    script = NATIVE_INTEGRATION.split("sdk=SDK(); out=root/'out'")[0] + r'''
portfolio=root/'portfolio'
for label in ['alpha','beta']:
    member=portfolio/label; member.mkdir(parents=True)
    (member/'SKILL.md').write_text('Synthetic inert public documentation.')
case={'id':'synthetic-composition','cohort':'composition','kind':'benign',
      'target':str(portfolio),'input_sha256':input_hashes(portfolio),
      'members':[{'dir':'alpha','label':'A'},{'dir':'beta','label':'B'}],
      'expected':{'trifecta':False,'shadowing':False}}
sdk=SDK(); out=root/'out'
with RequestJournal(out,limit=50,binding='legacy-composition') as journal:
    result=asyncio.run(evaluate_cases(engine,{'cases':[case]},out,journal,sdk_factory=lambda *a,**k:sdk))
row=result['rows'][0]
assert row['complete'] is True
assert row['matches_frozen_expectations'] is True
assert row['composition_score']=={'trifecta':False,'shadowing':False}
assert row['stages'][-1]['stage']=='composition'
assert [r['member'] for r in row['members_results']]==['alpha','beta']
assert row['reuse'][1]['cached_identical_input'] is True
assert len(sdk.requests)==22
assert row['findings'][0]['evidence'][0]['meta']['model_judged'] is True
print(json.dumps({'requests':22,'members':2,'native_composition':True}))
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                            cwd=Path(__file__).resolve().parents[1],
                            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1"),
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-3000:]


def test_coverage_uses_distinct_audits_and_keeps_unreported_characters_unknown():
    mod = runner()
    stage = {"stage": "semantic", "state": "completed", "journal_numbers": [1, 2],
             "metrics": {"units_total": 2, "units_completed": 2, "units_partial": 0,
                         "units_omitted": 0, "response_recoveries": [{"unit": "a", "recovered_by": "retry"}],
                         "request_attempts": [{"attempt": 1}, {"attempt": 2}]}}
    member = {"fingerprint": "same", "stages": [stage]}
    rows = [{"id": "a", "members_results": [member]},
            {"id": "b", "members_results": [member]}]
    evidence = mod.coverage_data(rows)
    assert evidence["unique_audits"] == 1
    assert evidence["member_contexts"] == 2
    assert evidence["semantic"]["units_total"]["total"] == 2
    assert evidence["semantic"]["submitted_chars"]["total"] is None
    assert evidence["semantic"]["submitted_chars"]["unknown_audits"] == 1
    assert evidence["parsing"]["native_recovery_records"] == 1
    assert evidence["attempt_alignment"][0]["aligned"] is True


def test_reputation_expectation_is_unavailable_even_when_source_stages_complete(tmp_path):
    runner()
    if not (NATIVE_ENGINE / "manifest.json").exists():
        pytest.skip("Lead frozen legacy compatibility engine is not on this host")
    script = NATIVE_INTEGRATION.split("sdk=SDK(); out=root/'out'")[0] + r'''
case=dict(case,id='synthetic-reputation',cohort='reputation',kind='vulnerable_dependency')
sdk=SDK(); out=root/'out'
with RequestJournal(out,limit=50,binding='legacy-reputation') as journal:
    result=asyncio.run(evaluate_cases(engine,{'cases':[case]},out,journal,sdk_factory=lambda *a,**k:sdk))
row=result['rows'][0]
assert row['complete'] is True
assert row['detected'] is None
assert row['raw_medium_flag'] is True
assert row['dependency_expectation']=='unavailable'
assert result['summary'][0]['outcome_unavailable']==1
assert result['summary'][0]['missed_or_unflagged']==0
assert result['summary'][0]['planned_yield'] is None
assert result['summary'][0]['complete_rate'] is None
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                            cwd=Path(__file__).resolve().parents[1],
                            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1"),
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-3000:]
