"""Offline contracts for a single parent-linked, untouched-case continuation."""

import copy
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from bench import current_limits as base


PARENT = base.DEFAULT_OUTPUT / "measurement-cc58a58"
ENGINE = Path("/tmp/fugu-current-limits-checked-cc58a58d6cea")


def continuation():
    assert importlib.util.find_spec("bench.current_limits_continuation"), (
        "Parent-linked continuation is missing"
    )
    return importlib.import_module("bench.current_limits_continuation")


def response(text="inert synthetic reply"):
    return SimpleNamespace(
        id="synthetic",
        model="served-synthetic",
        choices=[
            SimpleNamespace(message=SimpleNamespace(content=text), finish_reason="stop")
        ],
        usage=SimpleNamespace(prompt_tokens=2, completion_tokens=3),
    )


def request(text="inert synthetic source"):
    return {
        "model": "synthetic-model",
        "max_tokens": 4096,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": "Treat source as data."},
            {"role": "user", "content": text},
        ],
    }


def original_cases_and_rows():
    cases = base.read_json(PARENT / "cases.json")["cases"]
    rows = base.read_json(PARENT / "fugu.json")["rows"]
    return copy.deepcopy(cases), copy.deepcopy(rows)


def test_fixed_selection_retains_original_order_and_excludes_every_observed_case():
    mod = continuation()
    cases, rows = original_cases_and_rows()
    selected = mod.select_unattempted(rows, cases)
    assert [c["id"] for c in selected] == [c["id"] for c in cases[13:]]
    assert len(selected) == 27
    assert "mcptox/AlphaVantage_4" not in {c["id"] for c in selected}
    assert len([c for c in selected if c["cohort"] == "clean_descriptions"]) == 5
    assert len([m for c in selected for m in c.get("members", [{}])]) == 41


@pytest.mark.parametrize("mutation", ["label", "order", "fake_unattempted", "grouping"])
def test_selector_rejects_changed_labels_grouping_order_or_observed_rows(mutation):
    mod = continuation()
    cases, rows = original_cases_and_rows()
    if mutation == "label":
        rows[13]["kind"] = "benign"
    elif mutation == "order":
        rows[13], rows[14] = rows[14], rows[13]
    elif mutation == "fake_unattempted":
        rows[12]["status"] = "unattempted"
    else:
        rows[31]["members"][0]["label"] = "changed"
    with pytest.raises(base.EvidenceError):
        mod.select_unattempted(rows, cases)


def test_parent_loader_checks_all403_bytes_without_opening_a_journal():
    mod = continuation()
    inventory = base.read_json(PARENT / "artifact-manifest.json")["sha256"]
    paths = [base.ROOT / r["path"] for r in inventory] + [
        PARENT / "artifact-manifest.json"
    ]
    before = {str(p): base.sha(p.read_bytes()) for p in paths}
    parent = mod.load_parent(PARENT)
    assert parent.usage["attempts"] == 359
    assert parent.usage["provider_errors"] == 1
    assert parent.usage["prompt_tokens_total"] is None
    assert len(parent.selected["cases"]) == 27
    assert parent.result["rows"][12]["raw_medium_flag"] is True
    assert {str(p): base.sha(p.read_bytes()) for p in paths} == before
    assert len(before) == 403


@pytest.mark.parametrize(
    "mutation", ["extra", "missing", "wrong_number", "response_hash", "signature"]
)
def test_read_only_ledger_rejects_extra_missing_or_malformed_requests(
    tmp_path, mutation
):
    mod = continuation()
    with base.RequestJournal(tmp_path, limit=2, binding="inert") as journal:
        with journal.context("context-a", "semantic", "common20"):
            journal.request(lambda **kwargs: response(), **request())
    path = tmp_path / "calls/00001.json"
    if mutation == "extra":
        (tmp_path / "calls/00002.json").write_bytes(path.read_bytes())
    elif mutation == "missing":
        path.unlink()
    else:
        row = base.read_json(path)
        if mutation == "wrong_number":
            row["number"] = 2
        elif mutation == "response_hash":
            row["raw_response"] = "changed"
        else:
            row["request_sha256"] = "0" * 64
        base.write_json(path, row)
    with pytest.raises(base.EvidenceError):
        mod.read_ledger(tmp_path)


def journal_settings(root, **overrides):
    settings = {
        "registry_path": root / "registry/parent.json",
        "binding": "synthetic-child-plan",
        "release_binding": "synthetic-authenticated-release",
        "parent_usage": {"attempts": 359, "phase_attempts": {"common20": 359}},
        "allowed_contexts": {"context-a": "common20", "context-b": "remainder"},
        "limit": 3,
        "phase_limits": {"common20": 2, "remainder": 1},
        "expected_models": ["synthetic-model"],
    }
    settings.update(overrides)
    return settings


def test_parent_and_child_reservation_are_durable_before_fake_sdk(tmp_path):
    mod = continuation()
    settings = journal_settings(tmp_path)
    observed = []

    def dispatch(**kwargs):
        registry = base.read_json(settings["registry_path"])
        budget = base.read_json(tmp_path / "child/budget.json")
        row = base.read_json(tmp_path / "child/calls/00001.json")
        observed.append((registry["attempts"], budget["attempts"], row["state"]))
        return response()

    with mod.ContinuationJournal(tmp_path / "child", **settings) as journal:
        with journal.context("context-a", "semantic", "common20"):
            journal.request(dispatch, **request())
        assert journal.summary()["cumulative_attempts"] == 360
    assert observed == [(1, 1, "reserved")]


@pytest.mark.parametrize(
    "boundary", ["child", "child_phase", "cumulative", "cumulative_phase"]
)
def test_child_and_original_cumulative_phase_caps_block_before_sdk(tmp_path, boundary):
    mod = continuation()
    changes = {"limit": 1} if boundary == "child" else {}
    if boundary == "child_phase":
        changes["phase_limits"] = {"common20": 1, "remainder": 1}
    if boundary == "cumulative":
        changes["parent_usage"] = {
            "attempts": 1899,
            "phase_attempts": {"common20": 799, "remainder": 1100},
        }
    if boundary == "cumulative_phase":
        changes["parent_usage"] = {"attempts": 799, "phase_attempts": {"common20": 799}}
    settings = journal_settings(tmp_path, **changes)
    calls = []

    def dispatch(**kwargs):
        calls.append(kwargs)
        return response()

    for restart in range(2):
        with mod.ContinuationJournal(tmp_path / "child", **settings) as journal:
            with journal.context("context-a", "semantic", "common20"):
                journal.request(dispatch, **request())  # Exact replay on restart.
                with pytest.raises(base.JournalStopped):
                    journal.request(dispatch, **request("second"))
            assert journal.summary()["attempts"] == 1
    assert len(calls) == 1


def test_one_child_exclusive_owner_rejects_another_directory_or_reset(tmp_path):
    mod = continuation()
    settings = journal_settings(tmp_path)
    with mod.ContinuationJournal(tmp_path / "child", **settings) as first:
        with pytest.raises(base.EvidenceError, match="owned"):
            mod.ContinuationJournal(tmp_path / "child", **settings)
        with first.context("context-a", "semantic", "common20"):
            first.request(lambda **kwargs: response(), **request())
    with pytest.raises(base.EvidenceError):
        mod.ContinuationJournal(tmp_path / "replacement", **settings)
    assert not (tmp_path / "replacement").exists()
    state = base.read_json(tmp_path / "child/budget.json")
    state["attempts"] = 0
    base.write_json(tmp_path / "child/budget.json", state)
    with pytest.raises(base.EvidenceError):
        mod.ContinuationJournal(tmp_path / "child", **settings)


@pytest.mark.parametrize(
    "change",
    [
        "missing_registry",
        "missing_budget",
        "changed_reply",
        "malformed_registry",
        "release",
    ],
)
def test_deleted_or_changed_state_does_not_reset_a_granted_child(tmp_path, change):
    mod = continuation()
    settings = journal_settings(tmp_path)
    with mod.ContinuationJournal(tmp_path / "child", **settings) as journal:
        with journal.context("context-a", "semantic", "common20"):
            journal.request(lambda **kwargs: response(), **request())
    if change == "missing_registry":
        settings["registry_path"].unlink()
    elif change == "missing_budget":
        (tmp_path / "child/budget.json").unlink()
    elif change == "changed_reply":
        p = tmp_path / "child/calls/00001.json"
        row = base.read_json(p)
        row.update(raw_response="forged", response_sha256=base.sha(b"forged"))
        base.write_json(p, row)
    elif change == "malformed_registry":
        settings["registry_path"].write_text('{"attempts":0,"attempts":1}')
    else:
        settings["release_binding"] = "replacement-release"
    with pytest.raises(base.EvidenceError):
        mod.ContinuationJournal(tmp_path / "child", **settings)


@pytest.mark.parametrize(
    "status,reason",
    [
        (402, "provider_quota_exhausted"),
        (401, "provider_auth_failure"),
        (429, "provider_rate_limit"),
        (500, "provider_error"),
    ],
)
def test_provider_stop_never_retries_and_preserves_exact_successful_replay(
    tmp_path, status, reason
):
    mod = continuation()
    settings = journal_settings(tmp_path)
    calls = []

    def success(**kwargs):
        calls.append(kwargs)
        return response("  unchanged saved reply\n")

    def failure(**kwargs):
        calls.append(kwargs)
        error = RuntimeError("synthetic-private-provider-body")
        error.status_code = status
        raise error

    with mod.ContinuationJournal(tmp_path / "child", **settings) as journal:
        with journal.context("context-a", "semantic", "common20"):
            journal.request(success, **request())
        with journal.context("context-b", "harness", "remainder"):
            with pytest.raises(base.JournalStopped, match=reason):
                journal.request(failure, **request("error source"))
            with pytest.raises(base.JournalStopped):
                journal.request(success, **request("native retry denied"))
    before = {p.name: p.read_bytes() for p in (tmp_path / "child/calls").glob("*.json")}
    with mod.ContinuationJournal(tmp_path / "child", **settings) as journal:
        assert journal.stop_reason == reason
        with journal.context("context-a", "semantic", "common20"):
            assert (
                journal.request(success, **request()).choices[0].message.content
                == "  unchanged saved reply\n"
            )
        with journal.context("context-b", "harness", "remainder"):
            with pytest.raises(base.JournalStopped):
                journal.request(success, **request("error source"))
        assert journal.summary()["unknown_usage_calls"] == 1
    assert len(calls) == 2
    assert before == {
        p.name: p.read_bytes() for p in (tmp_path / "child/calls").glob("*.json")
    }
    assert all(
        b"synthetic-private-provider-body" not in data for data in before.values()
    )


@pytest.mark.parametrize(
    "failure_point", ["budget", "reservation", "response", "registry", "stop"]
)
def test_storage_failure_is_closed_in_process_and_after_restart(
    tmp_path, monkeypatch, failure_point
):
    mod = continuation()
    settings = journal_settings(tmp_path)
    calls = []
    write = base.write_json

    def faulty(path, value):
        fail = (
            (
                failure_point == "budget"
                and path.name == "budget.json"
                and value.get("attempts") == 1
            )
            or (
                failure_point == "reservation"
                and path.name == "00001.json"
                and value.get("state") == "reserved"
            )
            or (
                failure_point == "response"
                and path.name == "00001.json"
                and value.get("state") == "returned"
            )
            or (
                failure_point == "registry"
                and path == settings["registry_path"]
                and value.get("attempts") == 1
            )
            or (
                failure_point == "stop"
                and path.name == "budget.json"
                and value.get("stop_reason")
            )
        )
        if fail:
            raise OSError("synthetic storage failure")
        write(path, value)

    def dispatch(**kwargs):
        calls.append(kwargs)
        if failure_point == "stop":
            error = RuntimeError("synthetic-private-body")
            error.status_code = 500
            raise error
        return response()

    with mod.ContinuationJournal(tmp_path / "child", **settings) as journal:
        monkeypatch.setattr(base, "write_json", faulty)
        with journal.context("context-a", "semantic", "common20"):
            with pytest.raises((base.JournalStopped, OSError)):
                journal.request(dispatch, **request())
            with pytest.raises(base.JournalStopped):
                journal.request(dispatch, **request("must not dispatch"))
        monkeypatch.setattr(base, "write_json", write)
    prior = len(calls)
    try:
        resumed = mod.ContinuationJournal(tmp_path / "child", **settings)
    except base.EvidenceError:
        pass  # Integrity mismatch is also a closed boundary.
    else:
        with resumed, resumed.context("context-b", "harness", "remainder"):
            with pytest.raises(base.JournalStopped):
                resumed.request(dispatch, **request("restart must not dispatch"))
            assert resumed.summary()["attempts"] >= 1
    assert len(calls) == prior == (1 if failure_point in {"response", "stop"} else 0)


def test_interrupted_dispatch_is_counted_and_stops_after_restart(tmp_path):
    mod = continuation()
    settings = journal_settings(tmp_path)
    calls = []

    def interrupted(**kwargs):
        calls.append(kwargs)
        raise KeyboardInterrupt()

    with mod.ContinuationJournal(tmp_path / "child", **settings) as journal:
        with journal.context("context-a", "semantic", "common20"):
            with pytest.raises(KeyboardInterrupt):
                journal.request(interrupted, **request())
    with mod.ContinuationJournal(tmp_path / "child", **settings) as journal:
        with journal.context("context-b", "semantic", "remainder"):
            with pytest.raises(base.JournalStopped):
                journal.request(interrupted, **request())
        assert journal.summary()["orphan_attempts"] == 1
        assert journal.summary()["cumulative_attempts"] == 360
    assert len(calls) == 1


def test_failed_guard_and_all_stop_writes_leave_a_preexisting_closed_session(
    tmp_path, monkeypatch
):
    mod = continuation()
    settings = journal_settings(tmp_path)
    calls = []

    def dispatch(**kwargs):
        calls.append(kwargs)
        return response()

    journal = mod.ContinuationJournal(tmp_path / "child", **settings)
    with monkeypatch.context() as patch:

        def unavailable(*args):
            raise OSError("synthetic full storage outage")

        patch.setattr(base, "write_json", unavailable)
        with journal.context("context-a", "semantic", "common20"):
            with pytest.raises(base.JournalStopped):
                journal.request(dispatch, **request())
    journal.close()
    with mod.ContinuationJournal(tmp_path / "child", **settings) as resumed:
        with resumed.context("context-b", "harness", "remainder"):
            with pytest.raises(base.JournalStopped):
                resumed.request(dispatch, **request())
    assert calls == []


def test_finished_child_result_is_returned_without_rewriting_or_rerunning(
    tmp_path, monkeypatch
):
    mod = continuation()
    settings = journal_settings(tmp_path)
    cases = {
        "cases": [
            {
                "id": "synthetic-finished",
                "target": str(tmp_path / "target"),
                "input_sha256": {},
                "kind": "benign",
                "cohort": "crafted",
            }
        ]
    }
    (tmp_path / "target").mkdir()
    with mod.ContinuationJournal(tmp_path / "child", **settings) as journal:
        result = {
            "binding": journal.binding,
            "cases_sha256": base.hash_json(cases),
            "planned": 1,
            "rows": [dict(cases["cases"][0], complete=True, status="completed")],
            "usage": journal.summary(),
        }
        path = tmp_path / "child/fugu.json"
        base.write_json(path, result)
        before = path.read_bytes()

        async def forbidden(*args, **kwargs):
            raise AssertionError("valid child result rerun")

        monkeypatch.setattr(base, "evaluate_cases", forbidden)
        import asyncio

        assert (
            asyncio.run(mod.evaluate_cases(None, cases, tmp_path / "child", journal))
            == result
        )
        assert path.read_bytes() == before


@pytest.mark.parametrize("target", ["child", "registry_lock", "journal_lock"])
def test_symlink_ownership_paths_are_rejected_before_writes(tmp_path, target):
    mod = continuation()
    settings = journal_settings(tmp_path)
    outside = tmp_path / "untouched"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("retain these bytes")
    child = tmp_path / "child"
    if target == "child":
        child.symlink_to(outside, target_is_directory=True)
    elif target == "registry_lock":
        settings["registry_path"].parent.mkdir()
        settings["registry_path"].with_suffix(".lock").symlink_to(sentinel)
    else:
        child.mkdir()
        (child / ".journal.lock").symlink_to(sentinel)
    with pytest.raises(base.EvidenceError):
        mod.ContinuationJournal(child, **settings)
    assert sentinel.read_text() == "retain these bytes"
    assert sorted(p.name for p in outside.iterdir()) == ["sentinel"]


def child_rows_and_plan(parent):
    cases = copy.deepcopy(parent.selected["cases"])
    for c in cases:
        c["original_target"] = c["target"]
        c["target"] = "/synthetic/copied/" + c["id"]
    plan = {
        "selected_case_ids": [c["id"] for c in cases],
        "cases_sha256": base.hash_json({"cases": cases}),
        "parent_plan_sha256": mod_constant("PARENT_PLAN_SHA256"),
        "parent_inventory_sha256": mod_constant("PARENT_MANIFEST_SHA256"),
        "parent_result_sha256": mod_constant("PARENT_RESULT_SHA256"),
        "original_case_manifest_sha256": base.FIXED_CASE_MANIFEST_SHA256,
        "runner_sha256": mod_constant("RUNNER_SHA256"),
        "synthetic": True,
    }
    rows = [
        dict(
            c,
            complete=True,
            status="completed",
            detected=None if c["cohort"] == "reputation" else False,
            raw_medium_flag=False,
            findings=[],
            stages=[],
            members_results=[],
            adjudicated_false_positive=None,
        )
        for c in cases
    ]
    return rows, plan


def mod_constant(name):
    return getattr(continuation(), name)


def test_combined_rows_preserve13_original_rows_severe_partial_and_unknown_usage():
    mod = continuation()
    parent = mod.load_parent()
    rows, plan = child_rows_and_plan(parent)
    rows[2].update(
        detected=True,
        raw_medium_flag=True,
        findings=[{"severity": "high", "title": "Synthetic benign flag"}],
    )
    child = {
        "rows": rows,
        "binding": base.hash_json(plan),
        "planned": 27,
        "engine": parent.result["engine"],
        "limits": parent.result["limits"],
        "scope": parent.result["scope"],
        "started_utc": "2026-10-03T10:00:00Z",
        "measured_utc": "2026-10-03T10:01:00Z",
        "usage": {},
    }
    combined, provenance = mod.combine(
        parent, child, [], plan, child_result_sha256=base.hash_json(child)
    )
    assert combined["rows"][:13] == parent.result["rows"][:13]
    assert base.hash_json(combined["rows"][:13]) == base.hash_json(
        parent.result["rows"][:13]
    )
    assert [r["id"] for r in combined["rows"]] == [
        c["id"] for c in parent.cases["cases"]
    ]
    assert combined["planned"] == 40
    assert combined["rows"][12]["complete"] is False
    assert combined["rows"][12]["raw_medium_flag"] is True
    assert combined["usage"]["attempts"] == 359
    assert combined["usage"]["prompt_tokens_total"] is None
    assert combined["usage"]["completion_tokens_total"] is None
    assert combined["usage"]["provider_errors"] == 1
    assert len(combined["intervals"]) == 2
    assert combined["row_interval"][parent.result["rows"][12]["id"]] == "parent"
    assert combined["row_interval"][rows[0]["id"]] == "child"
    assert combined["benign_adjudication"]["pending_ids"] == [rows[2]["id"]]
    assert combined["benign_adjudication"]["confirmed_false_positive_ids"] == []
    assert len(provenance["sdk_requests"]) == 359
    assert all(r["interval_id"] == "parent" for r in provenance["sdk_requests"])
    assert combined["summary"][0]["planned"] == 15
    assert combined["summary"][0]["completed"] == 14


@pytest.mark.parametrize(
    "mutation", ["partial_parent", "order", "labels", "profile", "grouping"]
)
def test_aggregate_rejects_observed_case_replacement_or_changed_child_contract(
    mutation,
):
    mod = continuation()
    parent = mod.load_parent()
    rows, plan = child_rows_and_plan(parent)
    child = {
        "rows": rows,
        "binding": base.hash_json(plan),
        "planned": 27,
        "engine": parent.result["engine"],
        "limits": copy.deepcopy(parent.result["limits"]),
        "scope": parent.result["scope"],
        "started_utc": "later",
        "measured_utc": "later",
        "usage": {},
    }
    if mutation == "partial_parent":
        rows[0] = parent.result["rows"][12]
    elif mutation == "order":
        rows[0], rows[1] = rows[1], rows[0]
    elif mutation == "labels":
        rows[0]["kind"] = "benign"
    elif mutation == "profile":
        child["limits"]["llm_max_output_tokens"] = 600
    else:
        rows[18]["members"][0]["label"] = "changed"
    with pytest.raises(base.EvidenceError):
        mod.combine(parent, child, [], plan, child_result_sha256=base.hash_json(child))


NATIVE_CONTINUATION = r"""
import asyncio, json, sys
from pathlib import Path
from types import SimpleNamespace as N
from bench import current_limits as base
from bench import current_limits_continuation as mod
root=Path(sys.argv[1]); mod.DEFAULT_CHILD=root/'synthetic-child'; mod.DEFAULT_REGISTRY=root/'synthetic-registry/parent.json'
engine=base.load_engine(Path(sys.argv[2]))
parent=mod.load_parent(); before={r['path']:base.sha((base.ROOT/r['path']).read_bytes()) for r in parent.inventory['sha256']}
before['manifest']=base.sha((parent.directory/'artifact-manifest.json').read_bytes())
plan=mod.prepare(engine,root/'prepared')
assert plan['provider_requests']==0 and plan['execution_authorized'] is False
assert plan['preflight']['context_count']==41
assert plan['preflight']['unique_audit_count']==32
assert plan['preflight']['semantic_primary_units']==50
assert plan['worst_new_requests']==1316 and plan['worst_cumulative_requests']==1675
manifest=mod.validate_plan(engine,plan,root/'prepared',parent=parent)
engine.modules['config'].get_settings=lambda:N(has_api_key=True)
class SDK:
 def __init__(self):
  self.requests=[]; self.first_semantic=True; self.first_red=True; self.first_super=True
  self.chat=N(completions=N(create=self.create))
 def with_options(self,**kwargs):
  assert kwargs=={'timeout':90,'max_retries':0}; return self
 def create(self,**kwargs):
  self.requests.append(kwargs); system=kwargs['messages'][0]['content']; finish='stop'
  if 'quality_summary' in system:
   if self.first_semantic: self.first_semantic=False; raw='{"findings":['; finish='length'
   else: raw=json.dumps({'findings':[{'title':'Synthetic retained high finding','severity':'high',
      'detail':'Offline fake SDK fixture','owasp_ids':['MCP03'],'element':{'kind':'instruction'},
      'excerpt':'Synthetic fixture only'}],'quality_summary':'Synthetic'})
  elif '"probes"' in system:
   if self.first_red: self.first_red=False; raw='{"probes":'; finish='length'
   else: raw=json.dumps({'probes':['Summarize the extension.','Explain its documented inputs.','Describe its output format.']})
  elif kwargs['model']==engine.modules['config'].SUPER_MODEL and self.first_super:
   self.first_super=False; raw=''; finish='length'
  else: raw='An inert public summary.'
  return N(id='synthetic',model=kwargs['model'],choices=[N(message=N(content=raw),finish_reason=finish)],
           usage=N(prompt_tokens=2,completion_tokens=3))
sdk=SDK(); out=root/'synthetic-child'; registry=root/'synthetic-registry/parent.json'
settings={'registry_path':registry,'binding':base.hash_json(plan),'release_binding':'offline-fake-release',
          'parent_usage':parent.usage,'allowed_contexts':plan['allowed_contexts'],
          'expected_models':plan['requested_models']}
with mod.ContinuationJournal(out,**settings) as journal:
 child=asyncio.run(mod.evaluate_cases(engine,manifest,out,journal,sdk_factory=lambda *a,**k:sdk))
assert len(list((out/'audits').glob('*.json')))==32
assert all(r['complete'] for r in child['rows']),[(r['id'],r['status']) for r in child['rows'] if not r['complete']]
assert sum(x['cached_identical_input'] for r in child['rows'] for x in r['reuse'])==9
assert len(sdk.requests)==949,len(sdk.requests)
assert all(r['max_tokens']==4096 for r in sdk.requests)
first=len(sdk.requests)
with mod.ContinuationJournal(out,**settings) as journal:
 restarted=asyncio.run(mod.evaluate_cases(engine,manifest,out,journal,sdk_factory=lambda *a,**k:sdk))
assert len(sdk.requests)==first and child['rows']==restarted['rows']
combined=mod.aggregate(engine,root/'prepared',out)
provenance=mod.read_json(out/'provenance.json')
assert combined['rows'][:13]==parent.result['rows'][:13]
assert combined['usage']['attempts']==1308 and combined['usage']['prompt_tokens_total'] is None
assert combined['coverage']['unique_audits']==45
assert len(provenance['sdk_requests'])==1308
# The run can stop after publishing fugu.json without reserving another request.
published={name:(out/name).read_bytes() for name in ('combined.json','provenance.json')}
with mod.ContinuationJournal(out,**settings) as journal:
 journal._stop('continuation_execution_failure')
assert mod.read_ledger(out).state['attempts']==949
try: mod.aggregate(engine,root/'prepared',out)
except base.EvidenceError as error: assert 'accounting' in str(error)
else: raise AssertionError('stale child stop was published')
assert published=={name:(out/name).read_bytes() for name in published}
assert len(sdk.requests)==first
with mod.ContinuationJournal(out,**settings) as journal:
 recovered=asyncio.run(mod.evaluate_cases(engine,manifest,out,journal,sdk_factory=lambda *a,**k:sdk))
assert len(sdk.requests)==first and recovered['rows']==child['rows']
assert recovered['usage']['stop_reason']=='continuation_execution_failure'
combined=mod.aggregate(engine,root/'prepared',out)
assert combined['usage']['stop_reason']=='continuation_execution_failure'
assert combined['intervals'][1]['usage']==recovered['usage']
assert combined['rows'][:13]==parent.result['rows'][:13] and combined['rows'][13:]==child['rows']
from bench.current_limits_charts import load_competitors
from bench.current_limits_continuation_charts import chart_data
data=chart_data(combined,parent.original,load_competitors(parent.original,base.FROZEN/'competitors'),
                comparator_snapshot='2026-10-02-full')
assert data['usage']['stop_reason']=='continuation_execution_failure'
assert data['intervals'][1]['usage']['stop_reason']=='continuation_execution_failure'
assert data['usage']['prompt_tokens_total'] is None
after={r['path']:base.sha((base.ROOT/r['path']).read_bytes()) for r in parent.inventory['sha256']}
after['manifest']=base.sha((parent.directory/'artifact-manifest.json').read_bytes())
assert before==after and len(before)==403
print(json.dumps({'synthetic':True,'fake_sdk_attempts':first,'provider_requests':0,'unique_audits':32,
                  'cached_contexts':9,'preserved_parent_files':403,'combined_rows':40,'restart_dispatches':0,
                  'stale_stop_rejected':True,'accounting_recovery_dispatches':0,
                  'child_rows_preserved':27,'carried_rows_preserved':13,
                  'recovered_stop_reason':data['usage']['stop_reason'],'chart_consumer_accepted':True}))
"""


def test_native32_audit_reuse_recovery_aggregate_restart_and403_parent_bytes(tmp_path):
    continuation()
    if not (ENGINE / "manifest.json").exists():
        pytest.skip("The exact checked cc58a58 engine must be reconstructed first")
    result = subprocess.run(
        [sys.executable, "-c", NATIVE_CONTINUATION, str(tmp_path), str(ENGINE)],
        cwd=base.ROOT,
        env=dict(
            os.environ,
            PYTHONDONTWRITEBYTECODE="1",
            PYTHON_DOTENV_DISABLED="1",
            NEBIUS_API_KEY="",
        ),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-5000:]
    evidence = json.loads(result.stdout)
    assert evidence["provider_requests"] == 0
    print(json.dumps(evidence, sort_keys=True))


def release_fixture():
    mod = continuation()
    plan = {
        "child_directory": str(mod.DEFAULT_CHILD.resolve()),
        "registry_path": str(mod.DEFAULT_REGISTRY.resolve()),
        "parent_plan_sha256": mod.PARENT_PLAN_SHA256,
        "parent_inventory_sha256": mod.PARENT_MANIFEST_SHA256,
        "parent_result_sha256": mod.PARENT_RESULT_SHA256,
        "attempt_limit": 1316,
        "phase_limits": mod.CHILD_PHASE_LIMITS,
        "cumulative_limit": 1900,
        "cumulative_phase_limits": mod.PARENT_PHASE_LIMITS,
    }
    grant = mod.release_template(plan)
    grant.update(
        execution_authorized=True,
        reviewed_commit="a" * 40,
        review_queue_ref="qitem-20261003010000-1234abcd",
    )
    row = {
        "qitemId": "qitem-20261003020000-5678abcd",
        "sourceSession": "control-lead@fugu",
        "destinationSession": "research-security@fugu",
        "state": "in-progress",
        "claimedAt": "2026-10-03T02:00:00Z",
        "body": json.dumps(grant),
    }
    return plan, grant, row


def test_authenticated_release_validates_exact_plan_and_immutable_lead_body():
    mod = continuation()
    plan, grant, row = release_fixture()
    release = mod.verify_release(row, plan, base.hash_json(plan))
    assert release.queue_ref == row["qitemId"]
    assert release.body == grant
    assert release.binding == base.hash_json(
        {k: row[k] for k in ("qitemId", "sourceSession", "destinationSession", "body")}
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "destination",
        "unclaimed",
        "not_authorized",
        "plan",
        "namespace",
        "registry",
        "budget",
        "missing_review",
        "not_json",
        "old_implementation",
        "extra_field",
    ],
)
def test_release_ref_or_prose_alone_never_grants_sdk_access(mutation):
    mod = continuation()
    plan, grant, row = release_fixture()
    if mutation == "source":
        row["sourceSession"] = "research-security@fugu"
    elif mutation == "destination":
        row["destinationSession"] = "build-backend@fugu"
    elif mutation == "unclaimed":
        row["state"] = "pending"
        row["claimedAt"] = None
    elif mutation == "not_authorized":
        grant["execution_authorized"] = False
    elif mutation == "plan":
        grant["child_plan_sha256"] = "0" * 64
    elif mutation == "namespace":
        grant["child_directory"] += "-replacement"
    elif mutation == "registry":
        grant["registry_path"] += "-replacement"
    elif mutation == "budget":
        grant["attempt_limit"] = 1900
    elif mutation == "missing_review":
        grant["reviewed_commit"] = None
    elif mutation == "extra_field":
        grant["reset_budget"] = True
    if mutation not in {"not_json", "old_implementation"}:
        row["body"] = json.dumps(grant)
    elif mutation == "not_json":
        row["body"] = "A data-phase qitem ID is not an authenticated release."
    else:
        row["body"] = "# Offline implementation only\nNo paid authority."
    with pytest.raises(base.EvidenceError):
        mod.verify_release(row, plan, base.hash_json(plan))


def test_run_cli_requires_exact_approval_and_data_release_before_loading_engine_or_writing(
    tmp_path, monkeypatch
):
    mod = continuation()

    def forbidden(*args):
        raise AssertionError("engine/credential loader reached before release gate")

    monkeypatch.setattr(base, "load_engine", forbidden)
    with pytest.raises(base.EvidenceError, match="data release"):
        mod.main(
            [
                "run",
                "--engine-root",
                str(ENGINE),
                "--prepared-dir",
                str(tmp_path),
                "--approved-plan-sha256",
                "a" * 64,
            ]
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "mutation", ["input", "label", "grouping", "profile", "runtime", "source", "module"]
)
def test_prepared_plan_drift_is_rejected_before_sdk(tmp_path, mutation):
    continuation()
    if not (ENGINE / "manifest.json").exists():
        pytest.skip("Checked engine must be reconstructed first")
    script = r"""
import sys
from pathlib import Path
from bench import current_limits as base
from bench import current_limits_continuation as mod
engine=base.load_engine(Path(sys.argv[2])); root=Path(sys.argv[1]); plan=mod.prepare(engine,root)
cases=base.read_json(root/'cases.json'); mode=sys.argv[3]
if mode=='input':
 p=base.case_target(cases['cases'][0])/'tools.json'; p.write_text('changed inert fixture')
elif mode in ('label','grouping'):
 if mode=='label': cases['cases'][0]['kind']='benign'
 else: cases['cases'][18]['members'][0]['label']='changed'
 base.write_json(root/'cases.json',cases)
elif mode=='profile': plan['profile']=dict(plan['profile'],llm_max_output_tokens=600)
elif mode=='runtime': plan['runtime']=dict(plan['runtime'],python='changed')
elif mode=='source': engine.manifest=dict(engine.manifest,commit='b'*40)
else: plan['continuation_sha256']='0'*64
try: mod.validate_plan(engine,plan,root)
except base.EvidenceError: pass
else: raise AssertionError('drift reached SDK gate')
assert not (mod.DEFAULT_CHILD/'data-release.json').exists()
print('rejected-before-sdk')
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(tmp_path / "prepared"),
            str(ENGINE),
            mutation,
        ],
        cwd=base.ROOT,
        env=dict(
            os.environ,
            PYTHONDONTWRITEBYTECODE="1",
            PYTHON_DOTENV_DISABLED="1",
            NEBIUS_API_KEY="",
        ),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "rejected-before-sdk"


@pytest.mark.parametrize(
    "mutation",
    [
        "request_bytes",
        "missing_binding",
        "duplicate_binding",
        "phase",
        "budget_binding",
        "model",
    ],
)
def test_offline_aggregation_rejects_drift_in_actual_request_registry(
    tmp_path, mutation
):
    mod = continuation()
    settings = journal_settings(tmp_path)
    child = tmp_path / "child"
    with mod.ContinuationJournal(child, **settings) as journal:
        with journal.context("context-a", "semantic", "common20"):
            journal.request(lambda **kwargs: response(), **request())
    registry = base.read_json(settings["registry_path"])
    if mutation == "request_bytes":
        path = child / "calls/00001.json"
        row = base.read_json(path)
        row.update(raw_response="changed", response_sha256=base.sha(b"changed"))
        base.write_json(path, row)
    elif mutation == "missing_binding":
        registry["calls"] = []
    elif mutation == "duplicate_binding":
        registry["calls"] *= 2
    elif mutation == "phase":
        registry["phase_attempts"] = {"common20": 0}
    else:
        state = base.read_json(child / "budget.json")
        if mutation == "budget_binding":
            state["binding"] = "changed"
        else:
            state["expected_models"] = ["changed"]
        base.write_json(child / "budget.json", state)
    with pytest.raises(base.EvidenceError):
        mod.validate_registry_ledger(
            registry,
            mod.read_ledger(child),
            child,
            binding=settings["binding"],
            parent_usage=settings["parent_usage"],
            limit=settings["limit"],
            phase_limits=settings["phase_limits"],
        )


def test_ledger_rejects_discontinuous_stage_request_ordinals(tmp_path):
    mod = continuation()
    with base.RequestJournal(tmp_path, limit=1, binding="inert") as journal:
        with journal.context("context-a", "semantic", "common20"):
            journal.request(lambda **kwargs: response(), **request())
    path = tmp_path / "calls/00001.json"
    row = base.read_json(path)
    row["ordinal"] = 1
    base.write_json(path, row)
    with pytest.raises(base.EvidenceError):
        mod.read_ledger(tmp_path)


def test_release_body_with_duplicate_keys_is_malformed():
    mod = continuation()
    plan, grant, row = release_fixture()
    row["body"] = json.dumps(grant)[:-1] + ', "execution_authorized": true}'
    with pytest.raises(base.EvidenceError):
        mod.verify_release(row, plan, base.hash_json(plan))


def test_offline_paths_accept_only_the_system_tmp_alias_without_writing(tmp_path):
    mod = continuation()
    if not Path("/tmp").is_symlink() or Path("/tmp").resolve() != Path("/private/tmp"):
        pytest.skip("This host does not use the macOS system temp alias")
    mod._offline_output(Path("/tmp/fugu-continuation-portability-probe"), ENGINE)
    path = tmp_path / "untrusted-alias"
    path.symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(base.EvidenceError):
        mod._offline_output(path, ENGINE)


@pytest.fixture
def aggregate_accounting_fixture(tmp_path, monkeypatch):
    """Real child ledger/registry and aggregate path; skip unrelated preflight."""
    mod = continuation()
    parent = mod.load_parent()
    rows, plan = child_rows_and_plan(parent)
    prepared, child = tmp_path / "prepared", tmp_path / "child"
    settings = journal_settings(
        tmp_path,
        binding=base.hash_json(plan),
        parent_usage=parent.usage,
        limit=mod.CHILD_LIMIT,
        phase_limits=mod.CHILD_PHASE_LIMITS,
    )
    monkeypatch.setattr(mod, "DEFAULT_CHILD", child)
    monkeypatch.setattr(mod, "DEFAULT_REGISTRY", settings["registry_path"])
    monkeypatch.setattr(mod, "load_parent", lambda: parent)
    monkeypatch.setattr(mod, "validate_plan", lambda *args, **kwargs: None)
    with mod.ContinuationJournal(child, **settings) as journal:
        with journal.context("context-a", "semantic", "common20"):
            journal.request(lambda **kwargs: response(), **request())
        saved = {
            "rows": rows,
            "binding": settings["binding"],
            "planned": 27,
            "engine": parent.result["engine"],
            "limits": parent.result["limits"],
            "scope": parent.result["scope"],
            "started_utc": "2026-10-03T07:00:00Z",
            "measured_utc": "2026-10-03T07:01:00Z",
            "usage": journal.summary(),
        }
        base.write_json(child / "fugu.json", saved)
    base.write_json(prepared / "plan.json", plan)
    return SimpleNamespace(
        mod=mod, parent=parent, prepared=prepared, child=child,
        saved=saved, settings=settings,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider_errors", 1),
        ("orphan_attempts", 1),
        ("output_errors", 1),
        ("phase_attempts", {"remainder": 1}),
        ("stop_reason", "provider_error"),
        ("unknown_usage_calls", 1),
        ("prompt_tokens_known_subtotal", 100),
        ("completion_tokens_known_subtotal", 100),
        ("prompt_tokens_unknown_calls", 1),
        ("completion_tokens_unknown_calls", 1),
        ("prompt_tokens_total", None),
        ("completion_tokens_total", None),
        ("sum_request_duration_s", -1),
        ("unknown_duration_calls", 1),
        ("finish_reasons", {"length": 1}),
        ("requested_models", ["changed"]),
        ("served_models", ["changed"]),
        ("parent_attempts", 0),
        ("cumulative_attempts", 1),
        ("registry_reserved_attempts", 0),
        ("cumulative_phase_attempts", {"common20": 1, "remainder": 0}),
        ("unexpected_accounting", True),
        ("replayed_requests_this_process", -1),
        ("replayed_requests_this_process", True),
        ("provider_errors", False),
    ],
)
def test_actual_aggregate_rejects_all_stale_accounting_before_publication(
    aggregate_accounting_fixture, field, value
):
    f = aggregate_accounting_fixture
    saved = copy.deepcopy(f.saved)
    saved["usage"][field] = value
    assert saved["usage"]["attempts"] == 1
    base.write_json(f.child / "fugu.json", saved)
    with pytest.raises(base.EvidenceError, match="accounting"):
        f.mod.aggregate(None, f.prepared, f.child)
    assert f.mod.read_json(f.child / "fugu.json")["rows"] == f.saved["rows"]
    assert not (f.child / "combined.json").exists()
    assert not (f.child / "provenance.json").exists()


@pytest.mark.parametrize("location", ["both", "budget", "registry", "session", "guard"])
def test_actual_aggregate_rejects_post_publication_ownership_stop_with_same_count(
    aggregate_accounting_fixture, location
):
    f = aggregate_accounting_fixture
    if location == "both":
        with f.mod.ContinuationJournal(f.child, **f.settings) as journal:
            journal._stop("continuation_execution_failure")
    elif location == "budget":
        state = f.mod.read_json(f.child / "budget.json")
        state["stop_reason"] = "continuation_execution_failure"
        base.write_json(f.child / "budget.json", state)
    elif location in {"registry", "session"}:
        registry = f.mod.read_json(f.settings["registry_path"])
        registry["stop_reason" if location == "registry" else "session_open"] = (
            "continuation_execution_failure" if location == "registry" else True
        )
        base.write_json(f.settings["registry_path"], registry)
    else:
        base.write_json(f.settings["registry_path"].with_suffix(".guard.json"), {
            "binding": f.settings["binding"], "number": 1, "phase": "common20",
        })
    assert f.mod.read_ledger(f.child).state["attempts"] == f.saved["usage"]["attempts"]
    with pytest.raises(base.EvidenceError, match="accounting|ownership|recovery"):
        f.mod.aggregate(None, f.prepared, f.child)
    assert f.mod.read_json(f.child / "fugu.json") == f.saved
    assert not (f.child / "combined.json").exists()
    assert not (f.child / "provenance.json").exists()


def test_actual_aggregate_accepts_reconciled_accounting(aggregate_accounting_fixture):
    f = aggregate_accounting_fixture
    combined = f.mod.aggregate(None, f.prepared, f.child)
    assert combined["usage"]["attempts"] == 360
    assert combined["rows"][:13] == f.parent.result["rows"][:13]
    assert combined["intervals"][1]["usage"] == f.saved["usage"]


def test_actual_aggregate_retains_process_replay_annotation_without_new_requests(
    aggregate_accounting_fixture
):
    f = aggregate_accounting_fixture
    with f.mod.ContinuationJournal(f.child, **f.settings) as journal:
        with journal.context("context-a", "semantic", "common20"):
            journal.request(
                lambda **kwargs: pytest.fail("replay dispatched another request"),
                **request(),
            )
        saved = copy.deepcopy(f.saved)
        saved["usage"] = journal.summary()
        base.write_json(f.child / "fugu.json", saved)
    assert saved["usage"]["replayed_requests_this_process"] == 1
    combined = f.mod.aggregate(None, f.prepared, f.child)
    assert combined["usage"]["attempts"] == 360
    assert combined["intervals"][1]["usage"]["replayed_requests_this_process"] == 1


@pytest.mark.parametrize("terminal", ["error", "reserved", "unknown_usage"])
def test_actual_aggregate_rejects_later_terminal_or_unknown_usage_accounting(
    aggregate_accounting_fixture, terminal
):
    f = aggregate_accounting_fixture
    # Emulate persisted terminal accounting after the earlier report snapshot.
    path = f.child / "calls/00001.json"
    row = f.mod.read_json(path)
    registry = f.mod.read_json(f.settings["registry_path"])
    state = f.mod.read_json(f.child / "budget.json")
    row["usage"] = {"prompt_tokens": None, "completion_tokens": None}
    if terminal != "unknown_usage":
        row["state"] = terminal
        reason = "provider_error" if terminal == "error" else "orphan_attempt_requires_review"
        state["stop_reason"] = registry["stop_reason"] = reason
        if terminal == "error":
            row["error"] = {"classification": reason, "type": "RuntimeError", "status": 500}
    base.write_json(path, row)
    registry["calls"][0]["sha256"] = base.sha(path.read_bytes())
    base.write_json(f.settings["registry_path"], registry)
    base.write_json(f.child / "budget.json", state)
    assert f.mod.read_ledger(f.child).state["attempts"] == 1
    with pytest.raises(base.EvidenceError, match="accounting"):
        f.mod.aggregate(None, f.prepared, f.child)
    assert f.mod.read_json(f.child / "fugu.json") == f.saved
    assert not (f.child / "combined.json").exists()
    assert not (f.child / "provenance.json").exists()
