"""Native result contracts and actual journal accounting, without scanners/API calls."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from bench import competitive_scanners as scanners


def test_installed_pinned_mcp_native_interface_uses_fake_completion(tmp_path):
    python = Path("/tmp/fugu-competitors-20261005/bin/python")
    if not python.exists():
        pytest.skip("isolated pinned Cisco MCP dependencies not installed")
    root = Path(__file__).resolve().parents[1]
    script = root / "bench/results/2026-10-05-full-workflow/native-interface-correction/native_mcp_probe.py"
    output = tmp_path / "native-interface.json"
    result = subprocess.run([str(python), str(script), "--output", str(output)], cwd=root,
        env={"PATH": os.defpath, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1",
             "PYTHON_DOTENV_DISABLED": "1", "LITELLM_LOCAL_MODEL_COST_MAP": "True"},
        capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    proof = json.loads(output.read_text())
    assert proof["complete"] and proof["fake_dispatches"] == 2
    assert [r["content_type"] for r in proof["native_input_invocations"]] == [
        "description", "description", "parameters", "parameters"]
    assert proof["provider_calls"] == 0 and not proof["target_execution"]


def required(name):
    function = getattr(scanners, name, None)
    assert callable(function), f"scanner behavior missing: {name}"
    return function


def coverage(*names):
    return [{"analyzer": name, "invocation": 0, "success": True, "error_type": None} for name in names]


def test_cisco_mcp_swallowed_error_and_unknown_cannot_complete_or_detect():
    normalize = required("normalize_native")
    raw = {"status": "completed", "is_safe": False, "analyzers": ["YARA", "LLM"],
           "findings": [{"severity": "UNKNOWN", "analyzer": "LLM"}]}
    observed = coverage("YARA", "LLM")
    observed[1].update(success=False, error_type="ValueError")
    row = normalize("cisco-mcp", raw, analyzer_coverage=observed)
    assert row["status"] == "partial" and not row["complete"]
    assert row["flagged"] is False and row["any_alert"] is False
    assert "unknown_severity" in row["reasons"]


def test_cisco_mcp_requires_observed_native_analyzer_coverage():
    row = required("normalize_native")("cisco-mcp", {
        "status": "completed", "is_safe": True, "analyzers": ["YARA", "LLM"], "findings": []})
    assert not row["complete"] and "missing_analyzer_coverage" in row["reasons"]


@pytest.mark.parametrize("scanner,raw,observed,primary,secondary", [
    ("cisco-skill", {"is_safe": True, "findings": [{"severity": "MEDIUM"}],
                     "analyzers_used": ["static_analyzer", "behavioral_analyzer", "llm_analyzer"]},
     coverage("static_analyzer", "behavioral_analyzer", "llm_analyzer"), False, True),
    ("cisco-mcp", {"status": "completed", "is_safe": False,
                   "findings": [{"severity": "LOW"}], "analyzers": ["YARA", "LLM"]},
     coverage("YARA", "LLM"), True, True),
    ("sentinel", {"results": [{"severity": "MEDIUM"}], "summary": {"num_tools_scanned": 1}},
     [], False, True),
    ("mcp-sec-audit", {"total_score": 24.99, "findings": [{"capability": "network"}]},
     [], False, True),
])
def test_frozen_thresholds_keep_primary_and_any_alert_separate(scanner, raw, observed, primary, secondary):
    row = required("normalize_native")(scanner, raw, analyzer_coverage=observed)
    assert row["complete"] and row["flagged"] is primary and row["any_alert"] is secondary


def test_skill_failure_and_budget_notice_remain_partial_with_raw_alert():
    raw = {"is_safe": False, "findings": [{"severity": "HIGH"},
           {"severity": "INFO", "rule_id": "LLM_CONTEXT_BUDGET_EXCEEDED"}],
           "analyzers_used": ["static_analyzer", "behavioral_analyzer", "llm_analyzer"],
           "analyzers_failed": [{"analyzer": "llm_analyzer", "error": "truncated"}]}
    row = required("normalize_native")("cisco-skill", raw,
                    analyzer_coverage=coverage("static_analyzer", "behavioral_analyzer", "llm_analyzer"))
    assert row["flagged"] is True and row["status"] == "partial" and not row["complete"]


def test_absent_or_malformed_native_output_is_failed_not_zero():
    row = required("normalize_native")("sentinel", {"summary": {"num_tools_scanned": 1}})
    assert row["status"] == "failed" and row["flagged"] is None


def test_pairwise_intersection_excludes_partial_and_rejects_input_drift():
    compare = required("paired_summary")
    fugu = [{"id": str(i), "complete": True, "flagged": True, "input_sha256": {"x": "same"}} for i in range(3)]
    other = [dict(r, flagged=False) for r in fugu]
    other[2]["complete"] = False
    result = compare(fugu, other)
    assert result["n"] == 2 and result["fugu_only"] == 2
    assert result["excluded_ids"] == ["2"]
    assert result["fugu"]["wilson95"][0] < 1
    other[0]["input_sha256"] = {"x": "different"}
    with pytest.raises(ValueError, match="input"):
        compare(fugu, other)


def response():
    return SimpleNamespace(model="model", id="inert-response", choices=[SimpleNamespace(
        message=SimpleNamespace(content="{}"), finish_reason="stop")],
        usage=SimpleNamespace(prompt_tokens=5, completion_tokens=2))


class ProviderError(RuntimeError):
    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


def fake_sdk(create, timeout=120):
    return SimpleNamespace(max_retries=0, timeout=timeout, api_key="inert-fixture-key",
                           base_url="https://example.invalid/v1",
                           chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


def request(scanner="cisco-skill", response_format=None):
    return {"model": "openai/model", "messages": [{"role": "user", "content": "inert"}],
            "max_tokens": 8192 if scanner == "cisco-skill" else 1000,
            "temperature": 0.0 if scanner == "cisco-skill" else 0.1,
            "timeout": 120 if scanner == "cisco-skill" else 30,
            "response_format": response_format or {"type": "json_object"}, "drop_params": True}


def test_native_schema_400_fallback_counts_two_and_preserves_options(tmp_path):
    counter_type, bridge = required("NativeRequestCounter"), required("hosted_completion")
    dispatches = []
    def create(**kwargs):
        dispatches.append(kwargs)
        reserved = json.loads((tmp_path / "native/ledger.json").read_text())
        assert reserved["attempts"] == len(dispatches)
        assert reserved["requests"][-1]["state"] == "dispatched"
        if len(dispatches) == 1:
            raise ProviderError("unsupported response_format.json_schema", 400)
        return response()
    async def exercise():
        with counter_type(tmp_path / "native", binding="a" * 64, limit=3) as counter:
            async with bridge(counter, fake_sdk(create), lock=asyncio.Lock(), run_id="inert-run",
                              scanner_id="cisco-skill", context_id="case1",
                              model="model", base_url="https://example.invalid/v1") as completion:
                with pytest.raises(ProviderError):
                    await completion(**request(response_format={"type": "json_schema", "json_schema": {}}),
                                     reasoning_effort="low")
                assert (await completion(**request(), reasoning_effort="low")).choices[0].message.content == "{}"
            assert counter.state["attempts"] == 2 and counter.stop_reason is None
    asyncio.run(exercise())
    records = json.loads((tmp_path / "native/ledger.json").read_text())["requests"]
    assert [d["response_format"]["type"] for d in dispatches] == ["json_schema", "json_object"]
    assert all(d["max_tokens"] == 8192 and d["timeout"] == 120 and d["reasoning_effort"] == "low" for d in dispatches)
    assert [r["number"] for r in records] == [1, 2]
    assert [r["state"] for r in records] == ["error", "completed"]
    assert records[0]["native_options_sha256"] == hashlib.sha256(json.dumps(
        records[0]["native_options"], sort_keys=True).encode()).hexdigest()
    assert records[0]["usage"] is None and records[1]["usage"]["completion_tokens"] == 2
    assert all("inert-fixture-key" not in p.read_text() for p in (tmp_path / "native").rglob("*.json"))


def test_unsupported_native_options_fail_before_sdk_dispatch(tmp_path):
    counter_type, bridge = required("NativeRequestCounter"), required("hosted_completion")
    def create(**kwargs):
        pytest.fail("unsupported request reached SDK")
    async def exercise():
        with counter_type(tmp_path / "native", binding="b" * 64, limit=2) as counter:
            async with bridge(counter, fake_sdk(create, 30), lock=asyncio.Lock(), run_id="inert-run", scanner_id="cisco-mcp",
                              context_id="case1", model="model",
                              base_url="https://example.invalid/v1") as completion:
                with pytest.raises(ValueError, match="unsupported"):
                    await completion(**request("cisco-mcp"), tools=[])
            assert counter.state["attempts"] == 0
    asyncio.run(exercise())


@pytest.mark.parametrize("message,status,reason", [
    ("insufficient_quota", 429, "provider_quota_exhausted"),
    ("synthetic unauthorized", 401, "provider_auth_failure"),
])
def test_quota_auth_stops_survive_restart(tmp_path, message, status, reason):
    counter_type, bridge = required("NativeRequestCounter"), required("hosted_completion")
    dispatches = []
    def create(**kwargs):
        dispatches.append(kwargs)
        raise ProviderError(message, status)
    async def exercise():
        for restart in range(2):
            with counter_type(tmp_path / "native", binding="c" * 64, limit=3) as counter:
                async with bridge(counter, fake_sdk(create), lock=asyncio.Lock(), run_id="inert-run",
                                  scanner_id="cisco-skill", context_id="case1", model="model",
                                  base_url="https://example.invalid/v1") as completion:
                    with pytest.raises(ProviderError if restart == 0 else RuntimeError):
                        await completion(**request())
                assert counter.state["attempts"] == 1 and counter.stop_reason == reason
    asyncio.run(exercise())
    assert len(dispatches) == 1


def test_cap_across_native_fallback_and_both_lanes_persists(tmp_path):
    counter_type, bridge = required("NativeRequestCounter"), required("hosted_completion")
    dispatches = []
    def create(**kwargs):
        dispatches.append(kwargs)
        if len(dispatches) == 1:
            raise ProviderError("unsupported response_format.json_schema", 400)
        return response()
    async def exercise():
        with counter_type(tmp_path / "native", binding="d" * 64, limit=2) as counter:
            lock = asyncio.Lock()
            for scanner in ("cisco-skill", "cisco-mcp"):
                async with bridge(counter, fake_sdk(create, 120 if scanner == "cisco-skill" else 30), lock=lock,
                                  run_id="inert-run", scanner_id=scanner, context_id="case1", model="model",
                                  base_url="https://example.invalid/v1") as completion:
                    if scanner == "cisco-skill":
                        with pytest.raises(ProviderError):
                            await completion(**request(response_format={"type": "json_schema"}))
                        await completion(**request())
                    else:
                        with pytest.raises(RuntimeError, match="request_budget"):
                            await completion(**request(scanner))
            assert counter.state["attempts"] == 2 and counter.stop_reason == "request_budget"
        with counter_type(tmp_path / "native", binding="d" * 64, limit=2) as counter:
            assert counter.state["attempts"] == 2 and counter.stop_reason == "request_budget"
    asyncio.run(exercise())
    assert len(dispatches) == 2


@pytest.mark.parametrize("finding", [
    {"severity": "UNKNOWN", "rule_id": None},
    {"severity": "INFO", "threat_category": "ANALYZER INFRASTRUCTURE", "rule_id": None},
])
def test_exhausted_bounded_native_recovery_is_incomplete(tmp_path, finding):
    counter_type, bridge = required("NativeRequestCounter"), required("hosted_completion")
    dispatches = []
    def create(**kwargs):
        dispatches.append(kwargs)
        raise ProviderError("synthetic temporary rate limit", 429)
    async def exercise():
        with counter_type(tmp_path / "native", binding="e" * 64, limit=8) as counter:
            async with bridge(counter, fake_sdk(create, 30), lock=asyncio.Lock(), run_id="inert-run",
                              scanner_id="cisco-mcp", context_id="case1", model="model",
                              base_url="https://example.invalid/v1") as completion:
                class FakeNativeAnalyzer:
                    async def analyze(self):
                        for _ in range(4):  # Pinned MCP native retries=3; no SDK retries.
                            try:
                                await completion(**request("cisco-mcp"))
                            except ProviderError:
                                continue
                        return [SimpleNamespace(**finding)]
                analyzer, observed = FakeNativeAnalyzer(), coverage("YARA")
                scanners._observe(analyzer, "LLM", observed, asynchronous=True)
                findings = await analyzer.analyze()
                row = scanners.normalize_native("cisco-mcp", {
                    "status": "completed", "is_safe": False, "analyzers": ["YARA", "LLM"],
                    "findings": [vars(f) for f in findings]}, analyzer_coverage=observed)
                assert row["status"] == "partial" and not row["complete"] and not row["flagged"]
            assert counter.state["attempts"] == 4 and counter.stop_reason is None
    asyncio.run(exercise())
    assert len(dispatches) == 4 and all(d["max_tokens"] == 1000 and d["timeout"] == 30 for d in dispatches)


def test_orphan_dispatch_cannot_be_reissued_in_same_process_or_restart(tmp_path):
    counter_type, bridge = required("NativeRequestCounter"), required("hosted_completion")
    dispatches = []
    class Interrupted(BaseException):
        pass
    def create(**kwargs):
        dispatches.append(kwargs)
        raise Interrupted()
    async def exercise():
        for restart in range(2):
            with counter_type(tmp_path / "native", binding="f" * 64, limit=3) as counter:
                async with bridge(counter, fake_sdk(create), lock=asyncio.Lock(), run_id="inert-run",
                                  scanner_id="cisco-skill", context_id="case1", model="model",
                                  base_url="https://example.invalid/v1") as completion:
                    if restart == 0:
                        with pytest.raises(Interrupted):
                            await completion(**request())
                    with pytest.raises(RuntimeError, match="orphan"):
                        await completion(**request())
                assert counter.state["attempts"] == 1 and "orphan" in counter.stop_reason
    asyncio.run(exercise())
    assert len(dispatches) == 1


def test_observed_analyzer_marks_returned_infrastructure_finding_incomplete():
    observe = required("_observe")
    class Analyzer:
        def analyze(self, content, context=None):
            return [SimpleNamespace(severity="UNKNOWN", rule_id=None)]
    analyzer, records = Analyzer(), []
    observe(analyzer, "LLM", records, asynchronous=False)
    analyzer.analyze("inert")
    assert records[0]["success"] is False
    assert records[0]["error_type"] == "native_infrastructure_diagnostic"


def test_schema_packet_requires_two_native_invocations_per_mcp_analyzer():
    raw = {"status": "completed", "is_safe": True, "analyzers": ["YARA", "LLM"], "findings": []}
    row = required("normalize_native")("cisco-mcp", raw, analyzer_coverage=coverage("YARA", "LLM"),
                                       expected_invocations={"YARA": 2, "LLM": 2})
    assert not row["complete"] and "analyzer_invocation_count_mismatch" in row["reasons"]
