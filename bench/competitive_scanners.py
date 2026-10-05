"""Pinned native adapters. Importing this module performs no scans or requests."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import fcntl
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import tempfile
import time
from urllib.parse import urlsplit

from bench.competitive_corpus import input_hashes

PINS = {
    "cisco-skill": {"repository": "cisco-ai-defense/skill-scanner", "commit": "669a2cdf64f81f748f6590d421c935c01c5b01b5",
                    "package": "cisco-ai-skill-scanner", "version": "VCS-derived; verify installed metadata", "license": "Apache-2.0",
                    "cohorts": ["skills"], "threshold": "HIGH or CRITICAL", "analyzers": ["static_analyzer", "behavioral_analyzer", "llm_analyzer"]},
    "cisco-mcp": {"repository": "cisco-ai-defense/mcp-scanner", "commit": "f817899d9391b099f395acd5ae7ff435dccf2a47",
                  "package": "cisco-ai-mcp-scanner", "version": "4.8.5", "license": "Apache-2.0",
                  "cohorts": ["mcp_metadata"], "threshold": "native is_safe=false, excluding analyzer infrastructure", "analyzers": ["YARA", "LLM"]},
    "sentinel": {"repository": "Ventrova/sentinel-scan-cli", "commit": "5cde4b12221178b0ac41213a6b332f9c03fdccc4",
                 "package": "sentinel-scan-cli", "version": "1.4.16", "license": "MIT",
                 "cohorts": ["mcp_metadata"], "threshold": "HIGH (--fail-on high recommendation)", "analyzers": ["offline_manifest"]},
    "mcp-sec-audit": {"repository": "nyit-vancouver/mcp-sec-audit", "commit": "457057a7dfda6b81622a12ee68b74f76f3fbde85",
                      "package": "detection", "version": "0.1.0", "license": "not established; retain sources privately",
                      "cohorts": ["mcp_metadata"], "threshold": "native aggregate risk >=25", "analyzers": ["static_pipeline"]},
}
DIAGNOSTICS = {"LLM_ANALYSIS_FAILED", "LLM_CONTEXT_BUDGET_EXCEEDED"}
NATIVE_LLM = {
    "cisco-skill": {"max_tokens": 8192, "temperature": 0.0, "timeout": 120, "max_retries": 3},
    "cisco-mcp": {"max_tokens": 1000, "temperature": 0.1, "timeout": 30, "max_retries": 3},
}


def json_hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _write(path: Path, value: dict) -> None:
    path = Path(path)
    if path.is_symlink():
        raise ValueError("symlink evidence path")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.is_symlink():
        raise ValueError("symlink temporary evidence path")
    with temporary.open("w") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _incomplete(value) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"coverage_incomplete", "truncated", "omitted", "skipped"} and item:
                return True
            if key.startswith("omitted_") and isinstance(item, (int, list)) and item:
                return True
            if key == "complete" and item is False:
                return True
            if _incomplete(item):
                return True
    elif isinstance(value, list):
        return any(_incomplete(item) for item in value)
    return False


def _diagnostic(finding) -> bool:
    value = finding.get if isinstance(finding, dict) else lambda key: getattr(finding, key, None)
    return value("rule_id") in DIAGNOSTICS or value("threat_category") == "ANALYZER INFRASTRUCTURE"


def normalize_native(scanner_id: str, raw: dict, *, analyzer_coverage=None, expected_invocations=None) -> dict:
    """Preserve native alert thresholds while requiring independently observed coverage."""
    pin = PINS[scanner_id]
    observed = analyzer_coverage or []
    row = {"scanner": scanner_id, "status": "failed", "complete": False, "flagged": None,
           "any_alert": None, "threshold": pin["threshold"], "reasons": [], "per_analyzer": observed}
    if not isinstance(raw, dict):
        row["reasons"] = ["malformed_native_output"]
        return row
    findings = raw.get("results") if scanner_id == "sentinel" else raw.get("findings")
    if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
        row["reasons"] = ["malformed_native_output"]
        return row
    reasons = []
    if scanner_id.startswith("cisco-"):
        native_analyzers = raw.get("analyzers_used" if scanner_id == "cisco-skill" else "analyzers", [])
        expected = set(pin["analyzers"])
        if not expected.issubset(native_analyzers) or not expected.issubset({o.get("analyzer") for o in observed}):
            reasons.append("missing_analyzer_coverage")
        for name, count in (expected_invocations or {name: 1 for name in expected}).items():
            if sum(o.get("analyzer") == name for o in observed) != count:
                reasons.append("analyzer_invocation_count_mismatch")
        if any(o.get("success") is not True for o in observed) or raw.get("analyzers_failed") or raw.get("analyzer_errors"):
            reasons.append("analyzer_failure")
        if scanner_id == "cisco-mcp" and raw.get("status") != "completed":
            reasons.append("native_incomplete_status")
        if type(raw.get("is_safe")) is not bool:
            reasons.append("unknown_native_safety")
    if scanner_id == "sentinel" and raw.get("summary", {}).get("num_tools_scanned") != 1:
        reasons.append("native_input_count_mismatch")
    if _incomplete(raw.get("scan_metadata", {})):
        reasons.append("native_omitted_coverage")
    if any(_diagnostic(f) for f in findings):
        reasons.append("native_diagnostic_coverage")
    security = [f for f in findings if not _diagnostic(f)]
    if scanner_id == "mcp-sec-audit":
        score = raw.get("total_score")
        if type(score) not in (int, float) or not math.isfinite(score):
            row["reasons"] = ["malformed_native_score"]
            return row
        primary, secondary = score >= 25, bool(security)
    else:
        allowed = {"SAFE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if any(f.get("severity") not in allowed for f in security):
            reasons.append("unknown_severity")
        security = [f for f in security if f.get("severity") in allowed - {"SAFE"}]
        secondary = bool(security)
        primary = secondary if scanner_id == "cisco-mcp" else any(f["severity"] in {"HIGH", "CRITICAL"} for f in security)
    row.update(status="partial" if reasons else "completed", complete=not reasons,
               flagged=primary, any_alert=secondary, reasons=sorted(set(reasons)))
    return row


def _wilson(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    z = 1.959963984540054
    p, denominator = successes / total, 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0.0, center - radius), min(1.0, center + radius)]


def paired_summary(fugu: list[dict], competitor: list[dict]) -> dict:
    """Caller passes one supported cohort/label. Match complete identical input IDs."""
    if len({r["id"] for r in fugu}) != len(fugu) or len({r["id"] for r in competitor}) != len(competitor):
        raise ValueError("duplicate result identity")
    lookup = {r["id"]: r for r in competitor}
    pairs, excluded = [], []
    for left in fugu:
        right = lookup.get(left["id"])
        if right is not None and (not left.get("input_sha256") or left.get("input_sha256") != right.get("input_sha256")):
            raise ValueError("matched input hash drift")
        if right is None or not left.get("complete") or not right.get("complete") or type(left.get("flagged")) is not bool or type(right.get("flagged")) is not bool:
            excluded.append(left["id"])
        else:
            pairs.append((left, right))
    n = len(pairs)
    counts = [sum(pair[i]["flagged"] for pair in pairs) for i in (0, 1)]
    return {"n": n, "matched_ids": [p[0]["id"] for p in pairs], "excluded_ids": excluded,
            "fugu": {"alerts": counts[0], "wilson95": _wilson(counts[0], n)},
            "competitor": {"alerts": counts[1], "wilson95": _wilson(counts[1], n)},
            "fugu_only": sum(a["flagged"] and not b["flagged"] for a, b in pairs),
            "competitor_only": sum(b["flagged"] and not a["flagged"] for a, b in pairs)}


class NativeRequestCounter:
    """One private, persisted 1800-dispatch counter shared by both Cisco lanes.

    Ordinary provider exceptions are returned to native bounded recovery code.
    Quota/auth failure, an orphan dispatch, and the aggregate cap are sticky.
    This neither subclasses nor changes Fugu's first-error RequestJournal.
    """
    def __init__(self, root: Path, *, binding: str, limit: int = 1800):
        self.root = Path(root)
        if type(limit) is not int or not 0 < limit <= 1800 or len(binding) != 64:
            raise ValueError("invalid native counter plan/budget")
        if any(p.is_symlink() for p in (self.root, *self.root.parents)):
            raise ValueError("symlink native counter root")
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "ledger.json"
        lock_path = self.root / "counter.lock"
        if lock_path.is_symlink() or self.path.is_symlink():
            raise ValueError("symlink native counter evidence")
        self._lock = lock_path.open("a")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.state = json.loads(self.path.read_text()) if self.path.exists() else {
                "schema": 1, "binding": binding, "limit": limit,
                "attempts": 0, "stop_reason": None, "requests": []}
            if (self.state["schema"], self.state["binding"], self.state["limit"]) != (1, binding, limit):
                raise ValueError("native counter plan/budget drift")
            rows = self.state["requests"]
            if self.state["attempts"] != len(rows) or [r["number"] for r in rows] != list(range(1, len(rows) + 1)):
                raise ValueError("native dispatch ledger mismatch")
            if any(r["state"] == "dispatched" for r in rows):
                self.state["stop_reason"] = self.stop_reason or "orphan_dispatch_requires_review"
            if len(rows) >= limit:
                self.state["stop_reason"] = self.stop_reason or "request_budget"
            self._persist()
        except BaseException:
            self._lock.close()
            raise

    @property
    def stop_reason(self):
        return self.state["stop_reason"]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._lock.close()

    def _persist(self):
        try:
            _write(self.path, self.state)
        except Exception:
            self.state["stop_reason"] = "evidence_write_failure"
            raise

    def request(self, dispatch, *, request: dict, metadata: dict):
        if any(r["state"] == "dispatched" for r in self.state["requests"]):
            self.state["stop_reason"] = self.stop_reason or "orphan_dispatch_requires_review"
            self._persist()
        if self.stop_reason:
            raise RuntimeError(self.stop_reason)
        if self.state["attempts"] >= self.state["limit"]:
            self.state["stop_reason"] = "request_budget"
            self._persist()
            raise RuntimeError(self.stop_reason)
        number = self.state["attempts"] + 1
        row = {**metadata, "number": number, "state": "dispatched",
               "started_utc": datetime.now(timezone.utc).isoformat(),
               "request_sha256": json_hash(request), "response_sha256": None,
               "usage": None, "served_model": None, "finish_reason": None,
               "response_chars": None, "latency_s": None, "error": None}
        request_path = self.root / "requests" / f"{number:06d}.json"
        _write(request_path, request)
        row.update(request_artifact=request_path.relative_to(self.root).as_posix(),
                   request_artifact_sha256=hashlib.sha256(request_path.read_bytes()).hexdigest(),
                   response_artifact=None, response_artifact_sha256=None)
        self.state["attempts"] = number
        self.state["requests"].append(row)
        self._persist()  # Durable reservation BEFORE the real SDK create.
        started = time.monotonic()
        network_completed = False
        try:
            response = dispatch()
            network_completed = True
            plain = _plain(response.model_dump() if hasattr(response, "model_dump") else response)
            response_path = self.root / "responses" / f"{number:06d}.json"
            _write(response_path, plain)
            row.update(response_artifact=response_path.relative_to(self.root).as_posix(),
                       response_artifact_sha256=hashlib.sha256(response_path.read_bytes()).hexdigest())
            usage = plain.get("usage") or {}
            usage = {key: usage.get(key) if type(usage.get(key)) is int and usage[key] >= 0 else None
                     for key in ("prompt_tokens", "completion_tokens")}
            choice = (plain.get("choices") or [{}])[0]
            content = choice.get("message", {}).get("content")
            row.update(state="completed", response_sha256=json_hash(plain), usage=usage,
                       served_model=plain.get("model"), finish_reason=choice.get("finish_reason"),
                       response_chars=len(content) if isinstance(content, str) else None)
            return response
        except Exception as exc:
            status = getattr(exc, "status_code", None)
            status = status if type(status) is int else None
            # Inspect in memory only; never retain provider messages/body or credentials.
            message = (str(getattr(exc, "code", "")) + " " + str(exc)).lower()
            kind = "provider_error"
            if network_completed:
                kind = "evidence_capture_failure"
            elif status in (401, 403):
                kind = "provider_auth_failure"
            elif status == 402 or any(s in message for s in (
                "insufficient_quota", "quota exhausted", "quota exceeded", "insufficient balance",
                "credit balance", "daily quota", "credits exhausted")):
                kind = "provider_quota_exhausted"
            elif status == 429:
                kind = "provider_rate_limit"
            row.update(state="error", error={"type": type(exc).__name__, "status": status, "kind": kind})
            if kind in {"provider_auth_failure", "provider_quota_exhausted", "evidence_capture_failure"}:
                self.state["stop_reason"] = kind
            raise  # Preserve original exception for native schema fallback/transient recovery.
        finally:
            row["latency_s"] = time.monotonic() - started
            if row["state"] == "dispatched":
                self.state["stop_reason"] = self.stop_reason or "orphan_dispatch_requires_review"
            if number == self.state["limit"]:
                self.state["stop_reason"] = self.stop_reason or "request_budget"
            self._persist()


@asynccontextmanager
async def hosted_completion(counter, sdk, *, lock, run_id: str, scanner_id: str,
                            context_id: str, model: str, base_url: str):
    """Serialize native case callbacks; all actual creates enter one native counter.

    Supported native schema/reasoning parameters are forwarded unchanged. Full
    request and option hashes include them; there is no four-field Fugu wrapper.
    The caller shares lock and counter across BOTH Cisco lanes.
    """
    policy = NATIVE_LLM[scanner_id]
    if sdk.max_retries != 0 or sdk.timeout != policy["timeout"]:
        raise ValueError("SDK retry/timeout contract drift")
    parsed_url = urlsplit(base_url)
    if parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
        raise ValueError("unsafe provider URL for evidence")
    if str(sdk.base_url).rstrip("/") != base_url.rstrip("/"):
        raise ValueError("SDK provider routing contract drift")
    async with lock:
        ordinal = 0
        request_lock = asyncio.Lock()
        async def completion(**kwargs):
            nonlocal ordinal
            allowed = {"model", "messages", "max_tokens", "temperature", "timeout", "api_key",
                       "api_base", "drop_params", "response_format", "reasoning_effort"}
            if set(kwargs) - allowed:
                raise ValueError("unsupported native request options")
            requested_model = kwargs["model"]
            normalized_model = requested_model.removeprefix("openai/")
            if normalized_model != model or kwargs.get("api_base", base_url) != base_url:
                raise ValueError("native model/routing contract drift")
            if any(kwargs.get(key) != policy[key] for key in ("max_tokens", "temperature", "timeout")):
                raise ValueError("native cap/temperature/timeout contract drift")
            if kwargs.get("api_key", sdk.api_key) != sdk.api_key:
                raise ValueError("native credential routing mismatch")
            wire = {key: value for key, value in kwargs.items() if key not in {"api_key", "api_base", "drop_params"}}
            wire["model"] = normalized_model
            options = {"provider": "openai-compatible", "native_model": requested_model,
                       "sdk_model": normalized_model, "base_url": base_url, "sdk_max_retries": 0,
                       "native_drop_params": kwargs.get("drop_params"),
                       "native_max_retries": policy["max_retries"],
                       **{key: value for key, value in wire.items() if key not in {"model", "messages"}}}
            async with request_lock:
                metadata = {"run_id": run_id, "context_id": context_id, "stage": f"competitor:{scanner_id}",
                            "phase": "competitor", "ordinal": ordinal,
                            "native_options_sha256": json_hash(options), "native_options": options}
                ordinal += 1
                return await asyncio.to_thread(counter.request, lambda: sdk.chat.completions.create(**wire),
                                               request=wire, metadata=metadata)
        yield completion


def _plain(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if hasattr(value, "to_dict"):
        return _plain(value.to_dict())
    if hasattr(value, "__dict__"):
        return _plain(vars(value))
    return value


def _observe(analyzer, name: str, observations: list[dict], *, asynchronous: bool):
    original = analyzer.analyze
    def finish(row, result):
        error = getattr(analyzer, "last_error", None)
        if any(getattr(finding, "severity", None) == "UNKNOWN" or _diagnostic(finding)
               for finding in (result if isinstance(result, list) else [])):
            error = "native_infrastructure_diagnostic"
        row.update(success=not error, error_type="native_analyzer_error" if error else None)
        if error == "native_infrastructure_diagnostic":
            row["error_type"] = error
    def start():
        row = {"analyzer": name, "invocation": sum(r["analyzer"] == name for r in observations),
               "success": False, "error_type": None}
        observations.append(row)
        return row
    if asynchronous:
        async def observed(*args, **kwargs):
            row = start()
            try:
                result = await original(*args, **kwargs)
                finish(row, result)
                return result
            except Exception as exc:
                row["error_type"] = type(exc).__name__
                raise
    else:
        def observed(*args, **kwargs):
            row = start()
            try:
                result = original(*args, **kwargs)
                finish(row, result)
                return result
            except Exception as exc:
                row["error_type"] = type(exc).__name__
                raise
    analyzer.analyze = observed


async def run_native(scanner_id: str, target: Path, *, completion=None, llm_config=None,
                     source_root: Path | None = None) -> dict:
    """Data-phase entry point; caller owns release, source checks and counter context.

    Native output stays private. No auditee servers/target code are executed.
    Missing packages return unavailable; all other native failures retain errors.
    """
    input_hashes(target)
    observations = []
    raw = None
    expected_invocations = None
    try:
        if scanner_id in {"cisco-skill", "cisco-mcp"} and (completion is None or not llm_config):
            raise ModuleNotFoundError("observed hosted transport unavailable")
        if scanner_id == "cisco-skill":
            from skill_scanner.core.analyzers.static import StaticAnalyzer
            from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
            from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
            from skill_scanner.core.scanner import SkillScanner
            handler = importlib.import_module("skill_scanner.core.analyzers.llm_request_handler")
            llm = LLMAnalyzer(model=llm_config["model"], api_key=llm_config["api_key"],
                              provider="openai-compatible", base_url=llm_config["base_url"],
                              **NATIVE_LLM[scanner_id])
            analyzers = [StaticAnalyzer(), BehavioralAnalyzer(use_alignment_verification=False), llm]
            for analyzer, name in zip(analyzers, PINS[scanner_id]["analyzers"]):
                _observe(analyzer, name, observations, asynchronous=False)
            loop = asyncio.get_running_loop()
            async def routed(**kwargs):
                return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(completion(**kwargs), loop))
            previous = handler._get_litellm_acompletion
            handler._get_litellm_acompletion = lambda **kwargs: routed
            try:
                result = await asyncio.to_thread(SkillScanner(analyzers=analyzers).scan_skill, target)
                raw = _plain(result.to_dict())
            finally:
                handler._get_litellm_acompletion = previous
        elif scanner_id == "cisco-mcp":
            from mcpscanner.config import Config
            from mcpscanner.core.analyzers import YaraAnalyzer, LLMAnalyzer
            from mcpscanner.core.analyzers.static_analyzer import StaticAnalyzer
            module = importlib.import_module("mcpscanner.core.analyzers.llm_analyzer")
            config = Config(llm_model="openai/" + llm_config["model"], llm_provider_api_key=llm_config["api_key"],
                            llm_base_url=llm_config["base_url"], llm_max_tokens=NATIVE_LLM[scanner_id]["max_tokens"],
                            llm_max_retries=NATIVE_LLM[scanner_id]["max_retries"],
                            llm_timeout=NATIVE_LLM[scanner_id]["timeout"],
                            llm_temperature=NATIVE_LLM[scanner_id]["temperature"])
            analyzers = [YaraAnalyzer(), LLMAnalyzer(config)]
            for analyzer, name in zip(analyzers, PINS[scanner_id]["analyzers"]):
                _observe(analyzer, name, observations, asynchronous=True)
            previous = module.acompletion
            module.acompletion = completion
            try:
                results = await StaticAnalyzer(analyzers=analyzers, config=config).scan_tools_file(Path(target) / "tools.json")
                if len(results) != 1:
                    raise ValueError("unexpected native tool count")
                raw = _plain(results[0])
                tool = json.loads((Path(target) / "tools.json").read_text())["tools"][0]
                expected_invocations = {name: 1 + int("inputSchema" in tool) for name in PINS[scanner_id]["analyzers"]}
            finally:
                module.acompletion = previous
        elif scanner_id == "sentinel":
            native = importlib.import_module("sentinel_scan")
            raw = native.scan_mcp_manifest(json.loads((Path(target) / "tools.json").read_text()))
        elif scanner_id == "mcp-sec-audit":
            if source_root is None:
                raise ModuleNotFoundError("pinned source root unavailable")
            from detection.cli import _load_builtin_plugins
            from detection.core.registry import DetectorRegistry
            from detection.rules import load_rulebook
            from detection.pipelines import run_static_pipeline
            source_root = Path(source_root)
            rulebook = source_root / "detection/rules/keywords.toml"
            if hashlib.sha256(rulebook.read_bytes()).hexdigest() != "c7529b02d5ae056f67c6b46eb75616b897107044d1b6bf4a1c38af823fcce1b4":
                raise ValueError("native rulebook pin mismatch")
            registry = DetectorRegistry()
            _load_builtin_plugins(registry, load_rulebook(rulebook))
            tool = json.loads((Path(target) / "tools.json").read_text())["tools"][0]
            wrapper = {"tool_name": tool["name"], "tool_content": tool["description"]}
            with tempfile.TemporaryDirectory(prefix="fugu-competitive-mcp-sec-") as folder:
                (Path(folder) / "tool.json").write_text(json.dumps(wrapper, ensure_ascii=False))
                raw = _plain(run_static_pipeline(Path(folder), registry, source_root / "detection/mitigation/policy_templates"))
        else:
            raise ValueError("unknown scanner")
        return {**normalize_native(scanner_id, raw, analyzer_coverage=observations,
                                   expected_invocations=expected_invocations), "raw": raw}
    except Exception as exc:
        unavailable = isinstance(exc, (ImportError, ModuleNotFoundError))
        return {"scanner": scanner_id, "status": "unavailable" if unavailable else "failed", "complete": False,
                "flagged": None, "any_alert": None, "reasons": [type(exc).__name__], "per_analyzer": observations, "raw": raw}
