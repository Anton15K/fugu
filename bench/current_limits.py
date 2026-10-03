"""Fixed-input production benchmark. Preparation is offline; live dispatch is gated.

The SDK observer records responses unchanged. Parsing, model routing and narrow
response recovery belong to the frozen production engine, never this observer.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib
from importlib import metadata
import inspect
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "bench/results/2026-10-02-full"
DEFAULT_OUTPUT = ROOT / "bench/results/2026-10-03-current-limits"
METADATA_NAMES = {"manifest.json", "manifest.fugu.json", "set.json"}
MEDIUM = {"medium", "high", "critical"}
MAX_ATTEMPTS = 1900
FIXED_CASE_MANIFEST_SHA256 = "f9b31035908d217a822079dd190c4d5797f86646c65f01c2e06b1f57ae3e91b1"


class EvidenceError(RuntimeError):
    """An evidence/ownership mismatch: stop before a provider request."""


class JournalStopped(RuntimeError):
    """The persistent request budget or provider stop latch is closed."""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_json(value: Any) -> str:
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":")).encode())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _usage_number(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _provider_reason(exc: Exception) -> tuple[str, int | None]:
    status = getattr(exc, "status_code", None)
    status = status if type(status) is int else None
    # Only classify these strings in memory. Never retain the exception body.
    text = (str(getattr(exc, "code", "")) + " " + str(exc)).lower()
    if status in (401, 403):
        return "provider_auth_failure", status
    if status == 402 or any(s in text for s in (
        "insufficient_quota", "quota exhausted", "quota exceeded",
        "insufficient balance", "credit balance", "daily quota",
    )):
        return "provider_quota_exhausted", status
    if status == 429:
        return "provider_rate_limit", status
    return "provider_error", status


class RequestJournal:
    """Single-owner, durable reservations and exact successful-response replay.

    A reservation that has no terminal response is an orphan, not permission to
    reissue a request. POSIX flock releases ownership when the process exits.
    """

    def __init__(self, directory: Path, *, limit: int, binding: str,
                 phase_limits: dict[str, int] | None = None,
                 expected_output_tokens: int | None = None,
                 expected_models: list[str] | None = None) -> None:
        if not 1 <= limit <= MAX_ATTEMPTS:
            raise EvidenceError("attempt limit must be within 1..1900")
        self.directory, self.limit, self.binding = Path(directory), limit, binding
        self.directory.mkdir(parents=True, exist_ok=True)
        self._owner = (self.directory / ".journal.lock").open("a")
        try:
            fcntl.flock(self._owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._owner.close()
            raise EvidenceError("request journal already owned") from None
        self._lock = threading.RLock()
        self._context: tuple[str, str, str] | None = None
        self._ordinal = 0
        self.replayed = 0
        self.phase_limits = phase_limits or {}
        self.expected_output_tokens = expected_output_tokens
        self.expected_models = sorted(expected_models) if expected_models is not None else None
        self.records: list[dict] = []
        try:
            state_path = self.directory / "budget.json"
            self.state = read_json(state_path) if state_path.exists() else {
                "schema": 1, "binding": binding, "limit": limit,
                "phase_limits": self.phase_limits, "attempts": 0, "stop_reason": None,
                "expected_output_tokens": self.expected_output_tokens,
                "expected_models": self.expected_models,
            }
            if any(self.state[k] != v for k, v in (
                ("binding", binding), ("limit", limit), ("phase_limits", self.phase_limits),
                ("expected_output_tokens", self.expected_output_tokens),
                ("expected_models", self.expected_models),
            )):
                raise EvidenceError("journal binding or budget changed")
            provider_stop = None
            for number in range(1, self.state["attempts"] + 1):
                path = self._path(number)
                row = read_json(path) if path.exists() else {
                    "number": number, "state": "reserved", "context": None,
                    "stage": None, "phase": None, "ordinal": None,
                    "usage": {"prompt_tokens": None, "completion_tokens": None},
                }
                if not isinstance(row, dict) or type(row.get("number")) is not int or row["number"] != number:
                    raise EvidenceError("journal request number mismatch")
                if row.get("state") not in ("reserved", "returned", "error"):
                    raise EvidenceError("unknown journal request state")
                if row["state"] == "error":
                    error = row.get("error")
                    if (not isinstance(error, dict)
                        or error.get("classification") not in (
                            "provider_quota_exhausted", "provider_auth_failure",
                            "provider_rate_limit", "provider_error")
                        or type(error.get("status")) not in (int, type(None))
                        or not isinstance(error.get("type"), str) or not error["type"]):
                        raise EvidenceError("invalid saved provider error")
                    provider_stop = provider_stop or error["classification"]
                if row["state"] == "returned" and isinstance(row.get("raw_response"), str):
                    if sha(row["raw_response"].encode()) != row.get("response_sha256"):
                        raise EvidenceError("saved response hash mismatch")
                self.records.append(row)
            extra = list((self.directory / "calls").glob("*.json"))
            if len(extra) > self.state["attempts"]:
                raise EvidenceError("journal contains unowned request records")
            # A terminal error may have reached disk before its budget stop write.
            # Recover its original classification before exposing this journal.
            self.state["stop_reason"] = self.state["stop_reason"] or provider_stop
            if any(r["state"] == "reserved" for r in self.records):
                self.state["stop_reason"] = self.state["stop_reason"] or "orphan_attempt_requires_review"
            write_json(state_path, self.state)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self) -> None:
        if not self._owner.closed:
            fcntl.flock(self._owner, fcntl.LOCK_UN)
            self._owner.close()

    def _path(self, number: int) -> Path:
        return self.directory / "calls" / f"{number:05d}.json"

    @property
    def stop_reason(self) -> str | None:
        return self.state["stop_reason"]

    @contextmanager
    def context(self, audit: str, stage: str, phase: str):
        with self._lock:
            if self._context is not None:
                raise EvidenceError("concurrent or nested audit context")
            self._context, self._ordinal = (audit, stage, phase), 0
        try:
            yield
        finally:
            with self._lock:
                self._context = None

    def _stop(self, reason: str) -> None:
        with self._lock:
            self.state["stop_reason"] = self.state["stop_reason"] or reason
            write_json(self.directory / "budget.json", self.state)

    def _deny(self, message: str) -> None:
        self._stop("request_contract_drift")
        raise EvidenceError(message)

    def _write_record(self, row: dict) -> None:
        try:
            write_json(self._path(row["number"]), row)
        except OSError:
            row["state"] = "reserved"
            self.state["stop_reason"] = self.state["stop_reason"] or "journal_write_failure"
            try:
                write_json(self.directory / "budget.json", self.state)
            except OSError:
                pass  # The in-memory latch still prevents stage fallback.
            raise JournalStopped("journal_write_failure") from None

    def request(self, dispatch, **kwargs):
        # Deliberately whitelist the production request surface, not client config.
        if set(kwargs) != {"model", "messages", "temperature", "max_tokens"}:
            self._deny("unsupported request fields")
        if not isinstance(kwargs["model"], str) or type(kwargs["max_tokens"]) is not int or not 1 <= kwargs["max_tokens"] <= 4096:
            self._deny("unsupported request model/output limit")
        if self.expected_output_tokens is not None and kwargs["max_tokens"] != self.expected_output_tokens:
            self._stop("request_output_contract_drift")
            raise EvidenceError("request output contract changed")
        if self.expected_models is not None and kwargs["model"] not in self.expected_models:
            self._stop("request_model_contract_drift")
            raise EvidenceError("request model contract changed")
        messages = kwargs["messages"]
        if not isinstance(messages, list) or any(
            not isinstance(m, dict) or set(m) != {"role", "content"}
            or m["role"] not in {"system", "user"} or not isinstance(m["content"], str)
            for m in messages
        ):
            self._deny("unsupported request messages")
        with self._lock:  # Serialize all real SDK attempts, including stage fallback.
            if self._context is None:
                raise EvidenceError("request has no owned audit context")
            context, stage, phase = self._context
            ordinal = self._ordinal
            self._ordinal += 1
            signature = hash_json(kwargs)
            previous = next((r for r in self.records if
                             (r.get("context"), r.get("stage"), r.get("ordinal"))
                             == (context, stage, ordinal)), None)
            if previous is not None:
                if previous.get("request_sha256") != signature or previous.get("phase") != phase:
                    self._deny("saved request drift")
                if previous["state"] == "returned":
                    self.replayed += 1
                    usage = previous["usage"]
                    return SimpleNamespace(
                        id=previous.get("response_id"), model=previous.get("served_model"),
                        choices=[SimpleNamespace(message=SimpleNamespace(
                            content=previous["raw_response"]),
                            finish_reason=previous["finish_reason"])] if previous["choice_present"] else [],
                        usage=SimpleNamespace(**usage) if previous["usage_object_present"] else None,
                    )
                raise JournalStopped(self.stop_reason or "orphan_attempt_requires_review")
            if self.stop_reason:
                raise JournalStopped(self.stop_reason)
            if self.state["attempts"] >= self.limit:
                self._stop("attempt_budget_exhausted")
                raise JournalStopped(self.stop_reason)
            phase_count = sum(r.get("phase") == phase for r in self.records)
            if phase in self.phase_limits and phase_count >= self.phase_limits[phase]:
                self._stop("phase_attempt_budget_exhausted")
                raise JournalStopped(self.stop_reason)
            number = self.state["attempts"] + 1
            row = {
                "number": number, "context": context, "stage": stage, "phase": phase,
                "ordinal": ordinal, "state": "reserved", "reserved_utc": utc(),
                "request_sha256": signature, "messages_sha256": hash_json(messages),
                "messages": messages, "requested_model": kwargs["model"],
                "max_tokens": kwargs["max_tokens"], "temperature": kwargs["temperature"],
                "usage": {"prompt_tokens": None, "completion_tokens": None},
            }
            self.state["attempts"] = number
            self.records.append(row)
            try:
                write_json(self.directory / "budget.json", self.state)
            except OSError:
                self.state["stop_reason"] = "journal_write_failure"
                raise JournalStopped("journal_write_failure") from None
            self._write_record(row)
            started = time.perf_counter()
            try:
                result = dispatch(**kwargs)
            except Exception as exc:
                reason, status = _provider_reason(exc)
                row.update(state="error", duration_s=time.perf_counter() - started,
                           error={"classification": reason, "status": status,
                                  "type": type(exc).__name__})
                self._write_record(row)
                self._stop(reason)
                raise JournalStopped(reason) from None
            except BaseException:
                # Its dispatch state is unknown; retain the reservation and stop.
                self._stop("orphan_attempt_requires_review")
                raise
            # No parsing or repair; return the original SDK object unchanged.
            choices = getattr(result, "choices", [])
            choice = choices[0] if choices else None
            raw = getattr(getattr(choice, "message", None), "content", None)
            valid_raw = raw is None or isinstance(raw, str)
            model = getattr(result, "model", None)
            response_id = getattr(result, "id", None)
            finish_reason = getattr(choice, "finish_reason", None)
            usage = getattr(result, "usage", None)
            row.update(
                state="returned", duration_s=time.perf_counter() - started,
                served_model=model if isinstance(model, str) else None,
                response_id=response_id if isinstance(response_id, str) else None,
                raw_response=raw if valid_raw else None,
                response_sha256=sha(raw.encode()) if isinstance(raw, str) else None,
                finish_reason=finish_reason if isinstance(finish_reason, str) else None,
                choice_present=choice is not None,
                usage_object_present=usage is not None,
                usage={k: _usage_number(getattr(usage, k, None))
                       for k in ("prompt_tokens", "completion_tokens")},
                output_error=None if choice and valid_raw else "missing_or_invalid_choice",
            )
            self._write_record(row)
            return result

    def wrap_client(self, sdk):
        journal = self

        class ObservedClient:
            def __init__(self, delegate):
                self._delegate = delegate
                self.chat = SimpleNamespace(completions=SimpleNamespace(
                    create=lambda **kwargs: journal.request(delegate.chat.completions.create, **kwargs)))

            def with_options(self, **options):
                if options != {"max_retries": 0, "timeout": 90}:
                    raise EvidenceError("SDK policy changed")
                return ObservedClient(self._delegate.with_options(**options))

        return ObservedClient(sdk)

    def summary(self) -> dict:
        result = {"attempts": self.state["attempts"], "stop_reason": self.stop_reason,
                  "replayed_requests_this_process": self.replayed,
                  "orphan_attempts": sum(r["state"] == "reserved" for r in self.records),
                  "provider_errors": sum(r["state"] == "error" for r in self.records),
                  "output_errors": sum(bool(r.get("output_error")) for r in self.records),
                  "sum_request_duration_s": sum(r.get("duration_s", 0) for r in self.records),
                  "unknown_duration_calls": sum("duration_s" not in r for r in self.records),
                  "unknown_usage_calls": sum(any(r["usage"][k] is None
                      for k in ("prompt_tokens", "completion_tokens")) for r in self.records),
                  "finish_reasons": dict(Counter(r.get("finish_reason") or "unknown" for r in self.records)),
                  "requested_models": sorted({r["requested_model"] for r in self.records if "requested_model" in r}),
                  "served_models": sorted({r["served_model"] for r in self.records if r.get("served_model")}),
                  "phase_attempts": dict(Counter(r.get("phase") or "unknown" for r in self.records))}
        for field in ("prompt_tokens", "completion_tokens"):
            unknown = sum(r["usage"][field] is None for r in self.records)
            subtotal = sum(r["usage"][field] for r in self.records if r["usage"][field] is not None)
            result[field + "_known_subtotal"] = subtotal
            result[field + "_unknown_calls"] = unknown
            result[field + "_total"] = subtotal if not unknown else None
        return result


@contextmanager
def observe_sdk(journal: RequestJournal, sdk_factory=None):
    """Observe only make_client's SDK boundary, never stage make_call/recovery."""
    client_module = importlib.import_module("fugu.client")
    original = client_module.make_client
    factory = sdk_factory or original
    def observed_factory(*args, **kwargs):
        try:
            return journal.wrap_client(factory(*args, **kwargs))
        except Exception:
            journal._stop("provider_setup_failure")
            raise JournalStopped("provider_setup_failure") from None

    client_module.make_client = observed_factory
    try:
        yield
    finally:
        client_module.make_client = original


def input_hashes(target: Path) -> dict[str, str]:
    target = Path(target)
    if target.is_symlink():
        raise EvidenceError("symlink input")
    result = {}
    for path in sorted(target.rglob("*")):
        if path.is_symlink():
            raise EvidenceError("symlink input")
        if path.is_file() and path.name not in METADATA_NAMES:
            result[path.relative_to(target).as_posix()] = sha(path.read_bytes())
    return result


def fingerprint(hashes: dict) -> str:
    # Preserve the historical fixed-group identifier, including JSON whitespace.
    return sha(json.dumps(hashes, sort_keys=True).encode())


def case_target(case: dict) -> Path:
    target = Path(case["target"])
    return target if target.is_absolute() else ROOT / target


def prepare_inputs(manifest: dict, output: Path, source_root: Path) -> dict:
    cases = []
    for index, original in enumerate(manifest["cases"]):
        source = source_root / original["target"]
        if not source.resolve().is_relative_to(source_root.resolve()):
            raise EvidenceError("input path leaves source root")
        if input_hashes(source) != original["input_sha256"]:
            raise EvidenceError("frozen input hash mismatch")
        target = Path(output).resolve() / "targets" / f"{index:04d}"
        if target.exists():
            if input_hashes(target) != original["input_sha256"]:
                raise EvidenceError("copied input hash mismatch")
        else:
            target.mkdir(parents=True)
            for name, expected in original["input_sha256"].items():
                destination = target / name
                if not destination.resolve().is_relative_to(target):
                    raise EvidenceError("input filename leaves target")
                data = (source / name).read_bytes()
                if sha(data) != expected:
                    raise EvidenceError("input hash changed during copy")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
        portable = target.relative_to(ROOT.resolve()).as_posix() if target.is_relative_to(ROOT.resolve()) else str(target)
        cases.append(dict(original, target=portable, original_target=original["target"]))
    return {k: v for k, v in manifest.items() if k != "cases"} | {"cases": cases}


class AuditCache:
    def __init__(self, directory: Path, *, binding: str):
        self.directory, self.binding = Path(directory) / "audits", binding

    def _path(self, key: str) -> Path:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", key):
            raise EvidenceError("invalid cache key")
        return self.directory / (key + ".json")

    def get(self, key: str, hashes: dict) -> list[dict] | None:
        path = self._path(key)
        if not path.exists():
            return None
        data = read_json(path)
        if data["input_sha256"] != hashes or data["binding"] != self.binding:
            raise EvidenceError("cache input or engine binding mismatch")
        return data["stages"]

    def save(self, key: str, hashes: dict, stages: list[dict]) -> None:
        write_json(self._path(key), {"binding": self.binding, "input_sha256": hashes, "stages": stages})


def stage_state(result: dict) -> str:
    metrics = result.get("metrics", {})
    if metrics.get("unattempted"):
        return "unattempted"
    if not result.get("ok"):
        return "failed"
    if metrics.get("skipped"):
        return "unavailable"
    if metrics.get("coverage_incomplete") or metrics.get("omitted_units", 0):
        return "partial"
    return "completed"


def summarize_rows(rows: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for row in rows:
        groups[(row["cohort"], row["kind"])].append(row)
    results = []
    for (cohort, kind), group in groups.items():
        complete = [r for r in group if r["complete"]]
        scored = [r for r in complete if r.get("detected") is not None]
        detected = sum(r.get("detected") is True for r in complete)
        results.append({"cohort": cohort, "kind": kind, "planned": len(group),
                        "completed": len(complete), "detected": detected,
                        "missed_or_unflagged": sum(r.get("detected") is False for r in complete),
                        "outcome_unavailable": sum(r.get("detected") is None for r in complete),
                        "incomplete": sum(not r["complete"] and r["status"] != "unattempted" for r in group),
                        "unattempted": sum(r["status"] == "unattempted" for r in group),
                        "raw_flags": sum(r.get("raw_medium_flag", r.get("detected")) is True for r in group),
                        "planned_yield": detected / len(group) if cohort != "reputation" else None,
                        "complete_rate": detected / len(scored) if scored else None,
                        "incomplete_ids": [r["id"] for r in group if not r["complete"]]})
    return results


def coverage_data(rows: list[dict]) -> dict:
    """Count cached input audits once; missing telemetry remains unknown."""
    unique = {}
    contexts = 0
    for row in rows:
        for member in row.get("members_results", []):
            contexts += 1
            unique[member["fingerprint"]] = member["stages"]
    planned = set()
    for row in rows:
        hashes = row.get("input_sha256")
        if hashes is None:
            continue
        for member in row.get("members") or [{"dir": None}]:
            prefix = member["dir"] + "/" if member["dir"] else ""
            subset = {name[len(prefix):]: value for name, value in hashes.items() if name.startswith(prefix)}
            planned.add(fingerprint(subset))
    audit_keys = planned | set(unique)
    result = {"unique_audits": len(unique), "planned_unique_audits": len(audit_keys),
              "member_contexts": contexts, "unknown_audits": len(audit_keys - set(unique)),
              "basis": "Distinct input fingerprints; cached contexts count once",
              "attempt_alignment": [], "parsing": {"native_recovery_records": 0,
              "retry_recoveries": 0, "reparse_recoveries": 0, "unresolved_recoveries": 0,
              "super_retry_records": 0, "parse_error_records": 0, "call_error_records": 0}}
    fields = {
        "semantic": ["source_chars", "submitted_chars", "omitted_chars", "units_total",
                     "units_completed", "units_partial", "units_omitted", "skipped_large",
                     "skipped_undecodable", "skipped_unreadable", "skipped_max_files"],
        "harness": ["source_chars", "mounted_chars", "mounted_content_chars", "omitted_chars",
                    "red_chars", "red_mounted_chars", "red_probes_generated", "red_probes_omitted",
                    "red_probe_chars_omitted", "files_omitted", "mount_omitted_files",
                    "comparisons_expected", "comparisons_completed"],
    }
    for stage_name, names in fields.items():
        metrics_by_audit = {}
        for key, stages in unique.items():
            stage = next((s for s in stages if s["stage"] == stage_name), None)
            if stage is None:
                continue
            metrics = metrics_by_audit[key] = stage.get("metrics", {})
            attempts = metrics.get("request_attempts")
            numbers = stage.get("journal_numbers", [])
            result["attempt_alignment"].append({"fingerprint": key, "stage": stage_name,
                "journal_numbers": numbers, "native_attempt_count": len(attempts) if isinstance(attempts, list) else None,
                "aligned": len(attempts) == len(numbers) if isinstance(attempts, list) else None,
                "native_evidence": f"audits/{key}.json"})
            recoveries = metrics.get("response_recoveries", [])
            parsing = result["parsing"]
            parsing["native_recovery_records"] += len(recoveries)
            parsing["retry_recoveries"] += sum("retry" in (r.get("recovered_by") or "") for r in recoveries)
            parsing["reparse_recoveries"] += sum("reparse" in (r.get("recovered_by") or "") for r in recoveries)
            parsing["unresolved_recoveries"] += sum(not r.get("recovered_by") for r in recoveries)
            parsing["super_retry_records"] += len(metrics.get("inference_retries", []))
            parsing["parse_error_records"] += len(metrics.get("parse_errors", []))
            parsing["call_error_records"] += len(metrics.get("call_errors", []))
        result[stage_name] = {}
        for name in names:
            known = [_usage_number(m.get(name)) for m in metrics_by_audit.values()]
            values = [v for v in known if v is not None]
            unknown = len(audit_keys) - len(values)
            subtotal = sum(values)
            result[stage_name][name] = {"known_subtotal": subtotal, "unknown_audits": unknown,
                                        "total": subtotal if not unknown else None}
    return result


def load_engine(engine_root: Path) -> SimpleNamespace:
    """Only lead-created snapshots; refuse existing/mixed fugu module imports."""
    engine_root = engine_root.resolve()
    manifest = read_json(engine_root / "manifest.json")
    verify_inventory(engine_root, manifest)
    if any(name == "fugu" or name.startswith("fugu.") for name in sys.modules):
        raise EvidenceError("fugu already imported; use an isolated process")
    sys.path.insert(0, str(engine_root / "src"))
    modules = {name: importlib.import_module("fugu." + name) for name in (
        "pipeline", "pipeline.stages.semantic", "pipeline.stages.harness",
        "pipeline.stages.composition", "server.composition_jobs", "types",
        "dedupe", "verdict", "config", "client", "model_router",
    )}
    for name, module in list(sys.modules.items()):
        if name == "fugu" or name.startswith("fugu."):
            if not Path(module.__file__).resolve().is_relative_to(engine_root / "src"):
                raise EvidenceError("mixed engine imports")
    return SimpleNamespace(root=engine_root, manifest=manifest, modules=modules,
                           pipeline=modules["pipeline"], types=modules["types"])


def verify_engine(engine: SimpleNamespace) -> None:
    verify_inventory(engine.root, engine.manifest)


def verify_inventory(root: Path, manifest: dict) -> None:
    hashes = manifest.get("hashes", {})
    if not re.fullmatch(r"[0-9a-f]{40}", manifest.get("commit", "")):
        raise EvidenceError("engine inventory needs the full checked commit")
    required = {"src/fugu/config.py", "src/fugu/client.py", "src/fugu/types.py",
                "src/fugu/pipeline/assemble.py", "src/fugu/pipeline/stages/semantic.py",
                "src/fugu/pipeline/stages/harness.py", "src/fugu/pipeline/stages/composition.py"}
    files = list((root / "src/fugu").rglob("*"))
    if any(p.is_symlink() or p.suffix == ".pyc" for p in files):
        raise EvidenceError("engine inventory has symlinks or bytecode")
    paths = {p.relative_to(root).as_posix() for p in files if p.is_file() and p.suffix == ".py"}
    if set(hashes) != paths or not required <= paths:
        raise EvidenceError("engine inventory must cover every Python source")
    if root.resolve() == ROOT or any(not re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes.values()):
        raise EvidenceError("engine inventory is not a frozen snapshot")
    if any(sha((root / name).read_bytes()) != value for name, value in hashes.items()):
        raise EvidenceError("engine snapshot hash mismatch")


def validate_output(output: Path) -> None:
    resolved = output.resolve()
    if resolved.is_relative_to(ROOT) and not resolved.is_relative_to(DEFAULT_OUTPUT):
        raise EvidenceError("output is outside the assigned benchmark territory")


def validate_plan(engine: SimpleNamespace, plan: dict, output: Path, *, profile=None) -> dict:
    profile = engine_profile(engine) if profile is None else profile
    if engine.manifest != plan["engine"] or profile != plan["profile"]:
        raise EvidenceError("approved engine/profile changed")
    if sha(Path(__file__).read_bytes()) != plan["runner_sha256"]:
        raise EvidenceError("runner changed after plan approval")
    if "runtime" in plan and runtime_versions() != plan["runtime"]:
        raise EvidenceError("runtime dependencies changed after plan approval")
    cases = read_json(output / "cases.json")
    if hash_json(cases) != plan["cases_sha256"]:
        raise EvidenceError("approved case manifest changed")
    for case in cases["cases"]:
        if input_hashes(case_target(case)) != case["input_sha256"]:
            raise EvidenceError("approved input hash changed")
    return cases


def engine_profile(engine: SimpleNamespace) -> dict:
    cfg = engine.modules["config"]
    if hasattr(cfg, "get_production_limits"):
        return cfg.get_production_limits().to_dict()
    # This is explicitly legacy compatibility evidence, never a profile override.
    semantic, harness = engine.modules["pipeline.stages.semantic"], engine.modules["pipeline.stages.harness"]
    return {"legacy_compatibility_only": True,
            "initial_output_tokens": inspect.signature(semantic._default_make_call).parameters["max_tokens"].default,
            "semantic_max_units": semantic.MAX_UNITS,
            "semantic_chunk_chars": semantic.MAX_CHARS_PER_UNIT,
            "harness_mount_chars": harness.MOUNT_CHAR_BUDGET,
            "red_exposure_chars": 2500, "red_probe_count": harness.RED_PROBE_COUNT}


def profile_ready(profile: dict) -> bool:
    expected = {"llm_max_output_tokens": 4096, "semantic_max_units": 24,
                "semantic_max_chars_per_unit": 6000, "harness_mount_char_budget": 32000,
                "red_probe_count": 3, "red_probe_max_chars": 200,
                "sdk_max_retries": 0, "request_timeout_seconds": 90,
                "source_max_entries": 20000, "source_max_bytes": 536870912,
                "git_clone_timeout_seconds": 120, "fanout_max_units": 24}
    return all(profile.get(key) == value for key, value in expected.items())


def preflight(engine: SimpleNamespace, manifest: dict) -> dict:
    semantic = engine.modules["pipeline.stages.semantic"]
    stage = semantic.SemanticStage()
    contexts, unique = [], {}
    for case in manifest["cases"]:
        target = case_target(case)
        if input_hashes(target) != case["input_sha256"]:
            raise EvidenceError("input hash mismatch in preflight")
        members = [(m["dir"], target / m["dir"]) for m in case.get("members", [])] or [(None, target)]
        for member, directory in members:
            hashes = input_hashes(directory)
            files, stats = semantic.collect_text_files(directory, stage.max_file_bytes, stage.max_files)
            units = [part for file in files if Path(file.rel).name.lower() not in semantic._SEMANTIC_SKIP_FILES
                     for part in semantic._chunks(file.text)]
            item = {"context": case["id"] + ("/" + member if member else ""),
                    "fingerprint": fingerprint(hashes), "input_sha256": hashes,
                    "semantic_units": len(units), "maximum_unit_chars": max(map(len, units), default=0),
                    "collection": stats}
            contexts.append(item)
            unique.setdefault(item["fingerprint"], item)
    return {"contexts": contexts, "unique_audits": list(unique.values()),
            "context_count": len(contexts), "unique_audit_count": len(unique),
            "semantic_primary_units": sum(r["semantic_units"] for r in unique.values())}


def link_native_attempts(public: dict, journal: RequestJournal, key: str) -> dict:
    records = [r for r in journal.records if r.get("context") == key and r.get("stage") == public["stage"]]
    public["journal_numbers"] = [r["number"] for r in records]
    native = public.get("metrics", {}).get("request_attempts")
    public["native_request_links"] = None
    if isinstance(native, list) and len(native) == len(records):
        public["native_request_links"] = []
        for index, (attempt, record) in enumerate(zip(native, records)):
            fields = {"requested_model": record.get("requested_model"), "served_model": record.get("served_model"),
                      "max_tokens": record.get("max_tokens"), "finish_reason": record.get("finish_reason"),
                      "response_sha256": record.get("response_sha256"), "usage": record["usage"]}
            same = all(attempt.get(name) == value for name, value in fields.items())
            public["native_request_links"].append({"native_index": index,
                                                   "journal_number": record["number"], "identity_matches": same})
    return public


def text_contracts(engine: SimpleNamespace) -> dict:
    semantic = engine.modules["pipeline.stages.semantic"]
    harness = engine.modules["pipeline.stages.harness"]
    probes = harness.STATIC_PROBES[:harness.FULL_DEPTH_PROBES]
    return {"semantic_system_sha256": sha(semantic._JUDGE_SYSTEM.encode()),
            "harness_operator_sha256": sha(harness._OPERATOR_PERSONA.encode()),
            "harness_mount_template_sha256": sha(harness._MOUNT_TEMPLATE.encode()),
            "static_probes_sha256": hash_json(probes), "static_probes_chars": list(map(len, probes)),
            "red_prompt_construction_sha256": engine.manifest["hashes"]["src/fugu/pipeline/stages/harness.py"],
            "per_request_system_messages": "Exact constructed messages retained and hashed at SDK boundary"}


def runtime_versions() -> dict:
    versions = {}
    for name in ("openai", "httpx", "pydantic", "pydantic-settings", "fastapi", "python-dotenv"):
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    return {"python": sys.version.split()[0], "dependencies": versions,
            "project_files_sha256": {name: sha((ROOT / name).read_bytes())
                                     for name in ("pyproject.toml", "uv.lock") if (ROOT / name).exists()}}


async def evaluate_cases(engine: SimpleNamespace, manifest: dict, output: Path,
                         journal: RequestJournal, *, sdk_factory=None) -> dict:
    """Original grouping, native stage execution and preserved input cache."""
    validate_output(output)
    stages = engine.pipeline.build_stages(include_detonation=False, include_reputation=False)
    if [s.name for s in stages] != ["concealment", "static", "semantic", "harness"]:
        raise EvidenceError("unexpected source/inference stage assembly")
    cache = AuditCache(output, binding=journal.binding)
    cases = manifest["cases"]
    manifest_hash = hash_json(manifest)
    rows = [dict(case, complete=False, detected=None, status="unattempted",
                 stages=[], findings=[], unavailable_reason="not started") for case in cases]
    result_path = output / "fugu.json"
    started_utc = utc()
    if result_path.exists():
        previous = read_json(result_path)
        if previous.get("binding") != journal.binding or previous.get("cases_sha256") != manifest_hash:
            raise EvidenceError("result binding or case manifest changed")
        if [r["id"] for r in previous["rows"]] != [c["id"] for c in cases]:
            raise EvidenceError("saved result case order changed")
        rows = previous["rows"]
        started_utc = previous["started_utc"]

    async def audit(target: Path, phase: str, progress) -> tuple[list[dict], str, bool]:
        hashes = input_hashes(target)
        key = fingerprint(hashes)
        saved = cache.get(key, hashes)
        if saved and [r["stage"] for r in saved] != [s.name for s in stages[:len(saved)]]:
            raise EvidenceError("saved stage prefix drift")
        if saved is not None and len(saved) == len(stages):
            progress(saved, key, True)
            return saved, key, True
        job = engine.types.AuditJob(id=key, source=str(target), depth="full")
        results = list(saved or [])
        if results:
            progress(results, key, True)
        for stage in stages[len(results):]:
            verify_engine(engine)
            if journal.stop_reason and stage.name in {"semantic", "harness"}:
                public = {"stage": stage.name, "ok": False, "findings": [],
                          "metrics": {"unattempted": journal.stop_reason}, "error": None}
            else:
                with journal.context(key, stage.name, phase):
                    result = (await engine.pipeline.run_stages(job, target, [stage]))[0]
                public = asdict(result)
            public["state"] = stage_state(public)
            link_native_attempts(public, journal, key)
            # Native request_attempts/recovery records remain unchanged in metrics.
            results.append(public)
            cache.save(key, hashes, results)
            progress(results, key, False)
        return results, key, False

    def publish():
        document = {"schema": 1, "protocol": "current-production-source-inference-v1",
                    "binding": journal.binding, "cases_sha256": manifest_hash,
                    "started_utc": started_utc, "measured_utc": utc(),
                    "scope": "S0/S1/S2/S4 plus source composition; no target execution or live reputation",
                    "planned": len(cases), "rows": rows, "summary": summarize_rows(rows),
                    "coverage": coverage_data(rows),
                    "usage": journal.summary(), "cost": None, "remaining_quota": None,
                    "engine": engine.manifest, "limits": engine_profile(engine)}
        write_json(result_path, document)
        return document

    publish()  # Every planned row survives a process interruption before a response.
    try:
        with observe_sdk(journal, sdk_factory):
            for index, case in enumerate(cases):
                if input_hashes(case_target(case)) != case["input_sha256"]:
                    raise EvidenceError("case input hash drift")
                phase = "common20" if case["cohort"] in {"mcptox", "clean_descriptions"} else "remainder"
                if journal.stop_reason:
                    if not rows[index]["complete"]:
                        rows[index]["unavailable_reason"] = journal.stop_reason
                    publish()
                    continue
                rows[index] = dict(case, complete=False, detected=None, status="partial",
                                   stages=[], findings=[], members_results=[], reuse=[],
                                   unavailable_reason="in progress or interrupted")
                publish()
                target = case_target(case)
                member_results, member_stages = [], []
                members = case.get("members") or [{"dir": None, "label": case["id"]}]
                for member in members:
                    directory = target / member["dir"] if member["dir"] else target
                    def progress(results, key, cached):
                        latest = {"member": member["dir"], "fingerprint": key, "stages": list(results)}
                        existing = [r for r in rows[index]["members_results"] if r["member"] != member["dir"]]
                        rows[index]["members_results"] = existing + [latest]
                        rows[index]["reuse"] = [r for r in rows[index]["reuse"] if r["member"] != member["dir"]] + [
                            {"member": member["dir"], "fingerprint": key, "cached_identical_input": cached}]
                        rows[index]["stages"] = [s for r in rows[index]["members_results"] for s in r["stages"]]
                        rows[index]["findings"] = [f for s in rows[index]["stages"] for f in s["findings"]]
                        rows[index]["raw_medium_flag"] = any(f["severity"] in MEDIUM for f in rows[index]["findings"])
                        rows[index]["detected"] = rows[index]["raw_medium_flag"] if case["cohort"] != "reputation" else None
                        publish()
                    results, key, cached = await audit(directory, phase, progress)
                    findings = [f for stage in results for f in stage["findings"]]
                    member_stages.append({"member": member["dir"], "fingerprint": key, "stages": results})
                    if case.get("members"):
                        composition = engine.modules["pipeline.stages.composition"]
                        public_finding = engine.modules["server.composition_jobs"]
                        native_findings = [engine.types.Finding(**{
                            **f, "evidence": [engine.types.EvidenceSnippet(**e) for e in f.get("evidence", [])]
                        }) for f in findings]
                        native_findings = engine.modules["dedupe"].dedupe_findings(native_findings)
                        member_results.append(composition.MemberResult(
                            label=member.get("label") or member["dir"], slug=member["dir"],
                            findings=native_findings, tool_names=public_finding.harvest_tool_names(directory),
                            target_dir=directory))
                all_stages = [s for r in member_stages for s in r["stages"]]
                all_findings = [f for s in all_stages for f in s["findings"]]
                if case.get("members"):
                    verify_engine(engine)
                    comp = engine.modules["pipeline.stages.composition"].CompositionStage()
                    comp._member_results = member_results
                    result = asdict(await comp.run(engine.types.AuditJob(
                        id=case["id"], source=str(target), depth="full"), target))
                    result["state"] = stage_state(result)
                    all_stages.append(result)
                    all_findings.extend(result["findings"])
                    titles = [f["title"].lower() for f in result["findings"]]
                    score = {"trifecta": any("trifecta" in t for t in titles),
                             "shadowing": any("shadowing" in t for t in titles)}
                    matches = all(score[name] == case["expected"].get(name, False) for name in score)
                    detected = any(score.values())
                else:
                    score, matches = None, None
                    detected = any(f["severity"] in MEDIUM for f in all_findings) if case["cohort"] != "reputation" else None
                complete = all(s["state"] == "completed" for s in all_stages)
                rows[index].update(stages=all_stages, findings=all_findings,
                                   members_results=member_stages, complete=complete, detected=detected,
                                   raw_medium_flag=any(f["severity"] in MEDIUM for f in all_findings),
                                   status="completed" if complete else "partial",
                                   unavailable_reason=journal.stop_reason if not complete else None,
                                   composition_score=score, matches_frozen_expectations=matches,
                                   adjudicated_false_positive=None,
                                   excluded_capabilities=["detonation", "reputation"],
                                   dependency_expectation="unavailable" if case["cohort"] == "reputation" else None)
                publish()
        verify_engine(engine)
    finally:
        publish()  # Account for failed/orphan attempts even on interruption.
    return publish()


def prepare(engine: SimpleNamespace, output: Path, *, attempt_limit: int = MAX_ATTEMPTS) -> dict:
    validate_output(output)
    if output.resolve().is_relative_to(engine.root.resolve()):
        raise EvidenceError("output overlaps the frozen engine")
    if not 1 <= attempt_limit <= MAX_ATTEMPTS:
        raise EvidenceError("invalid attempt limit")
    if (output / "plan.json").exists():
        raise EvidenceError("pre-call plan already exists; use its exact resume binding")
    if sha((FROZEN / "cases.json").read_bytes()) != FIXED_CASE_MANIFEST_SHA256:
        raise EvidenceError("original frozen case manifest changed")
    verify_engine(engine)
    original = read_json(FROZEN / "cases.json")
    copied = prepare_inputs(original, output, ROOT)
    inspected = preflight(engine, copied)
    if (len(copied["cases"]), inspected["context_count"], inspected["unique_audit_count"],
        inspected["semantic_primary_units"]) != (40, 54, 45, 63):
        raise EvidenceError("fixed input/group/unit preflight drift")
    profile = engine_profile(engine)
    plan = {"schema": 1, "created_utc": utc(), "engine": engine.manifest,
            "profile": profile, "profile_sha256": hash_json(profile),
            "frozen_case_manifest_sha256": sha((FROZEN / "cases.json").read_bytes()),
            "cases_sha256": hash_json(copied),
            "runner_sha256": sha(Path(__file__).read_bytes()),
            "charts_sha256": sha((ROOT / "bench/current_limits_charts.py").read_bytes()),
            "text_contracts": text_contracts(engine), "runtime": runtime_versions(),
            "preflight": inspected, "attempt_limit": attempt_limit,
            "phase_limits": {"common20": 800, "remainder": 1100},
            "primary_maximum": 1323, "native_retry_maximum": 513,
            "worst_cumulative_requests": 1836, "timeout_s": 90, "sdk_retries": 0,
            "capabilities_excluded": ["detonation", "reputation", "fresh comparator execution"],
            "requested_models": [engine.modules["config"].ULTRA_MODEL, engine.modules["config"].SUPER_MODEL],
            "ready_for_live_review": profile_ready(profile),
            "live_authority": "Requires independent checked candidate review and explicit lead data-phase release"}
    write_json(output / "cases.json", copied)
    write_json(output / "plan.json", plan)
    write_json(output / "plan-hash.json", {"plan_sha256": hash_json(plan)})
    return plan


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run"])
    parser.add_argument("--engine-root", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--attempt-limit", type=int, default=MAX_ATTEMPTS)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--data-release-ref", help="Explicit later lead queue release; offline grant is insufficient")
    args = parser.parse_args(argv)
    validate_output(args.output)
    engine = load_engine(args.engine_root)
    if args.action == "prepare":
        plan = prepare(engine, args.output, attempt_limit=args.attempt_limit)
        print(json.dumps({"plan_sha256": hash_json(plan), "ready_for_live_review": plan["ready_for_live_review"]}))
        return 0
    plan = read_json(args.output / "plan.json")
    if not args.approved_plan_sha256 or hash_json(plan) != args.approved_plan_sha256:
        raise EvidenceError("exact approved pre-call plan hash is required")
    if not plan["ready_for_live_review"] or not profile_ready(engine_profile(engine)):
        raise EvidenceError("legacy compatibility profile cannot make live calls")
    if not args.data_release_ref or not re.fullmatch(r"qitem-[0-9]{14}-[0-9a-f]{8}", args.data_release_ref):
        raise EvidenceError("explicit later data-phase release reference is required")
    cases = validate_plan(engine, plan, args.output)
    write_json(args.output / "data-release.json", {"queue_ref": args.data_release_ref,
               "approved_plan_sha256": args.approved_plan_sha256})
    with RequestJournal(args.output, limit=plan["attempt_limit"], binding=hash_json(plan),
                        phase_limits=plan["phase_limits"], expected_output_tokens=4096,
                        expected_models=plan["requested_models"]) as journal:
        result = asyncio.run(evaluate_cases(engine, cases, args.output, journal))
    print(json.dumps({"planned": result["planned"], "attempts": result["usage"]["attempts"],
                      "stop_reason": result["usage"]["stop_reason"]}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, JournalStopped) as exc:
        # These errors contain only our bounded classification, never provider bodies.
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None
