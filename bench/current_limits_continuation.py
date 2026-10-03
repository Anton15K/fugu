"""One reviewed child for untouched cases of the sealed cc58a58 benchmark.

Preparation and aggregation are offline. Only the separately authenticated
lead data release can open the SDK boundary. The original runner is reused.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

from bench import current_limits as base

EvidenceError = base.EvidenceError
JournalStopped = base.JournalStopped
PROTOCOL = "current-production-source-inference-continuation-v1"
RELEASE_PROTOCOL = "fugu-current-limits-untouched-data-release-v1"
ENGINE_COMMIT = "cc58a58d6cea861510980814ae2e70b7bdf24e63"
PARENT_MANIFEST_SHA256 = "63240327fc6adf050b6cefbd0340f1fb6c16700c48551bc12548b071a057783e"
PARENT_PLAN_SHA256 = "8f304c3da81e0db091da6e2c324c064d013129d63644b278079c4cf8ad9ef725"
PARENT_RESULT_SHA256 = "708623e0fac256a4cb2810bdddc2875ba22a1ad3b16bbdb7ed39324821d3b987"
RUNNER_SHA256 = "2e69cd6654ec8158d3de968ad026c56d2e04179574c0667133cac8edadea002d"
DEFAULT_PARENT = base.DEFAULT_OUTPUT / "measurement-cc58a58"
DEFAULT_CHILD = base.DEFAULT_OUTPUT / "continuation-cc58a58-untouched"
DEFAULT_OFFLINE = base.DEFAULT_OUTPUT / "continuation-offline/prepared"
DEFAULT_REGISTRY = base.DEFAULT_OUTPUT / "continuation-registry" / (PARENT_RESULT_SHA256 + ".json")
CHILD_LIMIT = 1316
CHILD_PHASE_LIMITS = {"common20": 280, "remainder": 1036}
PARENT_PHASE_LIMITS = {"common20": 800, "remainder": 1100}


def _parse_json(text: str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise EvidenceError("duplicate JSON field")
            result[key] = value
        return result
    def nonfinite(value):
        raise EvidenceError("non-finite JSON value")
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, TypeError):
        raise EvidenceError("missing or malformed evidence JSON") from None


def read_json(path: Path) -> Any:
    """Reject symlinks and ambiguous JSON rather than accepting its last key."""
    _regular(path)
    try:
        return _parse_json(path.read_text())
    except OSError:
        raise EvidenceError("missing or malformed evidence JSON") from None


def _regular(path: Path) -> None:
    if not path.is_file() or _has_symlink(path):
        raise EvidenceError("evidence must be a regular file without symlink ancestors")


def _has_symlink(path: Path) -> bool:
    # macOS's /tmp alias is within the explicitly permitted /private/tmp root.
    return any(p.is_symlink() and not (p == Path("/tmp") and p.resolve() == Path("/private/tmp"))
               for p in (path, *path.parents))


def _integer(value: Any, *, maximum: int = 1900) -> bool:
    return type(value) is int and 0 <= value <= maximum


def read_ledger(directory: Path, *, allow_orphans: bool = False) -> SimpleNamespace:
    """Validate/count durable numbered requests without constructing a journal."""
    state = read_json(directory / "budget.json")
    if (not isinstance(state, dict) or not _integer(state.get("attempts"))
        or not isinstance(state.get("binding"), str)
        or not _integer(state.get("limit")) or state["attempts"] > state["limit"]
        or not isinstance(state.get("phase_limits"), dict)
        or state.get("stop_reason") is not None and not isinstance(state["stop_reason"], str)):
        raise EvidenceError("malformed request budget")
    paths = list((directory / "calls").glob("*"))
    wanted = {f"{i:05d}.json" for i in range(1, state["attempts"] + 1)}
    if any(p.name not in wanted for p in paths):
        raise EvidenceError("extra or malformed parent request path")
    if not allow_orphans and {p.name for p in paths} != wanted:
        raise EvidenceError("missing request record")
    records, contexts, recovered_stop = [], Counter(), state["stop_reason"]
    for number in range(1, state["attempts"] + 1):
        path = directory / "calls" / f"{number:05d}.json"
        if not path.exists() and allow_orphans:
            records.append({"number": number, "state": "reserved", "context": None,
                            "stage": None, "phase": None, "ordinal": None,
                            "usage": {"prompt_tokens": None, "completion_tokens": None}})
            recovered_stop = recovered_stop or "orphan_attempt_requires_review"
            continue
        _regular(path)
        row = read_json(path)
        if (not isinstance(row, dict) or type(row.get("number")) is not int
            or row["number"] != number or row.get("state") not in {"reserved", "returned", "error"}
            or not isinstance(row.get("context"), str) or not row["context"]
            or row.get("stage") not in {"semantic", "harness"}
            or row.get("phase") not in PARENT_PHASE_LIMITS
            or not _integer(row.get("ordinal"))
            or not isinstance(row.get("usage"), dict)
            or set(row["usage"]) != {"prompt_tokens", "completion_tokens"}
            or any(v is not None and (type(v) is not int or v < 0) for v in row["usage"].values())):
            raise EvidenceError("malformed request record")
        key = (row["context"], row["stage"])
        if row["ordinal"] != contexts[key]:
            raise EvidenceError("duplicate or discontinuous request ordinal")
        contexts[key] += 1
        kwargs = {"model": row.get("requested_model"), "messages": row.get("messages"),
                  "temperature": row.get("temperature"), "max_tokens": row.get("max_tokens")}
        if (not isinstance(kwargs["model"], str) or kwargs["max_tokens"] != 4096
            or kwargs["temperature"] != 0.1 or not isinstance(kwargs["messages"], list)
            or any(not isinstance(m, dict) or set(m) != {"role", "content"}
                   or m["role"] not in {"system", "user"} or not isinstance(m["content"], str)
                   for m in kwargs["messages"])
            or base.hash_json(kwargs) != row.get("request_sha256")
            or base.hash_json(kwargs["messages"]) != row.get("messages_sha256")):
            raise EvidenceError("request signature or production contract drift")
        models = state.get("expected_models")
        if models is not None and (not isinstance(models, list) or row["requested_model"] not in models):
            raise EvidenceError("request model differs from the approved journal contract")
        if row["state"] == "returned":
            raw = row.get("raw_response")
            if (raw is not None and not isinstance(raw, str)
                or row.get("response_sha256") != (base.sha(raw.encode()) if isinstance(raw, str) else None)
                or type(row.get("choice_present")) is not bool
                or type(row.get("usage_object_present")) is not bool):
                raise EvidenceError("saved response hash or shape mismatch")
        elif row["state"] == "error":
            error = row.get("error")
            if (not isinstance(error, dict) or error.get("classification") not in {
                "provider_error", "provider_auth_failure", "provider_quota_exhausted", "provider_rate_limit"}
                or type(error.get("status")) not in {int, type(None)}
                or not isinstance(error.get("type"), str) or not error["type"]):
                raise EvidenceError("malformed saved provider error")
            recovered_stop = recovered_stop or error["classification"]
        else:
            recovered_stop = recovered_stop or "orphan_attempt_requires_review"
        records.append(row)
    summary_owner = SimpleNamespace(state=state, records=records, replayed=0, stop_reason=recovered_stop)
    return SimpleNamespace(state=state, records=records, usage=base.RequestJournal.summary(summary_owner))


def select_unattempted(rows: list[dict], cases: list[dict]) -> list[dict]:
    if len(rows) != len(cases) or [r.get("id") for r in rows] != [c.get("id") for c in cases]:
        raise EvidenceError("parent case order changed")
    if len({c["id"] for c in cases}) != len(cases):
        raise EvidenceError("duplicate case identifier")
    selected = []
    for row, case in zip(rows, cases):
        if any(row.get(k) != v for k, v in case.items()):
            raise EvidenceError("parent labels, grouping or input bindings changed")
        if row.get("status") == "unattempted":
            if (row.get("complete") is not False or row.get("stages") or row.get("findings")
                or row.get("members_results") or row.get("detected") is not None):
                raise EvidenceError("observed case cannot be selected as untouched")
            selected.append(copy.deepcopy(case))
        elif (row.get("status"), row.get("complete")) not in {("completed", True), ("partial", False)}:
            raise EvidenceError("invalid parent coverage state")
    if len(cases) != 40 or len(selected) != 27:
        raise EvidenceError("fixed untouched selection changed")
    return selected


def load_parent(directory: Path = DEFAULT_PARENT) -> SimpleNamespace:
    directory = directory.resolve()
    inventory_path = directory / "artifact-manifest.json"
    _regular(inventory_path)
    if base.sha(inventory_path.read_bytes()) != PARENT_MANIFEST_SHA256:
        raise EvidenceError("accepted parent inventory changed")
    inventory = read_json(inventory_path)
    entries = inventory.get("sha256")
    if (inventory.get("schema") != 2 or not isinstance(entries, list) or len(entries) != 402
        or len({r.get("path") for r in entries}) != 402):
        raise EvidenceError("parent inventory shape changed")
    for item in entries:
        name = Path(item["path"])
        if name.is_absolute() or ".." in name.parts:
            raise EvidenceError("unsafe parent inventory path")
        path = base.ROOT / name
        _regular(path)
        if base.sha(path.read_bytes()) != item["sha256"]:
            raise EvidenceError("sealed parent file changed")
    if directory != DEFAULT_PARENT.resolve():
        raise EvidenceError("sealed parent directory changed")
    original_path = base.FROZEN / "cases.json"
    if base.sha(original_path.read_bytes()) != base.FIXED_CASE_MANIFEST_SHA256:
        raise EvidenceError("original case manifest changed")
    original = read_json(original_path)
    plan, result, cases = (read_json(directory / name) for name in ("plan.json", "fugu.json", "cases.json"))
    if (base.hash_json(plan) != PARENT_PLAN_SHA256
        or base.sha((directory / "fugu.json").read_bytes()) != PARENT_RESULT_SHA256
        or base.hash_json(cases) != plan["cases_sha256"]
        or plan["engine"]["commit"] != ENGINE_COMMIT
        or result["engine"] != plan["engine"] or result["limits"] != plan["profile"]
        or result["binding"] != PARENT_PLAN_SHA256):
        raise EvidenceError("accepted parent plan/result/source binding changed")
    restored = copy.deepcopy(cases)
    for case in restored["cases"]:
        case["target"] = case.pop("original_target")
    if restored != original:
        raise EvidenceError("parent case fields differ from the original manifest")
    selected_cases = select_unattempted(result["rows"], cases["cases"])
    ledger = read_ledger(directory)
    if (ledger.state["binding"] != PARENT_PLAN_SHA256 or ledger.state["attempts"] != 359
        or ledger.state["stop_reason"] != "provider_error"
        or ledger.usage != result["usage"] or ledger.usage["orphan_attempts"] != 0
        or ledger.usage["provider_errors"] != 1
        or ledger.records[-1]["state"] != "error"
        or ledger.records[-1]["error"]["status"] != 500):
        raise EvidenceError("stopped parent ledger changed")
    selected = {k: copy.deepcopy(v) for k, v in original.items() if k != "cases"}
    selected["cases"] = []
    for case in selected_cases:
        case["target"] = case.pop("original_target")
        selected["cases"].append(case)
    old_keys = {m["fingerprint"] for r in result["rows"] for m in r.get("members_results", [])}
    return SimpleNamespace(directory=directory, plan=plan, result=result, cases=cases,
                           selected=selected, original=original, records=ledger.records,
                           usage=ledger.usage, old_keys=old_keys, inventory=inventory)


def _continuation_usage(usage: dict, parent_usage: dict, registry: dict) -> dict:
    """Use the same durable ownership totals in owner and offline summaries."""
    result = copy.deepcopy(usage)
    result.update(parent_attempts=parent_usage["attempts"],
                  cumulative_attempts=parent_usage["attempts"] + registry["attempts"],
                  registry_reserved_attempts=registry["attempts"],
                  cumulative_phase_attempts={k: parent_usage["phase_attempts"].get(k, 0)
                                            + registry["phase_attempts"].get(k, 0)
                                            for k in PARENT_PHASE_LIMITS})
    return result


class ContinuationJournal(base.RequestJournal):
    """Reuse native response observation, with an outside-child ownership ledger.

    A durable guard precedes each reservation. It is cleared only after a saved
    successful response and registry update. A crash or failed write leaves the
    guard and closes future dispatch, including after restart.
    """

    def __init__(self, directory: Path, *, registry_path: Path, binding: str,
                 release_binding: str, parent_usage: dict, allowed_contexts: dict,
                 expected_models: list[str], limit: int = CHILD_LIMIT,
                 phase_limits: dict[str, int] | None = None):
        for path in (directory, registry_path, registry_path.with_suffix(".lock"), directory / ".journal.lock"):
            if _has_symlink(path):
                raise EvidenceError("symlink ownership boundary")
        directory, registry_path = directory.resolve(), registry_path.resolve()
        self._clean_exit = False
        phase_limits = dict(CHILD_PHASE_LIMITS if phase_limits is None else phase_limits)
        if (registry_path.is_relative_to(directory) or directory.is_relative_to(registry_path.parent)
            or not 1 <= limit <= CHILD_LIMIT or set(phase_limits) != set(CHILD_PHASE_LIMITS)
            or any(type(v) is not int or not 1 <= v <= CHILD_PHASE_LIMITS[k] for k, v in phase_limits.items())
            or not _integer(parent_usage.get("attempts"))
            or not isinstance(parent_usage.get("phase_attempts"), dict)
            or sum(parent_usage["phase_attempts"].values()) != parent_usage["attempts"]
            or any(k not in PARENT_PHASE_LIMITS or not _integer(v, maximum=PARENT_PHASE_LIMITS[k])
                   for k, v in parent_usage["phase_attempts"].items())
            or not allowed_contexts or any(v not in PARENT_PHASE_LIMITS for v in allowed_contexts.values())):
            raise EvidenceError("invalid continuation budget or ownership boundary")
        for path in (directory, registry_path, registry_path.parent):
            if _has_symlink(path):
                raise EvidenceError("symlink ownership boundary")
        self.registry_path = registry_path
        self.guard_path = registry_path.with_suffix(".guard.json")
        self.parent_usage, self.allowed_contexts = copy.deepcopy(parent_usage), dict(allowed_contexts)
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._registry_owner = registry_path.with_suffix(".lock").open("a+")
        try:
            fcntl.flock(self._registry_owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._registry_owner.close()
            raise EvidenceError("continuation registry already owned") from None
        config = {"schema": 1, "child_directory": str(directory), "binding": binding,
                  "release_binding": release_binding, "parent_usage": self.parent_usage,
                  "limit": limit, "phase_limits": phase_limits,
                  "allowed_contexts_sha256": base.hash_json(allowed_contexts),
                  "expected_models": sorted(expected_models)}
        try:
            self._registry_owner.seek(0)
            seal = self._registry_owner.read()
            fresh = not registry_path.exists()
            if not fresh:
                self.registry = read_json(registry_path)
                if not isinstance(self.registry, dict) or any(self.registry.get(k) != v for k, v in config.items()):
                    raise EvidenceError("one-child registry or immutable release binding changed")
                if (not _integer(self.registry.get("attempts"), maximum=limit)
                    or not isinstance(self.registry.get("phase_attempts"), dict)
                    or not isinstance(self.registry.get("calls"), list)
                    or type(self.registry.get("journal_initialized")) is not bool
                    or type(self.registry.get("session_open")) is not bool
                    or self.registry.get("stop_reason") is not None and not isinstance(self.registry["stop_reason"], str)):
                    raise EvidenceError("malformed continuation registry")
            else:
                if seal or directory.exists() and any(directory.iterdir()) or self.guard_path.exists():
                    raise EvidenceError("missing registry cannot reset an existing child")
                self.registry = dict(config, attempts=0, phase_attempts={}, calls=[],
                                     stop_reason=None, journal_initialized=False, session_open=False)
                base.write_json(registry_path, self.registry)
            if not seal:
                self._registry_owner.write(base.hash_json(config))
                self._registry_owner.flush()
                os.fsync(self._registry_owner.fileno())
            elif seal != base.hash_json(config):
                raise EvidenceError("one-child owner seal changed")
            state_path = directory / "budget.json"
            if self.registry["journal_initialized"] and not state_path.exists():
                raise EvidenceError("missing child journal cannot reset its counter")
            if not fresh and not self.registry["journal_initialized"] and not self.guard_path.exists():
                raise EvidenceError("interrupted registry initialization requires review")
            ledger = read_ledger(directory, allow_orphans=True) if state_path.exists() else None
            bound = _request_bindings(self.registry)
            for number, expected in bound.items():
                path = directory / "calls" / f"{number:05d}.json"
                _regular(path)
                if base.sha(path.read_bytes()) != expected:
                    raise EvidenceError("child request bytes changed since ownership checkpoint")
            if self.registry["session_open"] and not self.guard_path.exists():
                phase = ledger.records[-1].get("phase") if ledger and ledger.records else "common20"
                base.write_json(self.guard_path, {"binding": binding, "number": self.registry["attempts"], "phase": phase})
                self.registry["stop_reason"] = self.registry["stop_reason"] or "interrupted_owner_requires_review"
            if self.guard_path.exists():
                guard = read_json(self.guard_path)
                if (not isinstance(guard, dict) or guard.get("binding") != binding
                    or not _integer(guard.get("number"), maximum=limit)
                    or guard.get("phase") not in PARENT_PHASE_LIMITS):
                    raise EvidenceError("malformed persistent continuation guard")
                count = max(self.registry["attempts"], guard["number"], ledger.state["attempts"] if ledger else 0)
                if count > limit:
                    raise EvidenceError("continuation reservation exceeds its fixed cap")
                if count > self.registry["attempts"]:
                    self.registry["phase_attempts"][guard["phase"]] = self.registry["phase_attempts"].get(guard["phase"], 0) + count - self.registry["attempts"]
                self.registry["attempts"] = count
                self.registry["stop_reason"] = (self.registry["stop_reason"]
                    or (ledger.usage["stop_reason"] if ledger else None)
                    or "registry_interrupted_or_storage_failure")
                state = copy.deepcopy(ledger.state) if ledger else {
                    "schema": 1, "binding": binding, "limit": limit, "phase_limits": phase_limits,
                    "expected_output_tokens": 4096, "expected_models": sorted(expected_models)}
                state.update(attempts=count, stop_reason=self.registry["stop_reason"])
                base.write_json(state_path, state)
                base.write_json(registry_path, self.registry)
            elif ((ledger.state["attempts"] if ledger else 0) != self.registry["attempts"]
                  or ledger and (ledger.usage["phase_attempts"] != self.registry["phase_attempts"]
                                 or ledger.usage["stop_reason"] != self.registry["stop_reason"])
                  or len(bound) != self.registry["attempts"]):
                raise EvidenceError("child journal/registry counter or stop mismatch")
            super().__init__(directory, limit=limit, binding=binding, phase_limits=phase_limits,
                             expected_output_tokens=4096, expected_models=expected_models)
            self.registry["journal_initialized"] = True
            self.registry["session_open"] = True
            base.write_json(registry_path, self.registry)
            self._clean_exit = not self.registry["stop_reason"]
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._clean_exit and not self._registry_owner.closed:
            self.registry["session_open"] = False
            try:
                base.write_json(self.registry_path, self.registry)
            except OSError:
                pass  # The prior durable open session closes a future restart.
            self._clean_exit = False
        if hasattr(self, "_owner"):
            super().close()
        if not self._registry_owner.closed:
            fcntl.flock(self._registry_owner, fcntl.LOCK_UN)
            self._registry_owner.close()

    def __exit__(self, exc_type, exc, traceback):
        if exc_type is not None:
            self._clean_exit = False
        self.close()

    def _guard(self, number: int, phase: str):
        if not self.guard_path.exists():
            base.write_json(self.guard_path, {"binding": self.binding, "number": number, "phase": phase})

    def _stop(self, reason: str):
        self._clean_exit = False
        self.state["stop_reason"] = self.state["stop_reason"] or reason
        self.registry["stop_reason"] = self.registry["stop_reason"] or self.state["stop_reason"]
        phase = self._context[2] if self._context else "common20"
        failed = False
        try:
            self._guard(self.registry["attempts"], phase)
            base.write_json(self.registry_path, self.registry)
        except OSError:
            self._clean_exit = False
            failed = True
        try:
            base.write_json(self.directory / "budget.json", self.state)
        except OSError:
            failed = True
        if failed:
            raise JournalStopped("continuation_stop_persistence_failure") from None

    def _reserve(self, phase: str):
        count = self.registry["attempts"]
        phase_count = self.registry["phase_attempts"].get(phase, 0)
        parent_phase = self.parent_usage["phase_attempts"].get(phase, 0)
        reason = ("child_attempt_budget_exhausted" if count >= self.limit else
                  "child_phase_budget_exhausted" if phase_count >= self.phase_limits[phase] else
                  "cumulative_attempt_budget_exhausted" if count + self.parent_usage["attempts"] >= 1900 else
                  "cumulative_phase_budget_exhausted" if phase_count + parent_phase >= PARENT_PHASE_LIMITS[phase] else None)
        if reason:
            self._stop(reason)
            raise JournalStopped(reason)
        try:
            self._guard(count + 1, phase)
            self.registry["attempts"] = count + 1
            self.registry["phase_attempts"][phase] = phase_count + 1
            base.write_json(self.registry_path, self.registry)
        except OSError:
            self.state["stop_reason"] = "continuation_reservation_storage_failure"
            self.registry["stop_reason"] = self.state["stop_reason"]
            # An outside-child reservation consumes budget even without dispatch.
            if self.registry["attempts"] > self.state["attempts"]:
                self.state["attempts"] = self.registry["attempts"]
                self.records.append({"number": self.state["attempts"], "state": "reserved",
                    "context": self._context[0], "stage": self._context[1], "phase": phase,
                    "ordinal": self._ordinal, "usage": {"prompt_tokens": None, "completion_tokens": None}})
            try:
                self._stop(self.state["stop_reason"])
            except JournalStopped:
                pass
            raise JournalStopped(self.state["stop_reason"]) from None

    def _write_record(self, row: dict):
        try:
            super()._write_record(row)
            path = self._path(row["number"])
            bindings = {r["number"]: r["sha256"] for r in self.registry["calls"]}
            bindings[row["number"]] = base.sha(path.read_bytes())
            self.registry["calls"] = [{"number": n, "sha256": h} for n, h in sorted(bindings.items())]
            if row["state"] == "error":
                self.registry["stop_reason"] = self.registry["stop_reason"] or row["error"]["classification"]
            base.write_json(self.registry_path, self.registry)
            if row["state"] == "returned" and not self.registry["stop_reason"]:
                self.guard_path.unlink()
                fd = os.open(self.guard_path.parent, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except (OSError, JournalStopped):
            self._clean_exit = False
            self.state["stop_reason"] = self.state["stop_reason"] or "continuation_record_storage_failure"
            self.registry["stop_reason"] = self.registry["stop_reason"] or self.state["stop_reason"]
            try:
                self._stop(self.state["stop_reason"])
            except JournalStopped:
                pass
            raise JournalStopped(self.state["stop_reason"]) from None

    def request(self, dispatch, **kwargs):
        with self._lock:
            if (self._context is None or self.allowed_contexts.get(self._context[0]) != self._context[2]
                or self._context[1] not in {"semantic", "harness"} or kwargs.get("temperature") != 0.1):
                self._stop("continuation_request_contract_drift")
                raise EvidenceError("continuation context/stage/temperature changed")
            previous = next((r for r in self.records if (r.get("context"), r.get("stage"), r.get("ordinal"))
                             == (self._context[0], self._context[1], self._ordinal)), None)
            if previous is not None:
                if previous["state"] == "returned":
                    bound = {r["number"]: r["sha256"] for r in self.registry["calls"]}
                    if bound.get(previous["number"]) != base.sha(self._path(previous["number"]).read_bytes()):
                        raise EvidenceError("response replay has no exact registry binding")
                return super().request(dispatch, **kwargs)
            if self.stop_reason or self.registry["stop_reason"]:
                raise JournalStopped(self.stop_reason or self.registry["stop_reason"])
            self._reserve(self._context[2])
            try:
                return super().request(dispatch, **kwargs)
            except BaseException:
                try:
                    self._stop(self.stop_reason or "continuation_request_failure")
                except JournalStopped:
                    pass
                raise

    def summary(self) -> dict:
        return _continuation_usage(super().summary(), self.parent_usage, self.registry)


async def evaluate_cases(engine, manifest: dict, output: Path, journal: ContinuationJournal, *, sdk_factory=None):
    """Return terminal child rows unchanged; only first execution uses the runner."""
    path = output / "fugu.json"
    if path.exists():
        saved = read_json(path)
        if (saved.get("binding") != journal.binding or saved.get("cases_sha256") != base.hash_json(manifest)
            or [r.get("id") for r in saved.get("rows", [])] != [c["id"] for c in manifest["cases"]]
            or any(any(row.get(k) != value for k, value in case.items())
                   for row, case in zip(saved["rows"], manifest["cases"]))):
            raise EvidenceError("saved continuation result bindings changed")
        for case in manifest["cases"]:
            if base.input_hashes(base.case_target(case)) != case["input_sha256"]:
                raise EvidenceError("continuation input changed on restart")
        if journal.stop_reason or all(r["status"] != "unattempted" for r in saved["rows"]):
            current = journal.summary()
            if current != saved["usage"]:
                # Preserve row evidence; only recover counters after an interruption.
                saved["usage"] = current
                saved["accounted_utc"] = base.utc()
                base.write_json(path, saved)
            return saved
    return await base.evaluate_cases(engine, manifest, output, journal, sdk_factory=sdk_factory)


def _offline_output(output: Path, engine_root: Path):
    if _has_symlink(output):
        raise EvidenceError("symlink preparation output")
    output = output.resolve()
    if (output.is_relative_to(DEFAULT_PARENT.resolve())
        or output.is_relative_to(DEFAULT_CHILD.resolve())
        or output.is_relative_to(engine_root.resolve())
        or output.is_relative_to(base.ROOT) and not output.is_relative_to(base.DEFAULT_OUTPUT / "continuation-offline")):
        raise EvidenceError("offline preparation output overlaps sealed or data territory")


def _bindings(engine, parent):
    base.verify_engine(engine)
    if (engine.manifest != parent.plan["engine"]
        or base.engine_profile(engine) != parent.plan["profile"]
        or base.runtime_versions() != parent.plan["runtime"]
        or base.text_contracts(engine) != parent.plan["text_contracts"]
        or [engine.modules["config"].ULTRA_MODEL, engine.modules["config"].SUPER_MODEL] != parent.plan["requested_models"]
        or base.sha(Path(base.__file__).read_bytes()) != RUNNER_SHA256):
        raise EvidenceError("frozen engine/profile/runtime/model/runner contract changed")


def prepare(engine, output: Path) -> dict:
    """Copy the fixed untouched inputs and bind a zero-call review candidate."""
    _offline_output(output, engine.root)
    if (output / "plan.json").exists():
        raise EvidenceError("continuation pre-call plan already exists")
    parent = load_parent()
    _bindings(engine, parent)
    for case in parent.original["cases"]:
        if base.input_hashes(base.ROOT / case["target"]) != case["input_sha256"]:
            raise EvidenceError("original source input changed")
    copied = base.prepare_inputs(parent.selected, output, base.ROOT)
    inspected = base.preflight(engine, copied)
    if (inspected["context_count"], inspected["unique_audit_count"], inspected["semantic_primary_units"]) != (41, 32, 50):
        raise EvidenceError("untouched context/audit/unit selection drift")
    context_phases = {case["id"] + ("/" + m["dir"] if m["dir"] else ""):
                      "common20" if case["cohort"] in {"mcptox", "clean_descriptions"} else "remainder"
                      for case in copied["cases"] for m in case.get("members") or [{"dir": None}]}
    allowed, bounds = {}, {k: {"unique_audits": 0, "semantic_units": 0, "primary": 0, "native_retries": 0}
                          for k in PARENT_PHASE_LIMITS}
    for item in inspected["contexts"]:
        key, phase = item["fingerprint"], context_phases[item["context"]]
        if key in parent.old_keys or key in allowed and allowed[key] != phase:
            raise EvidenceError("selected input overlaps observed parent or phase boundaries")
        if key in allowed:
            continue
        allowed[key] = phase
        units = item["semantic_units"]
        if units > 24 or item["maximum_unit_chars"] > 6000:
            raise EvidenceError("untouched source exceeds the checked unit profile")
        bound = bounds[phase]
        bound["unique_audits"] += 1
        bound["semantic_units"] += units
        bound["primary"] += units + 28
        bound["native_retries"] += units + 10
    for bound in bounds.values():
        bound["maximum"] = bound["primary"] + bound["native_retries"]
    if {k: v["maximum"] for k, v in bounds.items()} != CHILD_PHASE_LIMITS:
        raise EvidenceError("fixed-before-call request bound changed")
    plan = {"schema": 1, "protocol": PROTOCOL, "created_utc": base.utc(),
            "parent_plan_sha256": PARENT_PLAN_SHA256, "parent_inventory_sha256": PARENT_MANIFEST_SHA256,
            "parent_result_sha256": PARENT_RESULT_SHA256,
            "original_case_manifest_sha256": base.FIXED_CASE_MANIFEST_SHA256,
            "engine": engine.manifest, "profile": parent.plan["profile"],
            "profile_sha256": parent.plan["profile_sha256"], "runtime": parent.plan["runtime"],
            "text_contracts": parent.plan["text_contracts"], "requested_models": parent.plan["requested_models"],
            "runner_sha256": RUNNER_SHA256, "continuation_sha256": base.sha(Path(__file__).read_bytes()),
            "cases_sha256": base.hash_json(copied), "preflight": inspected,
            "selected_case_ids": [c["id"] for c in copied["cases"]], "allowed_contexts": allowed,
            "attempt_limit": CHILD_LIMIT, "phase_limits": CHILD_PHASE_LIMITS,
            "parent_attempts": 359, "cumulative_limit": 1900, "cumulative_phase_limits": PARENT_PHASE_LIMITS,
            "phase_bounds": bounds, "primary_maximum": 946, "native_retry_maximum": 370,
            "worst_new_requests": CHILD_LIMIT, "worst_cumulative_requests": 1675,
            "child_directory": str(DEFAULT_CHILD.resolve()), "registry_path": str(DEFAULT_REGISTRY.resolve()),
            "provider_requests": 0, "execution_authorized": False,
            "ready_for_live_review": True,
            "live_authority": "Exact independent review and authenticated separate lead data row required",
            "capabilities_excluded": parent.plan["capabilities_excluded"]}
    base.write_json(output / "cases.json", copied)
    base.write_json(output / "plan.json", plan)
    base.write_json(output / "plan-hash.json", {"plan_sha256": base.hash_json(plan)})
    base.write_json(output / "release-template.json", release_template(plan))
    return plan


def validate_plan(engine, plan: dict, prepared: Path, *, parent=None) -> dict:
    parent = load_parent() if parent is None else parent
    _offline_output(prepared, engine.root)
    _bindings(engine, parent)
    if (plan.get("protocol") != PROTOCOL or plan.get("continuation_sha256") != base.sha(Path(__file__).read_bytes())
        or plan.get("parent_plan_sha256") != PARENT_PLAN_SHA256
        or plan.get("parent_inventory_sha256") != PARENT_MANIFEST_SHA256
        or plan.get("parent_result_sha256") != PARENT_RESULT_SHA256
        or plan.get("attempt_limit") != CHILD_LIMIT or plan.get("phase_limits") != CHILD_PHASE_LIMITS
        or plan.get("cumulative_limit") != 1900 or plan.get("cumulative_phase_limits") != PARENT_PHASE_LIMITS
        or plan.get("worst_new_requests") != 1316 or plan.get("worst_cumulative_requests") != 1675
        or plan.get("child_directory") != str(DEFAULT_CHILD.resolve())
        or plan.get("registry_path") != str(DEFAULT_REGISTRY.resolve())
        or plan.get("execution_authorized") is not False or plan.get("provider_requests") != 0
        or plan.get("ready_for_live_review") is not True):
        raise EvidenceError("accepted continuation plan changed")
    cases = base.validate_plan(engine, plan, prepared)
    restored = copy.deepcopy(cases)
    for case in restored["cases"]:
        case["target"] = case.pop("original_target")
    if (restored != parent.selected or [c["id"] for c in cases["cases"]] != plan["selected_case_ids"]
        or base.preflight(engine, cases) != plan["preflight"]):
        raise EvidenceError("untouched inputs/labels/grouping/preflight changed")
    return cases


def combine(parent, child: dict, child_records: list[dict], plan: dict, *, child_result_sha256: str):
    """Combine intervals; leave every carried parent row structurally identical."""
    expected_ids = [c["id"] for c in parent.selected["cases"]]
    if (child.get("planned") != 27 or child.get("binding") != base.hash_json(plan)
        or [r.get("id") for r in child.get("rows", [])] != expected_ids
        or plan.get("selected_case_ids") != expected_ids
        or child.get("engine") != parent.result["engine"] or child.get("limits") != parent.result["limits"]
        or child.get("scope") != parent.result["scope"]):
        raise EvidenceError("child result selection/engine/profile/order changed")
    for row, case in zip(child["rows"], parent.selected["cases"]):
        if (row.get("original_target") != case["target"]
            or any(row.get(k) != v for k, v in case.items() if k != "target")):
            raise EvidenceError("child input/label/grouping bindings changed")
    replacements = {r["id"]: copy.deepcopy(r) for r in child["rows"]}
    rows = [replacements[r["id"]] if r["id"] in replacements else copy.deepcopy(r) for r in parent.result["rows"]]
    row_interval = {r["id"]: "child" if r["id"] in replacements else "parent" for r in rows}
    all_records = parent.records + child_records
    usage = base.RequestJournal.summary(SimpleNamespace(state={"attempts": len(all_records)},
        records=all_records, replayed=0, stop_reason=child.get("usage", {}).get("stop_reason")))
    usage["interval_stop_reasons"] = {"parent": parent.usage["stop_reason"], "child": usage["stop_reason"]}
    usage["basis"] = "Numbered SDK reservations in the two journals; cache/replay/lineage references excluded"
    intervals = [{"id": key, "started_utc": doc["started_utc"], "measured_utc": doc["measured_utc"],
                  "result_sha256": digest, "usage": copy.deepcopy(doc["usage"])}
                 for key, doc, digest in [("parent", parent.result, PARENT_RESULT_SHA256),
                                          ("child", child, child_result_sha256)]]
    coverage = base.coverage_data(rows)
    for alignment in coverage["attempt_alignment"]:
        interval = "parent" if alignment["fingerprint"] in parent.old_keys else "child"
        alignment["interval_id"] = interval
        alignment["audit_directory"] = str(DEFAULT_PARENT if interval == "parent" else DEFAULT_CHILD) + "/audits"
    lineage = {"parent": {"plan_sha256": PARENT_PLAN_SHA256, "inventory_sha256": PARENT_MANIFEST_SHA256,
                           "result_sha256": PARENT_RESULT_SHA256},
               "child": {"plan_sha256": base.hash_json(plan), "result_sha256": child_result_sha256},
               "original_case_manifest_sha256": base.FIXED_CASE_MANIFEST_SHA256,
               "reused_runner_sha256": RUNNER_SHA256}
    benign = [r for r in rows if r["kind"] == "benign"]
    combined = {k: copy.deepcopy(v) for k, v in parent.result.items()
                if k not in {"schema", "protocol", "binding", "rows", "usage", "summary", "coverage", "measured_utc"}}
    combined.update(schema=2, protocol=PROTOCOL, binding=base.hash_json(lineage), rows=rows,
                    measured_utc=child["measured_utc"], summary=base.summarize_rows(rows),
                    coverage=coverage, usage=usage, parent_result_sha256=PARENT_RESULT_SHA256,
                    child_result_sha256=child_result_sha256, intervals=intervals,
                    row_interval=row_interval, lineage=lineage,
                    benign_adjudication={"raw_flag_ids": [r["id"] for r in benign if r.get("raw_medium_flag")],
                        "pending_ids": [r["id"] for r in benign if r.get("raw_medium_flag") and r.get("adjudicated_false_positive") is None],
                        "confirmed_false_positive_ids": [r["id"] for r in benign if r.get("adjudicated_false_positive") is True],
                        "unattempted_ids": [r["id"] for r in benign if r["status"] == "unattempted"],
                        "incomplete_ids": [r["id"] for r in benign if not r["complete"] and r["status"] != "unattempted"],
                        "basis": "Source-inference flags; pending judgments remain unadjudicated"})
    provenance = {"schema": 1, "protocol": PROTOCOL, "lineage": lineage, "row_interval": row_interval,
                  "sdk_requests": [{"interval_id": interval, "number": r["number"], "state": r["state"],
                                    "context": r.get("context"), "stage": r.get("stage"), "phase": r.get("phase"),
                                    "request_sha256": r.get("request_sha256"), "response_sha256": r.get("response_sha256")}
                                   for interval, records in [("parent", parent.records), ("child", child_records)] for r in records],
                  "native_attempt_alignment": copy.deepcopy(coverage["attempt_alignment"])}
    return combined, provenance


def release_template(plan: dict) -> dict:
    """A non-authorizing template for the later immutable lead queue body."""
    return {"schema": 1, "protocol": RELEASE_PROTOCOL, "execution_authorized": False,
            "owner": "research-security@fugu", "reviewed_commit": None, "review_queue_ref": None,
            "engine_commit": ENGINE_COMMIT, "child_plan_sha256": base.hash_json(plan),
            "parent_plan_sha256": PARENT_PLAN_SHA256, "parent_inventory_sha256": PARENT_MANIFEST_SHA256,
            "parent_result_sha256": PARENT_RESULT_SHA256,
            "child_directory": str(DEFAULT_CHILD.resolve()), "registry_path": str(DEFAULT_REGISTRY.resolve()),
            "attempt_limit": CHILD_LIMIT, "phase_limits": CHILD_PHASE_LIMITS,
            "cumulative_limit": 1900, "cumulative_phase_limits": PARENT_PHASE_LIMITS}


def verify_release(row: dict, plan: dict, approved_plan_sha256: str) -> SimpleNamespace:
    """Validate an authenticated queue row; a bare reference is insufficient."""
    if (base.hash_json(plan) != approved_plan_sha256 or not isinstance(row, dict)
        or not re.fullmatch(r"qitem-[0-9]{14}-[0-9a-f]{8}", row.get("qitemId", ""))
        or row.get("sourceSession") != "control-lead@fugu"
        or row.get("destinationSession") != "research-security@fugu"
        or row.get("state") != "in-progress" or not isinstance(row.get("claimedAt"), str)
        or not row["claimedAt"] or not isinstance(row.get("body"), str)):
        raise EvidenceError("separate authenticated claimed lead data release is required")
    body = _parse_json(row["body"])
    expected = release_template(plan)
    if (not isinstance(body, dict) or set(body) != set(expected)
        or body.get("execution_authorized") is not True
        or not re.fullmatch(r"[0-9a-f]{40}", body.get("reviewed_commit") or "")
        or not re.fullmatch(r"qitem-[0-9]{14}-[0-9a-f]{8}", body.get("review_queue_ref") or "")
        or any(body[k] != value for k, value in expected.items()
               if k not in {"execution_authorized", "reviewed_commit", "review_queue_ref"})):
        raise EvidenceError("data release review/plan/parent/namespace/budget contract changed")
    immutable = {k: row[k] for k in ("qitemId", "sourceSession", "destinationSession", "body")}
    return SimpleNamespace(queue_ref=row["qitemId"], binding=base.hash_json(immutable), body=body)


def _rig_json(arguments: list[str]) -> dict:
    try:
        result = subprocess.run(["rig", *arguments], capture_output=True, text=True, timeout=15)
        if result.returncode != 0 or len(result.stdout) > 2_000_000:
            raise EvidenceError("authenticated OpenRig evidence unavailable")
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise EvidenceError("authenticated OpenRig response shape changed")
        return value
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise EvidenceError("authenticated OpenRig evidence unavailable") from None


def authenticate_release(queue_ref: str, plan: dict, approved_plan_sha256: str):
    identity = _rig_json(["whoami", "--json"])["identity"]
    if (identity.get("logicalId") != "research.security"
        or identity.get("sessionName") != "research-security@fugu" or identity.get("rigName") != "fugu"):
        raise EvidenceError("data release belongs to the research.security seat in fugu")
    row = _rig_json(["queue", "show", queue_ref, "--full", "--json"])
    if row.get("qitemId") != queue_ref:
        raise EvidenceError("authenticated queue reference changed")
    return verify_release(row, plan, approved_plan_sha256)


def _child_output(output: Path):
    if _has_symlink(output) or output.resolve() != DEFAULT_CHILD.resolve():
        raise EvidenceError("only the canonical explicitly granted child directory is allowed")


def _request_bindings(registry: dict) -> dict:
    rows = registry.get("calls")
    count = registry.get("attempts")
    if (not _integer(count) or not isinstance(rows, list)
        or any(not isinstance(r, dict) or set(r) != {"number", "sha256"}
               or not _integer(r["number"], maximum=count) or r["number"] < 1
               or not isinstance(r["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", r["sha256"])
               for r in rows)):
        raise EvidenceError("malformed registry request binding")
    bindings = {r["number"]: r["sha256"] for r in rows}
    if len(bindings) != len(rows):
        raise EvidenceError("duplicate registry request binding")
    return bindings


def validate_registry_ledger(registry: dict, ledger, directory: Path, *, binding: str,
                             parent_usage: dict, limit: int = CHILD_LIMIT,
                             phase_limits: dict | None = None):
    phase_limits = CHILD_PHASE_LIMITS if phase_limits is None else phase_limits
    if (registry.get("binding") != binding or ledger.state.get("binding") != binding
        or registry.get("child_directory") != str(directory.resolve())
        or registry.get("parent_usage") != parent_usage
        or registry.get("attempts") != ledger.state["attempts"]
        or registry.get("limit") != limit or ledger.state.get("limit") != limit
        or registry.get("phase_limits") != phase_limits or ledger.state.get("phase_limits") != phase_limits
        or ledger.state.get("expected_output_tokens") != 4096
        or ledger.state.get("expected_models") != registry.get("expected_models")
        or not isinstance(registry.get("phase_attempts"), dict)
        or sum(registry["phase_attempts"].values()) != registry["attempts"]
        or any(k not in phase_limits or not _integer(v, maximum=phase_limits[k])
               for k, v in registry["phase_attempts"].items())
        or parent_usage["attempts"] + registry["attempts"] > 1900
        or any(parent_usage["phase_attempts"].get(k, 0) + registry["phase_attempts"].get(k, 0) > v
               for k, v in PARENT_PHASE_LIMITS.items())):
        raise EvidenceError("aggregate child ownership/budget/model/counter binding changed")
    if (registry.get("journal_initialized") is not True
        or type(registry.get("session_open")) is not bool
        or registry.get("stop_reason") != ledger.usage["stop_reason"]
        or registry["session_open"] and not registry.get("stop_reason")):
        raise EvidenceError("child ownership stop accounting needs owner recovery")
    if (ledger.usage["phase_attempts"].get("unknown", 0) == 0
        and registry["phase_attempts"] != ledger.usage["phase_attempts"]):
        raise EvidenceError("aggregate phase accounting changed")
    bound = _request_bindings(registry)
    for row in ledger.records:
        path = directory / "calls" / f"{row['number']:05d}.json"
        if row["number"] in bound:
            _regular(path)
            if base.sha(path.read_bytes()) != bound[row["number"]]:
                raise EvidenceError("aggregate request bytes differ from the durable registry")
        elif row["state"] != "reserved":
            raise EvidenceError("terminal request lacks a durable registry binding")


def aggregate(engine, prepared: Path, output: Path) -> dict:
    """Read journals offline; publish combined data and qualified provenance."""
    _child_output(output)
    lock_path = DEFAULT_REGISTRY.with_suffix(".lock")
    _regular(lock_path)
    with lock_path.open("r") as owner:
        try:
            fcntl.flock(owner, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise EvidenceError("child journal is still owned") from None
        try:
            return _aggregate_locked(engine, prepared, output)
        finally:
            fcntl.flock(owner, fcntl.LOCK_UN)


def _aggregate_locked(engine, prepared: Path, output: Path) -> dict:
    parent = load_parent()
    plan = read_json(prepared / "plan.json")
    validate_plan(engine, plan, prepared, parent=parent)
    ledger = read_ledger(output, allow_orphans=True)
    registry = read_json(DEFAULT_REGISTRY)
    validate_registry_ledger(registry, ledger, output, binding=base.hash_json(plan), parent_usage=parent.usage)
    guard_path = DEFAULT_REGISTRY.with_suffix(".guard.json")
    if _has_symlink(guard_path):
        raise EvidenceError("symlink child ownership guard")
    if guard_path.exists():
        guard = read_json(guard_path)
        if (not isinstance(guard, dict) or set(guard) != {"binding", "number", "phase"}
            or guard["binding"] != base.hash_json(plan)
            or not _integer(guard["number"]) or guard["number"] != registry["attempts"]
            or guard["phase"] not in PARENT_PHASE_LIMITS or not registry["stop_reason"]):
            raise EvidenceError("child ownership guard accounting needs owner recovery")
    child = read_json(output / "fugu.json")
    current = _continuation_usage(ledger.usage, parent.usage, registry)
    saved_usage = child.get("usage")
    # The process replay annotation is not a durable SDK reservation. Retain its
    # validated value; every other field must equal the ledger/registry summary.
    replayed = saved_usage.get("replayed_requests_this_process") if isinstance(saved_usage, dict) else None
    if type(replayed) is not int or replayed < 0:
        raise EvidenceError("child result replay accounting is malformed")
    current["replayed_requests_this_process"] = replayed
    if base.hash_json(saved_usage) != base.hash_json(current):
        raise EvidenceError("child result accounting needs owner recovery before aggregation")
    combined, provenance = combine(parent, child, ledger.records, plan,
                                  child_result_sha256=base.sha((output / "fugu.json").read_bytes()))
    if (combined["usage"]["attempts"] > 1900 or ledger.state["attempts"] > CHILD_LIMIT
        or any(combined["usage"]["phase_attempts"].get(k, 0) > v for k, v in PARENT_PHASE_LIMITS.items())):
        raise EvidenceError("aggregate exceeded accepted attempt ceilings")
    base.write_json(output / "combined.json", combined)
    base.write_json(output / "provenance.json", provenance)
    load_parent()  # Verify every sealed byte after publication.
    return combined


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run", "aggregate"])
    parser.add_argument("--engine-root", required=True, type=Path)
    parser.add_argument("--prepared-dir", type=Path, default=DEFAULT_OFFLINE)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--data-release-ref")
    args = parser.parse_args(argv)
    if args.action == "run":
        if (not args.approved_plan_sha256 or not re.fullmatch(r"[0-9a-f]{64}", args.approved_plan_sha256)
            or not args.data_release_ref or not re.fullmatch(r"qitem-[0-9]{14}-[0-9a-f]{8}", args.data_release_ref)):
            raise EvidenceError("exact approved plan and separate authenticated data release are required")
        plan = read_json(args.prepared_dir / "plan.json")
        release = authenticate_release(args.data_release_ref, plan, args.approved_plan_sha256)
    else:
        # Never read .env during preparation or aggregation.
        os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    engine = base.load_engine(args.engine_root)
    if args.action == "prepare":
        plan = prepare(engine, args.output or args.prepared_dir)
        print(json.dumps({"plan_sha256": base.hash_json(plan), "provider_requests": 0,
                          "ready_for_live_review": True, "execution_authorized": False}))
        return 0
    output = args.output or DEFAULT_CHILD
    _child_output(output)
    if args.action == "aggregate":
        combined = aggregate(engine, args.prepared_dir, output)
        print(json.dumps({"planned": 40, "attempts": combined["usage"]["attempts"], "provider_requests": 0}))
        return 0
    parent = load_parent()
    cases = validate_plan(engine, plan, args.prepared_dir, parent=parent)
    cfg = engine.modules["config"]
    settings = cfg.get_settings()  # Approved application loader, after the release gate.
    if not settings.has_api_key or settings.base_url != cfg.DEFAULT_BASE_URL:
        raise EvidenceError("approved provider credentials/default endpoint unavailable")
    with ContinuationJournal(output, registry_path=DEFAULT_REGISTRY, binding=base.hash_json(plan),
            release_binding=release.binding, parent_usage=parent.usage,
            allowed_contexts=plan["allowed_contexts"], expected_models=plan["requested_models"]) as journal:
        try:
            release_record = {"queue_ref": release.queue_ref, "binding": release.binding, "contract": release.body}
            for name, value in [("plan.json", plan), ("cases.json", cases), ("data-release.json", release_record)]:
                path = output / name
                if path.exists():
                    if read_json(path) != value:
                        raise EvidenceError("immutable child plan/cases/release changed")
                else:
                    base.write_json(path, value)
            result = asyncio.run(evaluate_cases(engine, cases, output, journal))
            load_parent()
        except BaseException:
            try:
                journal._stop("continuation_execution_failure")
            except JournalStopped:
                pass
            raise
    print(json.dumps({"planned": result["planned"], "child_attempts": result["usage"]["attempts"],
                      "cumulative_attempts": 359 + result["usage"]["attempts"],
                      "stop_reason": result["usage"]["stop_reason"]}))
    return 2 if result["usage"]["stop_reason"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, JournalStopped) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None
