"""Prepare and execute a bounded, fresh full-workflow Fugu benchmark.

Preparation is offline. The run action requires an exact frozen plan hash and
a separate later data-phase queue reference; target code is never run on the
host by this runner.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import threading
from typing import Any, Callable

from bench import current_limits as limits


ROOT = Path(__file__).resolve().parents[1]
SCRATCH_ROOT = Path("/tmp/fugu-full-workflow-backend-20261005")
SCANNER_BINDING = ROOT / ".fugu-private/full-workflow-20261005/static-scanner-binding.json"
SCANNER_VERIFICATION = ROOT / ".fugu-private/full-workflow-20261005/prerequisites/scanner-verification.json"
CHAMBER_PREREQUISITE_ROOT = ROOT / ".fugu-private/full-workflow-20261005/prerequisites"
CHAMBER_STATUS_PATH = CHAMBER_PREREQUISITE_ROOT / "status.json"
CHAMBER_DENIAL_STATUS = "unverified; known Buildx denial unchanged"
CHAMBER_UNAVAILABLE_REASON = (
    "Native Docker chamber unavailable: retained prerequisite records the known Buildx denial; "
    "no retry or alternate driver is permitted."
)
METADATA_NAMES = {"manifest.json", "manifest.fugu.json", "set.json"}
NATIVE_BATCH_LIMIT = 1800
NATIVE_BATCH_COUNT = 3
MAX_NATIVE_ATTEMPTS = NATIVE_BATCH_LIMIT * NATIVE_BATCH_COUNT
COMPETITOR_LIMIT = 1800
SEARCH_LIMIT = 480
MAX_OUTPUT_TOKENS = 4096
REQUEST_TIMEOUT_SECONDS = 90
SDK_MAX_RETRIES = 0
MEDIUM_OR_HIGHER = {"medium", "high", "critical"}
NATIVE_STAGE_NAMES = ("concealment", "static", "semantic", "harness", "reputation", "detonation")
REQUIRED_STAGE_NAMES = NATIVE_STAGE_NAMES + ("composition",)
PROFILE_KEYS = {
    "llm_max_output_tokens": 4096,
    "semantic_max_units": 24,
    "semantic_max_chars_per_unit": 6000,
    "harness_mount_char_budget": 32000,
    "red_probe_count": 3,
    "red_probe_max_chars": 200,
    "sdk_max_retries": 0,
    "request_timeout_seconds": 90,
    "source_max_entries": 20000,
    "source_max_bytes": 536870912,
    "git_clone_timeout_seconds": 120,
    "fanout_max_units": 24,
}

EvidenceError = limits.EvidenceError
JournalStopped = limits.JournalStopped
RequestJournal = limits.RequestJournal
AuditCache = limits.AuditCache


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_json(value: Any) -> str:
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":")).encode())


def write_json(path: Path, value: Any) -> None:
    limits.write_json(Path(path), value)


def read_json(path: Path) -> Any:
    return limits.read_json(Path(path))


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def input_hashes(target: Path) -> dict[str, str]:
    return limits.input_hashes(Path(target))


def fingerprint(hashes: dict[str, str]) -> str:
    return limits.fingerprint(hashes)


def native_batch_specs() -> list[dict[str, Any]]:
    """The three immutable native budgets; tests may inspect but not override them."""
    return [{"id": f"fugu-{index + 1}", "limit": NATIVE_BATCH_LIMIT}
            for index in range(NATIVE_BATCH_COUNT)]


def _skipped_reason_is_inapplicable(stage: str, reason: str) -> bool:
    lowered = reason.lower()
    if stage == "detonation":
        return "no runnable triggers" in lowered or "no triggers derived" in lowered
    if stage == "composition":
        return "single-source job" in lowered or "no composition members" in lowered
    if stage == "reputation":
        return "no searchable identifiers" in lowered or "no identifiers to search" in lowered
    if stage in {"semantic", "harness"}:
        return "no analyzable text" in lowered or "no supported source text" in lowered
    return False


def stage_state(result: dict[str, Any]) -> str:
    """Return honest stage coverage without converting skips into successes."""
    metrics = result.get("metrics") or {}
    if metrics.get("unattempted"):
        return "unattempted"
    if not result.get("ok"):
        if (result.get("stage") == "detonation"
                and str(result.get("error", "")).startswith("ChamberUnavailableError:")):
            return "unavailable"
        return "failed"
    skipped = metrics.get("skipped")
    if skipped:
        return "not_applicable" if _skipped_reason_is_inapplicable(
            str(result.get("stage", "")), str(skipped)) else "unavailable"
    if result.get("journal_alignment", {}).get("aligned") is False:
        return "partial"
    member_coverage = metrics.get("member_coverage")
    if isinstance(member_coverage, list) and any(
        isinstance(row, dict) and row.get("state") not in {"completed", "not_applicable"}
        for row in member_coverage
    ):
        return "partial"
    scanner_alignment = result.get("scanner_prerequisite_alignment")
    if scanner_alignment and scanner_alignment.get("verified") is False:
        return "partial"
    incomplete_keys = (
        "coverage_incomplete", "omitted_units", "units_omitted", "units_partial",
        "skipped_binary", "skipped_large",
        "skipped_undecodable", "skipped_unreadable", "skipped_max_files",
        "call_errors", "parse_errors", "probe_errors", "red_probes_omitted",
        "red_probe_chars_omitted", "mount_omitted_files", "files_omitted",
        "trigger_results_missing", "trigger_results_duplicate", "trigger_results_unselected",
        "trigger_results_unexpected",
    )
    if any(metrics.get(name) for name in incomplete_keys):
        return "partial"
    triggers = metrics.get("triggers")
    completed_triggers = metrics.get("trigger_results_completed")
    if type(triggers) is int and triggers > 0 and completed_triggers != triggers:
        return "partial"
    expected_comparisons = metrics.get("comparisons_expected")
    completed_comparisons = metrics.get("comparisons_completed")
    if (type(expected_comparisons) is int and type(completed_comparisons) is int
            and completed_comparisons < expected_comparisons):
        return "partial"
    surface = metrics.get("tool_surface")
    if isinstance(surface, dict) and any(surface.get(name) for name in (
        "coverage_incomplete", "omitted_tools", "parse_errors")):
        return "partial"
    return "completed"


def case_complete(stages: list[dict[str, Any]]) -> bool:
    """All required stages must be present for each member and composition."""
    if not stages:
        return False
    groups: dict[str, dict[str, str]] = defaultdict(dict)
    for row in stages:
        stage = row.get("stage")
        if stage not in REQUIRED_STAGE_NAMES:
            return False
        group = "composition" if stage == "composition" else str(row.get("member") or "__single__")
        if stage in groups[group]:
            return False
        groups[group][stage] = row.get("state", "unattempted")
    for group, group_rows in groups.items():
        expected = {"composition"} if group == "composition" else set(NATIVE_STAGE_NAMES)
        if set(group_rows) != expected:
            return False
        if any(state not in {"completed", "not_applicable"} for state in group_rows.values()):
            return False
    if not any("composition" in group_rows for group_rows in groups.values()):
        return False
    return True


def _safe_relative_path(value: str, *, field: str) -> Path:
    candidate = Path(value)
    if not value or candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise EvidenceError(f"unsafe {field}")
    return candidate


def freeze_manifest(manifest: dict[str, Any], *, source_root: Path) -> dict[str, Any]:
    """Validate schema-1 case metadata and raw input hashes without copying data."""
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or not isinstance(manifest.get("cases"), list):
        raise EvidenceError("case manifest must use schema 1 and contain cases")
    if not manifest["cases"]:
        raise EvidenceError("case manifest is empty")
    root = Path(source_root).resolve()
    seen: set[str] = set()
    cases = []
    for original in manifest["cases"]:
        if not isinstance(original, dict):
            raise EvidenceError("invalid case record")
        case = dict(original)
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise EvidenceError("case ids must be unique non-empty strings")
        seen.add(case_id)
        if not all(isinstance(case.get(key), str) and case[key] for key in ("cohort", "kind", "target")):
            raise EvidenceError("case cohort, kind, and target are required")
        if not isinstance(case.get("provenance"), (str, dict, list)):
            raise EvidenceError("case provenance must be explicit")
        if not isinstance(case.get("overlap"), (str, list, dict)):
            raise EvidenceError("case overlap must be explicit")
        target_value = case["target"]
        target_path = Path(target_value)
        if target_path.is_absolute():
            source = target_path
        else:
            source = root / _safe_relative_path(target_value, field="target path")
        if source.is_symlink() or not source.exists() or not source.is_dir():
            raise EvidenceError("case target must be an existing regular directory")
        resolved = source.resolve()
        if not resolved.is_relative_to(root):
            raise EvidenceError("case target leaves source root")
        actual = input_hashes(source)
        expected = case.get("input_sha256")
        if not isinstance(expected, dict) or expected != actual:
            raise EvidenceError("frozen input hash mismatch")
        for name, digest in expected.items():
            rel = _safe_relative_path(name, field="input filename")
            if rel.name.lower() in METADATA_NAMES or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise EvidenceError("input hash map contains metadata or invalid digest")
        members = case.get("members")
        if members is not None:
            if not isinstance(members, list) or not members:
                raise EvidenceError("composition members must be a non-empty list")
            member_dirs: set[str] = set()
            for member in members:
                if not isinstance(member, dict) or not isinstance(member.get("dir"), str):
                    raise EvidenceError("invalid composition member")
                member_dir = _safe_relative_path(member["dir"], field="member directory")
                if member["dir"] in member_dirs:
                    raise EvidenceError("duplicate composition member directory")
                member_dirs.add(member["dir"])
                if not isinstance(member.get("label"), str) or not member["label"]:
                    raise EvidenceError("composition member labels are required")
                directory = source / member_dir
                if directory.is_symlink() or not directory.is_dir():
                    raise EvidenceError("composition member directory is unavailable")
                input_hashes(directory)
        case["source_target"] = target_value
        cases.append(case)
    return {**{key: value for key, value in manifest.items() if key != "cases"}, "cases": cases}


def _copy_case_inputs(cases: list[dict[str, Any]], *, source_root: Path, output: Path) -> list[dict[str, Any]]:
    root, destination_root = Path(source_root).resolve(), Path(output).resolve()
    copied_cases = []
    target_root = destination_root / "targets"
    target_root.mkdir(parents=True, exist_ok=True)
    for index, original in enumerate(cases):
        source_target = Path(original["source_target"])
        source = source_target if source_target.is_absolute() else root / _safe_relative_path(
            str(source_target), field="target path")
        if input_hashes(source) != original["input_sha256"]:
            raise EvidenceError("input changed before copy")
        target = target_root / f"{index:04d}"
        if target.exists():
            raise EvidenceError("target copy already exists")
        target.mkdir(parents=True)
        for name, expected_hash in original["input_sha256"].items():
            relative = _safe_relative_path(name, field="input filename")
            src = source / relative
            dst = target / relative
            if not src.is_file() or src.is_symlink():
                raise EvidenceError("input changed during copy")
            data = src.read_bytes()
            if sha(data) != expected_hash:
                raise EvidenceError("input changed during copy")
            if not dst.resolve().is_relative_to(target):
                raise EvidenceError("copied input leaves target")
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
        if input_hashes(target) != original["input_sha256"]:
            raise EvidenceError("copied input hash mismatch")
        row = dict(original)
        row["target"] = str(target)
        copied_cases.append(row)
    return copied_cases


def _read_scanner_prerequisite(engine: Any, *, binding_path: Path = SCANNER_BINDING,
                               verification_path: Path = SCANNER_VERIFICATION) -> dict[str, Any]:
    binding = read_json(binding_path)
    proof = read_json(verification_path)
    binary = Path(binding["binary"])
    if binary.is_symlink() or not binary.is_file():
        raise EvidenceError("pinned static scanner binary is unavailable")
    binary_hash = sha(binary.read_bytes())
    if binary_hash != binding.get("sha256") or binary.stat().st_size != binding.get("bytes"):
        raise EvidenceError("pinned static scanner binary changed")
    if not isinstance(binding.get("image"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", binding["image"]):
        raise EvidenceError("pinned static scanner image digest is invalid")
    tool_surface = importlib.import_module("fugu.pipeline.stages.tool_surface")
    if binding.get("expected_source_commit") != tool_surface.ENGINE_PIN:
        raise EvidenceError("pinned static scanner source does not match the engine")
    result = proof.get("result", {})
    metrics = result.get("metrics", {})
    surface = metrics.get("tool_surface", {})
    if (proof.get("engine_commit") != engine.manifest.get("commit")
            or proof.get("engine_mismatches_before_after") != []
            or result.get("stage") != "static" or result.get("ok") is not True
            or surface.get("enabled") is not True
            or surface.get("binary_sha256") != binary_hash
            or surface.get("coverage_incomplete") is not False
            or surface.get("omitted_tools") != 0 or surface.get("parse_errors") != []
            or proof.get("provider_calls") != 0 or proof.get("search_calls") != 0
            or proof.get("target_execution") is not False or proof.get("build_attempts") != 0):
        raise EvidenceError("pinned static scanner inert verification did not pass")
    return {
        "binary": str(binary.resolve()),
        "binary_sha256": binary_hash,
        "binary_bytes": binary.stat().st_size,
        "image": binding["image"],
        "expected_source_commit": binding["expected_source_commit"],
        "binding_path": str(Path(binding_path).resolve()),
        "binding_sha256": sha(Path(binding_path).read_bytes()),
        "verification_path": str(Path(verification_path).resolve()),
        "verification_sha256": sha(Path(verification_path).read_bytes()),
        "inert_surface_count": surface.get("tools"),
        "inert_finding_count": len(result.get("findings", [])),
        "inert_findings": [{key: finding.get(key) for key in (
            "title", "severity", "confidence", "owasp_ids")}
            for finding in result.get("findings", [])],
        "inert_ok": True,
        "target_execution": False,
        "provider_calls": 0,
        "search_calls": 0,
        "build_attempts": 0,
    }


def _validate_chamber_prerequisite(chamber: Any) -> None:
    if not isinstance(chamber, dict):
        raise EvidenceError("chamber prerequisite is missing or malformed")
    status = chamber.get("status")
    if status == "unverified":
        raise EvidenceError("chamber prerequisite remains unverified")
    if chamber.get("driver") != "docker" or chamber.get("target_execution") is not False:
        raise EvidenceError("chamber prerequisite must bind Docker without target execution")
    if status == "unavailable":
        evidence_ref = chamber.get("evidence_ref")
        evidence_digest = chamber.get("evidence_sha256")
        if (not isinstance(chamber.get("reason"), str) or not chamber["reason"].strip()
                or not isinstance(evidence_ref, str) or not evidence_ref
                or not isinstance(evidence_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", evidence_digest)
                or chamber.get("known_buildx_denial_retried") is not False):
            raise EvidenceError("unavailable chamber prerequisite lacks a frozen reason or evidence binding")
        return
    if status == "available":
        binding = chamber.get("verified_binding")
        if (not isinstance(binding, dict) or binding.get("verified") is not True
                or not isinstance(binding.get("evidence_ref"), str)
                or not binding["evidence_ref"]
                or not isinstance(binding.get("evidence_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", binding["evidence_sha256"])):
            raise EvidenceError("available chamber requires an explicit verified chamber binding")
        return
    raise EvidenceError(f"unsupported chamber prerequisite status: {status!r}")


def _read_chamber_prerequisite(status_path: Path | None = None) -> dict[str, Any]:
    """Bind the retained Docker denial; never infer chamber availability from Docker presence."""
    path = Path(status_path or CHAMBER_STATUS_PATH)
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("retained chamber prerequisite evidence is unavailable")
    raw = path.read_bytes()
    try:
        evidence = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise EvidenceError("retained chamber prerequisite evidence is malformed") from None
    if (not isinstance(evidence, dict)
            or evidence.get("chamber_target_runtime") != CHAMBER_DENIAL_STATUS
            or evidence.get("target_execution") is not False):
        raise EvidenceError("retained chamber evidence no longer records the known Buildx denial")
    return {
        "status": "unavailable",
        "driver": "docker",
        "reason": CHAMBER_UNAVAILABLE_REASON,
        "evidence_ref": str(path.resolve()),
        "evidence_sha256": sha(raw),
        "target_execution": False,
        "known_buildx_denial_retried": False,
    }


def _verify_chamber_prerequisite(plan: dict[str, Any]) -> None:
    chamber = plan.get("chamber_prerequisite")
    _validate_chamber_prerequisite(chamber)
    if (not isinstance(plan.get("driver_selection"), dict)
            or plan["driver_selection"].get("selected") != "docker"):
        raise EvidenceError("chamber execution cannot switch drivers to bypass the retained Buildx denial")
    if chamber["status"] == "unavailable":
        path = Path(chamber["evidence_ref"])
        expected = Path(CHAMBER_STATUS_PATH).resolve()
        if (path.is_symlink() or not path.is_absolute() or path.resolve() != expected
                or not path.is_file()):
            raise EvidenceError("frozen unavailable chamber evidence path changed")
        raw = path.read_bytes()
        if sha(raw) != chamber["evidence_sha256"]:
            raise EvidenceError("frozen unavailable chamber evidence changed")
        try:
            evidence = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise EvidenceError("frozen unavailable chamber evidence is malformed") from None
        if (not isinstance(evidence, dict)
                or evidence.get("chamber_target_runtime") != CHAMBER_DENIAL_STATUS
                or evidence.get("target_execution") is not False):
            raise EvidenceError("frozen chamber evidence no longer records the retained denial")
        return

    binding = chamber["verified_binding"]
    path = Path(binding["evidence_ref"])
    prerequisite_root = Path(CHAMBER_PREREQUISITE_ROOT).resolve()
    if path.is_symlink() or not path.is_absolute() or not path.is_file():
        raise EvidenceError("verified chamber evidence file is unavailable")
    resolved = path.resolve()
    if not resolved.is_relative_to(prerequisite_root):
        raise EvidenceError("verified chamber evidence must stay in the retained prerequisite directory")
    raw = resolved.read_bytes()
    if sha(raw) != binding["evidence_sha256"]:
        raise EvidenceError("verified chamber evidence hash changed")
    try:
        proof = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise EvidenceError("verified chamber evidence is malformed") from None
    if (not isinstance(proof, dict) or proof.get("verified") is not True
            or proof.get("chamber_available") is not True or proof.get("driver") != "docker"
            or proof.get("target_execution") is not False):
        raise EvidenceError("verified chamber binding does not prove Docker chamber availability")


def _verify_scanner_prerequisite(scanner: dict[str, Any]) -> None:
    for key, path_key, digest_key in (
        ("binary", "binary", "binary_sha256"),
        ("binding_path", "binding_path", "binding_sha256"),
        ("verification_path", "verification_path", "verification_sha256"),
    ):
        path = Path(scanner[path_key])
        if not path.is_file() or sha(path.read_bytes()) != scanner[digest_key]:
            raise EvidenceError(f"pinned static scanner {key} evidence changed")
    binding = read_json(Path(scanner["binding_path"]))
    if binding.get("image") != scanner.get("image"):
        raise EvidenceError("pinned static scanner image binding changed")


def apply_scanner_environment(scanner: dict[str, Any], *, environ=None) -> None:
    environment = os.environ if environ is None else environ
    expected = {
        "FUGU_STATIC_RULES_BINARY": scanner["binary"],
        "FUGU_STATIC_RULES_IMAGE": scanner["image"],
        "FUGU_STATIC_RULES_SHA256": scanner["binary_sha256"],
    }
    for key, value in expected.items():
        existing = environment.get(key)
        if existing and existing != value:
            raise EvidenceError(f"{key} differs from the frozen scanner plan")
        environment[key] = value


def _ensure_scratch_output(output: Path) -> Path:
    resolved = Path(output).resolve()
    root = SCRATCH_ROOT.resolve()
    if not resolved.is_relative_to(root):
        raise EvidenceError("runner output must stay in the assigned /tmp scratch root")
    if resolved == root:
        raise EvidenceError("runner output must use a dedicated child directory")
    return resolved


def _materialize_engine_snapshot(engine_root: Path) -> Path:
    """Adapt the lead's read-only engine-manifest snapshot for current_limits."""
    source_root = Path(engine_root).resolve()
    if (source_root / "manifest.json").is_file():
        return source_root
    source_manifest_path = source_root / "engine-manifest.json"
    if not source_manifest_path.is_file():
        raise EvidenceError("frozen engine needs manifest.json or engine-manifest.json")
    source_manifest_bytes = source_manifest_path.read_bytes()
    source_manifest = json.loads(source_manifest_bytes)
    commit, tree = source_manifest.get("commit"), source_manifest.get("tree")
    hashes = source_manifest.get("files")
    if (not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or not isinstance(tree, str) or not re.fullmatch(r"[0-9a-f]{40}", tree)
            or not isinstance(hashes, dict) or not hashes):
        raise EvidenceError("frozen engine manifest is malformed")
    python_root = source_root / "src" / "fugu"
    paths = list(python_root.rglob("*"))
    if any(path.is_symlink() or path.suffix == ".pyc" for path in paths):
        raise EvidenceError("frozen engine contains symlinks or bytecode")
    actual_paths = {path.relative_to(source_root).as_posix() for path in paths
                    if path.is_file() and path.suffix == ".py"}
    if actual_paths != set(hashes):
        raise EvidenceError("frozen engine source inventory differs from its manifest")
    for name, digest in hashes.items():
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or sha((source_root / name).read_bytes()) != digest):
            raise EvidenceError("frozen engine source hash mismatch")
    manifest_digest = sha(source_manifest_bytes)
    normalized_manifest = {
        "commit": commit,
        "tree": tree,
        "hashes": hashes,
        "source_manifest_path": str(source_manifest_path),
        "source_manifest_sha256": manifest_digest,
    }
    cache_root = SCRATCH_ROOT / "engine-snapshots" / commit
    if cache_root.exists():
        if read_json(cache_root / "manifest.json") != normalized_manifest:
            raise EvidenceError("normalized frozen engine binding changed")
        limits.verify_inventory(cache_root, normalized_manifest)
        return cache_root

    cache_root.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix=f".{commit}-", dir=cache_root.parent))
    try:
        shutil.copytree(source_root / "src", staging_root / "src")
        write_json(staging_root / "manifest.json", normalized_manifest)
        limits.verify_inventory(staging_root, normalized_manifest)
        if sha(source_manifest_path.read_bytes()) != manifest_digest:
            raise EvidenceError("frozen engine manifest changed while materializing")
        for name, digest in hashes.items():
            if sha((source_root / name).read_bytes()) != digest:
                raise EvidenceError("frozen engine source changed while materializing")
        os.replace(staging_root, cache_root)
    except BaseException:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise
    return cache_root


def _verify_source_engine_manifest(engine: Any) -> None:
    path = engine.manifest.get("source_manifest_path")
    digest = engine.manifest.get("source_manifest_sha256")
    if path is not None and (not Path(path).is_file() or sha(Path(path).read_bytes()) != digest):
        raise EvidenceError("original frozen engine manifest changed")


def prepare(engine: Any, manifest_path: Path, output: Path, *, source_root: Path = ROOT,
            scanner_binding_path: Path = SCANNER_BINDING,
            scanner_verification_path: Path = SCANNER_VERIFICATION) -> dict[str, Any]:
    """Freeze a zero-call plan and byte-preserving target copy in /tmp."""
    output = _ensure_scratch_output(output)
    if output.exists() and any(output.iterdir()):
        raise EvidenceError("preparation output already contains evidence")
    if output.resolve().is_relative_to(engine.root.resolve()):
        raise EvidenceError("preparation output overlaps the frozen engine")
    limits.verify_engine(engine)
    manifest_path = Path(manifest_path).resolve()
    manifest_bytes = manifest_path.read_bytes()
    manifest = freeze_manifest(json.loads(manifest_bytes), source_root=source_root)
    output.mkdir(parents=True, exist_ok=True)
    cases = _copy_case_inputs(manifest["cases"], source_root=source_root, output=output)
    frozen_manifest = {**{key: value for key, value in manifest.items() if key != "cases"}, "cases": cases}
    profile = limits.engine_profile(engine)
    if not limits.profile_ready(profile) or any(profile.get(key) != value for key, value in PROFILE_KEYS.items()):
        raise EvidenceError("current full-workflow production profile is not ready")
    scanner = _read_scanner_prerequisite(
        engine, binding_path=scanner_binding_path,
        verification_path=scanner_verification_path)
    driver_env = os.environ.get("FUGU_DRIVER", "").strip().lower()
    if driver_env not in {"", "docker"}:
        raise EvidenceError("cannot switch detonation drivers to bypass the retained Buildx denial")
    chamber = _read_chamber_prerequisite(CHAMBER_STATUS_PATH)
    runtime = limits.runtime_versions()
    plan = {
        "schema": 1,
        "protocol": "fugu-full-workflow-v1",
        "created_utc": utc(),
        "execution_authorized": False,
        "engine": engine.manifest,
        "profile": profile,
        "profile_sha256": hash_json(profile),
        "requested_models": [engine.modules["config"].ULTRA_MODEL,
                             engine.modules["config"].SUPER_MODEL],
        "cases_sha256": hash_json(frozen_manifest),
        "source_case_manifest": {
            "path": str(manifest_path),
            "sha256": sha(manifest_bytes),
            "schema": manifest.get("schema"),
            "status": manifest.get("status"),
        },
        "case_count": len(cases),
        "runner_sha256": sha(Path(__file__).read_bytes()),
        "runtime": runtime,
        "native_batches": native_batch_specs(),
        "native_attempt_limit": MAX_NATIVE_ATTEMPTS,
        "competitor_attempt_limit": COMPETITOR_LIMIT,
        "search_limit": SEARCH_LIMIT,
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "sdk_max_retries": SDK_MAX_RETRIES,
        "search_provider": "existing Tavily configuration only",
        "scanner_prerequisite": scanner,
        "chamber_prerequisite": chamber,
        "driver_selection": {
            "FUGU_DRIVER": driver_env,
            "selected": "docker",
        },
        "cache_policy": "same-run content identity only; exact plan and input hashes bound",
        "coverage_policy": (
            "each native stage is completed or genuinely not_applicable; no-trigger detonation "
            "retains the native informational result and does not establish full runtime behavior, "
            "while trigger-positive detonation is "
            "unavailable under the retained Buildx denial; all omissions, errors, and unavailable "
            "stages remain incomplete"
        ),
        "data_phase_release_required": True,
    }
    limits.write_json(output / "cases.json", frozen_manifest)
    write_json(output / "plan.json", plan)
    write_json(output / "plan-hash.json", {"plan_sha256": hash_json(plan)})
    return plan


def require_execution_release(plan: dict[str, Any], *, approved_plan_sha256: str | None,
                              data_release_ref: str | None) -> bool:
    digest = hash_json(plan)
    if not approved_plan_sha256 or approved_plan_sha256 != digest:
        raise EvidenceError("exact plan hash approval is required")
    if not data_release_ref or not re.fullmatch(r"qitem-[0-9]{14}-[0-9a-f]{8}", data_release_ref):
        raise EvidenceError("later data-phase release reference is required")
    if plan.get("execution_authorized") is not False or plan.get("data_phase_release_required") is not True:
        raise EvidenceError("plan is not a zero-call plan awaiting later release")
    return True


def validate_plan(engine: Any, output: Path, plan: dict[str, Any], plan_sha256: str) -> dict[str, Any]:
    _verify_chamber_prerequisite(plan)
    if engine.manifest != plan.get("engine"):
        raise EvidenceError("frozen engine changed")
    _verify_source_engine_manifest(engine)
    source_manifest = plan.get("source_case_manifest")
    if source_manifest:
        source_path = Path(source_manifest["path"])
        if (not source_path.is_file()
                or sha(source_path.read_bytes()) != source_manifest.get("sha256")):
            raise EvidenceError("original candidate case manifest changed")
    limits.verify_engine(engine)
    profile = limits.engine_profile(engine)
    if profile != plan.get("profile") or hash_json(profile) != plan.get("profile_sha256"):
        raise EvidenceError("production profile changed")
    if sha(Path(__file__).read_bytes()) != plan.get("runner_sha256"):
        raise EvidenceError("runner changed after plan freeze")
    if limits.runtime_versions() != plan.get("runtime"):
        raise EvidenceError("runtime changed after plan freeze")
    if os.environ.get("FUGU_DRIVER", "").strip().lower() != plan.get("driver_selection", {}).get("FUGU_DRIVER"):
        raise EvidenceError("native detonation driver selection changed")
    _verify_scanner_prerequisite(plan["scanner_prerequisite"])
    cases = read_json(Path(output) / "cases.json")
    if hash_json(cases) != plan.get("cases_sha256"):
        raise EvidenceError("frozen case manifest changed")
    if len(cases.get("cases", [])) != plan.get("case_count"):
        raise EvidenceError("frozen case count changed")
    for case in cases["cases"]:
        if input_hashes(Path(case["target"])) != case["input_sha256"]:
            raise EvidenceError("frozen input changed")
    if hash_json(plan) != plan_sha256:
        raise EvidenceError("frozen plan hash changed")
    return cases


class JournalRouter:
    """Route one native stage stream through fixed, separately bound journals."""

    def __init__(self, journals: list[Any], *, batch_ids: list[str] | None = None):
        if not journals:
            raise EvidenceError("native request router needs at least one journal")
        self.journals = journals
        self.batch_ids = batch_ids or [f"native-{i + 1}" for i in range(len(journals))]
        if len(self.batch_ids) != len(self.journals):
            raise EvidenceError("native request batch labels do not match journals")
        self.stop_reason: str | None = None
        self._active: tuple[str, str, str] | None = None
        self._lock = threading.RLock()
        self._links: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    @contextmanager
    def context(self, audit: str, stage: str, phase: str):
        with self._lock:
            if self._active is not None:
                raise EvidenceError("concurrent or nested native audit context")
            self._active = (audit, stage, phase)
        try:
            with ExitStack() as stack:
                for journal in self.journals:
                    stack.enter_context(journal.context(audit, stage, phase))
                yield
        finally:
            with self._lock:
                self._active = None

    def _find_record(self, journal: Any, context: tuple[str, str, str], ordinal: int):
        return next((row for row in journal.records if
                     (row.get("context"), row.get("stage"), row.get("ordinal"))
                     == (context[0], context[1], ordinal)), None)

    def _choose(self, context: tuple[str, str, str]) -> tuple[int, Any, int]:
        # Existing exact replay rows take precedence even in a full batch. This
        # reconstructs the same batch boundary after a process restart.
        for index, journal in enumerate(self.journals):
            ordinal = journal._ordinal
            if self._find_record(journal, context, ordinal) is not None:
                return index, journal, ordinal
        for journal in self.journals:
            reason = journal.stop_reason
            if reason and reason != "attempt_budget_exhausted":
                self.stop_reason = reason
                raise JournalStopped(reason)
        for index, journal in enumerate(self.journals):
            if journal.state["attempts"] < journal.limit and journal.stop_reason is None:
                return index, journal, journal._ordinal
        self.stop_reason = self.stop_reason or "native_attempt_budget_exhausted"
        last = self.journals[-1]
        if last.stop_reason is None:
            last._stop("attempt_budget_exhausted")
        raise JournalStopped(self.stop_reason)

    def request(self, dispatch, **kwargs):
        with self._lock:
            context = self._active
            if context is None:
                raise EvidenceError("native SDK request has no stage context")
            index, journal, ordinal = self._choose(context)
            try:
                response = journal.request(dispatch, **kwargs)
            except BaseException:
                record = self._find_record(journal, context, ordinal)
                if record and (record.get("request_sha256") != limits.hash_json(kwargs)
                               or record.get("phase") != context[2]):
                    record = None
                self._record_link(index, context, ordinal, record)
                if journal.stop_reason and journal.stop_reason != "attempt_budget_exhausted":
                    self.stop_reason = journal.stop_reason
                raise
            record = self._find_record(journal, context, ordinal)
            self._record_link(index, context, ordinal, record)
            return response

    def _record_link(self, index: int, context: tuple[str, str, str], ordinal: int,
                     record: dict[str, Any] | None) -> None:
        self._links[(context[0], context[1])].append({
            "batch_id": self.batch_ids[index],
            "batch_index": index + 1,
            "journal_number": record.get("number") if record else None,
            "ordinal": ordinal,
            "state": record.get("state") if record else "not_dispatched",
            "request_sha256": record.get("request_sha256") if record else None,
        })

    def links_for(self, audit: str, stage: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self._links.get((audit, stage), [])]

    def wrap_client(self, sdk: Any):
        router = self

        class ObservedClient:
            def __init__(self, delegate):
                self._delegate = delegate
                self.chat = SimpleNamespace(completions=SimpleNamespace(
                    create=lambda **kwargs: router.request(delegate.chat.completions.create, **kwargs)))

            def with_options(self, **options):
                if options != {"max_retries": SDK_MAX_RETRIES,
                               "timeout": REQUEST_TIMEOUT_SECONDS}:
                    raise EvidenceError("native SDK retry/timeout policy changed")
                return ObservedClient(self._delegate.with_options(**options))

        from types import SimpleNamespace
        return ObservedClient(sdk)


@contextmanager
def observe_sdk_router(router: JournalRouter):
    """Observe the native make_client SDK boundary without changing stage code."""
    client_module = importlib.import_module("fugu.client")
    original = client_module.make_client

    def observed_factory(*args, **kwargs):
        try:
            return router.wrap_client(original(*args, **kwargs))
        except Exception:
            router.stop_reason = router.stop_reason or "provider_setup_failure"
            raise JournalStopped(router.stop_reason) from None

    client_module.make_client = observed_factory
    try:
        yield
    finally:
        client_module.make_client = original


class DurableSearchBudget:
    """Reserve-before-dispatch Tavily ledger with restart-safe global ceiling."""

    def __init__(self, directory: Path, *, binding: str, limit: int = SEARCH_LIMIT,
                 dispatch: Callable[[str, str], Any] | None = None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.limit, self.binding = limit, binding
        if not 1 <= limit <= SEARCH_LIMIT:
            raise EvidenceError("search limit must be within the frozen 1..480 cap")
        self.dispatch = dispatch
        self.context = "unbound"
        self.stage = "reputation"
        self._ordinal = 0
        self.replayed = 0
        self._lock = threading.RLock()
        self._lock_file = (self.directory / ".search.lock").open("a")
        try:
            fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._lock_file.close()
            raise EvidenceError("search journal already owned") from None
        self.state_path = self.directory / "search-budget.json"
        self.calls_path = self.directory / "searches"
        self.calls_path.mkdir(exist_ok=True)
        if self.state_path.exists():
            self.state = read_json(self.state_path)
            if self.state.get("binding") != binding or self.state.get("limit") != limit:
                self.close()
                raise EvidenceError("search budget binding changed")
        else:
            self.state = {"schema": 1, "binding": binding, "limit": limit,
                          "attempts": 0, "stop_reason": None}
            write_json(self.state_path, self.state)
        self.records: list[dict[str, Any]] = []
        for number in range(1, self.state["attempts"] + 1):
            path = self._call_path(number)
            if not path.exists():
                self.state["stop_reason"] = self.state.get("stop_reason") or "orphan_search_requires_review"
                continue
            row = read_json(path)
            if not isinstance(row, dict) or row.get("number") != number or row.get("state") not in {
                "reserved", "returned", "error"
            }:
                self.close()
                raise EvidenceError("invalid saved search record")
            self.records.append(row)
            if row["state"] == "returned":
                response_hash = sha(json.dumps(row.get("response"), sort_keys=True,
                                               ensure_ascii=False).encode())
                if response_hash != row.get("response_sha256"):
                    self.close()
                    raise EvidenceError("saved search response hash mismatch")
            if row["state"] == "reserved":
                self.state["stop_reason"] = self.state.get("stop_reason") or "orphan_search_requires_review"
            elif row["state"] == "error":
                self.state["stop_reason"] = self.state.get("stop_reason") or row.get("stop_reason")
        write_json(self.state_path, self.state)

    def _call_path(self, number: int) -> Path:
        return self.calls_path / f"{number:04d}.json"

    @property
    def stop_reason(self) -> str | None:
        return self.state.get("stop_reason")

    def set_context(self, audit: str, stage: str = "reputation") -> None:
        if (audit, stage) != (self.context, self.stage):
            self._ordinal = 0
        self.context, self.stage = audit, stage

    def close(self) -> None:
        if not self._lock_file.closed:
            fcntl.flock(self._lock_file, fcntl.LOCK_UN)
            self._lock_file.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    @staticmethod
    def _failure_reason(exc: Exception) -> str:
        status = getattr(exc, "status_code", getattr(exc, "code", None))
        message = (str(getattr(exc, "code", "")) + " " + str(exc)).lower()
        if status in (402, 432, 433) or any(text in message for text in (
            "quota exhausted", "quota exceeded", "usage limit", "insufficient quota",
        )):
            return "tavily_quota_exhausted"
        if status in (401, 403):
            return "tavily_auth_failure"
        if status == 429:
            return "tavily_rate_limit"
        return f"tavily_error_{type(exc).__name__}_{status}"

    def __call__(self, key: str, query: str):
        with self._lock:
            query_hash = sha(query.encode())
            previous = next((row for row in self.records if
                             (row.get("context"), row.get("stage"), row.get("ordinal"))
                             == (self.context, self.stage, self._ordinal)), None)
            if previous is not None:
                if previous.get("query_sha256") != query_hash:
                    raise EvidenceError("saved search query drift")
                self._ordinal += 1
                if previous.get("state") == "returned":
                    self.replayed += 1
                    return previous["response"]
                if previous.get("state") == "error":
                    raise JournalStopped(previous.get("stop_reason") or self.stop_reason or "tavily_error")
                raise JournalStopped(self.stop_reason or "orphan_search_requires_review")
            if self.stop_reason:
                raise JournalStopped(self.stop_reason)
            if not key:
                self.state["stop_reason"] = "tavily_auth_unavailable"
                write_json(self.state_path, self.state)
                raise JournalStopped(self.state["stop_reason"])
            if self.state["attempts"] >= self.limit:
                self.state["stop_reason"] = "tavily_search_budget_exhausted"
                write_json(self.state_path, self.state)
                raise JournalStopped(self.state["stop_reason"])
            number = self.state["attempts"] + 1
            row = {"number": number, "context": self.context, "stage": self.stage,
                   "ordinal": self._ordinal, "query_sha256": query_hash,
                   "state": "reserved", "reserved_utc": utc()}
            self._ordinal += 1
            self.state["attempts"] = number
            self.records.append(row)
            write_json(self.state_path, self.state)
            write_json(self._call_path(number), row)
        dispatch = self.dispatch
        if dispatch is None:
            reputation = importlib.import_module("fugu.pipeline.stages.reputation")
            dispatch = reputation._default_search
        try:
            result = dispatch(key, query)
            serialized = json.dumps(result, sort_keys=True, ensure_ascii=False)
        except BaseException as exc:
            if isinstance(exc, Exception):
                reason = self._failure_reason(exc)
                row.update(state="error", stop_reason=reason, error_type=type(exc).__name__)
                self.state["stop_reason"] = reason
                write_json(self._call_path(number), row)
                write_json(self.state_path, self.state)
                raise JournalStopped(reason) from None
            self.state["stop_reason"] = "orphan_search_requires_review"
            write_json(self.state_path, self.state)
            raise
        row.update(state="returned", query=query, response=result,
                   response_sha256=sha(serialized.encode()), finished_utc=utc())
        write_json(self._call_path(number), row)
        return result

    def summary(self) -> dict[str, Any]:
        return {"attempts": self.state["attempts"], "limit": self.limit,
                "stop_reason": self.stop_reason,
                "replayed": self.replayed,
                "returned": sum(row.get("state") == "returned" for row in self.records),
                "errors": sum(row.get("state") == "error" for row in self.records),
                "orphans": sum(row.get("state") == "reserved" for row in self.records)}


def _public(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "__dict__"):
        return dict(vars(value))
    return value


def _finding_dict(finding: Any) -> dict[str, Any]:
    value = _public(finding)
    if not isinstance(value, dict):
        raise EvidenceError("native finding is not serializable")
    return value


def finalize_case(case: dict[str, Any], stages: list[dict[str, Any]], findings: list[Any],
                  *, verdict_fn: Callable[[list[Any], list[Any]], dict[str, Any]],
                  verdict_stage_results: list[Any] | None = None) -> dict[str, Any]:
    """Bind the native verdict to complete coverage while retaining all findings."""
    finding_rows = [_finding_dict(finding) for finding in findings]
    complete = case_complete(stages)
    raw_medium = any(row.get("severity") in MEDIUM_OR_HIGHER for row in finding_rows)
    composition_rows = [row for row in finding_rows if row.get("stage") == "composition"]
    titles = [str(row.get("title", "")).lower() for row in composition_rows]
    score = {"trifecta": any("trifecta" in title for title in titles),
             "shadowing": any("shadowing" in title for title in titles)}
    expected = case.get("expected")
    matches = None
    if isinstance(expected, dict) and case.get("members"):
        matches = all(score[key] == expected.get(key, False) for key in score)
        score = {"scope": expected.get("scope"), **score}
    verdict = verdict_fn(findings, verdict_stage_results or [])
    states = [row.get("state") for row in stages]
    status = "completed" if complete else (
        "unattempted" if not any(state not in {"unattempted", None} for state in states) else "partial")
    detected = (score["trifecta"] or score["shadowing"] if case.get("members") else raw_medium)
    return {
        **case,
        "stages": stages,
        "findings": finding_rows,
        "complete": complete,
        "status": status,
        "detected": detected,
        "raw_medium_flag": raw_medium,
        "verdict": verdict,
        "composition_score": score if case.get("members") else None,
        "matches_frozen_expectations": matches,
        "adjudicated_false_positive": None,
    }


def planned_rows(cases: list[dict[str, Any]], *, plan_sha256: str) -> list[dict[str, Any]]:
    return [dict(case, plan_sha256=plan_sha256, complete=False, detected=None,
                 status="unattempted", stages=[], findings=[], members_results=[],
                 unavailable_reason="not started") for case in cases]


def summarize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row.get("cohort", "unknown"), row.get("kind", "unknown"))].append(row)
    summary = []
    for (cohort, kind), group in sorted(grouped.items()):
        complete = [row for row in group if row.get("complete")]
        flagged = sum(row.get("detected") is True for row in complete)
        summary.append({"cohort": cohort, "kind": kind, "planned": len(group),
                        "completed": len(complete), "detected": flagged,
                        "unflagged": sum(row.get("detected") is False for row in complete),
                        "incomplete": sum(not row.get("complete") and row.get("status") != "unattempted" for row in group),
                        "unattempted": sum(row.get("status") == "unattempted" for row in group),
                        "complete_case_rate": flagged / len(complete) if complete else None,
                        "incomplete_ids": [row.get("id") for row in group if not row.get("complete")]})
    return summary


def _serialize_stage(result: Any) -> dict[str, Any]:
    value = _public(result)
    if not isinstance(value, dict):
        raise EvidenceError("native stage result is not serializable")
    value["state"] = stage_state(value)
    return value


def _restore_finding(engine: Any, value: dict[str, Any]):
    evidence = [engine.types.EvidenceSnippet(**item) for item in value.get("evidence", [])]
    return engine.types.Finding(**{**value, "evidence": evidence})


def _restore_stage(engine: Any, value: dict[str, Any]):
    findings = [_restore_finding(engine, item) for item in value.get("findings", [])]
    return engine.types.StageResult(stage=value["stage"], ok=value["ok"], findings=findings,
                                    metrics=value.get("metrics", {}), error=value.get("error"))


def _link_stage_requests(stage: dict[str, Any], router: JournalRouter, audit: str) -> None:
    stage_name = stage["stage"]
    links = router.links_for(audit, stage_name)
    native_attempts = (stage.get("metrics") or {}).get("request_attempts")
    native_list = native_attempts if isinstance(native_attempts, list) else None
    if stage_name not in {"semantic", "harness"} and not links:
        stage["journal_alignment"] = {"aligned": True, "native_attempts": 0,
                                      "observed_attempts": 0, "links": []}
        return
    aligned = native_list is not None and len(native_list) == len(links)
    link_rows = []
    for index, link in enumerate(links):
        record = None
        for batch_index, journal in enumerate(router.journals):
            if router.batch_ids[batch_index] == link["batch_id"]:
                record = next((row for row in journal.records
                               if row.get("number") == link.get("journal_number")), None)
                break
        same = bool(record)
        if native_list is not None and index < len(native_list) and record is not None:
            native = native_list[index]
            comparisons = {
                "requested_model": record.get("requested_model"),
                "served_model": record.get("served_model"),
                "max_tokens": record.get("max_tokens"),
                "finish_reason": record.get("finish_reason"),
                "response_sha256": record.get("response_sha256"),
                "usage": record.get("usage"),
            }
            relevant = {key: value for key, value in comparisons.items()
                        if key in native and value is not None}
            same = same and all(native.get(key) == value for key, value in relevant.items())
        aligned = aligned and same
        link_rows.append({**link, "native_index": index if native_list is not None else None,
                          "identity_matches": same})
    stage["journal_alignment"] = {
        "aligned": aligned,
        "native_attempts": len(native_list) if native_list is not None else None,
        "observed_attempts": len(links),
        "links": link_rows,
    }


def _make_stage_list(engine: Any, search_budget: DurableSearchBudget) -> tuple[list[Any], list[str]]:
    stages = engine.pipeline.build_stages()
    names = [getattr(stage, "name", None) for stage in stages]
    if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)):
        raise EvidenceError("native stage assembly has missing or duplicate names")
    unknown = set(names) - set(NATIVE_STAGE_NAMES)
    if unknown:
        raise EvidenceError("native stage assembly contains an unplanned stage")
    reputation = next((stage for stage in stages if stage.name == "reputation"), None)
    if reputation is None:
        raise EvidenceError("native reputation stage was not assembled")
    reputation._search_fn = search_budget
    missing = [name for name in NATIVE_STAGE_NAMES if name not in names]
    for name in missing:
        if name == "detonation":
            stages.append(_UnavailableStage(name, "native detonation driver unavailable"))
        else:
            raise EvidenceError(f"required native stage {name} was not assembled")
    return stages, missing


class _UnavailableStage:
    def __init__(self, name: str, reason: str):
        self.name, self.reason = name, reason

    async def run(self, _job, _target):
        return _make_stage_result(self.name, ok=False, error=self.reason,
                                  metrics={"unavailable": self.reason})


class ChamberUnavailableError(RuntimeError):
    """The frozen plan records that its native Docker chamber is unavailable."""


class _UnavailableChamberDriver:
    def __init__(self, reason: str):
        self.reason = reason

    async def detonate(self, _target_dir, _triggers, timeout_s=120):
        raise ChamberUnavailableError(self.reason)


def _guard_unavailable_chamber(stages: list[Any], chamber: dict[str, Any]) -> None:
    _validate_chamber_prerequisite(chamber)
    if chamber["status"] != "unavailable":
        return
    detonation = next((stage for stage in stages if getattr(stage, "name", None) == "detonation"), None)
    if detonation is None or isinstance(detonation, _UnavailableStage):
        return
    if not hasattr(detonation, "_driver"):
        raise EvidenceError("native detonation stage cannot be gated for the unavailable chamber")
    detonation._driver = _UnavailableChamberDriver(chamber["reason"])


def _mark_chamber_unavailable(stage: dict[str, Any]) -> None:
    error = stage.get("error")
    prefix = f"{ChamberUnavailableError.__name__}:"
    if stage.get("stage") != "detonation" or not isinstance(error, str) or not error.startswith(prefix):
        return
    reason = error[len(prefix):].strip()
    metrics = stage.setdefault("metrics", {})
    metrics["chamber_unavailable"] = reason
    metrics["coverage_incomplete"] = reason
    stage["state"] = "unavailable"


def _member_chamber_unavailable(stages: list[dict[str, Any]], reason: str) -> bool:
    for stage in stages:
        if stage.get("stage") == "detonation" and stage.get("state") == "unavailable":
            return True
        if stage.get("stage") != "composition":
            continue
        coverage = (stage.get("metrics") or {}).get("member_coverage")
        if isinstance(coverage, list) and any(
            row.get("stage") == "detonation" and row.get("reason") == reason
            for row in coverage if isinstance(row, dict)
        ):
            return True
    return False


def _make_stage_result(stage: str, *, ok: bool, error: str | None = None,
                       metrics: dict[str, Any] | None = None, findings=None):
    from fugu.types import StageResult
    return StageResult(stage=stage, ok=ok, error=error, metrics=metrics or {}, findings=findings or [])


async def evaluate_cases(engine: Any, cases: dict[str, Any], output: Path, plan: dict[str, Any],
                         router: JournalRouter, search_budget: DurableSearchBudget,
                         *, data_release_ref: str, observer=None, environ=None) -> dict[str, Any]:
    """Run fresh native stages; persist every planned row and completed stage."""
    _validate_chamber_prerequisite(plan.get("chamber_prerequisite"))
    output = Path(output)
    case_rows = cases["cases"]
    plan_digest = hash_json(plan)
    cache = AuditCache(output, binding=plan_digest)
    result_path = output / "fugu.json"
    started = utc()
    rows = planned_rows(case_rows, plan_sha256=plan_digest)
    if result_path.exists():
        prior = read_json(result_path)
        if prior.get("plan_sha256") != plan_digest or prior.get("cases_sha256") != hash_json(cases):
            raise EvidenceError("saved run plan or cases binding changed")
        if [row.get("id") for row in prior.get("rows", [])] != [case.get("id") for case in case_rows]:
            raise EvidenceError("saved run case order changed")
        rows = prior["rows"]
        started = prior.get("started_utc", started)
        for row, case in zip(rows, case_rows):
            if row.get("input_sha256") != case.get("input_sha256") or row.get("plan_sha256") != plan_digest:
                raise EvidenceError("saved case row binding changed")

    def publish() -> dict[str, Any]:
        for row in rows:
            if row.get("status") == "in_progress":
                states = [stage.get("state") for stage in row.get("stages", [])]
                row["status"] = "partial" if any(state not in {"unattempted", None} for state in states) else "unattempted"
        document = {
            "schema": 1,
            "protocol": "fugu-full-workflow-v1",
            "plan_sha256": plan_digest,
            "cases_sha256": hash_json(cases),
            "data_release_ref": data_release_ref,
            "started_utc": started,
            "measured_utc": utc(),
            "planned": len(case_rows),
            "rows": rows,
            "summary": summarize_rows(rows),
            "usage": {"native_batches": [journal.summary() for journal in router.journals],
                      "native_total_attempts": sum(journal.state["attempts"] for journal in router.journals),
                      "native_attempt_limit": MAX_NATIVE_ATTEMPTS,
                      "competitor_limit_reserved": COMPETITOR_LIMIT,
                      "search": search_budget.summary(),
                      "known_cost": None, "remaining_quota": None},
            "engine": engine.manifest,
            "profile": plan["profile"],
            "scanner_prerequisite": plan["scanner_prerequisite"],
            "chamber_prerequisite": plan["chamber_prerequisite"],
        }
        write_json(result_path, document)
        return document

    publish()  # Durable planned rows exist before the first native stage runs.
    native_stage_objects = None
    guard = observer if observer is not None else observe_sdk_router(router)
    try:
        with guard:
            apply_scanner_environment(plan["scanner_prerequisite"], environ=environ)
            native_stage_objects, _missing = _make_stage_list(engine, search_budget)
            _guard_unavailable_chamber(native_stage_objects, plan["chamber_prerequisite"])
            pipeline = engine.pipeline
            for index, case in enumerate(case_rows):
                if rows[index].get("complete"):
                    continue
                target = Path(case["target"])
                if input_hashes(target) != case["input_sha256"]:
                    raise EvidenceError("case input hash drift before audit")
                rows[index].update(status="in_progress", unavailable_reason="in progress or interrupted",
                                   stages=[], findings=[], members_results=[])
                publish()
                members = case.get("members") or [{"dir": None, "label": case["id"]}]
                member_result_objects = []
                all_public_stages: list[dict[str, Any]] = []
                all_native_stage_results: list[Any] = []
                all_findings: list[Any] = []
                member_progress = []
                phase = str(case.get("cohort", "native"))
                for member in members:
                    member_dir = member.get("dir")
                    directory = target / member_dir if member_dir else target
                    member_hashes = input_hashes(directory)
                    audit_key = fingerprint(member_hashes)
                    saved = cache.get(audit_key, member_hashes)
                    names = [stage.name for stage in native_stage_objects]
                    if saved is not None and [stage.get("stage") for stage in saved] != names[:len(saved)]:
                        raise EvidenceError("saved audit cache stage prefix drift")
                    stage_rows = list(saved or [])
                    was_cached = saved is not None
                    if saved is None or len(saved) < len(native_stage_objects):
                        job = engine.types.AuditJob(id=audit_key, source=str(directory), depth="full",
                                                    status=engine.types.JobStatus.running)
                        for stage in native_stage_objects[len(stage_rows):]:
                            limits.verify_engine(engine)
                            if stage.name in {"semantic", "harness"} and router.stop_reason:
                                result = _make_stage_result(stage.name, ok=False,
                                    error=router.stop_reason,
                                    metrics={"unattempted": router.stop_reason})
                            else:
                                search_budget.set_context(audit_key, "reputation")
                                with router.context(audit_key, stage.name, phase):
                                    result = (await pipeline.run_stages(job, directory, [stage]))[0]
                            public = _serialize_stage(result)
                            _mark_chamber_unavailable(public)
                            _link_stage_requests(public, router, audit_key)
                            if stage.name == "static":
                                surface = (public.get("metrics") or {}).get("tool_surface", {})
                                no_surface = surface.get("skipped") == "no supported tool or skill instruction surface"
                                verified = bool(
                                    surface.get("enabled") is True
                                    and surface.get("engine_pin") == plan["scanner_prerequisite"]["expected_source_commit"]
                                    and (no_surface or surface.get("binary_sha256") == plan["scanner_prerequisite"]["binary_sha256"])
                                    and not surface.get("coverage_incomplete")
                                    and surface.get("omitted_tools", 0) == 0
                                    and not surface.get("parse_errors")
                                )
                                public["scanner_prerequisite_alignment"] = {
                                    "verified": verified,
                                    "state": "not_applicable" if no_surface else ("verified" if verified else "incomplete"),
                                    "expected_binary_sha256": plan["scanner_prerequisite"]["binary_sha256"],
                                    "observed_binary_sha256": surface.get("binary_sha256"),
                                }
                            public["state"] = stage_state(public)
                            stage_rows.append(public)
                            cache.save(audit_key, member_hashes, stage_rows)
                            member_public = {"member": member_dir, "label": member.get("label"),
                                             "fingerprint": audit_key, "stages": list(stage_rows),
                                             "cached_identical_input": was_cached}
                            previous = [entry for entry in member_progress if entry["member"] != member_dir]
                            member_progress = previous + [member_public]
                            all_public_stages = [dict(stage, member=entry["member"])
                                                 for entry in member_progress for stage in entry["stages"]]
                            rows[index].update(stages=all_public_stages,
                                               members_results=member_progress,
                                               findings=[finding for entry in member_progress
                                                         for stage_row in entry["stages"]
                                                         for finding in stage_row.get("findings", [])])
                            publish()
                    else:
                        member_public = {"member": member_dir, "label": member.get("label"),
                                         "fingerprint": audit_key, "stages": list(stage_rows),
                                         "cached_identical_input": True}
                        member_progress.append(member_public)
                    stage_objects = [_restore_stage(engine, stage) for stage in stage_rows]
                    findings = [finding for stage in stage_objects for finding in stage.findings]
                    all_native_stage_results.extend(stage_objects)
                    all_findings.extend(findings)
                    if not any(entry.get("member") == member_dir for entry in member_progress):
                        member_progress.append({"member": member_dir, "label": member.get("label"),
                                                "fingerprint": audit_key, "stages": list(stage_rows),
                                                "cached_identical_input": was_cached})
                    all_public_stages = [dict(stage, member=entry["member"])
                                         for entry in member_progress for stage in entry["stages"]]
                    if case.get("members"):
                        composition = engine.modules["pipeline.stages.composition"]
                        composition_jobs = engine.modules["server.composition_jobs"]
                        member_result_objects.append(composition.MemberResult(
                            label=member.get("label") or member_dir,
                            slug=member_dir,
                            findings=engine.modules["dedupe"].dedupe_findings(findings),
                            tool_names=composition_jobs.harvest_tool_names(directory),
                            target_dir=directory,
                        ))
                composition_stage = engine.modules["pipeline.stages.composition"].CompositionStage()
                composition_stage._member_results = member_result_objects if case.get("members") else None
                comp_job = engine.types.AuditJob(id=case["id"], source=str(target), depth="full",
                                                 status=engine.types.JobStatus.running)
                try:
                    composition_result = await composition_stage.run(comp_job, target)
                except Exception as exc:
                    composition_result = _make_stage_result("composition", ok=False,
                        error=f"{type(exc).__name__}: {exc}")
                member_coverage = []
                for entry in member_progress:
                    for stage in entry["stages"]:
                        if stage.get("state") not in {"completed", "not_applicable"}:
                            member_coverage.append({
                                "member": entry.get("label") or entry.get("member"),
                                "job_id": entry["fingerprint"],
                                "stage": stage["stage"],
                                "state": "partial" if stage.get("state") in {
                                    "partial", "unavailable", "unattempted", "failed"} else stage.get("state"),
                                "reason": (stage.get("error") or (stage.get("metrics") or {}).get("skipped")
                                           or stage.get("state")),
                                "executed": stage.get("state") in {"completed", "partial"},
                            })
                if member_coverage:
                    composition_result.metrics["member_coverage"] = member_coverage
                comp_public = _serialize_stage(composition_result)
                comp_public["state"] = stage_state(comp_public)
                all_public_stages.append(comp_public)
                all_native_stage_results.append(composition_result)
                all_findings.extend(composition_result.findings)
                all_findings = engine.modules["dedupe"].dedupe_findings(all_findings)
                verdict = engine.modules["verdict"].aggregate_verdict(all_findings, all_native_stage_results)
                finalized = finalize_case(case, all_public_stages, all_findings,
                    verdict_fn=lambda _findings, _stages: verdict,
                    verdict_stage_results=all_native_stage_results)
                rows[index] = {**finalized, "plan_sha256": plan_digest,
                               "members_results": member_progress,
                               "unavailable_reason": (
                                   None if finalized["complete"] else
                                   router.stop_reason or (
                                       plan["chamber_prerequisite"]["reason"]
                                       if (plan["chamber_prerequisite"]["status"] == "unavailable"
                                           and _member_chamber_unavailable(
                                               all_public_stages,
                                               plan["chamber_prerequisite"]["reason"]))
                                       else None
                                   )
                               )}
                publish()
                limits.verify_engine(engine)
                if input_hashes(target) != case["input_sha256"]:
                    raise EvidenceError("case input hash drift after audit")
        limits.verify_engine(engine)
    finally:
        publish()  # Persist partial rows and usage on interruption or provider stop.
    return publish()


def _make_journals(output: Path, plan: dict[str, Any], plan_digest: str) -> tuple[list[Any], list[str]]:
    specs = plan.get("native_batches")
    if specs != native_batch_specs() or plan.get("native_attempt_limit") != MAX_NATIVE_ATTEMPTS:
        raise EvidenceError("native request batch limits changed")
    models = plan.get("requested_models")
    journals, batch_ids = [], []
    for index, spec in enumerate(specs, 1):
        binding = hash_json({"plan_sha256": plan_digest, "batch": spec["id"], "limit": spec["limit"]})
        journal = RequestJournal(
            Path(output) / "journals" / spec["id"],
            limit=NATIVE_BATCH_LIMIT,
            binding=binding,
            expected_output_tokens=MAX_OUTPUT_TOKENS,
            expected_models=models,
        )
        journals.append(journal)
        batch_ids.append(spec["id"])
    return journals, batch_ids


def run_frozen(engine: Any, output: Path, *, approved_plan_sha256: str,
               data_release_ref: str) -> dict[str, Any]:
    """Execute only after a distinct release has named the exact frozen plan."""
    output = _ensure_scratch_output(output)
    plan = read_json(output / "plan.json")
    require_execution_release(plan, approved_plan_sha256=approved_plan_sha256,
                              data_release_ref=data_release_ref)
    cases = validate_plan(engine, output, plan, approved_plan_sha256)
    scanner = plan["scanner_prerequisite"]
    apply_scanner_environment(scanner)
    release = {"queue_ref": data_release_ref,
               "approved_plan_sha256": approved_plan_sha256,
               "started_utc": utc(),
               "native_attempt_limit": MAX_NATIVE_ATTEMPTS,
               "competitor_attempt_limit": COMPETITOR_LIMIT,
               "search_limit": SEARCH_LIMIT,
               "provider_calls": 0}
    release_path = output / "data-release.json"
    if release_path.exists():
        prior = read_json(release_path)
        if prior.get("queue_ref") != data_release_ref or prior.get("approved_plan_sha256") != approved_plan_sha256:
            raise EvidenceError("data release reference changed")
    else:
        write_json(release_path, release)
    journals, batch_ids = _make_journals(output, plan, approved_plan_sha256)
    router = JournalRouter(journals, batch_ids=batch_ids)
    search_budget = DurableSearchBudget(output, binding=approved_plan_sha256, limit=SEARCH_LIMIT)
    try:
        result = asyncio_run(evaluate_cases(engine, cases, output, plan, router, search_budget,
                                             data_release_ref=data_release_ref))
        limits.verify_engine(engine)
        return result
    finally:
        search_budget.close()
        for journal in journals:
            journal.close()


def asyncio_run(awaitable):
    import asyncio
    return asyncio.run(awaitable)


def load_engine(engine_root: Path):
    normalized_root = _materialize_engine_snapshot(engine_root)
    # The engine snapshot is immutable evidence; imports must not add __pycache__.
    sys.dont_write_bytecode = True
    return limits.load_engine(normalized_root)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run"))
    parser.add_argument("--engine-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, help="schema-1 corpus manifest for prepare")
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--data-release-ref", help="later lead-owned data-phase queue release")
    args = parser.parse_args(argv)
    engine = load_engine(args.engine_root)
    if args.action == "prepare":
        if args.manifest is None:
            raise EvidenceError("prepare requires a frozen schema-1 case manifest")
        plan = prepare(engine, args.manifest, args.output, source_root=args.source_root)
        print(json.dumps({"plan_sha256": hash_json(plan), "planned": plan["case_count"],
                          "execution_authorized": False, "provider_calls": 0}))
        return 0
    if not args.approved_plan_sha256:
        raise EvidenceError("run requires the exact approved plan hash")
    if not args.data_release_ref:
        raise EvidenceError("run requires a later data-phase release reference")
    result = run_frozen(engine, args.output, approved_plan_sha256=args.approved_plan_sha256,
                        data_release_ref=args.data_release_ref)
    print(json.dumps({"planned": result["planned"],
                      "completed": sum(row["complete"] for row in result["rows"]),
                      "native_attempts": result["usage"]["native_total_attempts"],
                      "search_attempts": result["usage"]["search"]["attempts"]}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, JournalStopped) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None
