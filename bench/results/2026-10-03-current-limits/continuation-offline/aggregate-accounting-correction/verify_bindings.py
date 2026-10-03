"""Offline R1 plan/preservation check; never loads credentials or an SDK."""

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))

from bench import current_limits as base  # noqa: E402
from bench import current_limits_continuation as mod  # noqa: E402


def main():
    evidence = Path(__file__).parent
    prepared = evidence.parent / "prepared-v3"
    old_prepared = evidence.parent / "prepared-v2"
    parent = mod.load_parent()
    engine = base.load_engine(Path("/tmp/fugu-continuation-engine-cc58a58"))
    plan = mod.read_json(prepared / "plan.json")
    cases = mod.validate_plan(engine, plan, prepared, parent=parent)
    assert base.hash_json(plan) == mod.read_json(prepared / "plan-hash.json")["plan_sha256"]
    assert base.hash_json(plan) == "ea8cff37184b4dd7efe06d3494643462298b398bebcb471d50ce0d6d76f32835"
    assert plan["execution_authorized"] is False and plan["provider_requests"] == 0
    assert mod.read_json(prepared / "release-template.json")["execution_authorized"] is False

    old = mod.read_json(old_prepared / "plan.json")
    assert base.hash_json(old) == "0e859af4efdda0c6f8c0ee48664486444563ca3af21a4c2cc2ea4e9bf8e74f74"
    assert old["continuation_sha256"] != plan["continuation_sha256"]
    # Only creation time, relocated targets/case hash and module binding change.
    for key in old:
        if key not in {"created_utc", "continuation_sha256", "cases_sha256"}:
            assert old[key] == plan[key], key
    restored = copy.deepcopy(cases)
    for case in restored["cases"]:
        case["target"] = case.pop("original_target")
    assert restored == parent.selected
    assert [c["id"] for c in cases["cases"]] == plan["selected_case_ids"]
    assert plan["preflight"]["context_count"] == 41
    assert plan["preflight"]["unique_audit_count"] == 32
    assert plan["preflight"]["semantic_primary_units"] == 50
    assert len(plan["allowed_contexts"]) == 32
    assert not set(plan["allowed_contexts"]) & parent.old_keys
    assert plan["phase_limits"] == {"common20": 280, "remainder": 1036}
    assert plan["worst_new_requests"] == 1316
    assert plan["worst_cumulative_requests"] == 1675
    assert plan["cumulative_limit"] == 1900
    assert plan["profile"] == parent.plan["profile"]
    assert plan["profile"]["llm_max_output_tokens"] == 4096
    assert plan["engine"] == parent.plan["engine"]
    assert len(plan["engine"]["hashes"]) == 37

    original_files = copied_files = 0
    for collection, copied in [(parent.original["cases"], False), (cases["cases"], True)]:
        for case in collection:
            target = base.case_target(case) if copied else base.ROOT / case["target"]
            assert base.input_hashes(target) == case["input_sha256"]
            for path in target.rglob("*"):
                assert not path.is_symlink()
                if path.is_file():
                    if copied:
                        copied_files += 1
                    else:
                        original_files += 1
    assert original_files == 81 and copied_files == 68
    for name in plan["engine"]["hashes"]:
        assert base.sha((base.ROOT / name).read_bytes()) == plan["engine"]["hashes"][name]

    baseline_path = Path("/tmp/fugu-r1-protected-before.json")
    baseline = json.loads(baseline_path.read_text())
    changed = [item["path"] for item in baseline["files"]
               if not Path(item["path"]).is_file()
               or base.sha(Path(item["path"]).read_bytes()) != item["sha256"]]
    assert not changed, changed
    assert not mod.DEFAULT_CHILD.exists()
    assert not mod.DEFAULT_REGISTRY.parent.exists()
    code_docs = [base.ROOT / name for name in (
        "bench/current_limits_continuation.py", "tests/test_current_limits_continuation.py",
        "docs/benchmark-current-limits-continuation.md",
    )]
    whitespace = {str(path.relative_to(base.ROOT)): [number for number, line in
                  enumerate(path.read_text().splitlines(), 1) if line.rstrip() != line]
                  for path in code_docs}
    assert not any(whitespace.values())
    raw_log_whitespace = {path.name: [number for number, line in
                          enumerate(path.read_text().splitlines(), 1) if line.rstrip() != line]
                          for path in evidence.glob("*.log")}
    result = {
        "schema": 1, "checked_utc": datetime.now(timezone.utc).isoformat(),
        "assignment": "qitem-20261003065017-de9f0691",
        "base_commit": "0aca9deeddf6d79e0d7736e0915707dc0ee6db3e",
        "new_plan_sha256": base.hash_json(plan),
        "superseded_plan_sha256": base.hash_json(old),
        "module_sha256": plan["continuation_sha256"],
        "parent_inventory_sha256": mod.PARENT_MANIFEST_SHA256,
        "parent_sealed_files_preserved": 403,
        "protected_baseline_sha256": base.sha(baseline_path.read_bytes()),
        "protected_files_preserved": len(baseline["files"]), "changed_protected_files": changed,
        "original_regular_files": original_files, "copied_regular_files": copied_files,
        "selected_ids": plan["selected_case_ids"], "original_fields_and_order_preserved": True,
        "frozen_source_files": 37, "profile_sha256": plan["profile_sha256"],
        "member_contexts": 41, "unique_audits": 32, "semantic_units": 50, "cache_reuses": 9,
        "new_request_bound": 1316, "cumulative_request_bound": 1675,
        "cumulative_cap": 1900, "child_phase_caps": plan["phase_limits"],
        "real_child_created": False, "real_registry_created": False,
        "execution_authorized": False, "provider_requests": 0, "target_executions": 0,
        "source_docs_trailing_whitespace": whitespace,
        "raw_log_trailing_whitespace_lines": raw_log_whitespace,
        "verifier_sha256": base.sha(Path(__file__).read_bytes()),
    }
    base.write_json(evidence / "binding-check.json", result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
