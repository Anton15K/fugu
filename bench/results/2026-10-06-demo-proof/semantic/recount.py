"""Recount six retained stage comparisons. No inference, target or scanner runs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
NEW = Path("/tmp/fugu-full-workflow-backend-20261005/prepared140-frozen")
PUBLIC = REPO / "bench/results/2026-10-02-showcase"
OLD = REPO / "bench/results/2026-10-02"
MEDIUM = {"medium", "high", "critical"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    return digest(Path(path).read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def object_hash(value):
    return digest(canonical(value))


def load(path):
    return json.loads(Path(path).read_text())


def verify_engine(root, hashes):
    for rel, expected in hashes.items():
        if not rel.startswith("src/fugu/"):
            continue
        path = Path(root) / rel.removeprefix("src/")
        assert path.is_file() and not path.is_symlink(), rel
        assert file_hash(path) == expected, rel


def packet_files(target, expected):
    root = Path(target)
    assert not root.is_symlink()
    assert not any(p.is_symlink() for p in root.rglob("*"))
    actual = {p.relative_to(root).as_posix(): file_hash(p)
              for p in sorted(root.rglob("*")) if p.is_file()}
    assert actual == expected, (root, "input drift")


def stage_core(value):
    result = json.loads(json.dumps(value))
    result["metrics"].pop("duration_s", None)
    return result


def finding_metadata(stage):
    return [{"index": i, "stage": stage["stage"], "sha256": object_hash(f),
             "title": f["title"], "severity": f["severity"], "confidence": f["confidence"],
             "model_evidence_pointers": [e["source"] for e in f["evidence"]],
             "raw_evidence_sha256": [object_hash(e) for e in f["evidence"]]}
            for i, f in enumerate(stage["findings"])]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True,
                        help="Fresh output directory; use a dedicated /tmp path for reviewer replay")
    args = parser.parse_args()
    assert not args.out.exists(), "Refusing to overwrite a retained result"
    plan = load(HERE / "plan.json")
    assert plan["packet_size"] == 6 and not plan["new_inference_permitted_for_this_plan"]
    old = load(OLD / "semantic.json")
    old_static = load(OLD / "static.json")
    new = load(NEW / "fugu.json")
    public = load(PUBLIC / "measured.json")
    public_plan = load(PUBLIC / "measurement-plan.json")
    assert public["plan_sha256"] == file_hash(PUBLIC / "measurement-plan.json")
    assert new["plan_sha256"] == object_hash(load(NEW / "plan.json"))
    assert new["cases_sha256"] == object_hash(load(NEW / "cases.json"))
    assert new["engine"]["hashes"] == load("/tmp/fugu-full-workflow-engine-20261005/engine-manifest.json")["files"]
    raw_new_binding = load(REPO / "bench/results/2026-10-05-full-workflow/measurement/results.json")["raw_provenance"]["fugu.json"]
    assert file_hash(NEW / "fugu.json") == raw_new_binding
    engines = {
        "2026-10-02-label-free": {"commit": load(OLD / "source-hashes.json")["baseline_commit"],
            "pythonpath": str(OLD / "engine"), "hashes": old["source_hashes_before"]},
        "2026-10-02-public-source": {"commit": load(PUBLIC / "engine-manifest.json")["baseline_commit"],
            "pythonpath": "/tmp/fugu-composition-showcase-engine-20261002",
            "hashes": public["engine_hashes_before"]},
        "2026-10-05-full-workflow": {"commit": new["engine"]["commit"],
            "pythonpath": "/tmp/fugu-full-workflow-engine-20261005/src", "hashes": new["engine"]["hashes"]},
    }
    assert old["source_hashes_before"] == old["source_hashes_after"]
    assert file_hash(OLD / "measured-runner.py") == old["source_hashes_before"]["bench/fresh_benchmark.py"]
    assert public["engine_hashes_before"] == public["engine_hashes_after"]
    for engine in engines.values():
        verify_engine(engine["pythonpath"], engine["hashes"])
    datasets = {k: v for group in load(REPO / "bench/mcptox/data/pure_tool.json") for k, v in group.items()}
    assert file_hash(REPO / "bench/mcptox/data/pure_tool.json") == next(
        d["sha256"] for d in old["datasets"] if d["name"] == "mcptox_pure")
    rows, telemetry, tasks = [], [], {key: [] for key in engines}
    all_new_calls = [load(path) for path in sorted((NEW / "journals").glob("fugu-*/calls/*.json"))]
    public_calls = load(PUBLIC / "call-ledger.json")
    public_responses = {r["attempt"]: r for r in load(PUBLIC / "responses.json")}
    with TemporaryDirectory(prefix="fugu-demo-proof-semantic-20261006-recount-", dir="/tmp") as scratch:
        for number, selection in enumerate(plan["fixed_packet"]):
            interval, id = selection["interval"], selection["id"]
            container = {"2026-10-02-label-free": old, "2026-10-02-public-source": public,
                         "2026-10-05-full-workflow": new}[interval]
            original = next(r for r in container["rows"] if r["id"] == id)
            expected = original["input_sha256"]
            if interval == "2026-10-02-public-source":
                declared = next(r for r in public_plan["artifacts"] if r["id"] == id)
                assert declared["input_sha256"] == expected
                assert declared["commit"] == original["commit"]
            target = Path(scratch) / str(number)
            if interval == "2026-10-05-full-workflow":
                target = Path(original["target"])
            else:
                target.mkdir()
                if interval == "2026-10-02-label-free":
                    case = datasets[id.split("/", 1)[1]]
                    text = json.dumps({"tools": [{"name": case["tool_name"],
                        "description": case["tool_content"]}]}, indent=2) + "\n"
                    (target / "tools.json").write_text(text)
                else:
                    for rel in expected:
                        source = Path("/tmp/fugu-showcase-sources-20261002") / original["repository"].replace("/", "--") / rel
                        assert not source.is_symlink() and file_hash(source) == expected[rel]
                        dest = target / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, dest)
            packet_files(target, expected)
            stages = {s["stage"]: s for s in original["stages"]}
            selected = [stages[name] for name in ("concealment", "static", "semantic")]
            assert all(s["ok"] and not s["metrics"].get("call_errors") and not s["metrics"].get("parse_errors") for s in selected)
            assert not stages["concealment"]["findings"]
            baseline = [f for s in selected[:2] for f in s["findings"]]
            semantic = stages["semantic"]
            item = {**selection, "input_sha256": expected, "input_fingerprint": object_hash(expected),
                "engine_commit": engines[interval]["commit"],
                "engine_hashes_sha256": object_hash(engines[interval]["hashes"]),
                "source_commit": original.get("commit"), "repository": original.get("repository"),
                "baseline_medium_flag": any(f["severity"] in MEDIUM for f in baseline),
                "with_s2_medium_flag": any(f["severity"] in MEDIUM for f in baseline + semantic["findings"]),
                "s2_raw_findings": len(semantic["findings"]),
                "stages": [{"stage": s["stage"], "original_sha256": object_hash(s), "ok": s["ok"],
                    "core_sha256_excluding_duration": object_hash(stage_core(s)),
                    "coverage": {k: v for k, v in s["metrics"].items() if k not in ("llm_calls", "request_attempts", "duration_s", "hits", "match_contexts")},
                    "findings": finding_metadata(s)} for s in selected],
                "original_aggregate_flag_not_s2_attribution": original.get("raw_medium_flag", original.get("flagged")),
                "adjudicated_supported_marginal": None, "independent_review": "pending"}
            if interval == "2026-10-02-label-free":
                separate = next(r for r in old_static["rows"] if r["id"] == id)
                assert separate["input_sha256"] == expected
                assert [stage_core(s) for s in separate["stages"]] == [stage_core(s) for s in selected[:2]]
                item["separate_static_run_core_matches"] = True
            calls = semantic["metrics"]["llm_calls"]
            if interval == "2026-10-05-full-workflow":
                context = digest(json.dumps(expected, sort_keys=True).encode())
                records = [r for r in all_new_calls if r["stage"] == "semantic" and r["context"] == context]
                assert len(records) == len(calls)
                for record in records:
                    assert digest(record["raw_response"].encode()) == record["response_sha256"]
                    messages = record["messages"]
                    assert digest(json.dumps(messages, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()) == record["messages_sha256"]
                    assert object_hash({"model": record["requested_model"], "messages": messages,
                        "temperature": record["temperature"], "max_tokens": record["max_tokens"]}) == record["request_sha256"]
                    telemetry.append({"id": id, "interval": interval, "original_attempt": record["number"],
                        "requested_model": record["requested_model"], "served_model": record["served_model"],
                        "max_tokens": record["max_tokens"], "temperature": record["temperature"],
                        "finish_reason": record["finish_reason"], "latency_s": record["duration_s"],
                        "usage": record["usage"], "response_sha256": record["response_sha256"],
                        "system_sha256": digest(messages[0]["content"].encode()),
                        "user_sha256": digest(messages[1]["content"].encode()),
                        "request_sha256": record["request_sha256"],
                        "messages_sha256": record["messages_sha256"],
                        "original_journal_record_sha256": object_hash(record), "error": record["output_error"],
                        "new_sdk_dispatch": False})
            elif interval == "2026-10-02-public-source":
                records = [r for r in public_calls if r["artifact"] == id]
                assert len(records) == len(calls)
                for record in records:
                    response = public_responses[record["attempt"]]
                    assert digest(response["raw_response"].encode()) == record["response_sha256"]
                    telemetry.append({"id": id, "interval": interval, "original_attempt": record["attempt"],
                        "requested_model": record["model"], "served_model": None,
                        "max_tokens": record["max_completion_tokens"], "finish_reason": record["finish_reason"],
                        "latency_s": record["latency_s"], "usage": record["usage"],
                        "response_sha256": record["response_sha256"], "system_sha256": record["system_sha256"],
                        "user_sha256": record["user_sha256"], "error": None, "new_sdk_dispatch": False})
            else:
                for record in calls:
                    telemetry.append({"id": id, "interval": interval, "original_attempt": None,
                        "requested_model": record["model"], "served_model": None, "max_tokens": 1600,
                        "finish_reason": None, "latency_s": record["latency_s"], "usage": record["usage"],
                        "response_sha256": None, "system_sha256": None, "user_sha256": None,
                        "error": None, "new_sdk_dispatch": False,
                        "limit": "Original stage did not retain transport IDs, raw responses or finish/served-model fields."})
            tasks[interval].append({"id": id, "target": str(target)})
            rows.append(item)
        for interval, inputs in tasks.items():
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1", NEBIUS_API_KEY="", TAVILY_API_KEY="")
            process = subprocess.run([sys.executable, str(HERE / "bind_units.py")], input=json.dumps({
                "pythonpath": engines[interval]["pythonpath"], "inputs": inputs}),
                text=True, capture_output=True, check=True, env=env, cwd=REPO)
            bindings = json.loads(process.stdout)
            for bound in bindings:
                row = next(r for r in rows if r["interval"] == interval and r["id"] == bound["id"])
                original_calls = [r for r in telemetry if r["interval"] == interval and r["id"] == bound["id"]]
                assert len(bound["units_submitted"]) == len(original_calls)
                assert bound["units_omitted"] == 0
                for unit, call in zip(bound["units_submitted"], original_calls):
                    if call["system_sha256"] is not None:
                        assert call["system_sha256"] == unit["system_sha256"]
                        assert call["user_sha256"] == unit["user_sha256"]
                    else:
                        original = next(r for r in old["rows"] if r["id"] == bound["id"])
                        records = next(s for s in original["stages"] if s["stage"] == "semantic")["metrics"]["llm_calls"]
                        assert records[0]["prompt_chars"] == unit["system_chars"] + unit["user_chars"]
                        call["reconstructed_system_sha256"] = unit["system_sha256"]
                        call["reconstructed_user_sha256"] = unit["user_sha256"]
                row["semantic_input_binding"] = bound
    assert len(rows) == 6 and len(telemetry) == 13
    artifact_paths = [OLD / "semantic.json", OLD / "static.json", OLD / "source-hashes.json",
        OLD / "measured-runner.py", PUBLIC / "measured.json", PUBLIC / "measurement-plan.json",
        PUBLIC / "call-ledger.json", PUBLIC / "responses.json", PUBLIC / "adjudication.json",
        PUBLIC / "engine-manifest.json", NEW / "fugu.json", NEW / "plan.json", NEW / "cases.json"]
    data = {"schema": 1, "protocol": plan["protocol"], "plan_sha256": file_hash(HERE / "plan.json"),
        "new_sdk_dispatches": 0, "new_paid_searches": 0, "actual_target_executions": 0,
        "canonical_hash": "SHA256 UTF8 JSON sort_keys=True,separators=(',',':'),ensure_ascii=False",
        "original_canonical_bindings": {"2026-10-05-plan": new["plan_sha256"],
            "2026-10-05-cases": new["cases_sha256"]},
        "original_artifacts": [{"path": str(p.relative_to(REPO)) if p.is_relative_to(REPO) else str(p), "sha256": file_hash(p)} for p in artifact_paths],
        "engines": {key: {"commit": value["commit"], "pythonpath": value["pythonpath"],
            "source_files": [{"path": rel, "sha256": sha} for rel, sha in sorted(value["hashes"].items())],
            "original_source_map_sha256": object_hash(value["hashes"])} for key, value in engines.items()},
        "rows": rows,
        "independent_adjudication": "pending; raw alert count is not supported marginal value"}
    args.out.mkdir(parents=True)
    (args.out / "comparison.json").write_text(json.dumps(data, indent=2) + "\n")
    with (args.out / "telemetry.jsonl").open("w") as stream:
        for record in telemetry:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    totals = {k: sum(r["usage"][k] for r in telemetry) for k in ("prompt_tokens", "completion_tokens")}
    checks = {"schema": 1, "checks_passed": True, "packet_size": 6, "retained_semantic_requests": len(telemetry),
        "retained_usage": totals, "retained_sum_request_latency_s": round(sum(r["latency_s"] for r in telemetry), 3),
        "new_sdk_dispatches": 0, "new_searches": 0, "target_executions": 0,
        "all_original_source_and_engine_hashes_verified": True,
        "original_wire_user_system_hashes_match_reconstruction": 11,
        "older_requests_bound_by_source_hash_and_prompt_chars_only": 2,
        "independent_review": "pending"}
    (args.out / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    print(json.dumps(checks))


if __name__ == "__main__":
    main()
