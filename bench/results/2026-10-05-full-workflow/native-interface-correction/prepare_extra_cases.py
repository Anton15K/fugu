"""Append 20 pre-observation MCPTox packets from the pinned cache; never scan them."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from bench.competitive_corpus import append_metadata, content_hash, input_hashes
from bench.mcptox.fetch import load_cases

BASE = Path("bench/results/2026-10-05-full-workflow")
PRIVATE = Path(".fugu-private/full-workflow-20261005/research")
SEED = "fugu-full-workflow-20261005-extra20-v1"
SOURCE_SHA = "79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    data = json.dumps(value, sort_keys=True, indent=2) + "\n"
    if path.exists() and path.read_text() != data:
        raise ValueError("refusing changed extension artifact: " + path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


def main():
    original_path = BASE / "cases.json"
    original = json.loads(original_path.read_text())
    assert len(original["cases"]) == 120
    source = Path("bench/mcptox/data/response_all.json")
    assert sha(source) == SOURCE_SHA
    prior = json.loads((BASE / "prior-overlap.json").read_text())["records"]
    prior_ids = {row["id"] for row in prior}
    prior_content = {digest for row in prior for digest in row["tool_content_sha256"]}
    static_path = Path("bench/results/2026-10-04-integration/integration-verification/selected/extended-static.json")
    static_ids = {row["id"] for row in json.loads(static_path.read_text())["rows"]}
    candidates = []
    for raw in load_cases(source):
        tool = {"name": raw["poisoned_tool_name"], "description": raw["poisoned_description"]}
        identity = "mcptox/" + raw["case_id"]
        candidates.append({"id": identity, "tool": tool, "content_hash": content_hash(tool),
            "cohort": "mcp_metadata", "kind": "malicious",
            "stratum": f'{raw["category"]}|{raw["paradigm"]}|{raw["server"]}',
            "provenance": {"source": "MCPTox", "commit": "f85189f9ad12504c197c7f920ab818a40657b1fa",
                "source_path": "response_all.json", "source_sha256": SOURCE_SHA,
                "category": raw["category"], "paradigm": raw["paradigm"], "server": raw["server"],
                "schema_present": False, "label_source": "benchmark-author attack instance; no detector outcomes used"},
            "overlap": {"prior_full_ids": [], "prior_full_file_hash_overlap": [],
                "prior_static_case_ids": [identity] if identity in static_ids else [],
                "prior_source_visibility": "MCPTox source corpus previously visible; pre-observation availability expansion, not blind"}})
    result = append_metadata(original, candidates, count=20, seed=SEED,
        target_root=PRIVATE / "extra-targets", exclude_ids=prior_ids, exclude_content=prior_content)
    assert result["cases"][:120] == original["cases"] and len(result["cases"]) == 140
    for row in result["cases"]:
        assert input_hashes(Path(row["target"])) == row["input_sha256"]
    result["extension"]["original_manifest_sha256"] = sha(original_path)
    write(BASE / "cases-v2.json", result)
    extra = result["cases"][120:]
    original_content = {content_hash(tool) for row in original["cases"] if row["cohort"] == "mcp_metadata"
        for tool in json.loads((Path(row["target"]) / "tools.json").read_text())["tools"]}
    excluded_ids = prior_ids | {row["id"] for row in original["cases"]}
    excluded_content = prior_content | original_content
    summary = {"schema": 1, "status": "NOT RELEASED", "seed": SEED,
        "reason": "lead assigned before benchmark observations: 28 original cases have applicable unavailable detonation; preserve them and append20 metadata inputs",
        "original_manifest_sha256": sha(original_path), "cases_v2_sha256": sha(BASE / "cases-v2.json"),
        "original_count": 120, "appended_count": 20, "planned": 140,
        "cohorts": dict(Counter(row["cohort"] for row in result["cases"])),
        "kind_counts": dict(Counter(row["kind"] for row in result["cases"])),
        "selection": result["extension"], "candidate_count": len(candidates),
        "eligible_count": sum(row["id"] not in excluded_ids and row["content_hash"] not in excluded_content for row in candidates),
        "excluded_ids": sorted(excluded_ids), "excluded_content_sha256": sorted(excluded_content),
        "extra_ids": [row["id"] for row in extra],
        "extra_attack_servers": len({row["provenance"]["server"] for row in extra}),
        "extra_prior_static_ids": [row["id"] for row in extra if row["overlap"]["prior_static_case_ids"]],
        "availability": {"source": "lead assigned chamber-denial/native applicability assessment before observations",
            "original_applicable_unavailable_detonation": 28, "original_full_eligible_max": 92,
            "new_full_eligible_max": 112, "scope": "upper bound only; not completed cases or runtime coverage"},
        "unchanged_budgets": {"fugu_sdk": 5400, "competitor_sdk": 1800, "tavily": 480,
            "requested_output_token_ceiling": 36864000}}
    write(BASE / "selection-v2.json", summary)
    print(json.dumps({key: summary[key] for key in ("status", "planned", "cohorts", "kind_counts", "eligible_count")}))


if __name__ == "__main__":
    main()
