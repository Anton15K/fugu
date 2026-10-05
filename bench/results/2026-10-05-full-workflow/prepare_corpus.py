"""Rebuild the proposed corpus from pinned cached sources, without running targets.

Run from repository root. Source archives remain outside tracked deliverables.
The candidate index and all original payload bytes are written privately.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from bench.competitive_corpus import (
    content_hash, input_hashes, prepare, sha256, validate_sources,
)
from bench.mcptox.fetch import load_cases

SEED = "fugu-full-workflow-20261005-v1"
PUBLIC = Path("bench/results/2026-10-05-full-workflow")
PRIVATE = Path(".fugu-private/full-workflow-20261005/research")
MCPTox_SHA = "79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03"


def write(path, value):
    path = Path(path)
    data = json.dumps(value, sort_keys=True, indent=2) + "\n"
    if path.exists() and path.read_text() != data:
        raise ValueError(f"refusing changed artifact: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


def build(sources: Path):
    original = Path("bench/mcptox/data/response_all.json")
    if sha256(original.read_bytes()) != MCPTox_SHA:
        raise ValueError("MCPTox original source pin mismatch")
    prior_path = Path("bench/results/2026-10-02-full/cases.json")
    prior = json.loads(prior_path.read_text())["cases"]
    prior_content = defaultdict(list)
    prior_file_hashes = set()
    prior_ids = {r["id"] for r in prior}
    overlap_path = PUBLIC / "prior-overlap.json"
    if overlap_path.exists():
        prior_table = json.loads(overlap_path.read_text())
    else:
        records = []
        for row in prior:
            packet = Path(row["target"]) / "tools.json"
            fingerprints = []
            if "tools.json" in row["input_sha256"]:
                if sha256(packet.read_bytes()) != row["input_sha256"]["tools.json"]:
                    raise ValueError("earlier full packet hash mismatch")
                fingerprints = [content_hash(tool) for tool in json.loads(packet.read_text())["tools"]]
            records.append({"id": row["id"], "input_sha256": row["input_sha256"], "tool_content_sha256": fingerprints})
        prior_table = {"schema": 1, "source_manifest_sha256": sha256(prior_path.read_bytes()), "records": records}
        write(overlap_path, prior_table)
    if prior_table["source_manifest_sha256"] != sha256(prior_path.read_bytes()) or [
        {k: row[k] for k in ("id", "input_sha256")} for row in prior_table["records"]
    ] != [{k: row[k] for k in ("id", "input_sha256")} for row in prior]:
        raise ValueError("earlier full identity table drift")
    for row in prior_table["records"]:
        prior_file_hashes.update(row["input_sha256"].values())
        for key in row["tool_content_sha256"]:
            prior_content[key].append(row["id"])
    static_path = Path("bench/results/2026-10-04-integration/integration-verification/selected/extended-static.json")
    static_ids = {r["id"] for r in json.loads(static_path.read_text())["rows"]}

    def overlap(identity, hashes=(), key=None, visibility="no earlier Fugu result identified in the bound tables"):
        return {"prior_full_ids": sorted(set(([identity] if identity in prior_ids else []) + prior_content.get(key, []))),
                "prior_full_file_hash_overlap": sorted(set(hashes) & prior_file_hashes),
                "prior_static_case_ids": [identity] if identity in static_ids else [],
                "prior_source_visibility": visibility}

    def directory(identity, root, cohort, kind, provenance, *, members=None, expected=None, files=None, visibility=None):
        hashes = input_hashes(root)
        if files is not None:
            hashes = {k: v for k, v in hashes.items() if k in files}
        if not hashes:
            raise ValueError("empty candidate")
        validity = validate_sources(root)
        invalid = [r["path"] for r in validity if r["path"] in hashes and r["status"] != "valid"]
        if invalid:
            raise ValueError("invalid selected candidate syntax: " + identity)
        row = {"id": identity, "cohort": cohort, "kind": kind, "stratum": provenance.get("family", identity),
               "source_directory": str(root.resolve()), "source_hashes": hashes, "provenance": provenance,
               "overlap": overlap(identity, hashes.values(), visibility=visibility or "no earlier Fugu result identified in bound tables")}
        if members is not None:
            row["members"] = members
        if expected is not None:
            row["expected"] = expected
        return row

    attacks = []
    for case in load_cases(original):
        tool = {"name": case["poisoned_tool_name"], "description": case["poisoned_description"]}
        identity = "mcptox/" + case["case_id"]
        key = content_hash(tool)
        attacks.append({"id": identity, "cohort": "mcp_metadata", "kind": "malicious", "tool": tool,
                        "stratum": f'{case["category"]}|{case["paradigm"]}|{case["server"]}', "content_hash": key,
                        "provenance": {"source": "MCPTox", "commit": "f85189f9ad12504c197c7f920ab818a40657b1fa",
                                       "source_path": "response_all.json", "source_sha256": MCPTox_SHA,
                                       "category": case["category"], "paradigm": case["paradigm"],
                                       "server": case["server"], "schema_present": False,
                                       "label_source": "benchmark-author attack instance; no detector outcomes used"},
                        "overlap": overlap(identity, key=key, visibility="MCPTox source corpus previously visible; not a blind selection")})
    clean_path = Path("bench/real/fuzzd-cache/clean_tools.json")
    controls = []
    for tool in json.loads(clean_path.read_text()):
        if tool.get("_meta", {}).get("is_attack") is not False:
            raise ValueError("unexpected clean label")
        identity, key = "clean/" + tool["name"], content_hash(tool)
        controls.append({"id": identity, "cohort": "mcp_metadata", "kind": "benign", "tool": tool,
                         "stratum": "clean", "content_hash": key,
                         "provenance": {"source": "fuzzd retained original clean_tools", "source_path": str(clean_path),
                                        "source_sha256": sha256(clean_path.read_bytes()), "schema_present": True,
                                        "label_source": "original _meta.is_attack=false; label removed from scanned packet"},
                         "overlap": overlap(identity, key=key, visibility="all20 clean sources previously visible; five prior full controls retained because pool contains20")})
    skills_attack, skills_clean = [], []
    skill_root = sources / "cisco-skill/evals/skills"
    excluded_families = {"hardcoded-secrets", "harmful-content", "malware", "resource-exhaustion"}
    for metadata_path in sorted(skill_root.rglob("_expected.json")):
        metadata = json.loads(metadata_path.read_text())
        rel = metadata_path.parent.relative_to(skill_root).as_posix()
        if metadata["package_label"] not in {"malicious", "benign"} or rel.split("/")[0] in excluded_families:
            continue
        kind = "malicious" if metadata["package_label"] == "malicious" else "benign"
        row = directory("cisco-skill/" + rel, metadata_path.parent, "skills", kind,
                        {"source": "Cisco first-party human-reviewed inert fixture", "commit": "669a2cdf64f81f748f6590d421c935c01c5b01b5",
                         "source_path": "evals/skills/" + rel, "license": "Apache-2.0", "family": rel.split("/")[0],
                         "label_source": "producer package_label and human-reviewed provenance", "label_metadata_sha256": sha256(metadata_path.read_bytes()),
                         "label_scope": "authored unsafe/benign package; not observed wild malware"})
        (skills_attack if kind == "malicious" else skills_clean).append(row)
    formatter_root = sources / "cisco-skill/evals/test_skills/safe/simple-formatter"
    skills_clean.append(directory("cisco-skill/safe/simple-formatter", formatter_root, "skills", "benign",
                                  {"source": "Cisco documented clean formatter example", "commit": "669a2cdf64f81f748f6590d421c935c01c5b01b5",
                                   "source_path": "evals/test_skills/safe/simple-formatter", "label_source": "published clean example plus manual content inspection",
                                   "license": "MIT skill declaration; source repository Apache-2.0"}))
    anthropic_meta = json.loads((sources.parent / "anthropic-source.json").read_text())
    for skill in sorted((sources / "anthropic-skills").rglob("SKILL.md")):
        rel = skill.relative_to(sources / "anthropic-skills")
        if rel.parts[0] not in {"skills", "template"} or len(skill.read_text()) > 6000:
            continue
        skills_clean.append(directory("anthropic-skill/" + rel.parent.as_posix(), skill.parent, "skills", "benign",
                                      {"source": "Anthropic published skill instruction packet", "commit": anthropic_meta["commit"],
                                       "source_path": rel.as_posix(), "family": "published_instruction_packet",
                                       "label_source": "manual task-scope review of original instruction packet", "packet_only": True,
                                       "omitted_package_resources": "SKILL.md-only input; complete original bytes, no bundled helper scripts/resources"}, files={"SKILL.md"}))
    compositions = {"malicious": [], "benign": []}
    excluded_composition = []
    for path in sorted(Path("corpus/composition-v2").glob("*/set.json")):
        metadata = json.loads(path.read_text())
        if any(path.parent.rglob("*.js")):
            excluded_composition.append(metadata["name"])
            continue
        kind = "malicious" if metadata["kind"] == "attack" else "benign"
        family = "shell" if "shell" in path.parent.name else "schema" if "schema" in path.parent.name or "name-" in path.parent.name else "python"
        compositions[kind].append(directory("composition-v2/" + metadata["name"], path.parent, "composition", kind,
                                           {"source": "existing Fugu composition-v2 authored corpus", "source_path": str(path.parent),
                                            "family": family, "label_source": "original set.json expected values", "label_metadata_sha256": sha256(path.read_bytes()),
                                            "label_scope": "cross-member composition claim; controls may contain risky single members"},
                                           members=metadata["members"], expected={**metadata["expected"], "scope": "composition_trifecta_or_shadowing"},
                                           visibility="composition-v2 sources previously visible in static tests/diagnostics; not blind"))
    source_cases = []
    for name in ["03-env-harvest-installer", "04-credential-reader", "05-obfuscated-payload"]:
        source_cases.append(directory("source/" + name, Path("corpus") / name, "source", "malicious",
                                      {"source": "existing Fugu crafted synthetic source", "source_path": "corpus/" + name,
                                       "label_source": "original crafted manifest", "family": "shell" if name.startswith("03") else "python"},
                                      visibility="same source previously visible/full workflow; new measurement only"))
    source_cases.append(directory("source/cisco-environment-secrets", skill_root / "data-exfiltration/environment-secrets", "source", "malicious",
                                  {"source": "Cisco authored environment-access risk source", "commit": "669a2cdf64f81f748f6590d421c935c01c5b01b5",
                                   "source_path": "evals/skills/data-exfiltration/environment-secrets/get_info.py", "license": "Apache-2.0",
                                   "label_source": "producer HIGH finding bound to get_info.py; source-only risk fixture"}, files={"get_info.py"}))
    for identity, root, filename in [("cisco-math", skill_root / "safe-skills/simple-math", "math_ops.py"),
                                     ("cisco-validator", skill_root / "safe-skills-2/file-validator", "validate.py"),
                                     ("cisco-formatter", formatter_root, "formatter.py"),
                                     ("csv-tidy", Path("corpus/09-clean-installer"), "csv_tidy.py")]:
        source_cases.append(directory("source/" + identity, root, "source", "benign",
                                      {"source": "authored clean source/control", "source_path": str(root / filename),
                                       "label_source": "original clean fixture plus manual source-slice inspection", "family": "python"}, files={filename}))
    groups = [{"count": 60, "candidates": attacks, "exclude_ids": sorted(prior_ids), "exclude_content": sorted(prior_content)},
              {"count": 20, "candidates": controls}, {"count": 10, "candidates": skills_attack},
              {"count": 10, "candidates": skills_clean},
              {"count": 6, "candidates": compositions["malicious"]}, {"count": 6, "candidates": compositions["benign"]},
              {"count": 8, "candidates": source_cases}]
    spec = {"schema": 1, "seed": SEED, "selection_protocol": "SHA256(seed+NUL+id), deterministic round-robin hash-ranked strata; no detector outputs",
            "groups": groups, "exclusions": {"skill_families": sorted(excluded_families), "composition_js": excluded_composition,
                                               "invalid_old_source": "corpus/06-rugpull-pair/v2/server.py contains JSON Boolean Name in Python"}}
    write(PRIVATE / "candidate-index.json", spec)
    manifest = prepare(spec, PRIVATE / "targets")
    write(PUBLIC / "cases.json", manifest)
    validity = []
    for row in manifest["cases"]:
        validity.extend(dict(item, id=row["id"]) for item in validate_sources(Path(row["target"])))
    write(PUBLIC / "syntax-preflight.json", {"scope": "syntax only; no target import/entrypoint/chamber/scanner/inference", "rows": validity})
    summary = {"status": "NOT RELEASED", "planned": len(manifest["cases"]),
               "cohorts": dict(Counter(r["cohort"] for r in manifest["cases"])),
               "kind_counts": dict(Counter(r["kind"] for r in manifest["cases"])),
               "attack_servers": len({r["provenance"].get("server") for r in manifest["cases"] if r["id"].startswith("mcptox/")}),
               "prior_full_same_content": [r["id"] for r in manifest["cases"] if r["overlap"]["prior_full_ids"] or r["overlap"]["prior_full_file_hash_overlap"]],
               "source_case_scope": "source risk fixtures, not real-world incidents; imports do not establish function invocation",
               "composition_control_scope": "negative cross-member claim only, not clean-package innocence",
               "exclusions": spec["exclusions"]}
    write(PUBLIC / "selection-summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k in {"status", "planned", "cohorts", "kind_counts", "attack_servers"}}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=Path("/tmp/fugu-full-workflow-research-20261005/sources"))
    build(parser.parse_args().sources)
