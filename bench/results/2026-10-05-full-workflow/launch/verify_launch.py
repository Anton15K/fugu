"""Read-only AST, file-hash and installed-metadata checks; no native imports."""
import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = Path("/Users/antonkogun/dev/nebius_hack")
ENGINE = Path("/tmp/fugu-full-workflow-engine-20261005")
MCP_SEC = Path("/tmp/fugu-full-workflow-research-20261005/sources/mcp-sec-audit/detection")
launch = HERE / "launch.py"
tree = ast.parse(launch.read_text())
compile(tree, str(launch), "exec")
allowed = {"sha", "read", "check_bindings", "check_native_packages", "native_jobs"}
definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in allowed]
namespace = dict(HERE=HERE, ROOT=ROOT, ENGINE=ENGINE, MCP_SEC=MCP_SEC, Path=Path,
                 sys=sys, hashlib=hashlib, json=json, importlib=importlib, re=re)
exec(compile(ast.Module(body=definitions, type_ignores=[]), str(launch), "exec"), namespace)
binding_hash = hashlib.sha256((HERE / "bindings.json").read_bytes()).hexdigest()
binding = namespace["check_bindings"](SimpleNamespace(bindings_sha256=binding_hash))
namespace["check_native_packages"](binding)
cases = json.loads((ROOT / "bench/results/2026-10-05-full-workflow/cases-v2.json").read_text())
jobs = namespace["native_jobs"](cases)
counts = dict(Counter(scanner for scanner, case in jobs))
assert counts == {"sentinel": 100, "mcp-sec-audit": 100, "cisco-skill": 20, "cisco-mcp": 100}
assert all(case["cohort"] == ("skills" if scanner == "cisco-skill" else "mcp_metadata")
           for scanner, case in jobs)
assert sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
           and node.func.id == "load_engine" for node in ast.walk(tree)) == 1
assert sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
           and node.func.id == "NativeRequestCounter" for node in ast.walk(tree)) == 1
proof = {
    "schema": 1, "at": datetime.now(timezone.utc).isoformat(),
    "scope": "syntax and read-only hashes/installed metadata plus pure cohort work-list function only",
    "bootstrap_sha256": hashlib.sha256(launch.read_bytes()).hexdigest(),
    "launch_bindings_sha256": binding_hash,
    "syntax": "AST parse and in-memory compile passed",
    "accepted_file_bindings": len(binding["files"]),
    "frozen_engine_files_checked": 39,
    "installed_native_file_hashes_checked": sum(len(p["files"]) for p in
        json.loads(Path(binding["dependency_inventory"]).read_text())["installed_roots"]),
    "native_source_and_transitive_bindings": "passed; no native module import",
    "planned_pairs": len(jobs), "planned_by_scanner": counts,
    "cold_engine_loader_call_sites": 1, "shared_native_counter_call_sites": 1,
    "credentials_accessed": False, "provider_calls": 0, "search_calls": 0,
    "native_scanner_invocations": 0, "chamber_calls": 0, "target_execution": False,
    "measurement_or_inference_validation": False,
    "corrected_preflight_error": "Initial hash check used global distribution discovery, which resolved source-tree detection egg-info. Final check discovers installed wheel metadata only in the isolated site-packages, and verifies source-tree bytes separately. Initial attempt ran no native imports or calls.",
    "remaining": "Lead fills integrated final plan hash and separately grants authenticated data authority/output territory. Native execution and measured evidence not validated by this proof."
}
(HERE / "zero-call-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
print(json.dumps(proof))
