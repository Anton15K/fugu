"""Task-local launch prescription. A queue string is not execution authority.

Do not execute prepare/live actions until the lead assigns their output paths.
The preparation task validates this file with AST/compile only.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import re
import sys

ROOT = Path("/Users/antonkogun/dev/nebius_hack")
HERE = Path(__file__).resolve().parent
ENGINE = Path("/tmp/fugu-full-workflow-engine-20261005")
MCP_SEC = Path("/tmp/fugu-full-workflow-research-20261005/sources/mcp-sec-audit/detection")
MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"
BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
HOSTED = {"cisco-skill", "cisco-mcp"}
STOP_PAID = {"provider_auth_failure", "provider_quota_exhausted"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def write(path, value):
    # Private metadata only; use the accepted atomic writer when running.
    from bench.current_limits import write_json
    write_json(Path(path), value)


def check_bindings(args):
    path = HERE / "bindings.json"
    if sha(path) != args.bindings_sha256:
        raise ValueError("launch binding changed")
    binding = read(path)
    for record in binding["files"]:
        if sha(record["path"]) != record["sha256"]:
            raise ValueError("accepted source or evidence hash changed")
    manifest = read(ENGINE / "engine-manifest.json")
    if len(manifest["files"]) != 39:
        raise ValueError("frozen engine inventory changed")
    for name, expected in manifest["files"].items():
        if sha(ENGINE / name) != expected:
            raise ValueError("frozen engine source changed")
    return binding


def check_native_packages(binding):
    inventory = read(binding["dependency_inventory"])
    if Path(sys.prefix).resolve() != Path(inventory["venv"]).resolve():
        raise ValueError("isolated native environment required")
    site = Path(inventory["venv"]) / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    def normalized(name):
        return re.sub(r"[-_.]+", "-", name).lower()
    installed = {normalized(d.metadata["Name"]): d for d in
                 importlib.metadata.Distribution.discover(path=[str(site)])}
    for package in inventory["installed_roots"]:
        distribution = installed[normalized(package["name"])]
        if distribution.version != package["version"]:
            raise ValueError("native installed version changed")
        for name, expected in package["files"].items():
            if sha(distribution.locate_file(name)) != expected:
                raise ValueError("native installed bytes changed")
    for package in inventory["transitive_packages"]:
        if installed[normalized(package["name"])].version != package["version"]:
            raise ValueError("native transitive version changed")
    for name, expected in inventory["modules"]["detection"]["source_files"].items():
        if sha(MCP_SEC / name) != expected:
            raise ValueError("MCP-Sec pinned source-tree bytes changed")
    pins = read(ROOT / "bench/results/2026-10-05-full-workflow/source-pins.json")
    for source in pins["sources"]:
        if source["tool"] not in {"cisco-skill", "cisco-mcp", "sentinel", "mcp-sec-audit"}:
            continue
        source_root = MCP_SEC.parent if source["tool"] == "mcp-sec-audit" else MCP_SEC.parents[1] / source["tool"]
        for record in source["source_files"]:
            if sha(source_root / record["path"]) != record["sha256"]:
                raise ValueError("pinned native source bytes changed")
    if not sys.path or str(MCP_SEC) not in sys.path:
        raise ValueError("explicit MCP-Sec source-tree PYTHONPATH required")


def frozen_inputs(args):
    # The final runner hash is supplied by the lead's later immutable plan.
    plan = read(args.fugu_output / "plan.json")
    if digest(plan) != args.approved_plan_sha256:
        raise ValueError("approved Fugu plan changed")
    if sha(ROOT / "bench/full_workflow_competitive.py") != plan["runner_sha256"]:
        raise ValueError("integrated runner differs from final plan")
    from bench.full_workflow_competitive import require_execution_release
    from bench.competitive_corpus import input_hashes
    require_execution_release(plan, approved_plan_sha256=args.approved_plan_sha256,
                              data_release_ref=args.data_release_ref)
    cases = read(args.fugu_output / "cases.json")
    originals = read(ROOT / "bench/results/2026-10-05-full-workflow/cases-v2.json")
    if digest(cases) != plan["cases_sha256"] or plan["case_count"] != 140:
        raise ValueError("prepared case manifest changed")
    if [c["id"] for c in cases["cases"]] != [c["id"] for c in originals["cases"]]:
        raise ValueError("case order or identities changed")
    for case, original in zip(cases["cases"], originals["cases"]):
        if case["input_sha256"] != original["input_sha256"]:
            raise ValueError("original input binding changed")
        if input_hashes(Path(case["target"])) != case["input_sha256"]:
            raise ValueError("prepared input bytes changed")
    return plan, cases


def project_dotenv():
    # Explicit supported loader, followed by disabling later auto-discovery.
    from dotenv import load_dotenv
    os.environ.pop("PYTHON_DOTENV_DISABLED", None)
    load_dotenv(ROOT / ".env", override=False)
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    if not os.environ.get("NEBIUS_API_KEY", "").strip():
        raise ValueError("configured Nebius credential unavailable")
    if os.environ.get("NEBIUS_BASE_URL", BASE_URL).rstrip("/") != BASE_URL.rstrip("/"):
        raise ValueError("provider endpoint differs from accepted route")


def paid_stop(output):
    reasons = [read(p).get("stop_reason")
               for p in output.glob("journals/fugu-*/budget.json")]
    return next((r for r in reasons if r in STOP_PAID), None)


def native_jobs(cases):
    jobs = [(scanner, case) for scanner, cohort in (
        ("sentinel", "mcp_metadata"), ("mcp-sec-audit", "mcp_metadata"),
        ("cisco-skill", "skills"), ("cisco-mcp", "mcp_metadata"))
        for case in cases["cases"] if case["cohort"] == cohort]
    if len(jobs) != 320:
        raise ValueError("native planned pairing count changed")
    return jobs


async def competitors(args, binding):
    check_native_packages(binding)
    plan, cases = frozen_inputs(args)
    from bench.competitive_scanners import NativeRequestCounter, hosted_completion, run_native, NATIVE_LLM
    jobs = native_jobs(cases)
    output = args.competitor_output.resolve()
    private_root = Path("/tmp/fugu-full-workflow-research-20261005").resolve()
    if output == private_root or not output.is_relative_to(private_root):
        raise ValueError("competitor evidence must use a dedicated private task child")
    output.mkdir(parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    os.chdir(output)  # Keep native relative files/config discovery in task scratch.
    results_path = output / "competitors.json"
    rows = [{"scanner": scanner, "id": case["id"], "cohort": case["cohort"],
             "kind": case["kind"], "input_sha256": case["input_sha256"],
             "status": "unattempted", "complete": False, "flagged": None,
             "any_alert": None, "reasons": [], "per_analyzer": [], "request_numbers": []}
            for scanner, case in jobs]
    document = {"schema": 1, "protocol": "fugu-full-workflow-native-competitors-v1",
                "plan_sha256": args.approved_plan_sha256,
                "cases_sha256": plan["cases_sha256"], "data_release_ref": args.data_release_ref,
                "launch_bindings_sha256": args.bindings_sha256,
                "planned": 320, "planned_by_scanner": {"sentinel": 100, "mcp-sec-audit": 100,
                    "cisco-skill": 20, "cisco-mcp": 100},
                "started_utc": datetime.now(timezone.utc).isoformat(), "rows": rows}
    if results_path.exists():
        prior = read(results_path)
        for key in ("protocol", "plan_sha256", "cases_sha256", "data_release_ref",
                    "launch_bindings_sha256", "planned", "planned_by_scanner"):
            if prior[key] != document[key]:
                raise ValueError("saved native run binding changed")
        def identity(row):
            return row["scanner"], row["id"], row["input_sha256"]
        if list(map(identity, prior["rows"])) != list(map(identity, rows)):
            raise ValueError("saved native row order or inputs changed")
        document, rows = prior, prior["rows"]
    with NativeRequestCounter(output / "hosted-counter", binding=args.approved_plan_sha256, limit=1800) as counter:
        def publish():
            document.update(measured_utc=datetime.now(timezone.utc).isoformat(),
                            attempts=counter.state["attempts"], stop_reason=counter.stop_reason)
            write(results_path, document)
        publish()  # ALL 320 planned pairs exist before any native invocation.
        if args.initialize_only:
            return
        project_dotenv()
        # Native defaults only: discard dotenv-provided policy/routing overrides.
        allowed_environment = {"PATH", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE",
            "PYTHON_DOTENV_DISABLED", "UV_CACHE_DIR", "NEBIUS_API_KEY", "NEBIUS_BASE_URL"}
        for name in list(os.environ):
            if name not in allowed_environment:
                os.environ.pop(name)
        from openai import OpenAI
        from bench.competitive_corpus import input_hashes
        key = os.environ["NEBIUS_API_KEY"]
        lock = asyncio.Lock()
        for index, ((scanner, case), row) in enumerate(zip(jobs, rows)):
            if row["status"] != "unattempted":
                if row["status"] == "in_progress":
                    row.update(status="partial", complete=False, reasons=["interrupted_no_automatic_rerun"])
                    publish()
                continue
            stop = paid_stop(args.fugu_output) or counter.stop_reason
            if scanner in HOSTED and stop:
                row["reasons"] = [stop]
                publish()
                continue
            row.update(status="in_progress", started_utc=datetime.now(timezone.utc).isoformat())
            publish()
            if input_hashes(Path(case["target"])) != case["input_sha256"]:
                raise ValueError("case input changed before native invocation")
            before = counter.state["attempts"]
            if scanner in HOSTED:
                with OpenAI(api_key=key, base_url=BASE_URL, max_retries=0,
                            timeout=NATIVE_LLM[scanner]["timeout"]) as sdk:
                    async with hosted_completion(counter, sdk, lock=lock, run_id=output.name,
                            scanner_id=scanner, context_id=case["id"], model=MODEL, base_url=BASE_URL) as completion:
                        result = await run_native(scanner, Path(case["target"]), completion=completion,
                            llm_config={"model": MODEL, "api_key": key, "base_url": BASE_URL})
            else:
                result = await run_native(scanner, Path(case["target"]), source_root=MCP_SEC)
            raw_path = output / "native" / f"{index:04d}.json"
            write(raw_path, result)  # Raw native findings stay private.
            row.update({k: result[k] for k in ("status", "complete", "flagged", "any_alert", "reasons", "per_analyzer")})
            row.update(native_artifact=str(raw_path), native_artifact_sha256=sha(raw_path),
                       request_numbers=list(range(before + 1, counter.state["attempts"] + 1)),
                       measured_utc=datetime.now(timezone.utc).isoformat())
            publish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "fugu", "competitors"))
    parser.add_argument("--bindings-sha256", required=True)
    parser.add_argument("--fugu-output", type=Path, required=True)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--data-release-ref")
    parser.add_argument("--competitor-output", type=Path)
    parser.add_argument("--initialize-only", action="store_true")
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT))
    binding = check_bindings(args)
    os.umask(0o077)
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    logging.disable(logging.CRITICAL)
    # Suppress native prints/logs and provider exception bodies; evidence is JSON.
    with open(os.devnull, "w") as sink, redirect_stdout(sink), redirect_stderr(sink):
        if args.action == "competitors":
            if args.competitor_output is None:
                raise ValueError("competitor output required")
            asyncio.run(competitors(args, binding))
        else:
            from bench.full_workflow_competitive import load_engine, prepare, run_frozen
            if args.action == "fugu":
                frozen_inputs(args)
                prior = args.competitor_output / "hosted-counter/ledger.json" if args.competitor_output else None
                if prior and prior.exists() and read(prior).get("stop_reason") in STOP_PAID:
                    raise ValueError("shared provider quota/auth stop retained")
                project_dotenv()
            engine = load_engine(ENGINE)  # Exactly once, in this cold process.
            if args.action == "prepare":
                prepare(engine, ROOT / "bench/results/2026-10-05-full-workflow/cases-v2.json",
                        args.fugu_output, source_root=ROOT)
            else:
                run_frozen(engine, args.fugu_output, approved_plan_sha256=args.approved_plan_sha256,
                           data_release_ref=args.data_release_ref)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # No traceback or exception message can expose auth/native/provider text.
        print(json.dumps({"launch_status": "failed", "error_type": type(exc).__name__}))
        raise SystemExit(1) from None
