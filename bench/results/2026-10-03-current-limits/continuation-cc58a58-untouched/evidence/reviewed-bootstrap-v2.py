"""Run only under the separately authenticated research.security data lease."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path("/Users/antonkogun/dev/nebius_hack")
ENGINE = Path("/tmp/fugu-continuation-engine-cc58a58")
PREPARED = ROOT / "bench/results/2026-10-03-current-limits/continuation-offline/prepared-v3"
PLAN_HASH = "ea8cff37184b4dd7efe06d3494643462298b398bebcb471d50ce0d6d76f32835"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-release-ref", required=True)
    parser.add_argument("--preflight-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    sys.path[:0] = [str(ROOT), str(ROOT / "bench")]
    import current_limits_continuation as continuation

    plan = continuation.read_json(PREPARED / "plan.json")
    continuation.authenticate_release(args.data_release_ref, plan, PLAN_HASH)
    receipt = {"plan_sha256": PLAN_HASH, "case_count": 27, "engine_files": 37,
               "provider_requests": 0, "credential_access": False}
    if args.preflight_only:
        # This short-lived process loads the engine and validates inputs only.
        # Neither Settings nor a provider client is constructed.
        engine = continuation.base.load_engine(ENGINE)
        cases = continuation.validate_plan(engine, plan, PREPARED,
                                            parent=continuation.load_parent())
        if len(cases["cases"]) != receipt["case_count"] or len(plan["engine"]["hashes"]) != 37:
            raise continuation.EvidenceError("preflight dimensions changed")
        print(json.dumps(receipt, sort_keys=True))
        return 0

    # Keep the live process cold: load_engine deliberately rejects already
    # imported fugu modules. An isolated child checks bindings before .env use.
    child_env = dict(os.environ, PYTHON_DOTENV_DISABLED="1")
    checked = subprocess.run([
        sys.executable, "-B", str(Path(__file__).resolve()), "--preflight-only",
        "--data-release-ref", args.data_release_ref,
    ], cwd=ROOT, env=child_env, capture_output=True, text=True, check=True, timeout=120)
    if json.loads(checked.stdout) != receipt:
        raise continuation.EvidenceError("isolated preflight receipt changed")
    if any(name == "fugu" or name.startswith("fugu.") for name in sys.modules):
        raise continuation.EvidenceError("live process must remain cold before main")

    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
    # main authenticates again, loads the frozen engine once, and revalidates
    # every binding before Settings/client/journal dispatch.
    return continuation.main([
        "run", "--engine-root", str(ENGINE), "--prepared-dir", str(PREPARED),
        "--approved-plan-sha256", PLAN_HASH, "--data-release-ref", args.data_release_ref,
    ])


if __name__ == "__main__":
    raise SystemExit(main())
