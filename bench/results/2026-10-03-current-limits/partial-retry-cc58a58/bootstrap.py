"""Exact-root bootstrap for the separately reviewed partial-case data grant."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path('/Users/antonkogun/dev/nebius_hack')
ENGINE = Path('/private/tmp/fugu-continuation-engine-cc58a58')
OUTPUT = Path('/Users/antonkogun/dev/nebius_hack/bench/results/2026-10-03-current-limits/partial-retry-cc58a58')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-release-ref', required=True)
    parser.add_argument('--approved-plan-sha256', required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    from bench import current_limits_partial_retry as mod
    plan = mod.base.read_json(OUTPUT / 'plan.json')
    mod.authenticate_release(args.data_release_ref, plan, args.approved_plan_sha256)
    common = ['--engine-root', str(ENGINE), '--output', str(OUTPUT),
              '--approved-plan-sha256', args.approved_plan_sha256,
              '--data-release-ref', args.data_release_ref]
    subprocess.run([sys.executable, '-B', '-m', 'bench.current_limits_partial_retry',
                    'preflight', *common], cwd=ROOT, check=True, timeout=90,
                   env=dict(os.environ, PYTHON_DOTENV_DISABLED='1', NEBIUS_API_KEY=''))
    from dotenv import load_dotenv
    load_dotenv(ROOT / '.env', override=False)
    return mod.main(['run', *common])

if __name__ == '__main__':
    raise SystemExit(main())
