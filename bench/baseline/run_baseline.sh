#!/bin/bash
# Baseline runner: Snyk agent-scan (v0.6.3) against the Fugu corpus.
#
# For each corpus sample:
#   1. `scan --json`  — the real verdict path. REQUIRES SNYK_TOKEN (server-side
#      analysis at api.snyk.io); we run it with SNYK_TOKEN unset to record the
#      exact auth failure per sample.
#   2. `inspect --json` — the only local (no-token) mode; produces discovery
#      output (what WOULD be sent for analysis), no verdicts.
#
# Each command is wrapped in a 120s timeout via Python (macOS has no GNU timeout).
# Raw stdout/stderr/exit-code land in bench/baseline/raw/<sample>.{scan,inspect}.*
set -u
cd "$(dirname "$0")/../.." || exit 1
RAW=bench/baseline/raw
mkdir -p "$RAW"

run_timed() {  # run_timed <out-file> <err-file> <cmd...>
  local out="$1" err="$2"; shift 2
  python3 - "$out" "$err" "$@" <<'PY'
import subprocess, sys
out, err, cmd = sys.argv[1], sys.argv[2], sys.argv[3:]
try:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    open(out, "w").write(p.stdout)
    open(err, "w").write(p.stderr)
    print(f"exit={p.returncode}")
except subprocess.TimeoutExpired as e:
    open(out, "w").write((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
    open(err, "w").write("TIMEOUT after 120s\n")
    print("exit=TIMEOUT")
PY
}

for d in corpus/*/; do
  name=$(basename "$d")
  [ -f "corpus/$name/manifest.json" ] || continue
  echo "=== $name"
  printf '%s\n' "scan:  $(run_timed "$RAW/$name.scan.out" "$RAW/$name.scan.err" \
    env -u SNYK_TOKEN uvx snyk-agent-scan@latest "corpus/$name" --json --print-errors)"
  printf '%s\n' "insp:  $(run_timed "$RAW/$name.inspect.out" "$RAW/$name.inspect.err" \
    env -u SNYK_TOKEN uvx snyk-agent-scan@latest inspect "corpus/$name" --json)"
done
echo "DONE"
