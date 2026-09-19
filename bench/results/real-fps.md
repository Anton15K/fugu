# Real-set false-positive log (bench/results/real-fps.md)

Static benchmark (S0 concealment + S1 static) over the external-validity
real set, `env -u NEBIUS_API_KEY uv run --no-sync python -m bench.run_bench`.

Run: 2026-09-19 · real n=76 (anthropic-skills 18 · superpowers 15 ·
office-skills 25 · skillsdirectory 18)

## Result

**0/76 benign real skills flagged medium+ → benign-FP rate 0%.**

Verified independently per sample: zero findings at ANY severity (not even
info/low) across all 76 samples; both stages report `ok=true` on every
sample (no silent skips). Same run: crafted corpus 6/6 detection, 0/4 FP —
the scanner demonstrably fires on real attacks, so 0/76 is a true quiet
result, not a harness failure.

## Diagnosis table (one line per medium+ flagged real skill)

| Skill | Rule | Verdict | Reason |
|---|---|---|---|
| — (none flagged) | — | — | — |

## Notes for the lead

- `anthropics/skills` `canvas-design` is now skipped by fetch (5.5 MB >
  2 MB per-skill cap); the earlier 19-sample set included it and it was
  also unflagged, so n went 19 → 18 for that source.
- Field contrast stands: MCPZoo reports 96.89% of registry servers flagged
  by existing scanners with <50% true-positive rate; Fugu's static stage
  flags 0% of this 76-skill uncurated public set. Caveat: this set is
  prose-heavy skills, not MCP server code — a server-dir source (npm/TS)
  would stress different S1 rules and is a natural next expansion.
