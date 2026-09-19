# Baseline comparison: Snyk agent-scan vs Fugu S0+S1 (static) on the Fugu corpus

**Date:** 2026-09-19 · **agent-scan:** v0.6.3 (`uvx snyk-agent-scan@latest`)
**Fugu:** S0 concealment + S1 static via `fugu.pipeline.run_audit(target, include_detonation=False,
include_semantic=False, include_harness=False, include_reputation=False)` with `NEBIUS_API_KEY`
unset (deterministic tiers only). Full write-up of the agent-scan blocker: `BLOCKED.md`.

## Verdict table

`agent-scan verdict` = any finding from `scan` on the sample dir. All 10 runs were blocked by
the mandatory `SNYK_TOKEN` (server-side analysis) — exit 1, no verdict, identical for malicious
and benign samples. The `inspect`-only column shows what its *local discovery* found (no
risk scoring exists in that mode).

| sample | kind | agent-scan verdict | agent-scan `inspect` discovery | fugu static (S0+S1) verdict | notes |
| --- | --- | --- | --- | --- | --- |
| 01-hidden-instructions-skill | malicious | **BLOCKED** (SNYK_TOKEN required; exit 1) | skill `daily-notes` found; SKILL.md+manifest uploaded-payload | **FLAG** — LLM01, MCP06 (1 finding) | injection prose visible in the payload agent-scan would upload |
| 02-unicode-smuggled-skill | malicious | **BLOCKED** (same) | skill `weather-helper` found; 97 invisible Tags chars preserved verbatim in payload | **FLAG** — LLM01, MCP03 (concealment) | whether their server-side analyzer decodes Tags-block is unknowable without a token |
| 03-env-harvest-installer | malicious | **BLOCKED** (same) | nothing (no SKILL.md / mcp.json) | **FLAG** — MCP01, LLM02, MCP05, LLM01 (3) | raw `install.sh` is not a component agent-scan discovers |
| 04-credential-reader | malicious | **BLOCKED** (same) | nothing | **FLAG** — MCP01, LLM02 (2) | bare `skill.py`, no SKILL.md wrapper |
| 05-obfuscated-payload | malicious | **BLOCKED** (same) | nothing | **FLAG** — MCP05, LLM01, MCP01, LLM02 (3) | `eval(base64...)` blob |
| 06-rugpull-pair | malicious | **BLOCKED** (same) | nothing | **FLAG** — MCP03, LLM01 + MCP01, LLM02, MCP06 (2) | v2 `server.py` needs an mcp.json entry for agent-scan to ever see it |
| 07-clean-skill | benign | **BLOCKED** (same) | skill `csv-tidy` found | **clean** (0 findings) | |
| 08-clean-mcp-server | benign | **BLOCKED** (same) | nothing | **clean** (0) | |
| 09-clean-installer | benign | **BLOCKED** (same) | nothing | **clean** (0) | |
| 10-clean-node-skill | benign | **BLOCKED** (same) | nothing | **clean** (0) | |

Fugu static raw per-sample detail: `fugu_static.json`; agent-scan raw outputs: `raw/`.

## Bottom line

- **Fugu S0+S1:** 6/6 malicious flagged with full expected-OWASP coverage, 4/4 benign clean
  (matches the corpus contract in `corpus/README.md`).
- **agent-scan v0.6.3:** 0/10 verdicts obtainable — every verdict path (`scan`, `--ci`, `evo`,
  README demo) uploads discovered content to `api.snyk.io` and hard-fails without `SNYK_TOKEN`.
  Additionally, even with a token its *directory* discovery would only surface components in
  3/10 samples (those containing a `SKILL.md`); samples 03–06, 08–10 have no SKILL.md and no
  mcp.json, so its local discovery stage finds nothing to score for them.
- **Coverage note (from `inspect`, token-free):** where agent-scan does discover a skill
  (01, 02, 07) it captures file content verbatim — including sample 02's invisible
  Unicode-Tags payload — so detection there depends entirely on the unavailable server-side
  analyzer.

## Caveats

- agent-scan version pinned by `@latest` on 2026-09-19 = 0.6.3; output format is explicitly
  experimental per their README.
- Modes exercised: `scan` (human + `--json`) and `inspect` (human + `--json`), per-sample,
  120 s timeout each. Not exercised: `evo`, `guard`, enterprise push-key mode (all also
  token-gated).
- Fugu side is static-only by design here (no LLM, no detonation), matching the eval
  harness's fast path.
