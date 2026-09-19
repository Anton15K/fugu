# BLOCKED: Snyk agent-scan baseline requires a Snyk API token for every verdict

**Date:** 2026-09-19 · **Tool:** `snyk-agent-scan` **v0.6.3** (via `uvx snyk-agent-scan@latest`, Apache-2.0, PyPI)
**Corpus:** 10 samples (6 malicious, 4 benign) under `corpus/` — see `corpus/README.md`.

## TL;DR

Every path that produces a *verdict* (`scan`, `--ci`, `evo`, the README demo) sends the
discovered skill/server content to Snyk's server-side analysis endpoint
(`https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10`) and **hard-requires
the `SNYK_TOKEN` environment variable** (a Snyk account API token). Without it the CLI exits 1
before analysis. There is **no local/offline verdict mode**. We do not have a Snyk account/token
in this offline environment, so no verdicts could be produced. No results were fabricated.

## Evidence (exact commands + outputs)

### 1. Tool installs and runs — the blocker is auth, not availability

```
$ uvx snyk-agent-scan@latest --help
Snyk Agent Scan: Security scanner for Model Context Protocol servers, agents, skills and tools
Commands:
  scan      Scan one or more MCP config files [default]
  inspect   Print descriptions of tools, prompts, and resources without verification
  ...
```

Version confirmed from the installed dist-info: `snyk_agent_scan-0.6.3.dist-info` (the CLI has
no `--version` flag; it prints `Snyk Agent Scan v0.6.3` at startup).

### 2. `scan` on every corpus sample: token wall, exit 1, no findings

Per-sample raw outputs in `raw/<sample>.scan.{out,err}` (all 10 identical):

```
$ env -u SNYK_TOKEN uvx snyk-agent-scan@latest corpus/01-hidden-instructions-skill
Snyk Agent Scan v0.6.3

To use Agent Scan, set the SNYK_TOKEN environment variable. To get a token, go
to https://app.snyk.io/account (API Token -> KEY -> click to show).
$ echo $?
1
```

Note: with `--json` the message is swallowed (`suppress_stdout()` wraps `run_scan` in JSON mode)
and the process just exits 1 with empty stdout/stderr — verified during the run; the
human-readable mode above is the reproducible evidence.

### 3. Invalid token proves the wall is server-side auth (not a local check)

```
$ SNYK_TOKEN=invalid-token-for-auth-wall-proof uvx snyk-agent-scan@latest \
    corpus/01-hidden-instructions-skill
Snyk Agent Scan v0.6.3

● Scanning corpus ● [X007 info]: Unauthorized. Please check your SNYK_TOKEN
environment variable or your push key. no mcp servers or skills found
```

(`raw/authwall-invalid-token.demo.out`. The X007 code fires after the HTTPS call to
`api.snyk.io` is rejected 401 — i.e. the CLI had already discovered the skill locally and tried
to upload it for analysis.)

### 4. Source-level confirmation (installed v0.6.3, `agent_scan/verify_api.py`)

```python
snyk_token = os.getenv("SNYK_TOKEN")
if push_key:
    ...  # enterprise MDM push-key mode
elif snyk_token:
    analysis_url = analysis_url.replace(..., "/hidden/mcp-scan/cli/analysis-machine")
    headers["Authorization"] = f"token {snyk_token}"
elif os.getenv("SNYK_CLI_USE", "false").lower() == "true":
    ...  # Snyk CLI proxy auth mode
else:
    rich.print("[bold red]To use Agent Scan, set the SNYK_TOKEN environment variable. ...")
    raise SnykTokenError("SNYK_TOKEN environment variable not set")
```

There is no code path that scores risks locally: the `ScanResponse` model (risk indexes per
skill/server) is only ever populated from the server's JSON reply. The bundled
`detect-secrets` dependency is used **only to redact secrets before upload**
(`agent_scan/redact.py`), not to emit findings.

### 5. What DOES work without a token: `inspect` (discovery only, no verdicts)

```
$ env -u SNYK_TOKEN uvx snyk-agent-scan@latest inspect corpus/01-hidden-instructions-skill --json
```

exits 0 and dumps the exact payload that *would* be uploaded for analysis
(`raw/<sample>.inspect.out`). This proves the tool sees our corpus content locally — but it
carries zero risk assessment (no risk_indexes, no pass/fail), so it cannot serve as a baseline
verdict. Per-sample discovery outcome:

| sample | discovered by `inspect` |
| --- | --- |
| 01-hidden-instructions-skill | skill `daily-notes` (SKILL.md + manifest.json uploaded) |
| 02-unicode-smuggled-skill | skill `weather-helper`; all 97 invisible Tags-block chars preserved in payload |
| 03…06, 08…10 | **nothing** — no SKILL.md and no mcp.json in those dirs → zero components, so even with a token the server would have nothing to score for 7/10 samples |
| 07-clean-skill | skill `csv-tidy` |

Directory-path scanning works (`client_to_inspect_from_path` treats a dir with SKILL.md as a
skill root; otherwise as a skills-dir / mcp-config path), but verdicts still go through the API.

### 6. Their documented demo hits the same wall

README "Demo" section: clone the repo, write an `mcp.json` pointing at
`demoserver/server.py`, run `uvx snyk-agent-scan@latest scan mcp.json`. That is still a
`scan` → same `SNYK_TOKEN` requirement (verified: `scan` is the only analysis entrypoint;
`inspect`/`guard` are the only token-free subcommands, and neither yields verdicts). Running it
would execute their demo MCP server locally AND require the token — no output shape beyond the
X007 auth error is obtainable without an account.

## Minimal alternative baselines (proposals, not executed)

1. **With a Snyk account (recommended if any team member has one):** `export SNYK_TOKEN=...`
   then re-run `bash bench/baseline/run_baseline.sh` (it already loops `scan` per sample with a
   120 s timeout and saves raw output). The one-line change needed: the loop currently unsets
   `SNYK_TOKEN`; drop the `env -u` once a real token exists. Caveats: content of the corpus is
   uploaded to Snyk (fine — synthetic), and 7/10 samples have no SKILL.md/mcp.json so agent-scan
   will report "no mcp servers or skills found" for them regardless — see assumption A2.
2. **Token-free structural baseline (available today):** use `inspect --json` output as a
   "discovery parity" baseline — it shows exactly which corpus components agent-scan's local
   discovery would submit for analysis (3/10 samples), which is itself an honest coverage
   datapoint against our S0+S1 (10/10). Recorded in `raw/*.inspect.out`.
3. **Different OSS baseline tool:** e.g. `mcpscan`/`mcp-security-audit`-style local scanners if
   the lead wants a runnable third-party comparator this week; out of scope for this workstream.

## Honest caveats

- Version tested: **0.6.3** exactly (`uvx snyk-agent-scan@latest` on 2026-09-19).
- Modes exercised: `scan` (default + `--json`), `inspect` (default + `--json`). Not exercised:
  `evo`, `guard` (hooks), enterprise `--push-key` mode — all also analysis/verdict paths gated
  on credentials we don't have.
- The v0.5.x line (`snyk-agent-scan@0.5.17`) has the same architecture (analysis is
  server-side); the README marks it planned-for-deprecation, so it was not benchmarked.
- Even with a token, a per-sample run would upload our synthetic corpus content to Snyk and be
  rate-limited (429 "Daily usage limit" handling exists in the client).
