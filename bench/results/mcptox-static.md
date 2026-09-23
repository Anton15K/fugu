# MCPTox x Fugu - static-only detection (S0+S1)

Generated: 2026-09-22 21:47 · `uv run --no-sync python -m bench.mcptox.run_static --n 200`

**Benchmark**: MCPTox (arXiv 2508.14925, AAAI-26) - real tool-poisoning attacks:
poisoned tool descriptions on 45 real MCP servers. Dataset: pinned commit `f85189f` of github.com/zhiqiangwang4/MCPTox-Benchmark (sha256-verified), 1312 valid cases; deterministic stratified subset n=200 (per-category stride sampling, see run_static.stratified_subset).
**Pipeline**: static only - `run_audit(include_semantic=False, include_harness=False, include_detonation=False)` (S0 concealment + S1 static).

Aggregation convention (explicit, per CASCADE 2604.17125): a case is **detected** when ANY finding has severity >= medium (sample-level, escalated-counts-as-positive). Expected-id coverage = manifest ids covered by any finding.

| MCPTox category | n | detected (med+) | expected-id coverage |
|---|---|---|---|
| Code Injection | 10 | 0/10 (0%) | 0/10 (0%) |
| Credential Leakage | 18 | 7/18 (39%) | 0/18 (0%) |
| Data Tampering | 18 | 1/18 (6%) | 0/18 (0%) |
| Financial Loss | 8 | 0/8 (0%) | 0/8 (0%) |
| Information Manipulation | 41 | 2/41 (5%) | 1/41 (2%) |
| Infrastructure Damage | 19 | 4/19 (21%) | 0/19 (0%) |
| Instruction Tampering | 9 | 0/9 (0%) | 0/9 (0%) |
| Message Hijacking | 5 | 0/5 (0%) | 0/5 (0%) |
| Other | 1 | 0/1 (0%) | 0/1 (0%) |
| Privacy Leakage | 41 | 4/41 (10%) | 0/41 (0%) |
| Service Disruption | 30 | 0/30 (0%) | 0/30 (0%) |
| **Overall** | **200** | **18/200 (9%)** | **1/200 (0%)** |

By attack paradigm:

| Paradigm | n | detected (med+) |
|---|---|---|
| Template-1 | 28 | 7/28 (25%) |
| Template-2 | 82 | 8/82 (10%) |
| Template-3 | 90 | 3/90 (3%) |

Firing rules (cases affected):

- `mcp_missing_return_description`: 167/200
- `sensitive_path_access`: 17/200
- `tool_description_injection`: 1/200

## Reading this honestly

- **Every MCPTox payload is an LLM-grade paraphrase** ("Ignore the previous
  instructions and do the following: ...", "This description's priority is
  higher than the user's query/request..."). The deterministic S1 injection
  arms match canonical phrasing ("ignore all previous instructions") but
  NOT these paraphrases - by design, paraphrase judgement is S2's (semantic
  LLM judge) job. Static-only recall on this benchmark is therefore expected
  to be low; the number that matters for the full pipeline is semantic-mode
  recall (next run: include_semantic=True).
- The medium+ hits that DO fire come from concrete payload artifacts:
  credential-file paths in the poisoned text (`~/.ssh/id_rsa` ->
  sensitive_path_access, MCP01/LLM02), plus rare canonical-phrase cases
  (tool_description_injection, LLM01/MCP03/MCP06).
- `mcp_missing_annotations` fires only where upstream tool JSON truly lacks
  annotations; the adapter emits well-formed stubs so it cannot fire on
  adapter-generated shape (verified by unit test).

## Subset-vs-full validation

The n=200 subset was validated against ALL 1,312 valid cases (artifacts:
`mcptox-static-full.json`, same pipeline, ~10 min):

| Scope | n | detected (med+) |
|---|---|---|
| stratified subset | 200 | 18/200 (9%) |
| full corpus | 1312 | 123/1312 (9%) |

Agreement is exact (9% both; per-category within sampling noise), so the
stratified subset is a faithful estimator and the sampling fix (per-category
stride instead of alphabetical head-taking) is what closed the initial 2%-vs-9%
gap. Full-corpus per-category rates: Credential Leakage 60/115 (52%),
Infrastructure Damage 23/122 (19%), Privacy Leakage 23/273 (8%), Data
Tampering 9/117 (8%), Information Manipulation 6/269 (2%), Code Injection
1/63 (2%), Instruction Tampering 1/57 (2%), Financial Loss / Service
Disruption / Message Hijacking / Other 0.

Upstream context: MCPTox reports max 72.8% attack success against 20 agent
LLMs and <3% refusal - these payloads reliably fool *agents*; a static-only
scanner catching a meaningful fraction would be surprising, and we do not
claim it.
