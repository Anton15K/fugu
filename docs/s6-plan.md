# S6 Composition — Implementation Plan

**Goal:** detect the *lethal trifecta* across an installed SET of extensions
(untrusted-content ingress + private-data access + egress channel, split
across ≥2 individually-clean extensions) plus cross-extension tool
shadowing. Positioning: "first shipped, evidence-backed composition-aware
auditor" (verified unoccupied in shipped tooling; cite CompoSkill arXiv
2608.16246 + Willison's lethal trifecta as concurrent research/terminology).

**Terminology for README/Devpost:** "lethal trifecta across your installed
set" (Willison), "compositional skill chain risk — a path-level property,
not a node-level property" (CompoSkill). OWASP mapping: trifecta → MCP03 +
MCP06 + LLM02 (+MCP07/MCP10 as applicable); shadowing → MCP03 (NOT MCP09).

## Phase 0 — preflight (done)

- [x] OWASP mapping corrected (e491605)
- [x] Cross-stage dedup live (subsumed echoes dropped; strong evidence never)

## Phase 1 — MVP slice (target: ~1 day of build; deadline-safe)

Zero changes to existing stages or `run_job`'s hot path.

### 1a. Capability mapper (pure functions, no LLM) — `src/fugu/pipeline/stages/composition.py`

Taxonomy per extension node: `INGRESS`, `PRIVATE-DATA`, `EGRESS`, `EXEC`
(legs) + modifiers `INJECTION-CARRIER`, `AGENT-INFLUENCE`, `DEFENSE-GAP`.
Strength from contributing finding's tier (deterministic/empirical=strong,
measured=medium, advisory=weak). Map from EXISTING signals:

| Signal (file:line) | Capability |
|---|---|
| static env_harvest / sensitive_path_access (static_scan.py:576-581) | PRIVATE-DATA strong |
| static curl_raw_ip (:573) / curl_pipe_shell (:570) | EGRESS strong (+EXEC med) |
| install_script_fetch / npm hooks / setup.py (:585-593) | EXEC strong |
| skill_injection_phrase / tool_description_injection (:597-602) | INJECTION-CARRIER |
| concealment payload families (concealment.py:102-112) | INJECTION-CARRIER strong |
| semantic findings by owasp_ids LLM01/MCP03/MCP06 | INJECTION-CARRIER weak |
| detonation canary-exfil (docker_driver.py:688) | EGRESS+PRIVATE-DATA strong |
| detonation unexpected-egress (:727) | EGRESS medium |
| harness disclose/target/sensitive/directive (harness.py:283-370) | AGENT-INFLUENCE |
| NEW ingress inventory: tool names/docs matching fetch|get|read|web|url|rss verbs (reuse `_TOOL_NAME_RE` static_scan.py:484) | INGRESS medium |

### 1b. Detectors (pure, unit-testable, deterministic)

- Trifecta: minimal 2- and 3-extension combos covering all three legs
  (distinct extensions; superset combos pruned); rank by leg-strength sum
  (+3 if ingress node is INJECTION-CARRIER/AGENT-INFLUENCE); emit ≤5.
- Shadowing: cross-extension tool-name index (normalize case + strip
  `mcp__server__` prefixes); one finding per collision group; severity
  medium (high if shadowING ext is a carrier).
- Honesty rules: bare weak co-existence with no carrier → severity low
  (hygiene note). Advisory-only combos → verdict WARN, never FAIL.
- Findings: ordinary `Finding`/`EvidenceSnippet` (stage='composition' is a
  legal StageName, types.py:24-27); one evidence snippet per leg citing the
  member's contributing finding.

### 1c. Multi-source plumbing

- `POST /audits` accepts optional `sources: [{ref, label}]` (2..8;
  validation reuses local-path + git checks, app.py:165-191).
- New `run_composition_job` (sibling of run_job, jobs.py): per source →
  child job via EXISTING `run_job` at depth=standard; evidence attribution
  `ext/<slug>/…` + `meta.ext`; sidecar ledger; composition stage runs last
  on the parent; parent publishes per-child log events (child_job_id).
- Single-source behavior byte-identical → all 211 tests untouched.
- UI: `STAGE_ORDER` re-adds composition ONLY on multi-source jobs (member
  strip + Combination view in Scorecard: chain ingress→private→egress with
  every node green, chain red).

### 1d. Corpus + tests — `corpus/composition/` (attack + controls)

- ATTACK sets: (a) canonical trifecta web-digest + notes-lookup +
  status-poster; (b) shuffled order; (c) dilution (+2 irrelevant); (d)
  shadow-combo (filesystem + filesystem-enhanced + help-docs).
- BENIGN controls (the FP guards): ingress+egress NO private-data (must
  stay clean); private+egress no ingress; single-ext trifecta + clean
  neighbors (must NOT report as cross-ext).
- Members must be individually clean — hard precondition, loader enforces.
- ~15 new tests: mapper per producer, distinctness, minimality, superset
  pruning, degradation, shadow grouping, endpoint e2e, 50-node <1s perf.

### 1e. Eval + publication

- loader.py branch for set.json; set-detection-rate + set-FP reported
  SEPARATELY from per-extension metrics; composition tier stays advisory
  until numbers stable across ≥2 runs, then upgrade to measured.

## Phase 2 — integration polish (2-3 days, only if Phase 1 lands early)

- `AuditJob.sources` field + unified fan-out in run_job (tech-lead change;
  types.py is READ-ONLY for workstreams).
- Semantic capability pass: judge emits structured tool_surface JSON block.
- Embedding-based shadow aliases (stretch), per-ext metrics breakdown,
  verdict coverage caveat, UI graph view.

## Phase 3 — runtime chaining (stretch / post-demo)

- Two-extension detonation: ingress content fed to a harness agent with B+C
  mounted → observed cross-extension flow (converts portfolio risk into
  empirical evidence). Needs chamber work, not new external APIs.

## What we need from outside — NOTHING for Phase 1-2

All inputs exist: existing findings + tool inventories (deterministic),
Nemotron via Token Factory (already wired), Docker chamber (deployed), OSV +
Tavily (already integrated). Optional, non-blocking:
1. Nebius Sandboxes beta approval (requested Sep 19) — nice judging story
   for detonation, not required for S6.
2. If we want to benchmark against CompoSkill-Bench (HF) later — just data
   download, no API key.

## Timeline (today is Sep 21; deadline Oct 30)

- Sep 22-23: Phase 1 build + tests + local demo
- Sep 24: eval run, publish numbers, deploy to VM
- Sep 25+: README/video work with S6 in the demo reel
- Slack: ~5 weeks of buffer for Phase 2/3 polish
