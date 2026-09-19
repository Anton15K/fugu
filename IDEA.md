# IDEA — Agentic security auditor for agent extensions

> Decided direction (2026-09-19). Concept proposed by Anton, pressure-tested against prior art and hackathon rules.
> Status: direction agreed; final track + name + effort level pending (see Open questions).

## One-liner

An agentic security pipeline that audits third-party agent extensions — **skills (SKILL.md), MCP servers, plugins** — before you install them and re-verifies them afterwards, mapping every finding to **OWASP** categories. Static analysis + LLM-as-judge (Nemotron on Token Factory) + **live detonation in Nebius Sandboxes** with canary credentials and egress capture. Output: an evidence-backed, OWASP-mapped scorecard — not a vibes-based "looks fine".

Story hook: third-party agent components are **fugu** — delicious, occasionally lethal, and currently eaten raw by millions of agents with zero inspection. Fugu chefs need a license; your agent's supply chain deserves the same.

## Why this idea (critique results)

### Strengths
1. **Real, urgent problem.** MCP/skill ecosystems exploding; rug pulls, tool poisoning, poisoned SKILL.md instructions are documented attack classes (Invariant Labs research; 30+ CVEs against MCP components in Jan–Feb 2026; Unit 42 measured 78.3% attack success with 5 servers connected). Nobody audits at *install time*.
2. **Literal Track 1 match.** Track text: "agents that write, run, and test code in Token Factory Sandboxes" — our agent runs and tests untrusted plugin code in Sandboxes. Stage-1 fit is a slam dunk, and deep Sandbox usage is exactly what "effective Token Factory use" rewards.
3. **Great demo material.** Show a clean-looking skill exfiltrating a canary AWS key to a webhook — caught live in the detonation chamber. Memorable, visual, narratable in <3 min.
4. **Model routing has a real job.** Nano = bulk static triage, Super = semantic audit of descriptions/SKILL.md, Ultra = adversarial adjudication of ambiguous cases. Not routing for routing's sake.
4b. **Privacy story:** static scanners ship your tool descriptions to Snyk's cloud; ours runs entirely on Nemotron via Token Factory — nothing leaves your Nebius account.
5. **Tavily bonus eligibility with an honest use.** Runtime reputation lookups: package/author history, typosquat checks, CVE search.
6. **Full-stack Nebius story.** Analysis on Nemotron via Token Factory, detonation in Sandboxes, deploy on AI Cloud — one vendor narrative for the README/video.

### Honest risks
1. **Prior art exists and is mature**: Invariant's mcp-scan (absorbed by Snyk as `agent-scan`, ~2.5k stars) already scans MCP servers AND agent skills statically, does hash-pinning against rug pulls, has a live proxy mode. Also MCPhound, VIPER-MCP (106 CVEs found across 39,884 repos). **Differentiation must be sharp** (below) or judges who know the space will dock "Quality of Idea".
2. **Prompt-injection detection is probabilistic.** Never sell "blocks all jailbreaks"; sell *evidence-based risk scoring* + defense-in-depth. Honest framing is also better for the feedback prize.
2b. **Self-hosted agents like Hermes ship a skills library** (see this repo's own environment) — meaning ecosystem momentum is real, but also that "audit your skills" is becoming routine hygiene, not novelty. Differentiation (dynamic detonation) carries the idea score.
3. ~~**Dynamic detonation is the hard 20%.**~~ **DE-RISKED by spike 001 (2026-09-19)**: local Docker detonation chamber validated all three egress vectors (HTTPS body via MITM proxy, DNS hex-exfil via our resolver, plain HTTP) with canary credentials — evidence archived in `spikes/001-canary-egress/`. Remaining unknowns are Sandboxes-driver-specific (env injection + collectors inside their network), not mechanism-level. Key lessons already baked in: mitmproxy needs `connection_strategy=lazy`; log on `request` hook, not `response` (dead C2 domains are the norm).
4. **Scope creep is the real enemy.** "Verify security of everything" is a company, not a hackathon. MVP discipline below is non-negotiable.

### Prior art (verified 2026-09-19)
- **Snyk Agent Scan** (ex-Invariant mcp-scan, 3,066★, Apache-2.0): auto-discovers agent configs (Claude, Cursor, Windsurf, Copilot, Gemini CLI…), reads MCP tool descriptions + skill files, classifies via local checks **+ Snyk's cloud API** (your skill content leaves your machine). 14 risk categories, ALL text-classification: prompt injection, dangerous words, untrusted content, private data, destructive capabilities, credential handling, secret detection. Hash-pinning vs rug pulls. Background/MDM mode → Snyk Evo. **Never executes the extension under instrumentation, never observes egress, never tests a live agent with the extension mounted.**
- MCPhound, VIPER-MCP (106 CVEs across 39,884 repos): static analysis research.
- glyphguard / unsmuggle (npm): Unicode-smuggling normalize/decode — proves the deterministic layer is a solved-problem pattern we can implement in Python; neither is an agent-supply-chain scanner.
- **MCPTox benchmark** (arxiv 2508.14925): 1,312 malicious tool-poisoning cases over 45 real MCP servers, 11 risk categories; agents refuse <3% of attacks. Our eval corpus + the "why now" stat. Snyk's own research: 36% of public skills contain prompt-injection techniques.

### Differentiation — REFINED after competitive scan (2026-09-19, see docs/strategy-competitive.md)
Dynamic analysis of MCP servers is no longer unique (SandScope SCORED'26, Meta MCPGuard-Dynamic — academic/defense-proxy shaped). Our defensible claim: **execution-based canary detonation for agent SKILLS + integrated judge/harness pipeline** — canary tokens, deterministic Unicode decoding, LLM-judge correlation, measured A/B harness, skills AND MCP coverage. No competitor replicates the combination. AgentSec (static A–F skill grades) validates the deliverable format; Snyk ToxicSkills validates the market; neither detonates.
1. **Egress-verified detonation (Stage 3).** Execute the extension in a Nebius Sandbox with canary env vars (fake AWS key, fake GitHub token, canary .netrc), all traffic forced through our collecting proxy (HTTP(S)_PROXY + DNS capture — DNS exfil is the classic bypass), fs snapshot diff, Sandboxes resource metrics. Fail condition is near-zero-FP: any canary substring in ANY captured byte (body, header, DNS label, file write) = confirmed exfil with forensic trail. Git-like branching: fork pre-install checkpoint, detonate triggers in parallel (install hook, import-time, first call), rerun with different canaries to catch conditional/delayed payloads.
2. **Deterministic concealment layer (Stage 0).** Unicode Tags U+E0000–U+E007F, zero-width, bidi Trojan Source, variation selectors, homoglyphs: detect + DECODE the hidden payload as evidence. Pure codepoint math — a theorem, not a prediction. ("This text contains zero hidden codepoints" is provably true for a defined codepoint set.)
3. **Empirical jailbreak test (Stage 4) — the star.** Mount the extension in a harness agent (Nemotron on Token Factory), fire a red-team probe battery (adapted from MCPTox + custom), run identical probes with extension ABSENT vs MOUNTED, diff trajectories → behavioral poisoning score. "Does this extension corrupt an agent?" becomes a measurement, not a vibe.
4. **Cross-extension lethal trifecta.** Compose capability analysis across the user's ACTUAL installed set: individually-clean extensions that together form untrusted-content + private-data + exfil-channel (trifecta is additive across extensions). Also say-vs-do differential: declared intent vs observed behavior, judged by LLM on Stage-3 telemetry (research shows descriptions misrepresent behavior pervasively — arxiv 2602.18914).

### The honest "~100% coverage" answer — tiered guarantees
Prompt injection has no grammar separating instruction from data → no escaping primitive → **nobody** can claim 100% detection of the general class. Instead we publish tiers:
1. **Deterministic** (true 100% for defined codepoint sets) — concealment layer
2. **Measured recall** — whole stack scored against MCPTox + crafted corpus; per-category precision/recall + confusion matrix published in the report AND README (no scanner publishes measured coverage today)
3. **Empirical evidence** — canary exfil (binary signal), harness A/B delta
4. **Advisory** — all LLM-judged findings, explicitly labeled probabilistic

Pitch: **"We don't promise safety. We produce evidence — with published coverage numbers."**
Privacy pitch: analysis runs on Nemotron in YOUR Nebius account; nothing shipped to a third-party cloud (agent-scan sends skill content to Snyk).

## Architecture

```
Input (git URL / zip / npm|PyPI id / MCP config / skills dir)
  │
  ├─ Stage 0 CONCEALMENT (local, deterministic) ── Unicode Tags / zero-width /
  │   bidi / variation-selector / homoglyph scan + DECODE hidden payloads;
  │   normalized-copy diff (what changed after normalization is itself a finding)
  │
  ├─ Stage 1 STATIC (local, fast, free) ── secrets regex, dangerous patterns
  │   (curl|wget to raw IPs, base64 blobs, ~/.ssh & ~/.aws access, env harvesting,
  │   install-scripts, obfuscation), dependency risk (typosquats, install hooks)
  │
  ├─ Stage 2 SEMANTIC (Token Factory, routed) ── LLM-as-judge over SKILL.md,
  │   tool descriptions, README vs actual code behavior; OWASP checklist-driven
  │   (MCP01–MCP10 + LLM01/02/03/06); Nano triage → Super audit → Ultra adjudication;
  │   input = raw + normalized + decoded-smuggled views
  │
  ├─ Stage 3 DYNAMIC DETONATION (Sandboxes) ── import OCI image, rsync extension,
  │   run install/hooks/invocation with canary env vars, egress proxy + DNS capture,
  │   fs snapshots, resource metrics; branch per trigger; rerun with fresh canaries
  │   (conditional-payload detection); output = telemetry for say-vs-do diff
  │
  ├─ Stage 4 HARNESS SIMULATION (Token Factory) ── probe battery (MCPTox-adapted
  │   + custom) against a Nemotron harness agent, extension ABSENT vs MOUNTED,
  │   trajectory diff → behavioral poisoning score (MCP06/LLM01, measured)
  │
  ├─ Stage 5 REPUTATION (Tavily) ── author history, package age/downloads,
  │   CVE/advisory search, community reports
  │
  ├─ COMPOSITION ── cross-extension lethal-trifecta analysis over the user's
  │  actual installed set; tool-name shadowing (MCP09)
  │
  └─ VERDICT ── OWASP-mapped scorecard, tiered confidence (deterministic /
      measured / empirical / advisory), evidence snippets, pass/warn/fail,
      SARIF + HTML export, hash-pinned snapshot + embedding diff for rug-pull re-checks
```

Runtime component ("don't corrupt me *during* coding"): CLI `fugu verify` re-hashes + embedding-diffs installed extensions vs pinned snapshot on every session start / reconnect → flags drift. (Live traffic proxy = v2, cut from MVP.)

## MVP scope

**MUST**
- [ ] Inputs: local skills folder, git URL, MCP server config (stdio command)
- [ ] Stages 0–3 + verdict report (5 = Tavily, cheap, keep; 4 = harness sim, minimal probe set)
- [ ] Stage 4: **red/blue/verifier harness** (drift D1, docs/strategy-arxiv-drift.md) — red Nemotron generates recorded probes, blue = agent w/ extension mounted, verifier diffs; canary env during runs
- [ ] **Eval honesty pack** (D2): crafted-vs-real split, explicit aggregation convention, ~50-alert manual validation subset
- [ ] S1 additions (D3): missing safety annotations, smell-lite checks; Detonation: non-start = evidence class (D5)
- [ ] 8–10 crafted sample corpus: hidden SKILL.md instructions, env-harvest install script, tool-poisoned description, rug-pull pair, typosquat dep, shadowing pair, invisible-unicode payload, delayed/conditional exfil
- [ ] React UI: submit → live pipeline view → OWASP scorecard w/ evidence + tiered-confidence labels
- [ ] CLI parity: `fugu audit <path|url>`
- [ ] Dogfood: run it on our own repo + a real public skills collection

**SHOULD** — rug-pull re-verify CLI, SARIF/HTML export, embedding-diff of tool defs
**CUT (v2)** — live MCP traffic proxy, CI/GitHub Action, browser extension, custom policies, batch/enterprise

## OWASP mapping (checklist drives Stage 2)

| OWASP category | Our check | Stage |
|---|---|---|
| MCP01 Token mismanagement / secrets | secrets in configs, canary-token exfil | S1+S3 |
| MCP02 Privilege escalation / scope creep | requested scopes vs declared purpose | S2 |
| MCP03 Tool poisoning | injection patterns in descriptions; behavior-vs-description diff | S2+S3 |
| MCP04 Supply chain / rug pull | dep typosquats, hash-pin drift, version diff | S1+S4+pin |
| MCP04B Rug pull detection | hash-pin + embedding diff on re-verify | pin |
| MCP05 Command injection | shell/eval sinks w/ attacker-controlled input | S1+S3 |
| MCP06 Intent flow subversion | hijack instructions ("ignore previous", "always call X first") | S2 |
| MCP07 AuthN/AuthZ gaps | unauth'd dangerous tools | S2 |
| MCP08 Audit/telemetry gaps | report as informational | S2 |
| MCP09 Shadow servers | cross-extension tool shadowing | S2 |
| MCP10 Context over-sharing | excessive context ingestion | S2 |
| LLM01 Prompt injection | adversarial red-team prompts against judged extension | S2+S3 |
| LLM02 Sensitive info disclosure | canary exfil, PII access patterns | S3 |
| LLM03 Supply chain | dep risk, provenance | S1+S4 |
| LLM06 Excessive agency | destructive ops w/o confirmation | S2 |

(OWASP MCP Top 10 is v0.1/beta — cite it + the official OWASP LLM Top 10 2025; "based on OWASP" is then literally true.)

## Stack (decision pending user confirm)

- **Keep**: Python 3.11 + uv, FastAPI, OpenAI SDK → Token Factory, `model_router.py`, pytest
- **Sandbox**: `contree-cli` (PyPI) or REST (`https://api.tokenfactory.nebius.com/sandboxes`; `NEBIUS_API_KEY` works as `CONTREE_TOKEN`, needs `NEBIUS_AI_PROJECT` id) — day-1 spike
- **Sandbox access**: beta — request drafted at `docs/sandbox-access-request.md` → send to `contree@nebius.com` (or Discord). Free during beta (per docs). Python SDK exists: `contree-sdk` + `contree_client.httpx` (async/sync), see `sandboxes/sdk/python_sdk/` docs; 7,000+ preloaded SWE environments (SWE-bench Verified, SWE-rebench) — useful later for eval corpus hosting
- **Models**: Nano = triage/bulk, `nemotron-3-super-120b-a12b` = semantic audit, `nemotron-3-ultra-550b` = adjudication; `Qwen3-Embedding-8B` = tool-def drift diff
- **Flyaway demo**: cheap VPS (Hetzner ~€5/mo) or Fly.io; demo must live until judging ends Dec 15
- **Frontend**: React + Vite + TS + Tailwind; pipeline + scorecard views
- **Storage**: SQLite (reports, pinned snapshots)
- **Deploy**: container on Fly.io/Render (runtime Token Factory calls satisfy the core requirement; optional Nebius AI Cloud flourish)
- **Tavily**: reputation stage (real runtime call → $3k bonus eligibility)

## Names (pick later, don't bikeshed now)

- **Fugu** — poison-taster story, short, CLI-friendly (`fugu audit ./skill`)
- Canary — the detonation metaphor
- Quarantine / Cordon / Taster

## Open questions

- [ ] Final track: 1 (recommended) vs 2
- [ ] Effort level / team size (scope above assumes ~60–80 h total)
- [ ] Frontend ownership (agent builds vs user builds)
- [ ] Name
