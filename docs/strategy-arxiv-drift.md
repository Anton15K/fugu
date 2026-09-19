# arXiv Deep-Dive → Plan Drift (2026-09-19)

> Full abstracts pulled via arXiv API (verifiable: ids below). Synthesizes the five
> papers surfaced by the competitive/tech-gap bots into concrete plan changes.

## Papers (verified abstracts)

1. **MCPZoo / Rethinking MCP Security** (2607.11086, Jul 2026): 64,611-server corpus; scanners flag 96.89% of servers risky; manual validation: **<50% of alerts are true positives**; cross-scanner inconsistency. MCPZoo itself = future real-world eval corpus (37,288 dynamically analyzable).
2. **SkillSecurer** (2609.14079, Sep 2026): red/blue/verifier agentic framework for skill injection — red generates recorded context-compatible injections (9 threat types), blue detects+localizes+patches, verifier enables injection-level eval. 100% detection w/ best backend; 17% of skills.sh skills have latent vulnerabilities; triggered real incidents. NO canary detonation, NO supply chain, NO OWASP mapping.
3. **Random Registry Draw** (2609.10962, Sep 2026): unbiased probe of 400 registry servers: only 48.8% complete initialize handshake; 37.5% never start; 58.8% of tools omit safety annotations (curated frames flatter to 41.5%). Methodological warning against curated-sample bias.
4. **Smell-Aware MCP Descriptions** (2602.18914, Feb 2026): 4-dimension quality standard (accuracy/functionality/completeness/conciseness), 18 smell categories, 10,831 servers; smells pervade (73% dup tool names) and degrade tool selection (+11.6%, p<0.001).
5. **CASCADE** (2604.17125, Apr 2026, v2): layered local defense + methodology audit. (a) aggregation convention dominates headline FPR (11.70% vs 1.51%); (b) detection NOT provenance-invariant — recall 86.2% original vs 99.88% template-generated (synthetic corpora inflate); (c) operating point recoverable only from record-level outputs; (d) human-referral escalation changed no outcomes.

## Drift decisions

| # | Change | Paper | Effort | Status |
|---|---|---|---|---|
| D1 | **S4 harness = red/blue/verifier pattern**: red Nemotron generates recorded probes (ground truth), blue = agent under test w/ extension mounted, verifier diffs trajectory vs recorded intent → injection-level P/R. Keep canary env during runs (our twist). | SkillSecurer | ~2d | adopt |
| D2 | **Eval honesty pack**: crafted-vs-real split metrics column; explicit aggregation convention (sample-level vs finding-level; escalated-counts-as-positive rule); manual-validation subset (~50 hand-verified alerts → estimated TP rate, citing MCPZoo's <50%). | CASCADE + MCPZoo | ~1d | adopt |
| D3 | **S1 additions**: missing-safety-annotation rule (readOnlyHint/destructiveHint absent → info, MCP08-adjacent); smell-lite (duplicate tool names, missing return descriptions → info quality findings). | Random Draw + Smells | ~0.5d | adopt |
| D4 | **S2 judge upgrade**: 4-dimension smell checklist in prompt + localization output (exact element carrying risk: description line, param schema, output template). | Smells + SkillSecurer | ~0.5d | adopt |
| D5 | **Detonation**: non-starting server = evidence class (info finding "failed to initialize — static-only verdict"), never a hard error. | Random Draw | ~1h | adopt |
| D6 | **README/pitch stats**: 96.89%-flagged-yet-<50%-true (MCPZoo); 17% of skills.sh latent vulns (SkillSecurer); 58.8% annotation omission (Random Draw); our split-metric rigor (CASCADE). | all | trivial | adopt |
| — | Patching/remediation of skills; provenance signing; eBPF capture | SkillSecurer etc. | — | **reject** (occupied lanes / scope sink) |

## Non-drift (validated core)
Canary detonation + Unicode layer + skills&MCP coverage + OWASP tiering + evidence artifacts — competitive scan says the combination is still unoccupied; papers above reinforce (none combine execution evidence with supply chain + judge pipeline).

## Sequence
D5 + D6 + D3 first (hours, immediate robustness/stats), D4 with S2 build (mine), D1 when S4 lands, D2 before publishing any eval numbers publicly.
