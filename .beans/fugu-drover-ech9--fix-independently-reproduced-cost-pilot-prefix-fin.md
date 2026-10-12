---
# fugu-drover-ech9
title: Fix independently reproduced cost pilot prefix findings
status: in-progress
type: bug
priority: high
created_at: 2026-10-12T17:00:48Z
updated_at: 2026-10-12T17:11:27Z
parent: fugu-drover-5vox
---

Resolve COST-PREFIX-01 through 07 with meaningful red/green tests: nested search usage, unknown separately billed reasoning, outbound SDK request limits, official endpoint consistency, cached source reply integrity, direct-agent client policy, and unique finalization transcript. Existing immutable reviewer reports/probes required. Same benchmark scope; no providers/keys/Docker/dependency changes. Root dispatches only once coder idle.

## Correction evidence

- [x] Reproduce all seven against full initial candidate 98d4fe6: seven failures for six IDs, COST-PREFIX-04 already green after prior Task2 correction.
- [x] COST-PREFIX-01: nested/top-level credit validation, observed/contractual distinction and persistent stop; prefix01-red.log 14 failed/2 passed, prefix01-green.log 48 passed.
- [ ] COST-PREFIX-02 separately billed reasoning.
- [ ] COST-PREFIX-03 outbound request bounds.
- [ ] COST-PREFIX-04 endpoint consistency regression.
- [ ] COST-PREFIX-05 cached source/cursor integrity.
- [ ] COST-PREFIX-06 direct client policy for both roles.
- [ ] COST-PREFIX-07 unique transcript with Super additions.
- [ ] Combined fake-only regressions and durable candidate/report.

Evidence directory: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/prefix-fixes-evidence/. Original candidate/report and approved documents preserved. Independent review remains pending under root routing.
