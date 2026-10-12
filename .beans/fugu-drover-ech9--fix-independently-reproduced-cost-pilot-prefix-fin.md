---
# fugu-drover-ech9
title: Fix independently reproduced cost pilot prefix findings
status: in-progress
type: bug
priority: high
created_at: 2026-10-12T17:00:48Z
updated_at: 2026-10-12T17:24:45Z
parent: fugu-drover-5vox
---

Resolve COST-PREFIX-01 through 07 with meaningful red/green tests: nested search usage, unknown separately billed reasoning, outbound SDK request limits, official endpoint consistency, cached source reply integrity, direct-agent client policy, and unique finalization transcript. Existing immutable reviewer reports/probes required. Same benchmark scope; no providers/keys/Docker/dependency changes. Root dispatches only once coder idle.

## Correction evidence

- [x] Reproduce all seven against full initial candidate 98d4fe6: seven failures for six IDs, COST-PREFIX-04 already green after prior Task2 correction.
- [x] COST-PREFIX-01: nested/top-level credit validation, observed/contractual distinction and persistent stop; prefix01-red.log 14 failed/2 passed, prefix01-green.log 48 passed.
- [x] COST-PREFIX-02 separately billed reasoning: prefix02-red.log 3 failed/10 passed; prefix02-green.log 61 passed. Missing required counter retains 21000micro and stops; inclusive details remain optional.
- [x] COST-PREFIX-03 outbound request bounds: prefix03-red-valid-response.log 20 failed/5 passed; prefix03-green.log 86 passed. Reject n/ambiguous output/default/override/malformed requests before admission and reservation; retain canonical settings.
- [ ] COST-PREFIX-04 endpoint consistency regression.
- [x] COST-PREFIX-05 cached source/cursor integrity: prefix05-red.log 10 failures; source-validation-red 8 failures; owner-path-red 4 failures; prefix05-final-green.log 133 passed. Owner HMAC/private storage plus independent exact source/range/cursor validation, no replay web dispatch.
- [x] COST-PREFIX-06 direct client policy for both roles: prefix06-red.log 30 failures; prefix06-green.log 112 passed; prefix06-policy-characterization.log 33 passed. Policy is mandatory and rechecked per role/native dispatch; fake fixtures explicitly carry policy.
- [ ] COST-PREFIX-07 unique transcript with Super additions.
- [ ] Combined fake-only regressions and durable candidate/report.

Evidence directory: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/prefix-fixes-evidence/. Original candidate/report and approved documents preserved. Independent review remains pending under root routing.
