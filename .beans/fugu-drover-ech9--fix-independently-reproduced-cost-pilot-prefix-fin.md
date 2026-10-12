---
# fugu-drover-ech9
title: Fix independently reproduced cost pilot prefix findings
status: completed
type: bug
priority: high
created_at: 2026-10-12T17:00:48Z
updated_at: 2026-10-12T17:36:11Z
parent: fugu-drover-5vox
---

Resolve COST-PREFIX-01 through 07 with meaningful red/green tests: nested search usage, unknown separately billed reasoning, outbound SDK request limits, official endpoint consistency, cached source reply integrity, direct-agent client policy, and unique finalization transcript. Existing immutable reviewer reports/probes required. Same benchmark scope; no providers/keys/Docker/dependency changes. Root dispatches only once coder idle.

## Correction evidence

- [x] Reproduce all seven against full initial candidate 98d4fe6: seven failures for six IDs, COST-PREFIX-04 already green after prior Task2 correction.
- [x] COST-PREFIX-01: nested/top-level credit validation, observed/contractual distinction and persistent stop; prefix01-red.log 14 failed/2 passed, prefix01-green.log 48 passed.
- [x] COST-PREFIX-02 separately billed reasoning: prefix02-red.log 3 failed/10 passed; prefix02-green.log 61 passed. Missing required counter retains 21000micro and stops; inclusive details remain optional.
- [x] COST-PREFIX-03 outbound request bounds: prefix03-red-valid-response.log 20 failed/5 passed; prefix03-green.log 86 passed. Reject n/ambiguous output/default/override/malformed requests before admission and reservation; retain canonical settings.
- [x] COST-PREFIX-04 endpoint consistency regression: original reviewer reproduction already passes against 98d4fe6 (prior 2c0299b correction). 9 added boundary tests pass before/after reusing canonical constants; prefix04-green.log 142 passed. No fabricated new red claim.
- [x] COST-PREFIX-05 cached source/cursor integrity: prefix05-red.log 10 failures; source-validation-red 8 failures; owner-path-red 4 failures; prefix05-final-green.log 133 passed. Owner HMAC/private storage plus independent exact source/range/cursor validation, no replay web dispatch.
- [x] COST-PREFIX-06 direct client policy for both roles: prefix06-red.log 30 failures; prefix06-green.log 112 passed; prefix06-policy-characterization.log 33 passed. Policy is mandatory and rechecked per role/native dispatch; fake fixtures explicitly carry policy.
- [x] COST-PREFIX-07 unique transcript with Super additions: prefix07-red.log 2 failures; prefix07-green.log 124 passed. Final principal preserves original assistant/tool pairs once and only appends new review coverage/tools/critique.
- [x] Combined fake-only regressions and durable candidate/report: terminal 236 benchmark passed (3 renderer skips covered separately), renderer 7 passed, reviewer probes 16 passed, guarded CLI/API 264 passed. Prefix-fixes candidate/report prepared; final exact head refreshed after this record-only commit.

Evidence directory: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/prefix-fixes-evidence/. Original candidate/report and approved documents preserved. Independent review remains pending under root routing.

COST-PREFIX-05 self-review: missing cached reply must not cause a second web dispatch, and missing owner integrity key must not reinitialize existing evidence. Additional red 2 failed, green 138 passed; exact logs prefix05-incomplete-journal-{red,green}.log preserved.

COST-PREFIX-01 self-review: an observed zero-credit success conflicting with a frozen authoritative exact-one-credit contract must stop rather than report free structural cost. Red 2 failed/11 passed; green 161 passed. This adds no authority or fallback; prior positive/missing/malformed cases retained.

## Summary of Changes

Resolved all current COST-PREFIX-01..07 defects with preserved behavioral red/green evidence. COST-PREFIX-04 was already corrected in the full initial candidate; retained fresh passing counterevidence and endpoint consistency tests. Original candidate/report/task evidence/approved spec and plan remain byte-identical. No paid/native credential/runtime execution or publication. Independent exact-head review remains pending and root routes it; parent epic/native phase are not marked completed.

Source: [transport](../bench/cost_pilot/transport.py), [pricing](../bench/cost_pilot/pricing.py), [tools](../bench/cost_pilot/tools.py), [agent](../bench/cost_pilot/agent.py), [behavioral tests](../tests/cost_pilot/test_prefix_fixes.py).

Review evidence: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/prefix-code-review.md and prefix-code-review.json.

Correction candidate: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/prefix-fixes-candidate.json.

Report: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/prefix-fixes-coder-report.md.
