---
# fugu-drover-ech9
title: Fix independently reproduced cost pilot prefix findings
status: completed
type: bug
priority: high
created_at: 2026-10-12T17:00:48Z
updated_at: 2026-10-12T18:23:12Z
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

## Residual trust-env continuation

Reopened for independent COST-PREFIX-06-TRUST-ENV against preserved complete candidate 4524fb51adf39d42e0597996e820ebe2c929d1e2. Only benchmark client policy/construction, relevant tests and this record; integrator owns corpus generator/tests.

- [x] Reproduce independent unsafe/unverified trust-env callbacks and native factory default: original independent terminal 22 failed/62 passed against 4524fb5; focused behavioral red 48 failed/2 passed.
- [x] Enforce exact False before initial liability and per callback; construct canonical native benchmark client proxy-free and restore scoped adapter. Focused green 50 passed (both endpoints; principal/reviewer/final drift; raw native drift; real SDK MockTransport; native constructor and callback exceptions; nested scope restoration).
- [x] Preserve prior evidence and run guarded focused/benchmark/native regressions: 113 captured references unchanged; benchmark 346 passed/3 existing plot skips, guarded CLI/API 264 passed/1 existing warning, retained prefix 16 passed, orchestration 6 passed and boundary passed. Renderer unaffected and not rerun.
- [x] Prepare durable exact-head trust-env candidate/report for root-routed independent review (refreshed after this scoped commit).

### Summary of Changes — trust-env continuation

Resolved the residual COST-PREFIX-06-TRUST-ENV implementation gap. Benchmark validation requires the actual underlying transport's trust_env to be exactly False, including initial preflight and every direct role/native proxy callback. Existing scoped native adapter constructs DefaultHttpxClient with trust_env=False before any HTTP transport/proxy mounts exist and restores its constructor and other adaptations on success/failure. No postconstruction policy mutation. Production settings/factory/limits, corpus and shared schemas remain unchanged; safe fake-client metadata explicitly records False without changing helper signatures or tariff contracts.

Original independent82 cases pass unchanged; two native factory probes run inside benchmark native_scope (84 total green), with original source and adaptation diff preserved. Production default True outside benchmark is deliberately retained and tested. This record completes assigned implementation only; independent exact-head review remains pending under root routing. No whole-branch, measured-runtime or landing approval is claimed.

Source: [transport](../bench/cost_pilot/transport.py), [focused tests](../tests/cost_pilot/test_trust_env.py).
Reviewer evidence: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/prefix-fixes-independent-check.md and prefix-fixes-independent-check.json.
Candidate: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/trust-env-fixes-candidate.json.
Report: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/trust-env-fixes-coder-report.md.
Evidence: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/implementation/trust-env-fixes-evidence/.

Only own corpus-specific claim released; integrator owns corpus work. All prior complete/prefix candidates and immutable evidence preserved; research/logs remain unread/unmodified. No real keys/storage/provider/target/Docker execution, installs, shared sync, peer prompts, native approvals, main/setup merge or publication. Return TRUST_ENV_FIXES_READY_FOR_REVIEW then idle.
