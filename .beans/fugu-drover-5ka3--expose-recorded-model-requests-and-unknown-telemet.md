---
# fugu-drover-5ka3
title: Expose recorded model requests and unknown telemetry in audit reports
status: completed
type: task
priority: high
tags:
    - parent-fugu-drover-utvh
created_at: 2026-10-07T15:59:18Z
updated_at: 2026-10-07T17:36:08Z
blocked_by:
    - fugu-drover-utvh
    - fugu-drover-24o8
---

# Show recorded model evidence for the current audit

## Current problem and point mapping

Parent baseline 2d117c1dc8c6358e856c5990a748f33ca628eb16 (2026-10-07): src/fugu/server/jobs.py:895-912,1032-1040 exposes stages[].metrics; semantic.py:83-103,269-287 and harness.py:465-473 expose requested/served models, logical llm_calls, request_attempts, usage and effective_limits. tests/test_server.py:546-615 already checks telemetry survives HTTP/SSE/restart. web/src/lib/auditResult.ts:15-38 drops model evidence and Scorecard.tsx has no recorded-model view. Existing README/intake sponsor/data-flow disclosures need no duplicate work. Addresses D2's missing 0.5 and inspectability within T4's missing 1.0; no runtime/efficiency gain is guaranteed.

## Narrow allowed paths

web/src/lib/auditResult.ts; web/src/views/Scorecard.tsx; new web/src/components/audit-provenance.tsx only if no suitable existing component; web/scripts/audit-result.mjs; new web/scripts/audit-provenance.mjs; built web/dist/index.html and web/dist/assets/*; this child's .beans record. Backend, exported StageResult/shared API contracts, App/PipelineMonitor/stylesheets and dependencies are read-only.

## Design and tradeoff

Normalize an allowlisted internal view from terminal stages[].metrics and add a compact expandable Recorded model requests section in Scorecard. Show per-stage requested/served IDs separately, logical-call/request-attempt counts with distinct labels, recorded token usage/nulls and selected effective bounds. Finite nonnegative numbers only: real zero remains zero; missing/malformed/null is not reported. Never infer served ID from requested ID, endpoint from constants, cost from tokens, total retries from logical calls, or complete member accounting from parent-only rows. State the scope is records supplied by this audit; fan-out member totals may be missing. No raw prompt/reply/source, SDK error body, secret or arbitrary JSON dump. Simulated metrics are illustrative. Legacy payloads stay readable with explicit unknowns; finding/verdict/coverage behavior is unchanged and no fetch/provider call is added.

## Acceptance

- [x] Current production metric shapes normalize and render in a completed semantic+harness fixture with distinct requested/served IDs, logical calls/request attempts, usage and selected bounds.
- [x] Null/absent/malformed/nonfinite/negative fields, skipped/failed/partial stages and legacy verdicts remain safe, explicitly unknown and scope-limited; actual zero stays zero.
- [x] Simulated and parent-only composition data never imply real inference or complete member accounting; no invented provider, cost, latency, safety or raw payload claim.
- [x] Literal expected mapper/render assertions cover missing fields, excluded secret-shaped fields and HTML-looking strings as text; new assertions fail on owned implementation reversion and pass after restoration, all old checks retained.
- [x] Real built desktop/mobile UI is discoverable and keyboard operable, long model IDs wrap without page overflow and verdict/evidence hierarchy remains intact; screenshots reviewed, all UI gates pass.
- [x] Only allowed files/own bean committed; pasted report and separate named review/third-agent handoff complete.

## Sequencing

Blocked by fugu-drover-utvh and fugu-drover-24o8, serializing generated web/dist assets. Start on current local main containing the accepted mobile task. No casebook dependency.

## UI verification gates

Run python3 tools/check_orchestration_boundary.py && npm --prefix web run build; then from web/: npm run lint -- --ignore-pattern dist; npm run contract; npm run smoke; node scripts/audit-result.mjs; node scripts/stream-lifecycle.mjs; node scripts/edge-reducer.mjs; node scripts/failed-audit.mjs plus the new/extended behavior scripts named below. Every command must finish with exit 0, no new lint warnings. These scripts currently exercise 6 stream, 25 reducer and 1 rendered-view checks; retain all existing checks and record the new count rather than assuming the baseline count. Verify actual built UI at 1440x1000 and 390x844, save screenshots and DOM measurements, label every controlled fixture, and separately mark live providers unverified. Revert only your owned implementation bytes, observe the new behavior assertions fail, restore in finally, observe pass. No text-grep or constant-mirroring test substitutes for real rendering/transport behavior.
## Ownership, isolation and review

Coder: fugu-codex-coder. Independent reviewer: fugu-codex-reviewer through existing fleet-watch. Integrator: fugu-codex-integrator through the existing third-agent PR/CI/return-to-fleet loop. Do not start work before fugu-drover-utvh is approved, merged, and synchronized to local application main; merge current LOCAL main on your assigned child branch first. Parent status on an unmerged task branch is not dispatch authorization. Claim exact paths before edits; reports outside the repository under /Users/antonkogun/.local/share/drover/reports/. Preserve pre-existing owner work and native permission/trust controls; do not answer another session's dialog.

No coder/reviewer push or landing, dependency/environment sync, shared API/dependency/schema/infrastructure changes, owner .env/database/log/credential access, historical benchmark mutation, paid evaluations, deployment, publication, visibility changes, submission or external messages. Python 3.10-compatible; use PYTHONPATH="$PWD/src:$PWD" PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY="" uv run --no-sync. Use temporary agent-owned fixture state; no shared server/database. File-based UI fixture or the explicitly authorized agent-owned loopback fixture on an unused ephemeral port only; close it and your browser afterward. Inspect production source and existing modules before creating files. Broader scope becomes a human-blocked proposal, not an implicit requirement.

Finish by recording exact SHAs, pasted finished checks, limitations and real revert-test-restore proof for any behavior fix, updating only this child checklist/record, and fleet-done for separate named review. Integrator publishes the task PR and merges only after independent approval and every local/CI gate; no direct coder dispatch to peers.


## Coder delivery — 2026-10-07

Normalized terminal semantic/harness telemetry through an internal allowlist; native Recorded model requests disclosure after findings preserves requested/served distinction, logical-call/attempt counts, supplied token usage and selected bounds. Missing/malformed/null/nonfinite/negative fields remain not reported; zero remains zero. Simulation and parent-only composition caveats prohibit inference/full-accounting claims. Existing valid finding/verdict/coverage behavior preserved. No provider, cost, endpoint, latency or raw payload inferred/displayed.

Merged accepted local main c481fdbc36f844e6ebb27a68e3660d11f04ae2f7 initially and 8ba3d69af391cf92db564e782fc30b6fc0a2d186 after casebook landing. All specified UI gates finished exit 0, 11 unchanged lint warnings; 59 node:test cases (14 new), original 10 mapper checks, contract/smoke retained. 94 built-browser checks; 1440x1000 and 390x844; 11 screenshots reviewed. Per-file mapper revert: 6/6 FAIL then 6/6 PASS restored; Scorecard revert: 8/8 FAIL then 8/8 PASS restored in finally. Agent-owned offline fixture and browser closed. Live providers and cost/performance gains unverified.

Report: /Users/antonkogun/.local/share/drover/reports/fugu-codex-coder-fugu-drover-5ka3.md; evidence sibling -evidence directory. Last acceptance checkbox records coder report/commit and fleet-done routing to named fugu-codex-reviewer / fugu-codex-integrator; independent approval, PR/CI and landing remain pending and are not asserted by coder completion. Pre-existing malformed primitive metrics in stage_done reach the read-only pipeline reducer before terminal mapping; fixture targets assigned terminal metrics. No pipeline reducer change included.
