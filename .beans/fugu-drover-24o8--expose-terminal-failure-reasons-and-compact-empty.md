---
# fugu-drover-24o8
title: Expose terminal failure reasons and compact empty mobile panels
status: todo
type: task
priority: high
tags:
    - parent-fugu-drover-utvh
created_at: 2026-10-07T15:58:20Z
updated_at: 2026-10-07T16:08:34Z
blocked_by:
    - fugu-drover-utvh
---

# Put terminal failure details where users can act

## Current problem and point mapping

At parent baseline 2d117c1dc8c6358e856c5990a748f33ca628eb16 (2026-10-07), web/src/views/PipelineMonitor.tsx:492-501 tells users to see the log; the retained extraction reason is only in the lower Stream log. The parent's real compiled UI fixture at 390x844 placed that reason at y=1125, with an empty evidence feed and a two-line stopped log each forced to 380px (source lines 702,751). No horizontal overflow; existing closed transports and retry already work. Do not redo PR 17. Addresses D3 recovery's missing 0.75 and D4 compact-layout part of the missing 0.75; any score gain requires new independent observation, not automatic credit.

## Narrow allowed paths

web/src/views/PipelineMonitor.tsx; web/scripts/failed-audit.mjs; web/scripts/edge-reducer.mjs; optionally new web/scripts/failure-recovery.mjs; the built application web/dist/index.html and web/dist/assets/* produced by build; this child's .beans record. Read other files only. No App/API/source-engine/stylesheet/dependency changes or broad redesign.

## Design and tradeoff

Promote the existing terminal error reason into the primary halted alert beside a useful retry action; do not parse an absent fatal flag or fabricate a verdict. Retain the original bounded log and findings. Render arbitrary reason text safely; long reasons may wrap or have an accessible expansion but never disappear. Closed stream without a server reason must say the reason was not supplied, not invent one. On narrow screens, stopped empty or short evidence/log areas use content-sized or collapsed containers instead of 380px minimum heights; populated findings/logs remain accessible. Keep desktop layout, running stream behavior, all historical findings and already-implemented stop/retry semantics.

## Acceptance

- [ ] Reproduce the baseline failure with actual rendered production UI; record reason/retry positions and empty-panel sizes at 390x844.
- [ ] Primary failure alert exposes the actual source-extraction reason; retained log agrees, unknown reason has explicit fallback, no PASS/completed verdict is synthesized.
- [ ] At 390x844 the short fixture reason and an operable New audit action are visible in the first viewport; empty stopped panels have no 380px forced minimum; populated/long evidence remains reachable with no horizontal page overflow.
- [ ] New audit clears the reason and old terminal state; successive failure/running/completed fixtures preserve current findings, stop behavior and keyboard access to recovery. Include long text and HTML-looking reason inputs.
- [ ] Meaningful real-render/reducer regressions fail on owned implementation reversion and pass after restoration; every existing and new UI gate passes, with desktop/mobile screenshots reviewed.
- [ ] Only allowed application assets and this child record committed; full report and independent named review/third-agent handoff complete.

## Sequencing

Blocked by fugu-drover-utvh. Execute this UI task before the model-evidence UI task: both rebuild tracked web/dist assets, so they must not start from a parallel base and compete over those files.

## UI verification gates

Run python3 tools/check_orchestration_boundary.py && npm --prefix web run build; then from web/: npm run lint -- --ignore-pattern dist; npm run contract; npm run smoke; node scripts/audit-result.mjs; node scripts/stream-lifecycle.mjs; node scripts/edge-reducer.mjs; node scripts/failed-audit.mjs plus the new/extended behavior scripts named below. Every command must finish with exit 0, no new lint warnings. These scripts currently exercise 6 stream, 25 reducer and 1 rendered-view checks; retain all existing checks and record the new count rather than assuming the baseline count. Verify actual built UI at 1440x1000 and 390x844, save screenshots and DOM measurements, label every controlled fixture, and separately mark live providers unverified. Revert only your owned implementation bytes, observe the new behavior assertions fail, restore in finally, observe pass. No text-grep or constant-mirroring test substitutes for real rendering/transport behavior.
## Ownership, isolation and review

Coder: fugu-codex-coder. Independent reviewer: fugu-codex-reviewer through existing fleet-watch. Integrator: fugu-codex-integrator through the existing third-agent PR/CI/return-to-fleet loop. Do not start work before fugu-drover-utvh is approved, merged, and synchronized to local application main; merge current LOCAL main on your assigned child branch first. Parent status on an unmerged task branch is not dispatch authorization. Claim exact paths before edits; reports outside the repository under /Users/antonkogun/.local/share/drover/reports/. Preserve pre-existing owner work and native permission/trust controls; do not answer another session's dialog.

No coder/reviewer push or landing, dependency/environment sync, shared API/dependency/schema/infrastructure changes, owner .env/database/log/credential access, historical benchmark mutation, paid evaluations, deployment, publication, visibility changes, submission or external messages. Python 3.10-compatible; use PYTHONPATH="$PWD/src:$PWD" PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY="" uv run --no-sync. Use temporary agent-owned fixture state; no shared server/database. File-based UI fixture or the explicitly authorized agent-owned loopback fixture on an unused ephemeral port only; close it and your browser afterward. Inspect production source and existing modules before creating files. Broader scope becomes a human-blocked proposal, not an implicit requirement.

Finish by recording exact SHAs, pasted finished checks, limitations and real revert-test-restore proof for any behavior fix, updating only this child checklist/record, and fleet-done for separate named review. Integrator publishes the task PR and merges only after independent approval and every local/CI gate; no direct coder dispatch to peers.
