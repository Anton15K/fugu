---
# fugu-drover-o04t
title: Build an offline judge decision casebook and audience validation protocol
status: todo
type: task
priority: normal
tags:
    - parent-fugu-drover-utvh
created_at: 2026-10-07T15:59:18Z
updated_at: 2026-10-07T16:08:34Z
blocked_by:
    - fugu-drover-utvh
---

# Ship a reproducible offline judge decision casebook

## Current problem and point mapping

Baseline 2d117c1dc8c6358e856c5990a748f33ca628eb16 (2026-10-07): docs/demo-script.md:1-36 is a 2:45 proposed live rehearsal, not a completed one. The parent's transport fixture and simulation audit no source. Existing tests/test_server.py already exercise API/configured stages; do not duplicate its telemetry/restart assertions. Frozen 5 October benchmarks are not a present-day end-user decision demonstration. Addresses D1's missing 0.5, explanatory I2 missing 1.0 and Q1 differentiated-case gap. Documentation alone cannot earn missing audience-outcome points.

## Narrow allowed paths

new docs/judge-casebook.md; docs/demo-script.md; new tests/test_judge_casebook.py; inert text fixtures under tests/fixtures/judge_casebook/; own .beans record. Engine/server/verdict, old fixtures, frozen benchmarks, README, UI, dependencies, shared contracts and runtime/framework artifacts are read-only.

## Design and tradeoff

Three authored cases: hidden instructions with source/decoded exhibit -> stop and inspect; ordinary instructions with local-only checks -> inspect coverage, no safety certification; absent source -> fix source/retry, no verdict. Run actual production concealment/static stages plus credential-disabled semantic/harness through create_app and TestClient, temporary owned database/snapshots. Exclude reputation/detonation network/execution stages. In test setup disable the optional tool-surface subprocess path with a monkeypatch of ToolSurfaceScanner.from_environment returning None before stage assembly; retain genuine production regex/concealment logic and never invoke an operator scanner or container. Fixtures are inert text, never imported/executed; never read owner credentials. Assert real source-backed finding and coverage/error boundaries, not model accuracy or result snapshots. Document actual commands, decisions, exhibits, engine commit/date and offline scope for secret-free, credit-free reproduction. Keep simulation, historical benchmark denominators and human live rehearsal separate. Add a human-run audience protocol with questions, decision/comprehension/confusion observations and blank results; no invented interviews, timing, savings or endorsements.

## Acceptance

- [ ] Three inert authored scenario fixtures and intended distinctions documented; label crafted demonstrations, not blind or representative inputs.
- [ ] Production local-stage/API test proves hidden content yields source/decoded exhibit and severe policy reason; ordinary content discloses hosted-stage skips and a verdict limited to performed checks; absent source emits terminal error without success verdict. Zero paid/network/target-execution calls.
- [ ] Casebook commands work in existing no-sync environment; record exact observed output, commit/date, exhibit and coverage; no unsupported hardcoded counts/limits.
- [ ] Demo script separates offline casebook, simulated UI and human-authorized live/provider/chamber rehearsal; preserves dated benchmark limits, public-access/recording gaps. No hosted-demo or NVIDIA-runtime claim for offline cases.
- [ ] Human audience protocol records decision correctness, reasons/coverage comprehension and confusion; all uncollected outcomes unverified and outreach human-only.
- [ ] Boundary/build and new casebook/existing server tests pass. No production fix asserted: no artificial mutation or rubric-mirroring tests. Discovered engine changes require a separate task.
- [ ] Only allowed docs/inert fixtures/test/own bean committed; pasted outputs/limits and separate named review/third-agent handoff complete.

## Verification

python3 tools/check_orchestration_boundary.py && npm --prefix web run build
PYTHONPATH="$PWD/src:$PWD" PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY="" uv run --no-sync python -m pytest tests/test_judge_casebook.py tests/test_server.py -q

Expected exit 0: all three casebook scenarios and existing 24 server cases pass. Inspect genuine finding payloads, error termination and coverage/skips. Existing telemetry/restart tests unchanged; new test checks decision-casebook outputs from real source input. No fresh browser gate for docs/test-only work; any supplied screenshots must be real and visibly label controlled/simulated content.

## Sequencing

Blocked by fugu-drover-utvh only. Independent of both UI scopes; consumes existing APIs. Start only through existing queue after approved parent records synchronize to main.

## Ownership, isolation and review

Coder: fugu-codex-coder. Independent reviewer: fugu-codex-reviewer through existing fleet-watch. Integrator: fugu-codex-integrator through the existing third-agent PR/CI/return-to-fleet loop. Do not start work before fugu-drover-utvh is approved, merged, and synchronized to local application main; merge current LOCAL main on your assigned child branch first. Parent status on an unmerged task branch is not dispatch authorization. Claim exact paths before edits; reports outside the repository under /Users/antonkogun/.local/share/drover/reports/. Preserve pre-existing owner work and native permission/trust controls; do not answer another session's dialog.

No coder/reviewer push or landing, dependency/environment sync, shared API/dependency/schema/infrastructure changes, owner .env/database/log/credential access, historical benchmark mutation, paid evaluations, deployment, publication, visibility changes, submission or external messages. Python 3.10-compatible; use PYTHONPATH="$PWD/src:$PWD" PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY="" uv run --no-sync. Use temporary agent-owned fixture state; no shared server/database. File-based UI fixture or the explicitly authorized agent-owned loopback fixture on an unused ephemeral port only; close it and your browser afterward. Inspect production source and existing modules before creating files. Broader scope becomes a human-blocked proposal, not an implicit requirement.

Finish by recording exact SHAs, pasted finished checks, limitations and real revert-test-restore proof for any behavior fix, updating only this child checklist/record, and fleet-done for separate named review. Integrator publishes the task PR and merges only after independent approval and every local/CI gate; no direct coder dispatch to peers.
