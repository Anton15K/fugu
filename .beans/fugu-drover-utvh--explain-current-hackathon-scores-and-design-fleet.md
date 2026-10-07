---
# fugu-drover-utvh
title: Explain current hackathon scores and design fleet improvement tasks
status: todo
type: task
priority: high
created_at: 2026-10-07T15:42:08Z
updated_at: 2026-10-07T15:42:08Z
---

# Human assignment — fresh hackathon rating and improvement task design

The human requests: ask the fleet to rate the project NOW, explain every point awarded under ALL hackathon criteria, decide what can be improved, design the tasks and send them to the fleet. This authorizes this finite assessment and creation of concrete improvement tasks, not arbitrary idle work.

Owner: fugu-codex-coder. Independent named reviewer: fugu-codex-reviewer, routed by fleet-watch. Integration: fugu-codex-integrator under its existing human-authorized runbook, after independent approval and every local/CI gate. The integrator may publish the task PR and merge on green CI; coder/reviewer cannot push or land. Parent assignment is assessment/documentation/task design, not implementing the child improvements.

## Session and scope

Run beans prime, read your applicable instructions and fleet-peers skill, and confirm your named session with herdr agent list. A missing HERDR_ENV in a subprocess alone is NOT proof you are outside Herdr: roster membership and your named worktree are authoritative for this assignment. Preserve native controls and never answer another session's permission/trust dialog.

Work in your assigned isolated task worktree/branch, merge current LOCAL application main first, and record its exact baseline SHA/date. Application main is /Users/antonkogun/dev/fugu-main; setup/drover is control only. PRs #17 and #18 are merged; verify current source rather than repeating the old 7.4 score or the now-fixed 12 failures. Read prior docs/reports for provenance, not fresh test results. Do not operate OpenRig or edit its artifacts.

Permitted edits on this parent: its own .beans record, new .beans child records explicitly designed for this request, docs/hackathon-assessment.md, and docs/hackathon-improvement-plan.md. Claim paths before edits. Inspect other tracked application files/evidence read-only. No source, dependencies, frozen benchmark artifacts, shared contracts, schemas or infrastructure changes in the parent. Runtime reports/config stay outside application main. Do not copy/read original .env, database, logs, credentials or uncommitted work. Do not sync dependencies/environments. Python uses PYTHONPATH="$PWD/src:$PWD" uv run --no-sync; offline tests use PYTHON_DOTENV_DISABLED=1 and an empty NEBIUS_API_KEY. Preserve Python 3.10 compatibility. No paid provider calls, deployment, public-site publication, repository visibility changes, Devpost submission or external messages. These human actions must be listed separately and must not block this assess-and-plan task's completion.

## Rating deliverable

Verify https://nebiusglobalaihackathon.devpost.com/rules NOW. Stage One viability and mandatory submission readiness are separate from the four equally weighted Stage Two criteria: Technological Implementation, Design, Potential Impact and Quality of the Idea. Cite rule links/access date; do not reproduce more than 25 verbatim words from this single source across the deliverable. The rules do not specify a numeric scale or detailed subcriterion weights: label your 0–10 scale and subcriterion breakdown as the fleet's advisory rubric, not official judging scores.

For EACH of the four criteria, supply a transparent point ledger: define relevant subcriteria whose maximum points add to exactly 10; each row states maximum points, awarded points, WHY precisely those points are earned, current source/file:line or observed evidence, WHY the remaining points are withheld, and the concrete change/evidence required to earn them. Fractions are allowed; explain every component of the total, not only broad praise or adjectives. Distinguish demonstrated current behavior, historical provider/benchmark evidence, unverified claims and subjective judgment. Show each sum and the equal-weight overall arithmetic; don't inflate ratings automatically because tests were fixed or tasks proposed. Explain changes from the previous assessment against the same evidence and note any changed rubric. Give score confidence and material unknowns.

Inspect the actual current user flow, core provider/model usage, quality/security boundaries, benchmark limitations, audience/problem evidence, and existing demo/submission materials. Run appropriate fresh offline checks that support your assessment; record exact commands, counts and limitations. Do not report previously recorded checks as freshly run. Assess UI via an existing safe fixture/browser approach if available. As the lead's assistant I authorize only an agent-owned temporary loopback fixture/static-preview server on an unused ephemeral port, with fake/offline providers and temporary state, shut down afterward; do not alter shared servers/databases, access live secrets, or claim live provider behavior from a fixture. If unavailable, explicitly mark browser/provider evidence unverified and score accordingly rather than fabricate it.

## Designed tasks and dispatch

Identify improvement opportunities against the missing-point ledger, rank by evidence, likely criterion benefit, effort and regression risk. Choose a finite highest-value set of roughly 2–5 independently reviewable tasks where justified, not a target number at the expense of quality. Existing work must not be duplicated. Cover all material deficits either with a scoped task or a documented reason/human-only action. A proposed score gain is a hypothesis, never guaranteed.

Create real child beans ON YOUR TASK BRANCH using beans create --body-file, status todo, priorities and dependencies. Each should be blocked-by this assessment bean so work cannot start before the assessed plan is accepted and integrated. Add additional dependencies where task scopes overlap. Each child needs: specific current problem and evidence, criterion/point gap addressed, narrow allowed file paths, explicit non-goals, measurable acceptance checklist, meaningful verification commands/results expected, dependency sequencing, assigned coder/reviewer/integrator roles, and a concise design explaining chosen behavior and tradeoffs. Use existing APIs/dependencies; shared contract/dependency/schema changes remain human-owned proposals unless already explicitly authorized. If broader approval is needed, create a draft or clearly human-blocked proposal rather than a runnable task silently requiring it. Human submission/visibility/publishing actions are separate from fleet-ready implementation tasks. Child tasks must not require unapproved paid evaluations or overwrite historical benchmarks.

Allowed child scopes: existing application source under src/, tests/, web/ excluding dependency files/directories, docs/ excluding frozen artifacts and OpenRig task artifacts, README.md, and the child's own .beans record. Narrow each task to relevant paths and request broader changes separately. Every child inherits secret handling, offline/worktree import rules, independent review, no coder/reviewer push/landing, and correct native controls. For behavior fixes use meaningful regression proof; changed UI requires build, lint, contract, smoke and desktop/mobile browser inspection. Done children enter the existing third-agent PR/CI/return-to-fleet loop.

Document real child IDs and scope, dependencies, priority, acceptance checks and missing-point mapping in docs/hackathon-improvement-plan.md. On the parent branch they are planned but not yet dispatchable: NEVER claim they are running. After the parent is independently approved and merged, the integrator syncs completed parent + child records to local application main and the existing fleet-watch queues ready children automatically. Do not start another watcher or prompt busy agents. Tell the lead exactly which child records were created so dispatch can be verified. The user already requested task design and dispatch; routine design choices in this authorized scope do not require another confirmation.

## Acceptance

- [ ] Fresh baseline pinned and current official criteria/eligibility/submission requirements verified; prior completed work acknowledged accurately.
- [ ] All four advisory criterion scores explained by complete earned/missing point ledgers with evidence, arithmetic, uncertainties and equal-weight overall rating.
- [ ] Actual current product/evidence reviewed and relevant fresh offline verification recorded, with historical/unverified evidence clearly separated.
- [ ] Highest-value gaps ranked and finite child tasks fully designed, with concrete scope, measurable acceptance, verification, priorities, dependencies and justified deferrals/human actions.
- [ ] Real child beans created on the task branch, blocked by this parent; user-facing assessment and improvement-plan docs include their IDs and honest dispatch status.
- [ ] Only assigned docs/task records committed; report includes every necessary non-merge SHA, exact test output and full score/task explanation, and fleet-done announces this parent for independent review.

Write reports under /Users/antonkogun/.local/share/drover/reports/. Report fresh observations only. Finish bean checklists and announce fleet-done as usual. End report with REBASED/VERIFIED/DONE evidence. This is a documentation/task-design change: don't invent implementation tests that merely mirror the rubric; run genuine current integration/product checks to support claims.

## Independent review expectations

Review exact named commits on detached current local main in the separate reviewer worktree. Independently verify official criteria, point totals/mean, each earned/withheld justification, evidence dates/source correctness, current product claims, and every child design's feasibility/scope/dependencies/verification. Challenge unsupported score inflation and task designs that won't close their claimed gap. Ensure no accidental framework/runtime files, source changes, credential material or historical evidence mutation. Confirm child IDs exist, are blocked-by this parent, and become appropriately ready only on accepted main. Run appropriate genuine integration checks and report BEAN: MET|UNMET, LANDABLE: YES|NO and VERDICT: APPROVE|CHANGES. Approved docs and task designs may then enter the already-authorized third-agent PR/CI merge loop, after which children can be dispatched.
