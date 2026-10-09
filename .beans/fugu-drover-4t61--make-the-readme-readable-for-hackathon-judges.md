---
# fugu-drover-4t61
title: Make the README readable for hackathon judges
status: completed
type: task
priority: normal
created_at: 2026-10-09T19:26:29Z
updated_at: 2026-10-09T19:37:06Z
---

User assignment: clean the README for the jury, preserving the use case, charts, sponsor integration and evidence boundaries. Scope: README.md, docs/readme-reference.md and this task record on a product branch from application main; no product behavior, dependency, runtime, publication or benchmark-artifact changes.

- [x] Reorganize the README with a clear use case and judge reading path, retaining all three charts and benchmark definitions.
- [x] Preserve installation and analysis boundaries; relocate detailed technical reference without losing information.
- [x] Add accurately attributed external maintainer confirmation and fix links.
- [x] Verify Markdown, local links, chart paths, source claims and orchestration boundaries.
- [x] Obtain a separate named Codex review in its own worktree and resolve findings.

Root lead coordinates delivery. No push, publication or main landing is authorized by this task.

## Summary of Changes

Reorganized README into a 206-line jury reading path with an authored install-decision example, exact sponsor model roles, unchanged frozen benchmark figures and all three charts, accurately attributed 9 October maintainer timeout fix, and local/live/simulated/saved-run instructions. Moved scanner configuration, retained source checks, limits and developer verification into docs/readme-reference.md. Documentation checks passed: 40 relative links, 8 anchors, 14 headings, 3 fenced blocks; chart bytes match application main; source model roles and limits inspected; orchestration boundary and diff checks passed.

Independent review approved; all task items completed. No push, publication or main landing performed. Existing untracked research and logs preserved.

## Independent Review Approval

Reviewer: fugu-codex-reviewer, in its own worktree at `/Users/antonkogun/.herdr/worktrees/fugu-drover/fleet-fugu-codex-reviewer`.
Implementation: `5e38f504edc7f09e60658a92d763fb3efcd25378`.
Detached review commit: `9dfc8b9e34a748cda0724972fe45e470dbf7c5f8` on application main `32d34176a4c32ae7853711b048c253f2fad7439b`.
Evidence: `/Users/antonkogun/.local/share/drover/reports/fugu-jury-readme-20261009/reviewer-report.md` — BEAN: MET; LANDABLE: YES; VERDICT: APPROVE; required corrections: none.

Human authorized this task-record-only finalization after approval. README.md and docs/readme-reference.md remain byte-identical to the reviewed implementation. Root will mirror this completed record into control. No push, main landing, fleet dispatch or new work performed.
