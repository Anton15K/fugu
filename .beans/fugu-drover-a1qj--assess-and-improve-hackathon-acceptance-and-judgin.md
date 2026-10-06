---
# fugu-drover-a1qj
title: Assess and improve hackathon acceptance and judging readiness
status: todo
type: task
priority: high
created_at: 2026-10-06T11:42:08Z
updated_at: 2026-10-06T11:42:08Z
---

# Human assignment

Rate the current Fugu project against the hackathon acceptance and judging criteria, then improve it wherever concrete, worthwhile opportunities exist. This is an application task, not Drover/OpenRig setup work.

## Rubric and evidence

Use https://nebiusglobalaihackathon.devpost.com/rules as the authoritative current rules. Assess Stage One viability and mandatory submission requirements separately from the four equally weighted Stage Two criteria: Technological Implementation, Design, Potential Impact, and Quality of the Idea. Score each criterion on an explicitly advisory 0–10 scale, calculate the equal-weight mean, cite supporting sources and current repository evidence, and distinguish demonstrated behavior, historical evidence, unverified claims, and human-only submission actions.

Read docs/hackathon-assessment.md as historical context; do not assume its 7.6/10 rating or readiness statements still describe current application main. Record the exact baseline commit and date. Inspect the real product flow and relevant code, tests, documentation, demo materials, and evidence before selecting improvements. Do not inflate scores merely because changes were made.

## Execution scope

Owner: fugu-codex-coder. Separate reviewer: fugu-codex-reviewer through fleet-watch. Work only in the assigned isolated worktree on fleet/fugu-codex-coder-<bean>, based on current local application main. Do not implement in the setup/drover control checkout.

Permitted files: this bean, relevant application source under src/, tests/, web/ (excluding dependency manifests, lockfiles and generated dependency directories), application documentation under docs/, and README.md. Narrow and record selected file scope in the report before editing; claim those paths with fleet-claim. Request human lead approval for changes to shared API contracts, dependencies, schemas, infrastructure or other paths. Preserve Python 3.10 compatibility and use PYTHONPATH="$PWD/src:$PWD" uv run --no-sync for Python. Do not synchronize environments, inspect credentials, copy original .env/database/logs/uncommitted work, or disturb active owner environments.

Prioritize gaps by likely criterion benefit, evidence, effort, and regression risk. Implement the highest-value feasible improvements within this scope, beginning with gaps that prevent a coherent, credible judge experience. Deliver concrete working improvements, not only recommendations or scorecard edits. Use existing dependencies and supported contracts. Avoid unbounded redesigns or a requirement to reach an arbitrary score. Document lower-priority opportunities and exact reasons for deferral. Changes requiring human actions or broader scope must be called out, not silently performed.

Do not push, land product commits, deploy, publish, change repository visibility, submit to Devpost, or send external communications. Prepare reviewable materials for human-controlled submission actions. Do not start shared dev servers without the lead's port approval. Native permission and trust dialogs remain for the human; report blockers without answering them.

## Acceptance criteria

- [ ] Verify current official rules and produce a baseline scorecard with dated source links, exact application commit, four justified criterion scores, equal-weight overall rating, and a separate viability/submission readiness checklist.
- [ ] Rank concrete improvement opportunities, identify the highest-value feasible ones, and record chosen implementation/file scope and deferred items with reasons.
- [ ] Implement the selected improvements on the assigned application task branch using existing dependencies/contracts, with meaningful regression coverage where behavior changes warrant it.
- [ ] Run scoped tests and required checks; for UI changes run build, lint, contract, smoke and browser inspection, recording real outputs and desktop/mobile observations. Mark unavailable validation explicitly; do not report success without evidence.
- [ ] Update docs/hackathon-assessment.md with current demonstrated behavior, baseline/candidate commit references, before/after advisory scores, readiness gaps and limitations. Maintain honest distinctions between benchmark evidence, product readiness and subjective scores.
- [ ] Commit only assigned changes and this bean; write the full coder report under the Drover reports directory with SHAs, pasted verification output, selected/deferred improvements, remaining human actions, and before/after assessment. Announce fleet-done for this bean so the separate named Codex reviewer can verify the changes independently before human landing.

## Review expectations

The reviewer must check the official rubric mapping, scoring arithmetic, evidence freshness and limits, verify the actual improvements, and test named commits on detached current local main in the separate reviewer worktree. Do not accept a recommendation-only deliverable when feasible implementation opportunities exist. Review required UI/integration checks where applicable. Report BEAN: MET|UNMET, LANDABLE: YES|NO, and VERDICT with actionable findings. Product integration and publishing remain human-controlled.
