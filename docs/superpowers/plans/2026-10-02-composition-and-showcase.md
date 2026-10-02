# Composition and Active Showcase Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or the installed OpenRig development-team workflow to implement this plan task-by-task. The existing durable rig seats are the selected execution method; no extra ephemeral delegation is needed.

**Goal:** Improve composition evidence and reporting, implement demonstrated detection fixes, and produce credible showcases from active smaller public MCP/skill projects.

**Architecture:** Preserve the existing pipeline and evidence tiers. Add a separate frozen composition corpus/baseline/evaluation runner, make minimal source/capability harvesting changes only for reproduced failures, and produce new charts from preserved historical counts plus new measured evidence. Run public showcase research in a disjoint territory with a pinned engine while detector work proceeds.

**Tech Stack:** Existing Python3.10+ Fugu pipeline, pytest via uv run --no-sync, existing chart tooling, gh public repository metadata/content; no dependency changes.

**Spec:** docs/rig-work/2026-10-02-composition-showcase/approved-design.md. Read the two work orders in that directory for exact territories, checks and evidence contracts.

## Global Constraints

- At most TWO concurrent writers, including research/docs; only lead mutates Git/shared contracts. No branch switches or Git integration while writers hold leases.
- Historical bench/results/2026-10-02-full/** and corpus/composition/** stay byte-identical. New chart presentation is written under new results, not over frozen charts.
- Retain source/label/engine/prompt hashes, failed checks, misses and exclusions; no desired-label tuning, relabeling failed cases, or pooled crafted/real-world accuracy.
- Existing quota only; bounded requests/retries; no quota purchases or billing changes. Keep current models/max efforts and all native permissions.
- Untrusted source remains inert on host. No real secrets/canaries, owner mounts, live service attacks, prior-block evasion, external issues/disclosures or deployment.

## Review Focus

- Capability inference must distinguish observed fact, heuristic risk and verified unauthorized effect.
- Namespace/permission assertions require an actual supported client/security contract; text claims alone are not enforced restrictions.
- Missing/private/egress legs, whole capability union inside one member, aliases and library indirection must have accurately documented expected rule outcomes.
- Scan bounds, symlinks and unavailable source must propagate honest coverage; no regression in containment or incomplete-verdict policy.
- Corpus diversity and reserved evaluation claims must distinguish invariance variants, authored regression results and truly independent data.

## Task1: Composition corpus, baseline and regression-driven changes

**Owner:** build.backend, lead-confirmed lease. **Files:** exact proposed paths in implementation-task.md.
**Consumes:** existing CompositionStage/MemberResult, harvest_tool_names and real audit assembly entry path. **Produces:** frozen new24-case corpus, baseline.json, after.json, new checked chart artifacts and scoped production patch if justified.

- [ ] Recover live identity; claim durable row; confirm lease/model and read approved design/current code.
- [ ] Author24 distinct cases (12positive/12controls) across >=8families; document expected trifecta/shadowing outcomes and evidence contracts. Keep duplicate/shuffled cases as separate invariance checks outside family counts.
- [ ] Freeze inputs/labels, record16development/8reserved IDs and seed, run untouched-engine baseline through the production member-harvest/stage path, retaining failures and hashes.
- [ ] For each demonstrated miss in development cases, write the meaningful failing source-level regression, run it to observe failure, and implement the smallest provenance-preserving fix. Existing shared contracts/dependencies remain frozen unless lead explicitly leases them.
- [ ] Run focused composition/server/corpus regressions and the reserved evaluation once; report every baseline/after outcome and holdout-author visibility. Independent reviewer checks additional source variants after release where practical.
- [ ] Triage the3frozen external-description misses and retain a separate bounded result. Any additional production fix requires explicit path lease and an independent failing regression, not a speculative rewrite.
- [ ] Clarify README/report composition labels and produce new charts without mutating original measured data. Inspect actual renders and verify chart-data semantics for detected attacks versus expected control outcomes.
- [ ] Return actual diff/evidence/test output and release lease. Any paid/sample experiment requires a numeric bounded plan recorded by lead.

## Task2: Active smaller public showcase candidates (parallel)

**Owner:** research.security. **Files:** docs/showcase/2026-10-02-active-repos/** and bench/results/2026-10-02-showcase/**. **Consumes:** live primary GitHub metadata/content, fixed engine manifest; seed caches in/tmp. **Produces:** shortlist5-8, <=5measured artifact audits and2-3ranked reproducible demos with clearly labeled scope.

- [ ] Claim row, confirm scope/model, freeze engine hashes before measurements and read the previous audit limits.
- [ ] Run focused public repository searches and verify exact current metadata/default-branch code or releases. Prefer<5000stars and code/release activity within60days; filter lists/mirrors/bot-only churn.
- [ ] Pin source snapshots and supported versions; record license, maintenance, artifact/use case, capability contract and current issue/advisory status.
- [ ] Inspect inert sources and run applicable Fugu checks with precise budgets/coverage. Keep denied/unavailable execution explicit and continue permitted independent work.
- [ ] Select2-3credible demos from results, with safe reproducible commands, actual findings/negative outcomes and caveats. Do not invent vulnerability findings to satisfy a showcase story.
- [ ] Have reviewer check maintenance/provenance, measured evidence and claims. Verified unpublished findings get local drafts only, excluded from public integration pending user review.
- [ ] Return durable result and release lease; no shared code/docs/Git writes.

## Task3: Independent review, integration and report

**Owner:** control.lead; independent quality.reviewer. Workers must be idle before Git mutations.

- [ ] Verify authored snapshots, integration tests and chart renders; run necessary full checks once the scoped changes settle.
- [ ] Commit only explicit assigned paths, preserving unrelated owner state. Obtain exact-commit independent review; repair findings and re-review changed candidate.
- [ ] Open scoped PR with gh --body-file, require actual CI and appropriate review conditions, then merge under existing user authorization. Never bypass protection/security checks or self-approve formally.
- [ ] Report original versus new composition outcomes, distinct family breadth, remaining misses/coverage/cost, credible real-world demo shortlist and local draft links if any. Record actual outcome/limits and return seats idle; no continuing backlog.
