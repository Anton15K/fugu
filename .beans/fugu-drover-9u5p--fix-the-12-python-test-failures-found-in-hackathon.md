---
# fugu-drover-9u5p
title: Fix the 12 Python test failures found in hackathon assessment
status: completed
type: task
priority: high
created_at: 2026-10-06T18:30:25Z
updated_at: 2026-10-06T18:45:51Z
---

# Human assignment

The human explicitly asked the Drover fleet to fix the 12 failing Python tests reported during fugu-drover-a1qj. Diagnose and repair the underlying behavior or test isolation, then obtain separate named review. Do not merely suppress failures, skip tests, relax meaningful assertions, increase timeouts without diagnosis, or delete historical benchmark evidence.

Owner: fugu-codex-coder. Independent reviewer: fugu-codex-reviewer, in its separate session/worktree through fleet-watch. Use a new fleet/fugu-codex-coder-<bean> branch based on current local application main. The previously approved UI/docs task remains on fleet/fugu-codex-coder-fugu-drover-a1qj; do not alter or mix its application commits into this repair task. Its PR can proceed separately because it changed no Python source/tests.

## Known failures, not yet confirmed root causes

Evidence: /Users/antonkogun/.local/share/drover/reports/fugu-codex-coder-fugu-drover-a1qj.md, broad-suite section. Original full run: 12 failed, 965 passed, 5 skipped; scoped repeat: 12 failed, 124 passed. No baseline attribution was established. Establish the baseline yourself before changing code.

1. tests/test_composition_expanded.py::test_import_alias_post_forms_complete_the_real_source_trifecta[v2-py-module-alias-post]
2. Same test [v2-py-symbol-alias-post]
3. tests/test_composition_expanded.py::test_case_result_marks_partial_and_failed_member_stages_incomplete_and_keeps_findings
4. tests/test_composition_expanded.py::test_run_suite_persists_cases_around_all_extraction_failure
5–11. tests/test_current_limits_continuation.py::test_prepared_plan_drift_is_rejected_before_sdk[input,label,grouping,profile,runtime,source,module] (seven separate parameter cases)
12. tests/test_store.py::test_get_audit_survives_server_restart

Composition tests expect attack detection but receive false/missed results. Continuation tests reach a historical data-release.json absence assertion even though the artifact already exists; investigate subprocess isolation and default paths, preserving the before-SDK rejection guarantee. Restart test times out with the job still running; diagnose scheduling, fake engine behavior and persistence lifecycle before selecting the fix. These observations do not establish root causes.

## Scope and operating constraints

Permitted files: this bean; tests/test_composition_expanded.py, tests/test_current_limits_continuation.py, tests/test_store.py and necessary related test helpers; relevant Python implementation under src/fugu/ and executable benchmark code under bench/ (excluding frozen corpora, manifests, measurements and results). Inspect existing modules first, identify the narrow actual file scope in the report, and claim it with fleet-claim before editing. Any dependency, shared API contract, schema, migration, frozen evidence, infrastructure or other-path change requires human lead approval. Do not alter the existing approved UI/docs task branch. Do not modify Drover/OpenRig runtime configuration as part of application fixes.

Preserve Python 3.10 compatibility. Use PYTHONPATH="$PWD/src:$PWD" uv run --no-sync for all Python execution, including subprocesses; do not synchronize environments or change dependencies. Tests must use isolated temporary state and fake/offline providers. Do not invoke paid provider calls, run benchmark continuations against historical state, delete releases/journals, modify existing audit databases, or read/copy original credentials, .env, database, logs or human uncommitted work.

Herdr roster previously verified both named workers in their isolated worktrees despite the HERDR_ENV shell marker failing. For this explicit human assignment, verify actual named session/worktree membership with herdr agent list rather than treating that missing subprocess marker alone as proof of being outside Herdr. Do not enter a repeated redispatch loop on the same marker. Do not answer native approval/trust dialogs; report those to the human.

Keep investigation evidence per root cause. Use failing behavioral tests first, minimal fixes, and prove regression tests fail against the relevant pre-fix files and pass after restoration. Preserve literal product expectations unless evidence shows the expectation is incorrect; document any justified assertion change. Do not obtain green results through weaker coverage.

No product landing, push, deployment, publishing, migrations, external communications or shared dev-server startup. Commit only assigned changes and this bean on the isolated task branch. The human controls integration and PR publishing.

## Acceptance criteria

- [x] Reproduce all 12 named cases on current local main in this worktree, record baseline commit/counts and diagnose each failure group with concrete evidence.
- [x] Record narrow permitted file claims and implement minimal fixes for composition, continuation isolation/rejection and audit restart behavior; preserve historical evidence and meaningful assertions.
- [x] Demonstrate regression behavior: relevant pre-fix files fail and restored fixes pass; verify the continuation rejection still occurs before SDK use and test writes stay in temporary locations.
- [x] Run the three affected test modules successfully, then the full Python suite with correct worktree imports and offline/fake provider isolation. Record exact passed/failed/skipped counts, including any newly discovered blocker rather than concealing it.
- [x] Run the application orchestration-boundary check and applicable required checks. Keep Python 3.10 compatibility and dependencies/contracts unchanged, or obtain explicit human approval for required scope changes.
- [x] Commit assigned repairs and this bean; report all required SHAs, root causes, before/after evidence and pasted test output under /Users/antonkogun/.local/share/drover/reports/. Announce fleet-done for independent reviewer verification before human integration.

Reviewer: independently apply named non-merge commits to detached current local main, verify the root-cause claims and absence of weakened tests/deleted evidence, run all three affected modules and the full Python suite with worktree-correct imports, and check integration/boundary behavior. Report BEAN: MET|UNMET, LANDABLE: YES|NO and VERDICT: APPROVE|CHANGES. A remaining failure in any of the 12 named cases is not complete.
