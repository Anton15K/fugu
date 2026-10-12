---
# fugu-drover-p440
title: Design whole-system Fugu versus same-model agent cost benchmark
status: in-progress
type: task
priority: normal
created_at: 2026-10-12T13:06:29Z
updated_at: 2026-10-12T14:57:27Z
---

User requests an end-to-end cost and correctness benchmark against direct repository auditing by an agent, preferably with the same models. User selected a USD 10 total pilot cap. Whole-system production execution, independent ground truth, matched source access, explicit model roles, all attempts/services/completion accounting and non-cherry-picked results required. Design approval precedes implementation under brainstorming skill.

- [x] Inspect existing full benchmark, execution and accounting interfaces.
- [x] Define matched whole-system/agent methodology and USD 10 cost guard.
- [x] Present concrete design and obtain human revision 3 written-spec approval.
- [x] Prepare and self-review the concrete implementation plan.
- [ ] HUMAN: Review the implementation plan before product implementation.
- [ ] Root: Route named independent plan review and implementation handoff after approval.

No live requests or product implementation before the design gates; USD 10 authorization persists.

User said proceed after the USD 10 cap and the matched whole-system/agent approach were presented. This approves preparing the written spec; no live provider requests have been made. Native production uses Ultra plus Super; historical Docker availability must be preflighted.

Written-spec candidate prepared at docs/superpowers/specs/2026-10-12-whole-system-cost-benchmark-design.md on fleet/fugu-codex-coder-cost-spec-20261012 from pinned application base f8a996807c5619a3965e7b1d25bcd5d827b48302. Source exploration and methodology are complete for this stage. Self-review corrects the ComfyUI repository identity, explicit canonical CLI reputation/detonation profile, native full-depth fan-out, context-limit provenance, native credential bridge, faithful tool journals, inclusive direct-agent turn limits and non-double-counted pair cost reservations. Human written-spec review and implementation handoff remain pending as required by the assigned stage; this does not claim the whole bean complete. Root routes independent review. Durable candidate/report evidence: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/candidate.json and coder-report.md. No implementation, tests, real credentials/keyring/providers, Docker, sync, servers, original logs, push or landing; untracked research/logs preserved without reading.

## Human-directed tool revision (12 October 2026)

Human direction: only Fugu may query OSV or run_sandbox. Both direct-agent roles now have exactly list_files, read_file, search_files and ordinary basic Tavily search_web; no direct/indirect OSV API, chamber, shell, arbitrary HTTP, target execution, installation or Fugu detector access. Revision 2 specifies registry/dispatcher/network enforcement and exact proposed principal/security-task/functional-task/Super-review/finalization prompts with a report contract. The defined baseline is a dependency-free generic Python loop using the existing OpenAI-compatible SDK/Nebius, not packaged Codex/OpenCode. Same snapshots/models/ceilings, unequal capabilities; no equal-tool orchestration claim or additional funded experiment.

Reconciled truth, native required runtime, baseline workflow completion versus evidence strength, unresolved/source-based findings, cost/subprocess accounting, reports, acceptance and roles/stories. Frozen per-finding evidence standards apply before outputs; absent forbidden tools alone never makes the baseline incomplete/incorrect, but missing issues remain misses. Source/allowed-tool failures and malformed/missing review/finalization still mark incomplete. Written spec only: no implementation, credentials, provider requests, tests or paid run. Parent remains in-progress, human written-spec review and implementation handoff pending. Root routes fresh exact-commit review.

Prior candidate/report/evidence preserved. Revised handoff: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/candidate-v2.json and coder-report-v2.md. Both ordered task commits above pinned f8a996807c5619a3965e7b1d25bcd5d827b48302 are required; no branch/base change, push or landing.

## Long-line reader contract correction (revision 3)

Named-review defect: line-only read_file pagination plus the 8192-character response cap made long-line tails unreachable. Added an opaque continuation cursor bound to run/snapshot/file hash, canonical path and effective requested line range, with next line/within-line offset, tamper/stale/mismatch rejection and explicit returned character segments. Lossless continuation stays within 200 requested lines and 8192 serialized result characters, including metadata. Coverage is based on returned ranges, not opening a file; partial tails and pending cursors remain visible. Tool description supplies the continuation rule identically to Ultra/Super; all six exact prompt text blocks remain unchanged. Future verification prose covers these requirements, but no controls/tests were implemented.

Only the assigned written spec and this bean changed. All four tool names, Fugu-only OSV/chamber and v2 semantics persist; human written-spec review/handoff remain pending and parent stays in-progress. Original/v2 candidates and reports are preserved. Revised evidence: /Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/candidate-v3.json and coder-report-v3.md. Full ordered set above pinned f8a996807c5619a3965e7b1d25bcd5d827b48302: fe32736924f16775ee5ade5e4c0c3d2d85768855, 3d225d9294576cc8e63b943263d44781c6e2b36b, and the correction commit named in candidate-v3.json. No broad source/pricing review, implementation, tests, credentials, requests or publication.


## Human-approved revision 3: implementation plan handoff

The human explicitly approved revision 3. Approved spec SHA256: `634e0fda03d87460d04c76f4105bbcced0307080a006b0ad6e4c87314c430017`; the spec remains byte-identical. Current gate supersedes historical pending written-spec notes above: written-spec human review is approved; human implementation-plan review and named independent review are pending.

Prepared and self-reviewed `docs/superpowers/plans/2026-10-12-whole-system-cost-benchmark.md`: eleven separately testable benchmark tasks, typed shared contracts, behavioral red/green snippets, exact file/commit map, durable microdollar ledger, SDK/urllib guards, the four-tool lossless reader, exact six prompts, canonical full Fugu observation, neutral complete corpus/truth separation, native owner credential/preflight commands, adjudication and isolated Matplotlib renderer. The USD 10 cap and native Drover fleet method persist. No implementation beans created; parent stays in-progress.

Durable evidence: `/Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/plan-candidate.json`, `plan-coder-report.md`, `plan-doc-checks.json`, and `plan-matplotlib-provenance.json`. Candidate identifies the actual plan commit plus all three existing ordered nonmerge spec commits above pinned application base `f8a996807c5619a3965e7b1d25bcd5d827b48302`. Previous v1/v2/v3 candidates/reports remain intact. Root routes review; READY_FOR_PLAN_REVIEW is not completion of the parent bean.

Only this bean and the assigned plan changed. Documentation checks and public/local package metadata reads do not constitute implementation tests or runtime evidence. No product code, corpus generation, installs/sync, real credential/native storage access, paid requests, Docker builds/runs, target execution, push or landing. Untracked research/logs preserved without reading. Readiness prerequisites for later measurement remain explicit in the plan: authoritative billing bounds, configured trusted scanner, actual native chamber evidence, independent real-source pins/truth and assigned isolated renderer setup.
