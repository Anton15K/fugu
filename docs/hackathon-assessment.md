# Fugu hackathon assessment — 6 October 2026

**Advisory candidate rating: 7.4/10; submission readiness: incomplete.**
Fugu has a credible developer-security use case and retained hosted-model
evidence. This task repairs a demonstrated failure-flow defect; it establishes
no new detector accuracy, fresh provider reliability or judge access.

Assessed **2026-10-06** against local application main
`2d6d7ca2d8a3437448d2fd63dc8ab7b45f7f21ef` (committed the same day).
The tested application candidate is
`4b66f67e3d20ae4182cd18a74fd081f58bfc4034`.
The documentation/checklist commit follows that candidate. Independent named
fleet review and human landing remain outstanding. The previous 2–3 October
7.6 rating is historical, not this baseline.

The [official rules, §§1, 3, 4 and 6](https://nebiusglobalaihackathon.devpost.com/rules),
retrieved **2026-10-06**, separate theme/API viability from four equal-weight
judging dimensions. These subjective 0–10 scores are not official marks or
predictions of acceptance or winning.

## Before and after

| Official criterion | Baseline | Candidate | Evidence and limit |
|---|---:|---:|---|
| Technological Implementation | 7.0 | 7.0 | [Hosted client](../src/fugu/client.py), [semantic](../src/fugu/pipeline/stages/semantic.py) and [A/B harness](../src/fugu/pipeline/stages/harness.py) implement real model roles. Retained 5 October measurements support platform use. Fresh build and 24 server tests pass, but the broad suite has 12 failures. Target execution was unavailable in the latest benchmark, and no fresh paid audit ran here. Stream correctness supports a narrow boundary; it does not justify a technical-score increase. |
| Design | 7.0 | 7.5 | [Entry/result flow](../web/src/App.tsx), coverage, exhibits, saved-run resume and labeled simulation form a coherent install decision. Baseline failure inspection reproduced continued reconnects, missing error detail and misleading listening text. Candidate desktop/mobile inspection shows a stopped stream, retained reason and working retry action. This demonstrated improvement earns 0.5. Long mobile panels, lint warnings, unverified fresh live success and absent public judge materials limit the score. |
| Potential Impact | 7.0 | 7.0 | Developers vetting community skills, MCP servers and plugins are a specific audience. Source evidence and dated fixture outcomes address the install decision. Small, clustered, previously visible inputs do not establish broad effectiveness; adoption, incident prevention and time savings are unmeasured. |
| Quality of the Idea | 8.0 | 8.0 | Concealment decoding, local matches, hosted semantic reading, two-model stated-response comparison and cross-member composition yield inspectable evidence. Nemotron has a substantive role. Existing scanners are prior art; no unique-invention or universal-superiority claim follows. |

Baseline mean: **(7.0 + 7.0 + 7.0 + 8.0) / 4 = 7.25 → 7.3/10**
(nearest tenth, half up). Candidate mean:
**(7.0 + 7.5 + 7.0 + 8.0) / 4 = 7.375 → 7.4/10**.
The small increase follows observed failure recovery. Documentation refresh
alone earns no additional points. The broad-suite failures and current evidence
gaps explain the lower fresh baseline relative to the old assessment.

## Viability and submission access

The rules require a working app with runtime Token Factory inference or AI Cloud
execution and an NVIDIA open model. Coding and Agentic Engineering is the
proposed fit; the human chooses the track. Stage One is an organizer decision.
Fugu's model-backed developer tool and historical runtime evidence support
viability; consistent operation of the eventual submitted build is unverified.
[Official requirements](https://nebiusglobalaihackathon.devpost.com/rules).

| Submission requirement | Current evidence / remaining action |
|---|---|
| Public licensed source and setup/model instructions | [MIT license](../LICENSE) and [README](../README.md) exist. Fresh `gh repo view --json nameWithOwner,isPrivate,url` reports `Anton15K/fugu`, `isPrivate: true`. Human publication and public installation check remain. |
| Working demo/test URL, free judge access through 15 December | No public URL verified. Local fixture QA is insufficient. Human deployment/access planning and rehearsal remain. |
| English description and public YouTube demonstration under three minutes | [2:45 rehearsal script](demo-script.md) is prepared; final description, recording and URL remain unverified. |
| Track, platform feedback and significant-update explanation if pre-existing | Submission fields unverified. Describe actual dated changes and model observations. |
| Eligibility, representative authority, ownership and integration/media permissions | Human confirmation outstanding. |
| Submission deadline: 30 October 2026, 17:00 UTC | Human submission outstanding. Judging runs 1–15 December. |

These requirements and dates come from the
[official rules](https://nebiusglobalaihackathon.devpost.com/rules).
Neither the rating nor a passing local build completes this checklist.

## Evidence ledger

| Evidence class | Supported | Not supported |
|---|---|---|
| Fresh source/automated checks, 6 October | Boundary check and production build exit 0; source lint exit 0 with 11 warnings; contract and scripted smoke pass; API server 24/24; stream lifecycle 6/6; reducer 25/25; actual React failure view passes. | Paid inference, real chamber execution, fresh successful live end-to-end audit, clean broad suite or public availability. |
| Fresh browser fixture, 6 October | Real production bundle at 1440×1000 and 390×844, controlled extraction failure. One stream closes, no polls follow; error remains visible, no success verdict is created, empty views stop listening, New audit clears the failure. No horizontal overflow. | The fixture supplies transport responses; it audits no source and calls no provider. LIVE ANALYSIS describes app mode, not a measured live audit. Screenshots carry a QA-fixture label. |
| Historical 5 October full workflow | Frozen engine `dbc4f641bfad39f7004e64f08bf8351697f5ae7c`: 110/140 Fugu cases complete, 30 partial; 314/320 native rows complete. 4,581 SDK dispatches and 46 searches, no recorded provider stop. | A run at baseline/candidate, target-execution proof, population accuracy, adjudicated false-positive rate, dollar cost or remaining credits. |
| Historical 2 October full capability | [Dated report](benchmark-full.md) retains Docker fake-canary observation and all-stage run. | Runtime availability on this candidate or activation of every target. Remote Nebius Sandboxes transport remains unverified. |
| Historical 3 October bounded inference | [Continuation](benchmark-current-limits-continuation.md): 39/40 complete across two intervals, original partial case retained. | An independent rerun or current all-stage result. |

The [5 October report](benchmark-full-workflow-20261005.md),
[safe results](../bench/results/2026-10-05-full-workflow/measurement/results.json)
and [provenance](../bench/results/2026-10-05-full-workflow/measurement/provenance.json)
retain exact inputs, native thresholds, exclusions and requested/served model
metadata. Original raw replies remain private.

On complete identical inputs, Fugu flagged 80/80 metadata attacks versus
Sentinel's 11/80 and MCP-Sec's 12/80 at their primary thresholds. Cisco MCP and
Fugu both flagged 74/74. Cisco Skill flagged 3/3 skill attacks versus Fugu's 2/3;
only three attack pairs and six control pairs completed. MCP-Sec's any-alert
result is separately 66/80, not its primary 12/80. Thresholds are uncalibrated;
these figures do not rank general scanner quality.

Fugu raw control flags are **1/19 metadata** and **2/6 skills**; adjudication
remains null. All eight source rows are partial, and composition has no complete
attack sets and only 2/6 complete control sets. Composition controls can include
risky members and do not form a clean-package denominator. Twenty-eight Fugu
partials retain unavailable applicable detonation; two retain harness
shortfalls. A completed process or model-only finding cannot erase these gaps.

The [production limits](production-limits.md) remain unchanged: bounded source
and probe inputs, 4,096 output tokens, 90-second request timeout and zero SDK
automatic retries; explicit response recovery is separately counted. Ultra
handles semantic/default harness calls, Super the everyday-agent arm. Nano is a
router option, not a demonstrated active analysis stage. Harness response text
is stated behavior, not executed tool behavior. A missing check is not safety.

## Selected improvement and deferred work

| Rank | Opportunity / likely benefit | Effort and risk | Decision |
|---|---|---|---|
| 1 | Terminal failures and stale streams: coherent judge experience | Small frontend change; stale evidence can contaminate later audits | Implemented and regression-tested against existing server `verdict`/`error` contract. No API/dependency changes. |
| 2 | Current evidence and rehearsal claims: credible explanation | Small documentation change; overclaim risk | Implemented; retain dated partials, raw control flags and human access gaps. |
| 3 | Public demo, repository and video: submission access | High benefit; owner credentials, deployment and publication decisions | Human-controlled, outside assignment authority. Rehearsal materials prepared. |
| 4 | Broad-suite failures and mobile panel sizing: reliability/usability | Separate failing contracts and existing layout; larger review surface | Recorded for follow-up; no Python or unrelated layout changes in this bounded fix. |
| 5 | Reliable chamber activation and raw-flag adjudication: stronger technical evidence | Requires authorized execution, fresh measurement and independent judgment | Deferred; no paid calls or benchmark rerolls authorized here. |
| 6 | Broad visual redesign | Larger regression surface with less immediate acceptance value | Deferred in favor of a reproduced failure defect. |

The [server](../src/fugu/server/app.py) already ends streams after `verdict` or
`error`. The candidate aligns [the browser client](../web/src/lib/api.ts),
records failure reasons and interrupted stages in
[the monitor](../web/src/views/PipelineMonitor.tsx), and never synthesizes PASS.
Completed findings remain available. Owned reconnect timers and late polling
callbacks cannot outlive a closed audit.

## Reproduction and validation limits

From repository root, without synchronizing a reused Python environment:

```sh
python3 tools/check_orchestration_boundary.py && npm --prefix web run build
PYTHONPATH="$PWD/src:$PWD" uv run --no-sync python -m pytest tests/test_server.py -q
cd web
npm run lint -- --ignore-pattern dist
npm run contract
npm run smoke
node scripts/audit-result.mjs
node scripts/stream-lifecycle.mjs
node scripts/edge-reducer.mjs
node scripts/failed-audit.mjs
```

All above completed with exit 0. Plain `npm run lint` also exited 0, but scans
minified distribution assets and prints substantial generated-code warnings;
the source-scoped invocation retains 11 existing warnings. The three new or
extended behavioral scripts each failed after per-file reversion of the source
fixes and passed after restoration.

The broad `PYTHONPATH="$PWD/src:$PWD" uv run --no-sync python -m pytest -q`
exited **1: 965 passed, 12 failed, 5 skipped, 23 subtests passed**. Four failures
are composition expectations, seven are continuation tests asserting absence
of a historical `data-release.json`, and one stored-run restart test never
finishes within its five-second window. Repeating those three files produced
the same 12 failures (124 passed). Python source/tests are unchanged from the
baseline. Root cause and fixes for composition/restart are not established
here; do not treat this as a green repository suite.

Desktop failure details and retry fit together; mobile error text wraps without
horizontal scrolling. Existing tall empty evidence/log panels require extra
vertical scrolling on mobile. Browser errors were empty in the owned fixture
session. Live paid success, fresh target execution, public deployment and
submission-state checks remain unavailable in this task. The coder handoff
stores pasted outputs, fixture generator and before/after screenshots outside
the application repository for independent fleet review.
