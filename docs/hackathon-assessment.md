# Fugu: hackathon assessment and readiness

Assessed 2026-10-02. This is an advisory 0–10 scale, not official scoring,
a winning-probability forecast or release acceptance. The [official overview](https://nebiusglobalaihackathon.devpost.com/)
and [rules §6](https://nebiusglobalaihackathon.devpost.com/rules) name four equally
weighted criteria. The table preserves the defect-verified baseline and separates
observed improvements from pending acceptance.

## Audience and intended decision

A developer wants to add a community skill to an AI coding assistant that can
read a workspace and invoke tools. The developer needs specific evidence before
granting access, rather than a warning without a source or a generic safety score.

**User story:** Before installing a community extension, I want to inspect its
suspicious instructions or behavior, distinguish model judgment from direct
evidence, and understand which checks completed, so I can reject it or review
the specific risk before granting access.

Success is observable: choose a supported source, start an audit, open the decisive
exhibit, interpret verdict and coverage, make an install decision, and revisit the
same audit URL. There is no measured adoption, prevented-incident or time-saving
claim. The persona and expected benefit are product hypotheses.

## Criterion assessment

“After” scores are conditional assessments of the observed working-tree
improvements, with integrated working-tree checks observed and independent
review of the exact commit still pending.
They are not evidence that a release is accepted.

| Official criterion | Before | Conditional after | Evidence and remaining limit |
|---|---:|---:|---|
| Technological Implementation | 4 | 7 | Baseline safe reproductions exposed outside-source symlink reads, failed inference counted successful, and parent PASS hiding child failures. Current source rejects descendant symlinks and carries failure/partial/member coverage. Backend owner evidence shows 133 scoped tests passing and lead integration reports 411 passed, 2 skipped; exact-commit review pending; no current live Docker/Sandboxes proof. |
| Design | 4 | 8 | Vite dev alias failure was reproduced then repaired. Frontend checked desktop/mobile live entry, result-first exhibits, simulated labels, error feedback and saved-run resume. The UI displays server caveats; that alone cannot prove server coverage correctness. |
| Potential Impact | 5 | 7 | Two bounded real UI sample audits demonstrated a suspicious FAIL and clean-sample PASS with inspectable evidence. This supports a believable install decision; crafted samples do not establish production incident prevention or ecosystem accuracy. |
| Quality of the Idea | 8 | 8 | Combining local decoding, semantic reading, canary observations and A/B intent comparisons with explicit evidence tiers remains compelling. Prior art and model variability remain; novelty is the decision workflow, not proven scanner superiority. |

## Evidence and verification status

Baseline backend assessment: qitem-20261002064850-aeff34c7; fabricated `/tmp`
notes and fake inference/stages reproduced the defects without reading real
credentials or making paid calls. The symlink case proves a prompt-boundary
failure, not measured live exfiltration. Baseline advisory scores are 4/4/5/8.

Frontend handoff: qitem-20261002064043-6c57943b. Owner-reported build, lint,
contract, smoke, mapper, 14 reducer checks and 17 scoped Python tests passed.
Lint retained warnings. Delivery inspected the final desktop live-result and
mobile entry captures: verdict reasons, coverage, evidence and source controls
are visible. Vite baseline failure concerns the dev import path; it does not
imply the existing built bundle was unavailable.

Exactly two paid UI audit observations were reported by frontend: hidden
instructions job `72006380c27f` returned FAIL with four findings in 50.6 seconds;
benign job `ab3f6401b3b2` returned PASS with one INFO in 46.6 seconds. The existing
suspicious audit URL restored its events. Those runs predate backend coverage
fixes and are neither new benchmark cases nor live detonation proof.

Backend current implementation is visible in [source safety](../src/fugu/source_safety.py),
[verdict policy](../src/fugu/verdict.py), semantic/harness stage completion and
composition member-coverage propagation. Delivery read the final backend report
and test output: 133 scoped tests passed
with one existing deprecation warning. They include external/internal/broken
symlink rejection, all-call and malformed-output failure, partial evidence
preservation, FAIL precedence, no-trigger skips, both composition paths,
fan-out caps and exact SSE/SQLite replay. Lead subsequently reported the full
integrated working-tree suite: **411 passed, 2 skipped**, one pre-existing
Starlette warning, using `uv run --no-sync pytest -q -p no:cacheprovider`
with dotenv disabled and empty provider keys. Lead also reported build and lint
passing with retained warnings. These are observed checks of the candidate,
not an independently reviewed commit; exact-commit review remains pending. The frontend
shows the human-readable caveats but does not yet consume the new structured
member-coverage or omitted-unit fields directly.

The [fresh benchmark](benchmark.md) is a separate frozen pre-fix S0/S1/S2
measurement: 26/30 planned attack detections, 28 completed with two misses and
two incomplete cases; constructed clean 0/20 flags; public skills 0/19 completed
with one incomplete of 20. Delivery independently counted raw rows. Results
remain separated by provenance; no full-corpus or zero-population-FPR inference
is justified. [Comparator context](head-to-head.md) explains label-contaminated
historical results and incompatible published protocols.

## Submission readiness, separate from scores

As checked against the official rules on 2026-10-02: a runtime Token Factory call
satisfies the platform requirement; Nebius deployment is optional. Submission
needs a working demo/test-build URL, public licensed repository, setup/model
explanation, public YouTube video under three minutes, track, description and
platform feedback. English materials and free judge access through December 15
are required. Deadline: October 30, 17:00 UTC; judging ends December 15, 20:00 UTC.
Pre-period projects need an update explanation. Tavily bonus requires a functional
runtime call. Rules §7 excludes harmful submission code; clarify treatment of
security-test fixtures with the organizer rather than asserting eligibility.

| Item | Actual status / next action |
|---|---|
| Repository | Private per lead; MIT license present. Publication/visibility remains an owner action. |
| Demo access | Local UI evidence exists; no assigned deployment target or published judge URL. Assign hosting/access and availability plan. |
| Video | Script prepared; recording, public YouTube publication and final URL not completed. |
| Final acceptance | Integrated working-tree checks passed as reported above; exact-commit independent review pending; after scores advisory and conditional. |
| Live execution | Docker unavailable in this environment; Nebius Sandboxes live transport unverified. Keep canary demo conditional. |
| Provider feedback | See observations below; author must supply submission feedback and confirm eligibility/registration. |

Observed sponsor feedback: Token Factory supported the bounded final run's
111 recorded successful API calls and retained usage. Three cases had model JSON
parse failures; raw completions/finish reasons were not retained, so cause is
unknown. No provider/quota error was observed in that run; remaining quota and
cost are unknown. No firsthand AI Cloud, live Sandbox or NVIDIA hardware
experience was established. Avoid invented testimonials or feedback.

Priorities within this outcome: verify the repaired boundary/coverage paths on
the integrated commit; rehearse the [script](demo-script.md) with actual sample
and resume controls; obtain authorized judge access and public materials. Source
preflight is not race-proof sandboxing, and owner-local path access/CORS/privileged
Docker operations need a target-specific review before public deployment.
