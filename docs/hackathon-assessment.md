# Fugu: current hackathon assessment

Ratings were first assessed 2 October 2026 after the full-capability benchmark; this evidence update is dated 3 October 2026. The [official rules, section 6](https://nebiusglobalaihackathon.devpost.com/rules) use four equally weighted criteria after a viability check. The 0–10 scale below is an advisory assessment, not an official score or a prediction of winning. The current production candidate passed independent correction review. Its separate 3 October current-profile run stopped early and is reported below. Readiness, review status, measured outcomes, and subjective scores are separate facts.

## Current rating: 7.6/10

| Official criterion | Advisory score | Evidence and what limits the score |
|---|---:|---|
| Technological Implementation | **7.5/10** | The immutable production profile permits larger, explicit semantic and harness inputs, and the evidence/coverage corrections received independent review. The 2 October full-capability run remains the all-stage result. The separate 3 October current-profile run stopped after 359 SDK attempts: 12/40 cases completed, one partial and 27 unattempted; its MCPTox primary result is 11/15 planned attacks. The A/B harness compares stated model responses, not executed tool actions, and remote Sandboxes transport remains unverified. |
| Design | **8/10** | The product supports source selection, result-first verdicts, inspectable exhibits, explicit coverage, saved-run resume and labeled simulation. Prior reviewed desktop/mobile observations and two live UI audits support the workflow. This assessment does not claim a new browser inspection, and no published judge demo is available. |
| Potential Impact | **7/10** | The audience and decision are specific: developers reviewing third-party skills, MCP servers and plugins before granting access. The dated 2 October attack sample, source findings and observed canary behavior demonstrate useful risk signals. Fifteen external attacks and authored fixtures do not establish broad effectiveness; there is no measured adoption, time saving or incident prevention. |
| Quality of the Idea | **8/10** | Combining concealment decoding, semantic reading, canary execution evidence, two-model behavioral comparison and cross-extension composition produces an inspectable install decision. The NVIDIA models serve real analysis roles. Prior art exists; novelty and value are the combined workflow, without a claim of unique runtime scanning or universal superiority. |

Equal-weight mean: **(7.5 + 8 + 7 + 8) / 4 = 7.625**, rounded to **7.6/10**. These advisory ratings remain anchored to the 2 October assessment; the stopped 3 October subset adds limited evidence but does not establish full-profile effectiveness or broader safety. The higher limits alone do not justify a score increase.

## Audience and demonstrated decision

A developer wants to install a community extension into an AI coding assistant that can read a workspace and invoke tools. Fugu returns localized evidence, a severity/evidence tier, verdict reasons and completed/skipped/partial coverage so the developer can decide whether to install or investigate the extension. PASS is limited to completed checks.

## Current production profile and verification

The corrected candidate `cc58a58d6cea861510980814ae2e70b7bdf24e63` uses the
larger production defaults below. The [production limits reference](production-limits.md)
documents the full file caps, omissions, and recovery metrics.

| Bound | Current default |
|---|---:|
| Model output / request timeout | 4,096 tokens / 90 seconds |
| Automatic SDK retries | 0 |
| Semantic input | Up to 24 units of at most 6,000 characters each |
| Harness source and RED packet | 32,000 characters, including headings and separators |
| Generated RED probes | First 3 valid probes, at most 200 characters each |
| Materialized source tree | 512 MiB / 20,000 entries |

Zero automatic SDK retries does not mean no stage-level recovery; explicit
response recovery remains separately counted. Source-tree caps apply after
materialization and do not bound bytes transferred during a shallow clone. A
larger limit is a product capacity change, not evidence that every target will
be fully analyzed. Coverage and omission metrics remain part of the install
decision.

An independent correction review recommended pass for this exact candidate and
accepted its pre-call plan. The lead's broader integration check reports **668
passed, 2 deselected, and one existing Starlette deprecation warning**; the two
deselected tests are the previously sandbox-denied Docker end-to-end checks.
The reviewer also recorded **62 current-engine fake-SDK tests passed with zero
skips** and **198 selected integration/source tests passed**, with one existing
warning. These verify implementation and coverage accounting; they are not a
fresh provider evaluation or proof of target execution. The lead owns final PR
integration and merge requirements ([PR #6](https://github.com/Anton15K/fugu/pull/6)).

The accepted current-profile plan fixes 40 selected, previously inspected
cases, grouped into 54 member contexts, 45 distinct audits, and 63 semantic
units. Its 3 October run stopped after covering 12 cases fully and one
partially; 27 were unattempted. Within 15 planned MCPTox attacks, it recorded
11 completed detections, one completed miss, one partial case and two
unattempted cases. This is **11/15 (73.3%)** on the primary planned denominator;
**11/12 (91.7%)** is secondary and covers only completed attacks. All 12
planned benign controls were unattempted, so benign flag and false-positive
rates are unmeasured. The set is selected and previously inspected, not blind or
representative.
All 12 completed cases and the one partial case came from the MCPTox cohort; no
clean control or later crafted, composition or dependency case was reached.

The observed scope was local concealment/static and hosted semantic/harness
analysis across 13 distinct audits; 32 of 45 planned audits have unknown
coverage. Harness analysis completed 221 of 234 expected comparisons among
those observed audits. No composition case started. Detonation, live reputation,
execution of audited code and fresh competitor runs were excluded. The stopped
run made 359 SDK dispatches: 358 returned replies and the last Super harness
request returned HTTP 500. Requested/served model counts, known token subtotals,
and all coverage caveats are in the [current-limit report](benchmark-current-limits.md).
One attempt has unknown usage; whole-run token totals, cost and remaining quota
are unknown, and quota exhaustion was not established. These outcomes do not
show that the larger profile improves detection or covers all source. The
historical full-capability evaluation above remains separate.

The UI and backend were integrated and independently reviewed in [PR #2](https://github.com/Anton15K/fugu/pull/2), merged at `270b9164e2e3d98a8b84bbdc111092f5fa5aaa5b`. That review recorded production build, lint, contract, smoke, mapper and reducer checks, desktop/mobile browser observations and two paid UI audits. Lint retained warnings. Those UI observations predate the 2 October full-capability benchmark and the larger current production profile; they are historical workflow evidence, not current-profile measurements or a fresh browser inspection.

## Historical full-capability benchmark (2 October 2026)

The following measured outcomes belong to the 2 October frozen inputs and
application snapshot. They remain useful full-capability history, but they are
not a result from the larger current profile described above. Frozen source and
application hashes are retained with the [original case manifest](../bench/results/2026-10-02-full/cases.json)
and [raw results](../bench/results/2026-10-02-full/fugu-recovered.json).

The [full benchmark report](benchmark-full.md) supersedes the older partial-stage headline evaluation. Forty cases were frozen before live inference: 15 MCPTox attack descriptions, five constructed clean descriptions, 11 source fixtures, seven composition sets and two dependency probes. Every applicable check completed after bounded recovery. Forty-five unique member/single audits and seven composition checks exercised every capability. Application hashes remained unchanged.

On identical description inputs, Fugu alerted on **12/15 attacks (80%)**, fuzzd on **10/15 (66.7%)** at medium severity or above, and fuzzd on **11/15** at any severity. **Confirmed false positives: 0**, using the agreed security-risk reporting classification. mcp-sec-audit capability hits and aggregate risk are separate outcomes; Snyk's hosted quota exhaustion leaves it unscored. No population false-positive rate or global competitor ranking follows from this sample.

The authored source attack fixtures produced **7/7 alerts**. Composition produced **4/4 attack-set rule alerts** and **0/3 control-set rule alerts**. Both dependency pins have exact-version OSV records, so the originally designated dependency control cannot establish clean-dependency specificity. These cohorts remain separate from the external attacks.

Initial completion was **15/40**. Seven malformed structured replies recovered with bounded retries, and 52 empty Super-arm replies recovered through one identical-prompt retry each with 4,096 output tokens. Valid original responses were retained. Final completion was **40/40**, with no unresolved parsing exclusions. That recovery changed benchmark completion, not the application source or defaults used for the 2 October run; the larger current profile is a separate later change.

The Docker chamber captured a fake-canary hit and six HTTP flows on the installer-exfil fixture. A supplementary diagnostic also observed an import trigger failing with `ModuleNotFoundError`; chamber execution coverage is not proof that every target activated. Remote Contree/Nebius Sandboxes behavior remains unverified.

## Submission readiness

The [official requirements](https://nebiusglobalaihackathon.devpost.com/rules) require a public licensed repository, a working demo or test-build URL, setup/model explanation, a public YouTube video under three minutes, and platform feedback. Judge access must remain free through 15 December. Runtime Token Factory calls satisfy the platform requirement; Nebius hosting is optional. Submission closes 30 October at 17:00 UTC.

| Item | Current status |
|---|---|
| Model/platform integration | The 2 October full-capability run recorded runtime Nebius Token Factory calls using NVIDIA models; Tavily reputation searches also ran. The 3 October stopped subset recorded requested/served model IDs and known usage in the current-limit report; one failed attempt has unknown usage. |
| Repository | Private, confirmed through GitHub on 2 October. MIT license and setup instructions are present. Visibility is unchanged by this publishing task. |
| Demo/test build | Local build and recorded UI evidence exist; no published judge-access URL is recorded. Deployment is not assigned by this task. |
| Video | A [2:45 recording script](demo-script.md) exists; recording and public YouTube URL remain outstanding. |
| Runtime reliability | Real Docker execution was demonstrated in the 2 October full-capability run. The 3 October current-profile run covered source/inference only and stopped at HTTP 500; it did not test detonation. Trigger activation remains a limit. |
| Provider feedback | Raw run evidence supports specific model/output observations; submission feedback has not been completed. |

The next submission steps are a reliable end-to-end judge demo, the public video, and access to the repository/test build. The corrected response and coverage handling has independent review. The stopped current-profile run leaves 28 of 40 cases unfinished and every benign control unattempted; it does not establish benign rates or complete-profile effectiveness. Avoid stronger effectiveness claims.
