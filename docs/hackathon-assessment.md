# Fugu: current hackathon assessment

Ratings were first assessed 2 October 2026 after the full-capability benchmark; this evidence update is dated 3 October 2026. The [official rules, section 6](https://nebiusglobalaihackathon.devpost.com/rules) use four equally weighted criteria after a viability check. The 0–10 scale below is an advisory assessment, not an official score or a prediction of winning. Independent review accepted source/plan/bootstrap candidate `2b5e134f11ff4a1349d519dfaa2f0051c2012e1f`; the measured engine is frozen at `cc58a58d6cea861510980814ae2e70b7bdf24e63` across 37 Python files. These documentation edits and the final integrated candidate still need lead review. Readiness, code review, measured outcomes, and subjective scores are separate facts.

## Current rating: 7.6/10

| Official criterion | Advisory score | Evidence and what limits the score |
|---|---:|---|
| Technological Implementation | **7.5/10** | The immutable production profile permits larger, explicit semantic and harness inputs, and the source/plan/bootstrap candidate received independent review. The 2 October run remains the all-stage result. The 3 October current-profile continuation completed 39/40 cases across two intervals, leaving the original case partial; its MCPTox primary result is 13/15 planned attacks. One clean-description raw flag awaits independent adjudication, so an adjudicated false-positive rate is unavailable. This source/inference measurement excluded detonation, reputation, and target execution. The A/B harness compares stated model responses, not executed tool actions, and remote Sandboxes transport remains unverified. |
| Design | **8/10** | The product supports source selection, result-first verdicts, inspectable exhibits, explicit coverage, saved-run resume and labeled simulation. Prior reviewed desktop/mobile observations and two live UI audits support the workflow. This assessment does not claim a new browser inspection, and no published judge demo is available. |
| Potential Impact | **7/10** | The audience and decision are specific: developers reviewing third-party skills, MCP servers and plugins before granting access. The dated 2 October attack sample, source findings and observed canary behavior demonstrate useful risk signals. Fifteen external attacks and authored fixtures do not establish broad effectiveness; there is no measured adoption, time saving or incident prevention. |
| Quality of the Idea | **8/10** | Combining concealment decoding, semantic reading, canary execution evidence, two-model behavioral comparison and cross-extension composition produces an inspectable install decision. The NVIDIA models serve real analysis roles. Prior art exists; novelty and value are the combined workflow, without a claim of unique runtime scanning or universal superiority. |

Equal-weight mean: **(7.5 + 8 + 7 + 8) / 4 = 7.625**, rounded to **7.6/10**. The ratings remain unchanged. The 3 October continuation adds evidence on the same selected case set, but one case remains partial and the benign flag is unresolved; it does not establish blind accuracy, population false-positive rate, or broader safety. The higher limits and additional completed cases alone do not justify a score increase.

## Audience and demonstrated decision

A developer wants to install a community extension into an AI coding assistant that can read a workspace and invoke tools. Fugu returns localized evidence, a severity/evidence tier, verdict reasons and completed/skipped/partial coverage so the developer can decide whether to install or investigate the extension. PASS is limited to completed checks.

## Current production profile and verification

The measured engine snapshot `cc58a58d6cea861510980814ae2e70b7bdf24e63` uses the
larger production defaults below. The separately reviewed source/plan/bootstrap
candidate is `2b5e134f11ff4a1349d519dfaa2f0051c2012e1f`; final documentation
integration and review remain pending. The [production limits reference](production-limits.md)
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

Independent review accepted the source, plan, and bootstrap for the exact
`2b5e134f11ff4a1349d519dfaa2f0051c2012e1f` candidate. The measured engine
snapshot remains pinned to `cc58a58d6cea861510980814ae2e70b7bdf24e63`. Those
checks support implementation and protocol integrity; they are not a provider
effectiveness result or proof of target execution. Lead integration, review of
this documentation candidate, and required CI remain pending; no final
integrated commit is claimed here.

The accepted plan fixes 40 selected, previously inspected cases: 15 MCPTox
attack descriptions, five clean descriptions, 11 crafted source cases, seven
composition sets, and two dependency source cases. It groups them into 54 member
contexts, 45 distinct audits, and 63 semantic units. The first interval stopped
at SDK attempt 359 on an HTTP 500 from the Super harness after 12 cases completed,
one became partial, and 27 remained unattempted. The authenticated continuation
completed those 27 cases with 919 further attempts and no child stop. Across the
two intervals, **39/40 cases completed, one original case remains partial, and
none are unattempted**; total SDK attempts were 1,278. The engine, limits, and
inputs did not change between intervals. This is a continuation of one fixed
case set, not a new independent 40-case rerun.

Within the 15 planned MCPTox attacks, **13 are completed detections**, one is a
completed miss, and one is incomplete with a retained high advisory finding
that receives no completed detection credit. The primary planned-denominator
result is **13/15 (86.7%)**; **13/14 (92.9%)** is secondary and covers completed
attacks only. All five clean descriptions completed; one produced a raw flag
pending independent adjudication, so an adjudicated false-positive rate is
unavailable. The retained author assessment links the `read_file` flag to
synthetic-canary text in mounted-model replies. No file tool or target
filesystem ran, and the source-classification judgment is not independently
adjudicated. The selected, previously inspected set is not blind or
representative.

On the same 14 completed MCPTox attack IDs, current Fugu recorded 13/14;
reused 2 October comparator outputs recorded 10/14 for fuzzd and 0/14 for
mcp-sec-audit. Fugu and fuzzd use medium-plus findings; mcp-sec-audit uses
aggregate risk 25+. The comparators were not
rerun and their risk contracts differ; these fixed-sample results are context,
not a universal ranking. The separate 2 October full-capability evaluation
above remains the only all-stage run.

The continuation covers local concealment/static, hosted semantic and
stated-intent harness analysis, and source composition. All 63 semantic units
completed; 779 of 792 expected harness comparisons completed, with 13 missing
from the original partial case. Crafted source cases recorded 7/7 attack
detections and 0/4 benign case flags; composition matched 3/4 attack rules and
0/3 control rules. Two composition controls also retain medium-plus findings
in member audits despite negative set-level composition outcomes; these are
separate measures. The two dependency cases completed source/inference stages,
but their reputation outcomes are unavailable. Detonation, live reputation,
target/tool execution, and fresh competitor execution were excluded. The first
interval's HTTP 500 remains in combined accounting; the failed request has
unknown usage, so whole-run token totals are null. Cost and remaining quota were
not measured. See the [first-interval stop report](benchmark-current-limits.md)
and the [sealed continuation report](benchmark-current-limits-continuation.md)
for input lineage, interval usage, charts, and evidence links.

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
| Model/platform integration | The 2 October full-capability run recorded runtime Nebius Token Factory calls using NVIDIA models; Tavily reputation searches also ran. The 3 October two-interval current-profile evaluation made 1,278 SDK attempts across the hosted model arms. The original HTTP 500 request has unknown usage, so whole-run token totals remain null; interval details are in the [continuation report](benchmark-current-limits-continuation.md). |
| Repository | Private, confirmed through GitHub on 2 October. MIT license and setup instructions are present. Visibility is unchanged by this publishing task. |
| Demo/test build | Local build and recorded UI evidence exist; no published judge-access URL is recorded. Deployment is not assigned by this task. |
| Video | A [2:45 recording script](demo-script.md) exists; recording and public YouTube URL remain outstanding. |
| Runtime reliability | Real Docker execution was demonstrated in the 2 October full-capability run. The 3 October current-profile measurement covered source/inference and source composition only; its first interval stopped at HTTP 500, and the continuation did not test detonation, reputation, or target execution. Trigger activation remains a limit. |
| Provider feedback | Raw run evidence supports specific model/output observations; submission feedback has not been completed. |

The next submission steps are a reliable end-to-end judge demo, the public video, and access to the repository/test build. The corrected response and coverage handling has independent review, while this documentation candidate still needs lead integration and review. The current-profile continuation leaves one of 40 cases partial; one clean-description flag awaits independent adjudication, so no adjudicated false-positive rate is available. The run excludes detonation and target execution and does not establish broad effectiveness. Avoid stronger claims.
