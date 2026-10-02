# Fugu: current hackathon assessment

Assessed 2 October 2026 after the full-capability benchmark. The [official rules, section 6](https://nebiusglobalaihackathon.devpost.com/rules) use four equally weighted criteria after a viability check. The 0–10 scale below is our advisory assessment, not an official score or a prediction of winning.

## Current rating: 7.6/10

| Official criterion | Advisory score | Evidence and what limits the score |
|---|---:|---|
| Technological Implementation | **7.5/10** | Nemotron Ultra and Super perform substantive runtime work on Nebius Token Factory. All seven pipeline capabilities were exercised, including real Docker canary observations and composition. The full Python suite passes 511 tests. The initial benchmark completed only 15/40 cases before benchmark-only response recovery; default output limits remain unchanged. The A/B harness measures stated plans, content is bounded, and remote Sandboxes transport remains unverified. |
| Design | **8/10** | The product supports source selection, result-first verdicts, inspectable exhibits, explicit coverage, saved-run resume and labeled simulation. Prior reviewed desktop/mobile observations and two live UI audits support the workflow. This assessment does not claim a new browser inspection, and no published judge demo is available. |
| Potential Impact | **7/10** | The audience and decision are specific: developers reviewing third-party skills, MCP servers and plugins before granting access. The external attack sample, source findings and observed canary behavior demonstrate useful risk signals. Fifteen external attacks and authored fixtures do not establish broad effectiveness; there is no measured adoption, time saving or incident prevention. |
| Quality of the Idea | **8/10** | Combining concealment decoding, semantic reading, canary execution evidence, two-model behavioral comparison and cross-extension composition produces an inspectable install decision. The NVIDIA models serve real analysis roles. Prior art exists; novelty and value are the combined workflow, without a claim of unique runtime scanning or universal superiority. |

Equal-weight mean: **(7.5 + 8 + 7 + 8) / 4 = 7.625**, rounded to **7.6/10**. The new execution evidence strengthens the technical case. It does not remove the observed response reliability problem or substitute for demonstrated use by the intended audience.

## Audience and demonstrated decision

A developer wants to install a community extension into an AI coding assistant that can read a workspace and invoke tools. Fugu returns localized evidence, a severity/evidence tier, verdict reasons and completed/skipped/partial coverage so the developer can decide whether to install or investigate the extension. PASS is limited to completed checks.

The UI and backend were integrated and independently reviewed in [PR #2](https://github.com/Anton15K/fugu/pull/2), merged at `270b9164e2e3d98a8b84bbdc111092f5fa5aaa5b`. That review recorded production build, lint, contract, smoke, mapper and reducer checks, desktop/mobile browser observations and two paid UI audits. Lint retained warnings. Those UI observations predate the new full benchmark; they are historical evidence, not a fresh live session for this assessment.

## Current benchmark and verification

The [full benchmark report](benchmark-full.md) supersedes the older partial-stage headline evaluation. Forty cases were frozen before live inference: 15 MCPTox attack descriptions, five constructed clean descriptions, 11 source fixtures, seven composition sets and two dependency probes. Every applicable check completed after bounded recovery. Forty-five unique member/single audits and seven composition checks exercised every capability. Application hashes remained unchanged.

On identical description inputs, Fugu alerted on **12/15 attacks (80%)**, fuzzd on **10/15 (66.7%)** at medium severity or above, and fuzzd on **11/15** at any severity. **Confirmed false positives: 0**, using the agreed security-risk reporting classification. mcp-sec-audit capability hits and aggregate risk are separate outcomes; Snyk's hosted quota exhaustion leaves it unscored. No population false-positive rate or global competitor ranking follows from this sample.

The authored source attack fixtures produced **7/7 alerts**. Composition produced **4/4 attack-set rule alerts** and **0/3 control-set rule alerts**. Both dependency pins have exact-version OSV records, so the originally designated dependency control cannot establish clean-dependency specificity. These cohorts remain separate from the external attacks.

Initial completion was **15/40**. Seven malformed structured replies recovered with bounded retries, and 52 empty Super-arm replies recovered through one identical-prompt retry each with 4,096 output tokens. Valid original responses were retained. Final completion was **40/40**, with no unresolved parsing exclusions. The recovery did not alter application defaults.

The Docker chamber captured a fake-canary hit and six HTTP flows on the installer-exfil fixture. A supplementary diagnostic also observed an import trigger failing with `ModuleNotFoundError`; chamber execution coverage is not proof that every target activated. Remote Contree/Nebius Sandboxes behavior remains unverified.

Fresh integration check for publication:

```sh
PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' TAVILY_API_KEY='' uv run --no-sync python -m pytest -q -p no:cacheprovider
```

Observed result: **511 passed**, with one existing Starlette/anyio deprecation warning. This check made no paid provider calls. The 37 scoped benchmark/harness/chart checks and independent artifact review additionally verified raw-result arithmetic, exact recovery prompts/models, preservation of 1,350 original evidence files and all application hashes. The separate reporting revision passed three chart tests and review. Commit-specific publishing review is recorded on the new task PR.

## Submission readiness

The [official requirements](https://nebiusglobalaihackathon.devpost.com/rules) require a public licensed repository, a working demo or test-build URL, setup/model explanation, a public YouTube video under three minutes, and platform feedback. Judge access must remain free through 15 December. Runtime Token Factory calls satisfy the platform requirement; Nebius hosting is optional. Submission closes 30 October at 17:00 UTC.

| Item | Current status |
|---|---|
| Model/platform integration | Demonstrated runtime Nebius Token Factory calls using NVIDIA models; Tavily reputation searches also ran. |
| Repository | Private, confirmed through GitHub on 2 October. MIT license and setup instructions are present. Visibility is unchanged by this publishing task. |
| Demo/test build | Local build and recorded UI evidence exist; no published judge-access URL is recorded. Deployment is not assigned by this task. |
| Video | A [2:45 recording script](demo-script.md) exists; recording and public YouTube URL remain outstanding. |
| Runtime reliability | Real Docker execution now demonstrated. Default harness response limits and trigger activation remain material limits. |
| Provider feedback | Raw run evidence supports specific model/output observations; submission feedback has not been completed. |

The next improvements with the largest effect on the demonstrated submission are a reliable end-to-end judge demo, the public video, and access to the repository/test build. Technical improvement should address the observed missing-response behavior and activation gaps before making stronger robustness claims.
