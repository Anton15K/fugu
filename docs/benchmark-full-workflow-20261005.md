# Full-workflow benchmark measurement, 2026-10-05

The frozen Fugu workflow processed all **140 planned cases: 110 completed and 30 partial**. Four native comparator lanes processed **320 rows: 314 completed and six partial**. Both processes exited successfully. Actual accounting is **4,581 SDK dispatches and 46 searches**, with no recorded provider error or quota/budget stop. Target execution remained unavailable under the retained chamber boundary.

Authenticated data grant: `qitem-20261005103009-2753fe32`. Parent: `qitem-20261005074008-c9c49a27`; original preparation: `qitem-20261005074955-950c0451`; import correction and expansion: `qitem-20261005092830-589f17b9`. The accepted inputs, engine, thresholds, native options and budgets were frozen before observation. No detector tuning or result reroll followed the measurements.

[Safe results](../bench/results/2026-10-05-full-workflow/measurement/results.json), [compact SDK metadata](../bench/results/2026-10-05-full-workflow/measurement/sdk-calls.jsonl), [provenance](../bench/results/2026-10-05-full-workflow/measurement/provenance.json), [checks](../bench/results/2026-10-05-full-workflow/measurement/checks.json) and [schema-2 inventory](../bench/results/2026-10-05-full-workflow/measurement/inventory.json) support offline recount and plotting. Original raw replies/findings remain private and hash-bound. These are clustered convenience fixtures with previously visible sources; they do not establish blind population performance.

## Complete matched comparisons

Each row uses exactly the complete case-ID/input-hash intersection for that scanner and label. Fractions show primary flags over matched cases. All planned exclusions remain in the coverage panel and safe rows.

| Comparator / cohort | Attack pairs / planned | Fugu attack flags | Native attack flags | Control pairs / planned | Fugu raw control flags | Native raw control flags |
|---|---:|---:|---:|---:|---:|---:|
| Sentinel / metadata | 80/80 | 80/80 | 11/80 | 19/20 | 1/19 | 2/19 |
| MCP-Sec / metadata | 80/80 | 80/80 | 12/80 | 19/20 | 1/19 | 0/19 |
| Cisco MCP / metadata | 74/80 | 74/74 | 74/74 | 19/20 | 1/19 | 0/19 |
| Cisco Skill / skills | 3/10 | 2/3 | 3/3 | 6/10 | 2/6 | 0/6 |

Cisco MCP and Fugu both flag 74/74 matched metadata attacks. Cisco Skill flags 3/3 matched skill attacks and Fugu flags 2/3; only three attack pairs and six control pairs are complete. Those small intersections support no broader skill, source or composition ranking. Fugu's raw control flags remain 1/19 metadata and 2/6 skills. All `adjudicated_false_positive` fields remain null; raw flags are not adjudicated false positives or a population FPR estimate.

Primary thresholds differ and are uncalibrated. The retained secondary `any_alert` counts are: Sentinel 12/80 attacks and 6/19 controls; MCP-Sec 66/80 and 6/19; Cisco MCP 74/74 and 0/19; Cisco Skill 3/3 and 1/6. MCP-Sec's 12/80 primary result therefore differs substantially from its 66/80 any-alert result. Neither metric should be substituted silently. Paired disagreements, matched IDs, excluded statuses and Wilson 95% intervals are in the safe results.

![MCP metadata primary flags on complete identical inputs](../bench/results/2026-10-05-full-workflow/measurement/metadata-paired.png)

![Skill primary flags on the supported complete intersection](../bench/results/2026-10-05-full-workflow/measurement/skills-paired.png)

## Planned coverage and exclusions

| Fugu cohort | Complete attacks / planned | Complete controls / planned | Partial cases |
|---|---:|---:|---:|
| MCP metadata | 80/80 | 19/20 | 1 |
| Skills | 3/10 | 6/10 | 11 |
| Composition | 0/6 | 2/6 | 10 |
| Source | 0/4 | 0/4 | 8 |

All 30 incomplete Fugu rows are partial: 28 have applicable detonation unavailable under the retained chamber boundary, and two have harness shortfalls. `clean/get_git_log` completed 17/18 harness comparisons with no final parse-error entries and one native call-error entry. `anthropic-skill/skills/web-artifacts-builder` completed 18/18 with no parse/call errors, but omitted 59 generated-probe characters. The latter is probe truncation. Both original histories are retained without another run. Per-case/member stage states and numeric omissions remain in the export.

Native completion is Sentinel 100/100, MCP-Sec 100/100, Cisco Skill 20/20 and Cisco MCP 94/100. Six Cisco MCP attack rows have unsuccessful LLM analyzer coverage and native infrastructure diagnostics: `Commander-71`, `SQLite-10`, `HyperBrowser-30`, `Git-0`, `Puppeteer-28` and `Gyazo-1`. YARA completed on those rows. Four still contain a retained raw security alert; all six remain partial and excluded from complete intersections. Infrastructure failures are not security detections or valid negatives. No planned case or comparator row is unattempted.

Composition controls test a cross-member claim and may contain risky individual members; they do not enter a clean-package false-alert denominator. Source/composition have no selected native comparator interface. Genuine zero-trigger N/A supplies no runtime-safety proof.

![All planned Fugu and native comparator completion coverage](../bench/results/2026-10-05-full-workflow/measurement/completion-coverage.png)

## Actual intervals and accounting

| Lane | UTC interval | Actual SDK dispatches | Prompt tokens | Completion tokens |
|---|---|---:|---:|---:|
| Fugu | 10:31:06.071889–12:41:46.784017 | 4,441 | 1,236,011 | 1,404,386 |
| Native competitors | 12:46:45.415865–12:54:36.402889 | 140 | 627,068 | 108,334 |
| Total, 2026-10-05 | Separate sequential intervals above | 4,581 | 1,863,079 | 1,512,720 |

All 4,581 SDK usage records have known prompt and completion token counts. Fugu journals contain 1,800 / 1,800 / 841 actual creates, each at 4,096 output tokens. Cisco Skill made 20 requests at 8,192 tokens; Cisco MCP made 120 at 1,000 tokens, reflecting description/schema invocations. The measured requested-output envelope is 18,474,176 tokens, within the fixed 36,864,000 ceiling; it is not actual completion usage or spend. Search accounting is 46/480 returned calls, zero errors/orphans/replays, no stop. Dollar cost and remaining credits are unknown.

No SDK provider errors, orphan attempts or persistent stops were recorded. Four Fugu responses and five Cisco responses finished with `length`; six Cisco native infrastructure diagnoses and the Fugu harness shortfalls remain visible independently. Final Fugu stages contain zero parse-error entries and one call-error entry. The 4,501 serialized Fugu stage request entries include repeated cached-member references; the network count is the 4,441 journal records. No extra hosted dispatch for retry or schema fallback was observed: 20 Skill requests used native JSON schema and 120 MCP requests had no response-format option. Native bounded recovery remained available under the fixed contract.

All 320 native planned rows existed before Fugu's first SDK reservation at `10:31:06.125775Z`. The first native comparator invocation was Sentinel at `12:46:45.415865Z`; the first hosted comparator reservation was shared-Cisco request 1 at `12:46:50.442041Z`. Full timestamps, nulls, models, options hashes and case links are retained in safe data. Known token usage does not establish an independently confirmed provider bill.

## Frozen cases

The current [schema-1 manifest](../bench/results/2026-10-05-full-workflow/cases-v2.json) contains 140 cases with original input hashes. It appends 20 metadata cases to the unchanged [original 120-case manifest](../bench/results/2026-10-05-full-workflow/cases.json). Targets remain under `.fugu-private/full-workflow-20261005/research/`. Labels, provenance, expected values and manifests are excluded from scanned targets.

| Cohort | Planned | Authored attack/risk | Controls | Matched competitors |
|---|---:|---:|---:|---|
| MCP metadata | 100 | 80 | 20 | Cisco MCP, Sentinel, MCP-Sec-Audit |
| Skills | 20 | 10 | 10 | Cisco Skill Scanner |
| Composition | 12 | 6 | 6 | None of these interfaces supports the full member-set contract |
| Source | 8 | 4 | 4 | Unsupported by the selected packet/skill interfaces |

The 80 MCPTox descriptions span 35 servers. Original selection uses `SHA256(seed + NUL + id)` with seed `fugu-full-workflow-20261005-v1`, followed by round-robin selection from hash-ranked category/paradigm/server strata. The extra 20 use fixed seed `fugu-full-workflow-20261005-extra20-v1` and the same ranking, excluding existing identities/name-description content and the original prior-full exclusions. It never reads detector outcomes. [Extension selection](../bench/results/2026-10-05-full-workflow/selection-v2.json) records all exclusions and the 1,251 eligible candidates. The [prior identity table](../bench/results/2026-10-05-full-workflow/prior-overlap.json) makes the earlier exclusions reproducible without distributing payloads.

The lead chose this allocation before benchmark observations because retained chamber unavailability affects 28 original cases. Every original row/input/label and unavailable case is preserved. Adding 20 metadata cases raises the maximum full-completion eligibility from 92 to 112; neither number is observed completion or a runtime demonstration on metadata. The original result artifacts and 19-file manifest remain unchanged, with authored source/report amendments and new artifacts bound separately.

The MCP packets retain only original name, description and genuinely supplied `inputSchema`. The pinned MCPTox loader extracts Tool/Description and normalizes its literal `\n`/`\t` escapes; it supplies no schema and none is invented from its Arguments string. All 20 original fuzzd controls have their genuine schemas preserved and `_meta.is_attack` removed. Five controls repeat prior full-workflow inputs because the retained original clean pool contains only 20. The controls were constructed by fuzzd, which also supplies Fugu's optional static component; this is a small convenience control set.

Ten skills are complete Cisco human-reviewed inert fixtures, including their supplied regular support files. Four controls are Cisco benign packages; six are complete original Anthropic `SKILL.md` instruction packets, including one published template. Those six are **packet-only** inputs: referenced helper scripts, themes and examples are absent. They test the original instructions, not the complete runnable packages. A native no-trigger result on such an input proves no package execution. Labels describe authored risk/clean fixtures and reviewed instruction scope; they do not establish real-world malware prevalence.

Composition controls are negative for the original cross-member `trifecta`/`shadowing` claim. Some contain risky individual members. Their expected scope is bound outside targets; they must not enter clean-package false-alert denominators. Retain both the raw medium-or-higher Fugu alert and the separate composition score. Source cases include three earlier crafted attack fixtures and an inert Cisco environment-access source, plus four clean source slices. Imports do not establish that a dangerous function was invoked.

This is not blind generalization. MCPTox, clean controls and composition sources were previously visible. Per-case overlap records preserve exact matching IDs and file fingerprints in the bound earlier tables; an empty match list is not a claim that no earlier person or model saw the source. [Original selection](../bench/results/2026-10-05-full-workflow/selection-summary.json) and [extension selection](../bench/results/2026-10-05-full-workflow/selection-v2.json) retain exclusions and known overlaps.

## Input validity and runtime boundary

All 163 selected Python/shell/JSON syntax checks passed: the original 143 plus 20 extra JSON packets. Python uses `ast.parse` with Python 3.10 syntax and rejects the known invalid JSON Boolean/null names. Shell uses `bash -n`; JSON uses `json.loads`. No target modules are imported and no target entry points run. No selected file exceeds 6,000 characters, case exceeds 27,000 characters, or case contains more than 24 files. These input checks do not prove runtime readiness or absence of native omissions. [Original syntax evidence](../bench/results/2026-10-05-full-workflow/syntax-preflight.json) and [extra syntax evidence](../bench/results/2026-10-05-full-workflow/native-interface-correction/extra-syntax.json) bind the checked files. [Extra trigger declarations](../bench/results/2026-10-05-full-workflow/extra-trigger-declarations.json) use only the frozen native metadata helper: all 20 packets have zero derived executable triggers, and no command was run.

The old rugpull `v2/server.py` still contains an invalid JSON Boolean name and is excluded. The known invalid clean server and Node CLI fixtures are not reused. Three JavaScript composition candidates are excluded before measurement because Node chamber readiness is unverified. The remaining cases declare Python, bash/curl and, for some composition members, `requests`/`httpx` requirements. Host Node availability is not chamber readiness. The accepted runner must retain native trigger commands/arguments, readiness and applicability reasons; missing runtime, dependencies or required arguments remain incomplete/unavailable.

The data release retains the existing Buildx denial and prohibits target execution, build retries, alternate chamber drivers and owner mounts. Cases requiring executable triggers remain incomplete or unavailable. Genuine zero-trigger stages may be N/A; this supplies no runtime safety proof.

## Frozen engine and native competitors

The released Fugu snapshot has 39 Python source files at `dbc4f641bfad39f7004e64f08bf8351697f5ae7c`. [The source inventory](../bench/results/2026-10-05-full-workflow/engine-source.json) and accepted data plan bind them. The run uses the native full workflow: every applicable S0–S5 stage, composition and verdict, with Super `nvidia/nemotron-3-super-120b-a12b`, Ultra `nvidia/Nemotron-3-Ultra-550b-a55b` and the frozen 4,096-token production profile. Native unavailable stages and coverage shortfalls remain visible.

Fugu's optional S1 component is fuzzd at `f739e120cd7dc253fead2a1f13668f9535e4d8a5`. The retained binary hash is `85224f942db23733bb4e3ccacbf246fe2cde266ca96321231973bef6d98ea208`; the configured image is `sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0`. The accepted plan binds `FUGU_STATIC_RULES_BINARY/IMAGE/SHA256`. Lead's separate inert activation proof verifies S1 activation only; it is not a selected benchmark result. No standalone fuzzd performance series is measured.

The frozen optional tool-surface extractor requires a dictionary `inputSchema` for JSON tools. MCPTox's schema-free packets therefore do not enter that optional S1 tool-surface path. File/static, semantic and harness paths still receive the original packet according to their native applicability. This coverage difference is retained; adding a fabricated schema would change the input. Cisco MCP's own internal empty-schema handling is an adapter behavior, with the original input bytes preserved.

| Competitor pin | Native input/mode | Primary alert fixed before outcomes | Secondary |
|---|---|---|---|
| [Cisco Skill Scanner 669a2cdf](https://github.com/cisco-ai-defense/skill-scanner/tree/669a2cdf64f81f748f6590d421c935c01c5b01b5) | Genuine skill directory; native static + local behavioral + LLM | HIGH or CRITICAL, matching native `is_safe` | Any recognized native security finding, including INFO/LOW/MEDIUM |
| [Cisco MCP Scanner 4.8.5, f817899d](https://github.com/cisco-ai-defense/mcp-scanner/tree/f817899d9391b099f395acd5ae7ff435dccf2a47) | Original tools wrapper; native YARA + LLM static packet mode | Native unsafe finding, including LOW/INFO; analyzer infrastructure is excluded | Any recognized native security finding |
| [Sentinel 1.4.16, 5cde4b12](https://github.com/Ventrova/sentinel-scan-cli/tree/5cde4b12221178b0ac41213a6b332f9c03fdccc4) | Original offline MCP manifest | HIGH, its documented `--fail-on high` recommendation | Any native finding |
| [MCP-Sec-Audit 0.1.0, 457057a7](https://github.com/nyit-vancouver/mcp-sec-audit/tree/457057a7dfda6b81622a12ee68b74f76f3fbde85) | Original name/description mapped only to `tool_name/tool_content`; native static pipeline | Aggregate native risk ≥25 | Any capability finding |

The frozen primary thresholds and `any_alert` secondary metric match the implemented normalizer. `any_alert` includes retained non-infrastructure security findings at any recognized severity. These thresholds are uncalibrated and differ. Capability/advisory alerts are not confirmed malicious behavior. MCP-Sec's native interface ignores the original schema; that transformation is disclosed and the original packet hash remains bound. Cisco MCP natively scans description and schema parameters separately when a schema exists. Analyzer invocations are observed separately because its static coordinator can swallow an analyzer error and still report `completed`. A missing analyzer, UNKNOWN/infrastructure finding, parse/budget diagnostic, omitted coverage or partial native status cannot earn complete-case credit. Valid raw alerts on incomplete rows remain retained.

The pinned MCP helper emits INFO `ANALYZER INFRASTRUCTURE` findings for empty/exhausted analyses. These are incomplete coverage rather than security detections, even when the native coordinator reports unsafe. The adapter observes that category as well as legacy UNKNOWN findings.

Cisco LLM modes use the existing Nebius OpenAI-compatible route and Ultra through the native custom-provider support. Their prompts, parsers and native finding policy are preserved; the transport is an injected zero-retry OpenAI SDK callback. This is a disclosed provider/model substitution. Cisco Skill retains its native 8,192-token cap, temperature 0, 120-second timeout and three-retry setting. Cisco MCP retains 1,000 tokens, temperature 0.1, 30 seconds and three retries. Optional behavioral LLM alignment is off, its native default. Supported native structured-output/reasoning options remain hash-bound and forwarded; unsupported options fail before dispatch. [The native contract](../bench/results/2026-10-05-full-workflow/native-contracts.json) binds the exact source functions, defaults and recovery behavior.

[Source/package/license hashes](../bench/results/2026-10-05-full-workflow/source-pins.json) and [exact proposed isolated install commands](../bench/results/2026-10-05-full-workflow/dependency-plan.json) are retained. Cisco uses Apache-2.0; Sentinel uses MIT. Cisco Skill's package version is VCS-derived and its source build requires Go 1.27.1+ for the native CEL helper; the accepted launcher verified installed version/helper provenance before dispatch. MCP-Sec has no established redistribution license in the pinned source, so its source stays in private scratch. Full upstream documents and binaries are not copied into tracked evidence. The accepted data launcher freezes native effective policy and a clean environment; undeclared policy, taxonomy, force-JSON, reasoning and routing overrides are excluded.

The accepted isolated environment uses Python 3.13.5, Cisco MCP 4.8.5, Cisco Skill `2.2.1.dev3+g669a2cdf6`, Sentinel 1.4.16 and MCP-Sec `detection` 0.1.0. Installed-root hashes (385 files) and 141 transitive package versions are bound in [measurement provenance](../bench/results/2026-10-05-full-workflow/measurement/provenance.json). MCP-Sec's installed wheel cannot import `detection.core` because its package list omits subpackages. The actual run uses the unchanged pinned source tree, `457057a7`, with `PYTHONPATH=/tmp/fugu-full-workflow-research-20261005/sources/mcp-sec-audit/detection`. Source-tree activation and installed-wheel inventory are verified separately; no working-wheel claim is made.

The lead's subsequent exact import proof verifies the unchanged MCP-Sec source-tree activation. Its metadata iterator accepts `tool.json` with nonblank `tool_content`; the warning about unsupported code files belongs to a separate AST shadow engine. There is no confirmed zero-input metadata defect. The mapping remains unchanged and no AST coverage is invented. [Source and packaging scope](../bench/results/2026-10-05-full-workflow/native-interface-correction/metadata-warning-scope.json) binds the source and lead proofs.

The installed Cisco MCP interface required one import correction: `StaticAnalyzer` lives in `mcpscanner.core.analyzers.static_analyzer` and is absent from the package exports. A failing installed-package test reproduced the import error before this correction. [The retained inert proof](../bench/results/2026-10-05-full-workflow/native-interface-correction/native-interface-proof.json) verifies the actual description/schema analyzer invocations and two fake completions at 1,000 tokens, temperature 0.1 and 30 seconds. Socket/DNS networking was denied; no provider/search/chamber or auditee execution occurred. Native thresholds, parsers and defaults were unchanged.

Snyk remains unmeasured/unavailable until existing CLI authentication and authorized volume are demonstrated. Successful repository CI does not prove that access. No unavailable scanner receives a zero detection score.

## Released finite accounting

[The frozen plan](../bench/results/2026-10-05-full-workflow/plan.json) binds the native 140-case run. A sequential request router fills three journals, each capped at 1,800 actual SDK creates; Fugu's total is 5,400. Cases are not assigned to fixed cohorts. The earlier [amended draft](../bench/results/2026-10-05-full-workflow/native-interface-correction/plan-amendment.json) and [original draft](../bench/results/2026-10-05-full-workflow/plan-draft.json) remain unchanged as preparation evidence. Both Cisco lanes share a separate 1,800-dispatch `NativeRequestCounter`; all hosted lanes total at most 7,200 attempts. The requested-output ceiling remains **36,864,000 tokens**: `5400 × 4096 + 1800 × 8192`. The second term uses the larger Cisco cap because that budget is shared. This is neither measured usage nor a price estimate. Research plus native reputation share a 480-call Tavily ceiling.

[Offline feasibility](../bench/results/2026-10-05-full-workflow/native-interface-correction/feasibility.json) estimates 4,580 Fugu dispatches across 156 native case/member units and 212 one-chunk text files, assuming nine full-depth probes and successful first responses. The same shape with maximum bounded response recoveries can require 6,508 requests, exceeding the aggregate cap. The capacity-based router does not reserve requests by case cohort. Cisco MCP's 120 description/schema analyses alone can require 1,920 requests under nested four-attempt transient/empty recovery, before Skill calls. These are conditional source/shape estimates, not guarantees. The hard budgets prevail; unfinished/partial rows stay visible. Historical metadata records show a median of 29 requests across 45 distinct native contexts, but those contexts are not fresh cases and are not reused as results or a quota forecast.

Fugu keeps its existing journals and 90-second SDK timeout unchanged. Cisco uses a thin separate counter because Fugu's first-provider-error latch would prevent Skill's supported JSON-schema-to-JSON-object fallback. Every actual Cisco SDK create, including that fallback and native transient/empty-response recovery, is durably counted before dispatch. A shared async lock serializes case callbacks across both lanes; the counter has one process owner. The SDK has zero hidden retries and each lane's native timeout. Full request and native-option hashes bind schema, reasoning and routing; safe ledger records carry run/context/stage/ordinal and the global dispatch number. Raw prompts/replies remain private.

Any provider error stops the affected **Fugu** journal and its latch stays unchanged. The Cisco counter returns original non-quota exceptions to the native recovery code: Skill recognizes unsupported schema errors and bounded rate-limit recovery; MCP retains its native bounded transient and empty-response loops. The observer adds no retries. Every recovery dispatch consumes the same 1,800 budget. Confirmed quota/auth exhaustion, aggregate cap and orphan/evidence failures are persistent hard stops; the caller stops all affected paid lanes on exhaustion. Rate limiting and server errors remain distinct from exhausted quota. No automatic new child, provider substitution or result reroll is authorized here. Actual tokens, usage nulls, errors and unattempted rows must survive interruption. Remaining Nebius balance, Tavily credits and dollar cost are unknown; the supported documentation check establishes authenticated console balance but supplies no credit API for this run. No endpoint is guessed and no quota is purchased.

## Completeness and safe export method

Two observed coverage exclusions illustrate the frozen completeness rule. `clean/get_git_log` completed 17/18 harness comparisons, with zero parse-error entries and one native call-error entry. `anthropic-skill/skills/web-artifacts-builder` completed 18/18 comparisons with no parse/call errors, but omitted 59 generated-probe characters. The latter is probe truncation. Both rows remain partial and excluded from complete matched intersections; their original attempt evidence and planned rows are preserved. No rerun or profile change follows these results.

The dated charts contain one **Fugu full workflow** series and the four measured native comparators. For each supported cohort and label, compare the identical completed case-ID/input-hash intersection. Show matched `n`, alert count, Wilson 95% interval, exclusions and native thresholds. Keep planned/completed/partial/failed/unavailable/unattempted coverage visible alongside complete-case metrics. Inputs are clustered convenience fixtures; these descriptive intervals do not establish population performance or independent natural sampling.

Keep paired Fugu-only/competitor-only disagreements. Clean-control alert rate remains separate from manually adjudicated false positives. Zero observed alerts means `0/n`, not population false-positive rate zero. Preserve raw alerts and any accepted adjudication separately without changing frozen inputs/labels or tuning detectors.

Portable export contains safe row metadata, input/source hashes, actual SDK usage/nulls, model/caps, errors, per-analyzer coverage and raw artifact hashes. Raw requests/replies, native finding payloads, scanned source bytes and synthetic token literals remain private. No historical charts, static-only Fugu baseline, capability-stage diagram or earlier headline score enters these figures.

## Original preparation reproduction

The original owner checks passed 26 focused tests and scoped Ruff. The correction adds append-only selection/preservation checks and the installed-native inert test; retained final outputs are in [correction checks](../bench/results/2026-10-05-full-workflow/native-interface-correction/checks.json). Fake-response tests cover two counted schema-fallback dispatches, exhausted recovery, quota/auth restart persistence, a shared cross-scanner cap and interrupted-dispatch refusal. The installed test establishes only the inert interface, not actual provider behavior or benchmark scores. [The original recount](../bench/results/2026-10-05-full-workflow/offline-recount.json) remains unchanged; the separate [correction recount](../bench/results/2026-10-05-full-workflow/native-interface-correction/recount.json) binds all 140 rows and 212 input files, original-prefix/checkpoint preservation and the amendment vector. The final independent combined result/README review follows the sealed measurement handoff.

Cache the exact upstream archives/commits in [source-pins.json](../bench/results/2026-10-05-full-workflow/source-pins.json); do not install or run them for input reconstruction. MCPTox's original `response_all.json` is pinned to [f85189f9](https://github.com/zhiqiangwang4/MCPTox-Benchmark/blob/f85189f9ad12504c197c7f920ab818a40657b1fa/response_all.json), SHA-256 `79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03`. Restore the original [20 fuzzd clean tools](https://github.com/ksek87/fuzzd/blob/f739e120cd7dc253fead2a1f13668f9535e4d8a5/bench/clean_tools.json) to `bench/real/fuzzd-cache/clean_tools.json`. Original caches are required and are not public payload artifacts. Verify their bound hashes before use.

From the repository root:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
uv run --no-sync python -m bench.results.2026-10-05-full-workflow.prepare_corpus

UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
uv run --no-sync python -m bench.results.2026-10-05-full-workflow.native-interface-correction.prepare_extra_cases

UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
uv run --no-sync python -m pytest \
  tests/test_competitive_corpus.py tests/test_competitive_scanners.py -q
```

Reconstruction preserves the accepted manifest rather than overwriting a different one. The prior-overlap table removes dependence on earlier private target bytes. Existing source candidates under `corpus/` must match the frozen input maps. Syntax passes do not claim fresh chamber or inference reproduction.

## Offline measurement reproduction and verification

The safe exports require no credentials, raw target cache, scanner installation or network. From the repository root, use the existing environment:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
uv run --no-sync --offline python \
  bench/results/2026-10-05-full-workflow/measurement/verify.py
```

For a standalone Python environment, the verifier uses only the standard library. Plotting needs Matplotlib 3.11.2 in an isolated environment; this changes no project dependencies. Install plotting dependencies separately, then regenerate to a new directory:

```sh
uv venv /tmp/fugu-full-workflow-plots
uv pip install --python /tmp/fugu-full-workflow-plots/bin/python matplotlib==3.11.2
MPLCONFIGDIR=/tmp/fugu-full-workflow-mpl PYTHONDONTWRITEBYTECODE=1 \
/tmp/fugu-full-workflow-plots/bin/python \
  bench/results/2026-10-05-full-workflow/measurement/plots.py \
  bench/results/2026-10-05-full-workflow/measurement/results.json \
  --output /tmp/fugu-full-workflow-replotted
```

The exact owner check used the existing isolated Matplotlib 3.11.2 interpreter, rendered and visually inspected all three measured PNGs, and reproduced all six PNG/SVG byte hashes in a separate scratch directory. `verify.py` independently checks 140/320 identities and order, original input hashes, fixed profile, caps, request numbering, usage/null accounting, complete intersections, disagreement membership, Wilson interval calculations and the schema-2 inventory. It rejects payload/credential field names; this is a structural field guard, not a claim of a general credential-pattern scan.

Separate private checks recompute all 4,441 Fugu message/request/response hashes and all 140 Cisco request/native-option/response hashes, raw native artifact links, per-case request ownership and preserved source/input bytes. SDK output hashes use their original encoding: Fugu request hashes use compact Unicode-preserving JSON, while native request/options/response hashes use default sorted JSON. No detector, scanner, chamber or provider is invoked by those checks. Original payloads stay private; portable reproduction verifies selected safe evidence and figures, not a new inference or target execution.

Final preservation checks bind 3,329 historical artifacts, three owner files, all 39 frozen source files, the original 120-case prefix and all 212 regular input files. The original 19-artifact checkpoint remains unchanged in its retained namespace; the assigned report amendment and new measurement inventory are separate. The accepted native plan remains `8b73703335e1d00d9af72431b7b3f69fee8909a275de5e10cbaeebdb55fda6af`; launcher SHA-256 remains `d7937e6bee3bd56bafb14d1951af0ea4815feeab7950b5a8d25ec1152037febd`. Final raw Fugu JSON SHA-256 is `9d3ab74e12cbb55a8516d2c4093ba922787bae99c92479d24a9b8fb2af8c42d3`; raw comparator JSON is `4ac6445f2709baffbbffd3a10e455a2f62ff536812fd45f0374c75c50cced267`.

Measurement ownership ends at the authenticated sealed handoff. The lead owns integration, the separately assigned README update and one combined independent result/README review. No further paid run, target execution, source change or Git mutation is part of this handoff.
