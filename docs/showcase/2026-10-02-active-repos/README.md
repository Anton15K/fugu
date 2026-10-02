# Maintained smaller projects: source-only showcase

Measured on 2026-10-02. Queue assignment: `qitem-20261002194404-31d6cd23`.

Use **Rust MCP Filesystem**, **Infrahub MCP**, and **AMD Hyperloom's bootstrap skill** for three honest walkthroughs: an installer warning, a scoped negative audit, and capability/coverage triage. Eight repositories were shortlisted; five selected packets comprising ten files were measured. All 18 semantic units completed in 18 hosted requests. No vulnerability was confirmed by this source review. Independent review is pending.

These are real public sources chosen deliberately for a demonstration after source inspection. They are not a blind benchmark, representative sample, or evidence of detection accuracy. The original six-project audit and full benchmark remain separate historical evidence.

## Measured results

| Selected packet | Files | S2 completed / planned units | Raw S0 / S1 / S2 alerts | Source adjudication |
|---|---:|---:|---:|---|
| Infrahub query/session | 3 | 3 / 3 | 0 / 0 / 0 | Scoped negative result; mutation rejection is visible in the query source |
| Rust filesystem README/core/listing | 3 | 6 / 6 | 0 / 1 / 2 | Official versioned installer fetch-and-execute patterns; overlapping hygiene warnings |
| AWS SageMaker operational-review skill | 1 | 3 / 3 | 0 / 0 / 1 | Referenced file omitted by our paid packet; it exists in the repository |
| AMD Hyperloom bootstrap skill | 1 | 2 / 2 | 0 / 0 / 4 | Unpinned downstream release, declared capabilities and downstream coverage gaps |
| Bifrost file access/redaction | 2 | 4 / 4 | 0 / 0 / 0 | Scoped negative result; path/sensitive-file checks are visible in selected source |

Every S0/S1/S2 stage returned `ok=true` for its selected packet. There were no collector skips, omitted/partial semantic units, parse failures, response repairs or provider errors. This coverage applies to the ten named files, not their repositories or dependencies. Bifrost's README and the AWS reference received additional manual inspection only.

S1 emits a **HIGH deterministic pattern match** for the Rust shell installer. S2 emits seven **LOW advisory** notes. Preserve those original labels when replaying the data. A deterministic match establishes that text matched a rule; it does not establish that a remote installer is malicious. S2 severity and OWASP mappings are model opinions. Its two Rust alerts overlap the static shell warning and add the PowerShell equivalent. Do not add these as independent vulnerabilities or call the selected packets an adjudicated benign population.

Only three of seven S2 excerpts are exact substrings of the corresponding source. Two additional excerpts match after whitespace normalization; the AWS and background-workload excerpts paraphrase or truncate the source. Some model line hints are inaccurate. [Adjudication](../../../bench/results/2026-10-02-showcase/adjudication.json) retains original alert hashes and corrected source ranges; [raw results](../../../bench/results/2026-10-02-showcase/measured.json) preserve the model's original evidence. No detector changes or repeated calls on valid results were made.

## Ranked walkthroughs

This ranking reflects clarity and reproducibility of the demo, not comparative security.

### 1. Rust MCP Filesystem: explain a concrete warning

Current pin: [`ef479736`](https://github.com/rust-mcp-stack/rust-mcp-filesystem/tree/ef4797360ea03eec5375e03a6f10d092dfc6a5e0), release **v0.4.5**. The [quick-start README](https://github.com/rust-mcp-stack/rust-mcp-filesystem/blob/ef4797360ea03eec5375e03a6f10d092dfc6a5e0/README.md#L31-L43) documents downloading official versioned shell and PowerShell installers directly into an evaluator. Fugu's static rule catches the shell pattern; S2 records both installer patterns. Explain the install-time execution and inspection/integrity tradeoff without claiming compromise.

The [filesystem core](https://github.com/rust-mcp-stack/rust-mcp-filesystem/blob/ef4797360ea03eec5375e03a6f10d092dfc6a5e0/src/fs_service/core.rs) uses capability directory handles and separately handles UNC paths. That source is useful context, but no runtime containment test was performed. The public [path-traversal advisory](https://github.com/rust-mcp-stack/rust-mcp-filesystem/security/advisories/GHSA-58gp-g6r5-8p6w) lists affected versions `<0.4.3` and patched version `0.4.4`; our pin is v0.4.5. Its published affected/patched fields leave v0.4.3 unspecified. Do not present the old advisory as a detected current vulnerability or downgrade the demo to a vulnerable release.

```sh
python3 bench/results/2026-10-02-showcase/demo.py --artifact rust-filesystem
```

Show the original HIGH/LOW labels, the pinned source links, and the adjudication. The replay executes our evidence reader only; it never downloads or runs either installer.

### 2. Infrahub MCP: show what a negative result covers

Current pin: [`1da6efc2`](https://github.com/opsmill/infrahub-mcp/tree/1da6efc2d8161522573ee77efadb2e28d17a3a00), latest observed release **v1.2.0**, with later changes on the stable branch. The [query tool](https://github.com/opsmill/infrahub-mcp/blob/1da6efc2d8161522573ee77efadb2e28d17a3a00/src/infrahub_mcp/tools/gql.py#L51-L64) parses the GraphQL AST and rejects mutations before calling the SDK. [Session introspection](https://github.com/opsmill/infrahub-mcp/blob/1da6efc2d8161522573ee77efadb2e28d17a3a00/src/infrahub_mcp/tools/session.py) reports the session branch and instance address. The README, query tool and session tool produced no S0/S1/S2 alerts.

```sh
python3 bench/results/2026-10-02-showcase/demo.py --artifact infrahub-query
```

Name the three files and 3/3 units. Explain that annotations and visible guards support the stated read contract. Write-tool registration, authorization, SDK behavior, complete branch enforcement and deployed behavior are outside this packet. Zero alerts is a scoped observation, not a safety certificate.

### 3. AMD Hyperloom: distinguish a declared capability from a violation

Current catalog pin: [`de0d03ae`](https://github.com/amd/skills/tree/de0d03ae90b37a4f5ef38e0cf26ef6e3d3af7e94). The [bootstrap skill](https://github.com/amd/skills/blob/de0d03ae90b37a4f5ef38e0cf26ef6e3d3af7e94/skills/hyperloom-workload-optimizer/SKILL.md#L45-L90) requires a dedicated workspace and user acceptance of `.env` changes, then describes installation of a wheel and agent skills. Its [launch instructions](https://github.com/amd/skills/blob/de0d03ae90b37a4f5ef38e0cf26ef6e3d3af7e94/skills/hyperloom-workload-optimizer/SKILL.md#L114-L127) require a user go-ahead on the resolved plan before hours-long GPU work.

```sh
python3 bench/results/2026-10-02-showcase/demo.py --artifact amd-hyperloom
```

Triage four LOW advisory notes. The floating wheel release affects repeatability; credential/setup handling belongs to unmeasured downstream code. Skill-directory installation and background GPU work are declared capabilities. Relative configuration paths do not prove writes outside the authorized workspace. The approval text is visible; enforcement by the installed wheel remains untested. This is a source-only triage demo: the wheel, GPU workload, credentials and delegated skills are not installed or run.

## Shortlist and maintenance evidence

Exact GitHub metadata was retrieved at **2026-10-02 19:46 UTC**; stars are point-in-time counts. All eight repositories were public, unarchived, nonfork entries and below 1,000 stars. Each had a code/release change within 60 days plus visible tests/evaluations or CI. These signals do not establish test quality, passing CI, maintainer capacity or long-term support. Latest observed release is context; the full commit is the audit pin.

| Repository / pin | Stars | Recent substantive activity / version context | License metadata; reason and scope |
|---|---:|---|---|
| [opsmill/infrahub-mcp](https://github.com/opsmill/infrahub-mcp/tree/1da6efc2d8161522573ee77efadb2e28d17a3a00) | 10 | v1.2.0 Sep30; Oct2 CI/image-tag fix; tests and 15 CI files | Apache-2.0; measured query/session contract; no live Infrahub account |
| [UCR-Research-Computing/ursa-bifrost](https://github.com/UCR-Research-Computing/ursa-bifrost/tree/35fe9ee7b161ae4b9c63be11de982a9c1870beb7) | 0 | v0.8.2 Oct2; internal-source release changes; tests and 2 CI files | Unrecognized/absent license metadata; no root license file in acquired inventory. Measured file/redaction sources; no cluster/identity execution |
| [rust-mcp-stack/rust-mcp-filesystem](https://github.com/rust-mcp-stack/rust-mcp-filesystem/tree/ef4797360ea03eec5375e03a6f10d092dfc6a5e0) | 180 | v0.4.5 Aug29; UNC code fix Aug29 and containment fix Aug27; tests and 8 CI files | MIT; measured README/core/listing; current source, not historical vulnerable release |
| [neondatabase/mcp-server-neon](https://github.com/neondatabase/mcp-server-neon/tree/00d82d4e5c925380fc077fe1932780035f564d8b) | 649 | Safer SQL explanation default Sep30; `@neon/tools` 2.0.1 bump; tests and 3 CI files; no GitHub release returned | MIT; source shortlist only. Delegated tools/OAuth/database boundaries need a broader packet; not measured |
| [aws/tools-for-devops-agent](https://github.com/aws/tools-for-devops-agent/tree/8b498ab9ba3b740a4c734fb765ea5a3119dc10e5) | 91 | Selected SageMaker skill 1.1.2 Oct1 corrects unsupported KMS advice; evaluations and 5 CI files | Apache-2.0 with root NOTICE; measured one read-only skill file. No AWS account/API calls or other catalog skills |
| [amd/skills](https://github.com/amd/skills/tree/de0d03ae90b37a4f5ef38e0cf26ef6e3d3af7e94) | 386 | Selected Hyperloom federation bump Sep25 to upstream revision 0012585; tests and 8 CI files | MIT root metadata; measured one bootstrap file. Catalog pin does not pin its wheel; downstream licensing/runtime unassessed |
| [Chemaclass/agnostic-ai](https://github.com/Chemaclass/agnostic-ai/tree/8a153461491df38caa785a2395f8bd50338cc38f) | 19 | v0.77.0 Oct2; CLI feature changes; tests and 8 CI files | MIT; responsive installer/skill-sync project, but larger orchestration scope; not measured |
| [sanjay3290/ai-skills](https://github.com/sanjay3290/ai-skills/tree/281d88df199357e3091a3be5c743a0fca9a9ae1b) | 429 | Google Chat code additions Sep10; latest observed tag v1.2.0 Jul9; five test-named files, no CI file found | Apache-2.0; smaller integration skills, but authentication/external-service scope; not measured |

Selection and per-artifact activity are retained in [shortlist.json](../../../bench/results/2026-10-02-showcase/shortlist.json) and [artifact-maintenance.json](../../../bench/results/2026-10-02-showcase/artifact-maintenance.json). Activity for AWS/AMD refers to the selected skill, not unrelated catalog edits. Tests were observed as source files, not executed.

Discovery used the lead's two seed caches and three focused `gh search repos` queries, each limited to eight results: filesystem MCP, database MCP and DevOps skills, with `<1000` stars and a pushed-after filter. Search filters were not reliable indicators of freshness; stale hits were rejected using exact repository metadata. [Search ledger](../../../bench/results/2026-10-02-showcase/search-ledger.json) records the queries and exclusions. This was bounded discovery, not an exhaustive market search.

The [known-issue ledger](../../../bench/results/2026-10-02-showcase/known-issues.json) retains up to five `security` search hits and twenty public advisory records per repository. Rust returned the published advisory above; the other seven returned empty advisory arrays on that endpoint. Search titles, closed issues and empty arrays are not vulnerability adjudication or proof of absence. AMD's surfaced CI-hardening issue and the older closed Google Workspace credential-flow issue in sanjay3290/ai-skills concern unmeasured scopes; neither is a new confirmed finding here.

## Provenance, inference and boundaries

The frozen Fugu engine is baseline **`62bfce0008c04f6ccbb068819ddcbf6fd4997418`**. [Engine manifest](../../../bench/results/2026-10-02-showcase/engine-manifest.json) pins all 37 Python files; their hashes matched before and after every packet. The engine copy stayed in `/tmp`. The 1,672 historical benchmark/composition files also matched the lead's baseline inventory before and after this task. No production code, target dependencies, shared environment, lockfile, historical evidence, database or Git state was edited by this worker.

The acquisition script copied regular files only, rejected unsafe archive paths, and omitted files over 2 MB. Across eight caches it retained 4,101 regular files and omitted six large files: four Infrahub, two Neon. Only the ten predeclared files entered Fugu. All selected files matched pinned hashes; no selected symlink or collector skip occurred. Full third-party source and caches stay outside tracked deliverables; retained metadata, hashes and short evidence pointers provide provenance without redistributing whole repositories or READMEs.

Paid inference ran **19:53:00–19:53:57 UTC** through Token Factory, with the request model **`nvidia/Nemotron-3-Ultra-550b-a55b`**, temperature 0.1, at most 4,096 completion tokens/call, timeout 90s and SDK retries 0. The pre-call [plan](../../../bench/results/2026-10-02-showcase/measurement-plan.json) specified 18 primary units under a hard 24-request total including repairs/retries. All 18 requests finished `stop`, using provider-reported **31,329 prompt + 15,430 completion tokens**; summed request latency was **56.780s**. Aggregate system+user input was 125,339 characters, including the repeated 2,859-character system rubric. Monetary cost was not measured; remaining provider quota was not queried and is unknown. Six authorized request slots were unused. The ledger proves the model identifier sent in each request; the provider-resolved response model was not retained or independently verified.

One earlier credential-lookup preflight made **zero hosted requests**, because the frozen `/tmp` copy changed dotenv discovery. Its deterministic results are retained in [offline.json](../../../bench/results/2026-10-02-showcase/offline.json). The runner then loaded existing authorized project configuration without printing or sending its contents. Network calls stop on any provider error, including quota/auth failure; a persisted cumulative counter blocks automatic paid reruns. There were no provider failures in the measured run.

Public source text was sent to hosted S2 inference. S0/S1 were local; this was not an entirely local audit. Prompts wrapped source as untrusted content. The exact system rubric is in [system-prompt.txt](../../../bench/results/2026-10-02-showcase/system-prompt.txt). File/chunk hashes plus the frozen S2 formatter reconstruct user prompts; the ledger records actual input sizes/hashes, usage, timing and finish states. Raw completions are retained in [responses.json](../../../bench/results/2026-10-02-showcase/responses.json). No auditee code was imported or executed.

S3 detonation and S4 behavioral testing were explicitly excluded, as were reputation and composition analysis. Earlier planned chamber execution in the separate maintained-extension audit was stopped by native cybersecurity enforcement, reported by the lead at 12:17Z. This worker did not receive a structured refusal or detailed policy reason; the [earlier report](../../security/2026-10-02-maintained-extensions/report.md) preserves that limit. It was not repeated or routed through another model/agent. This new grant covers inert source review and bounded S2 only. No unauthorized runtime behavior, deployed attack, dependency execution or exploit confirmation occurred. No issue draft or external disclosure was produced.

## Reproduce safely

Run from the Fugu repository root. Cached evidence replay and integrity checks require only Python3; they make no hosted calls and execute no auditee code.

```sh
python3 bench/results/2026-10-02-showcase/verify_evidence.py
python3 bench/results/2026-10-02-showcase/demo.py --artifact rust-filesystem
python3 bench/results/2026-10-02-showcase/demo.py --artifact infrahub-query
python3 bench/results/2026-10-02-showcase/demo.py --artifact amd-hyperloom
```

For a fresh S0/S1 replay, use fresh output/cache directories. Acquisition needs network access to GitHub; it reads public pinned archives as inert data. No target packages are installed. The baseline Git object must exist in the local Fugu checkout. `prepare_engine.py` uses read-only `git show` and verifies every source hash. The `uv` command uses the existing project Python environment, whose relevant installed versions are in [runtime.json](../../../bench/results/2026-10-02-showcase/runtime.json); it does not sync dependencies.

```sh
python3 bench/results/2026-10-02-showcase/prepare_engine.py --out /tmp/fugu-showcase-replay-engine
python3 bench/results/2026-10-02-showcase/acquire.py --cache /tmp/fugu-showcase-replay-sources --out /tmp/fugu-showcase-replay-acquisition.json
PYTHONPATH=/tmp/fugu-showcase-replay-engine UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python bench/results/2026-10-02-showcase/run_showcase.py --cache /tmp/fugu-showcase-replay-sources --out /tmp/fugu-showcase-replay-offline.json
PYTHONPATH=/tmp/fugu-showcase-replay-engine UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python bench/results/2026-10-02-showcase/verify_evidence.py --cache /tmp/fugu-showcase-replay-sources --engine /tmp/fugu-showcase-replay-engine --offline-result /tmp/fugu-showcase-replay-offline.json
```

The fresh replay reproduces S0/S1; S2 is shown from retained evidence. Its source formatting/model can be reconstructed, but outputs are stochastic. No paid rerun is part of these commands, and the consumed assignment counter must not be cleared to obtain one. A later paid run needs its own granted budget and evidence path.

Owner verification checked all artifact hashes, source pins, unit denominators, raw responses, alert adjudication and telemetry totals. It verified all 4,101 cached source files and 37 reconstructed engine files; S0/S1 replay matched. Offline guard checks refused requests at 24 and after quota/auth stop flags before accessing a client. The verifier scans deliverables for five common credential-like formats; its retained result states the exact scan scope and limitation. This is not proof that every possible secret format is absent. [Manifest](../../../bench/results/2026-10-02-showcase/manifest.json) and [verification](../../../bench/results/2026-10-02-showcase/verification.json) cover the released inventory. Independent reviewer acceptance remains a separate integration step.
