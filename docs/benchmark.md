# Fresh Fugu benchmark — 2026-10-02

**26 of 30 selected MCPTox attacks produced medium-or-higher detections (86.7%).**
There were two completed misses and two incomplete analyses. All 20 constructed
clean tool descriptions completed without flags. Public skills had 0/19 flags
among completed analyses, with one incomplete case out of 20 selected.

This is a bounded evaluation of a frozen S0/S1/S2 engine on cached inputs.
It does not measure detonation, agent behavior, reputation or the complete
server verdict. No detector or prompt was tuned on this evaluation.

![Fresh detection and benign flags](benchmark-charts/fresh-results.svg)

## Results, separated by provenance

Detection/flag rule: **any finding with severity medium, high or critical**.
In these frozen measurements, completion means every requested stage succeeded
for its submitted inputs without a skipped stage, call errors or JSON parse
errors. It does not establish full content coverage: the eight-unit semantic
cap could omit content. Incomplete cases retain `flagged: null`.

| Cohort | Mode | Planned / completed | Detections or benign flags | Incomplete |
|---|---|---:|---:|---:|
| Fugu-crafted attacks | S0+S1 | 7 / 7 | 7/7 (100%) detected | 0 |
| Fugu-crafted benign | S0+S1 | 4 / 4 | 0/4 flagged | 0 |
| MCPTox pure_tool attacks, all cached cases | S0+S1 | 485 / 485 | 41/485 (8.45%) detected | 0 |
| MCPTox full valid attack corpus | S0+S1 | 1,312 / 1,312 | 120/1,312 (9.15%) detected | 0 |
| fuzzd-constructed clean descriptions | S0+S1 | 20 / 20 | 0/20 flagged | 0 |
| Public skills, provisional benign labels | S0+S1 | 76 / 76 | 0/76 flagged | 0 |
| MCPTox pure_tool balanced sample | S0+S1+S2 | 30 / 28 | 26/30 planned (86.67%) detected | 2 |
| Same constructed clean descriptions | S0+S1+S2 | 20 / 20 | 0/20 flagged | 0 |
| Public-skills balanced sample | S0+S1+S2 | 20 / 19 | 0/19 completed flagged | 1 |

For the live attack sample the secondary rate conditional on completion is
26/28 (92.86%). The chart uses all planned cases as its primary denominator,
with incomplete cases shown separately. They are neither detections nor clean
results. The two MCPTox collections overlap and are never pooled.

Benign labels come from the retained curated sample manifests and the clean
fixture's authors. They are provisional, especially for public skills. With no
medium-or-higher flags in the final benign cohorts, there are no final positive
alerts to adjudicate. This does not establish that every skill is safe or that
the true false-positive rate is zero.

## Inputs and sampling

- MCPTox sources are pinned to
  [`f85189f9ad12504c197c7f920ab818a40657b1fa`](https://github.com/zhiqiangwang4/MCPTox-Benchmark/tree/f85189f9ad12504c197c7f920ab818a40657b1fa).
  The cached `pure_tool.json` was byte-checked against that revision. The full
  cached `response_all.json` matched the existing pinned SHA-256 contract.
- The live attack sample selects **10 per paradigm**, ranking stable case IDs
  by SHA-256 of `20261002:<id>`. This balances the three paradigms rather than
  estimating their natural proportions. Thirty cases do not establish a full
  corpus rate. Selection was fixed before the final run; no cases were replaced.
- All 20 [fuzzd clean descriptions](https://github.com/ksek87/fuzzd/blob/f739e120cd7dc253fead2a1f13668f9535e4d8a5/bench/clean_tools.json)
  were used. These are constructed examples, not independently sampled benign
  extensions. Both classes use identical `tools.json` packets containing only
  name and description. Existing literal escapes are preserved. No schema or
  safety annotations are invented; tool implementations are not included.
- Public skills are cached copies from Anthropic (18), skillsdirectory (18),
  claude-office-skills (25), and obra/superpowers (15). Five per repository are
  selected with the same hash-ranking rule. These copies were not refetched;
  per-file content hashes identify exactly what was scanned. Upstream revisions
  of the copied skill trees are not independently established here.
- Benchmark manifests and `case.json` are removed uniformly from scanned
  inputs. Directory symlinks are rejected before collection. Only copied
  regular text files enter the temporary target. Targets are never executed.
- S2 retains its existing limit of eight units per audit and approximately
  6,000 characters per unit. Large skills may therefore receive partial content
  coverage even when the submitted units complete. The structured API result
  is advisory model judgment; a finding is not proof that an attack succeeded.

## Failures and misses

| Case | Outcome | Evidence |
|---|---|---|
| `Prisma_20` | Completed without medium+ detection | No semantic findings; upstream attack label retained |
| `Prisma_9` | Completed without medium+ detection | One info-level description mismatch note |
| `EverArt_6` | Incomplete | JSON parse error for `tools.json:0` |
| `Prisma_4` | Incomplete | JSON parse error for `tools.json:0` |
| Anthropic `pptx` skill | Incomplete | JSON parse error for `scripts/add_slide.py:0` |

The two completed Prisma misses describe database reset as a migration step.
The description-only packet omits the implementation/context of that tool.
Their benchmark labels remain unchanged. Raw model completions and finish
reasons were not retained by the stage, so the exact cause of malformed JSON
cannot be established from this record. No retry or favorable replacement was
used to improve the score.

## Runtime, source version and usage

- Baseline: `25a7a4e85bc219ea03da20fd34a09826449c0a9b`.
  The lead compared all 36 frozen Python files to that commit: 35 matched;
  only `src/fugu/server/app.py` differed for a concurrent samples endpoint
  change. The benchmark does not import that module. Stage code and prompts
  matched baseline. This benchmark **predates subsequent backend fixes**.
- Source fingerprints were identical before and after each final run. The
  execution-only engine copy is not a deliverable; its baseline and
  [hash manifest](../bench/results/2026-10-02/source-hashes.json) make the
  relevant engine reproducible.
- Final static: 1,904 cases, 44.048 seconds, no model calls.
- Final semantic: 70 cases, 111 successful API calls, 257.001 seconds.
  Requested model: `nvidia/Nemotron-3-Ultra-550b-a55b` through existing Nebius
  configuration/client loaders. Temperature 0.1, maximum output 1,600 tokens,
  90-second call timeout, zero SDK retries. Cases and calls ran sequentially.
- Final reported API usage: **149,008 prompt tokens + 67,705 completion tokens**.
  Per-call model, duration and usage are retained. No provider error or quota
  exhaustion was observed. Remaining quota and actual monetary cost are unknown.
- A discarded pilot used invented empty schemas/annotations; a benign
  `write_file` alert exposed that adapter defect. It was stopped after 11
  completed cases. Its 27 recorded calls used 41,638 prompt and 15,532 completion
  tokens. At most one additional interrupted call has unretained usage.
  Final plus pilot: 138 recorded calls, at most 139 attempts, below the lead's
  cumulative 210-attempt ceiling. Pilot results are excluded from final rates.
  [Pilot note and evidence](../bench/results/2026-10-02/pilot/NOTE.md).

## Reproduction and artifacts

From the repository root, using cached corpora and the existing environment:

### Clean-tool fixture prerequisite

Full third-party documents and the fuzzd fixture are **not distributed** in
this repository's benchmark deliverables. The source index retains pinned URLs,
SHA-256 hashes and our extracted numeric claims. Local acquisition copies may
remain in `bench/results/2026-10-02/sources/` as untracked caches; the explicit
artifact inventory excludes them. Historical raw results keep their original
cache paths unchanged.

Detector reruns require this separately downloaded clean-tool fixture in the
already ignored `bench/real/` cache. Download it explicitly and verify the
expected hash before use:

```sh
mkdir -p bench/real/fuzzd-cache
curl --fail --location \
  'https://raw.githubusercontent.com/ksek87/fuzzd/f739e120cd7dc253fead2a1f13668f9535e4d8a5/bench/clean_tools.json' \
  --output bench/real/fuzzd-cache/clean_tools.json
printf '%s  %s\n' \
  '38b8fbf265e49147a6865836d1eff3796278625599ee47f3ffb2eb7b5f037348' \
  'bench/real/fuzzd-cache/clean_tools.json' | shasum -a 256 -c -
```

The runner uses this cache by default; `--clean-tools PATH` selects an alternate
local copy of the **same pinned bytes**. It fails clearly when the file is
missing or its hash differs, and never downloads automatically. The earlier
measured runner is retained as [a source snapshot](../bench/results/2026-10-02/measured-runner.py)
to match its recorded hash. The current runner adds cache selection and hash
verification, and uses a stricter completion rule with the current engine:
input collection omissions or any stage's `coverage_incomplete` signal exclude
the case from completed denominators. This includes semantic units omitted by
the cap and units with only partially valid findings. Findings and stage metrics
remain in the row; `flagged` stays null. Input collection counts are retained in
`input_collection`, and new result files declare `completion_scope`. Binary files
and deliberately excluded benchmark manifests remain outside the text scope.
The frozen result JSON, charts and measured runner retain the earlier rule;
their recorded counts have not been reclassified or rerun.

### Offline plotting and checks

For plotting on a new machine, first provision an isolated environment (network
download required only for setup; no project dependencies or lockfiles change):

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache uv venv /tmp/fugu-charts-venv
UV_CACHE_DIR=/tmp/fugu-uv-cache uv pip install \
  --python /tmp/fugu-charts-venv/bin/python matplotlib==3.11.2
```

```sh
# Fresh offline measurement of the CURRENT checkout; choose a new output path.
UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python -m bench.fresh_benchmark \
  --out bench/results/offline-rerun \
  --clean-tools bench/real/fuzzd-cache/clean_tools.json

# Offline tables and SVG/PNG from the retained 2026-10-02 evidence.
MPLCONFIGDIR=/tmp/fugu-mpl XDG_CACHE_HOME=/tmp/fugu-font-cache \
  /tmp/fugu-charts-venv/bin/python -m bench.benchmark_charts

# Scoped checks; python -m ensures the repository's bench module is importable.
UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python -m pytest \
  tests/test_benchmark_charts.py -q
```

To reproduce the frozen detector, the lead can export `src/fugu` from the full
baseline commit into a temporary `engine/fugu` directory and set
`PYTHONPATH=<absolute-engine-directory>` before running the historical protocol.
In a separate reproduction tree, place the retained `measured-runner.py` at
`bench/fresh_benchmark.py` (its root calculation depends on that location),
alongside the required input caches. That snapshot expects the pinned clean
fixture at its original local cache path,
`bench/results/2026-10-02/sources/fuzzd-bench_clean_tools.json`.
The current runner with the current engine uses the stricter completion rule
above and is a new evaluation. Verify the relevant source hashes against
`source-hashes.json` first;
the unused `server/app.py` difference is expected. The original execution copy
at `bench/results/2026-10-02/engine/` is local-only.

The runner requires the cached MCPTox JSON and curated `*-samples` directories.
It does not silently fetch missing datasets. Their hashes and pinned MCPTox
download URLs are in [sources/index.json](../bench/results/2026-10-02/sources/index.json).
Exact public-skill reproduction requires the matching cached copies, whose
per-file hashes are retained. A newly fetched upstream version is a new dataset.
Chart regeneration reads only retained measurement JSON and the source index;
it does not need third-party document copies, the clean fixture, the engine
execution copy or any of the other input caches.

Adding `--semantic` makes paid calls and requires an assigned bounded run; it
is unnecessary for regenerating these charts. Model reruns may differ.

- [Static per-case JSON](../bench/results/2026-10-02/static.json)
- [Semantic per-case JSON](../bench/results/2026-10-02/semantic.json)
- [Source hashes](../bench/results/2026-10-02/source-hashes.json)
- [Comparator source index](../bench/results/2026-10-02/sources/index.json)
- [Chart CSV](benchmark-charts/comparison-data.csv) · [Chart JSON](benchmark-charts/comparison-data.json)
- [Comparator caveats and historical contamination](head-to-head.md)

Historical raw results remain untouched. The earlier 484/485 and strict
160-case semantic headlines used label-bearing MCPTox adapters and are not
clean blind-evaluation evidence. The fresh evaluation supersedes them for
current presentation, without claiming an equivalent protocol or a measured
causal effect of removing labels.
