# Current production limits: benchmark protocol

**Status: offline checkpoint. Fresh inference has not run.** The checkpoint has
zero provider requests and zero target executions. Its charts contain simulated
Fugu values for layout review, with retained historical comparator and SDK data.
Every chart is marked **SYNTHETIC OFFLINE FIXTURE**. These images are not evidence
of improved accuracy, cost or speed.

The assigned outcome is a fresh run of the checked production version on the
same 40 cases, followed by measured charts. The offline checkpoint supplies the
runner, guards, tests and reporting method. The production candidate, its
independent review, final frozen source/profile and explicit lead data release
remain prerequisites.

## Inputs and scope

The original [40-case manifest](../bench/results/2026-10-02-full/cases.json) has
SHA-256 `f9b31035908d217a822079dd190c4d5797f86646c65f01c2e06b1f57ae3e91b1`.
The runner refuses a changed manifest, input bytes, grouping or prepared labels.

| Cohort | Planned cases | Provenance and interpretation |
|---|---:|---|
| MCPtox descriptions | 15 | Previously selected poisoned descriptions; existing labels retained |
| Clean descriptions | 5 | Constructed controls using the same description adapter |
| Crafted extensions | 11 | Authored examples: 7 attack labels and 4 controls |
| Composed sets | 7 | Original 4 attack labels, 3 controls and member grouping |
| Dependency reputation | 2 | Source analysis retained; reputation expectations unavailable |

This is a selected, previously inspected regression set. A new inference run on
these inputs does not create a blind evaluation or a representative sample of
extensions in the wild. The historical contaminated headline is not reused.
The separate composition-24 and showcase-5 sets are outside this run.

Preparation copies regular input files into opaque numbered directories and
rejects symlinks. Original filenames and bytes remain intact. Evaluation labels
stay in the manifest outside the audited input. Paths inside the checkout are
stored relative to it. The first 20 cases are the same 15 poisoned and 5 clean
descriptions. They belong to the same run/cache as the remaining cases.

Preflight verifies **40 cases, 54 member contexts, 45 distinct input audits and
63 semantic units**. Byte-identical members reuse the same saved native stage
results. Cache keys include source hashes and the approved plan binding.

The runner uses native `build_stages(include_detonation=False,
include_reputation=False)` with `AuditJob.depth="full"`: concealment, static,
semantic and harness. Original composed sets also use the production source
`CompositionStage`, native finding deserialization/deduplication and tool-name
harvesting. This adapter does not test HTTP auto-resolution or the UI. Harness
responses describe model behavior; they do not execute tools. Detonation,
live reputation, fetched-code execution and fresh competitor execution are
outside this protocol.

## Production profile and freeze

The runner reads `get_production_limits().to_dict()` from the frozen engine.
It supplies no alternate model routing, parser, repair rules or case settings.
The intended production defaults are:

| Limit | Default |
|---|---:|
| Initial output cap, all semantic/RED/BLUE requests | 4,096 tokens |
| Semantic units per audit | 24 |
| Maximum characters per semantic unit | 6,000 |
| Total harness mount packet, including headings/separators | 32,000 characters |
| Generated RED probes | First 3 valid probes, 200 characters each |
| Full-depth fixed probes | 6 |
| SDK retries / request timeout | 0 / 90 seconds |
| Source entries / bytes | 20,000 / 536,870,912 |
| Git clone timeout per attempt / fan-out maximum | 120 seconds / 24 |

Other file and probe caps remain in the complete serialized profile. Actual
effective limits and omissions must appear in retained production metrics.
The runner observes only the `fugu.client.make_client` SDK boundary. It returns
the original SDK response unchanged; native narrow response recovery owns any
additional request. Every live request must request 4,096 tokens and use one of
the frozen production model identifiers. Requested and served identifiers are
recorded separately.

The lead supplies a snapshot with `manifest.json` containing the full checked
commit and SHA-256 for every Python file under `src/fugu`. The loader verifies
the complete inventory, rejects symlinks/bytecode and already imported Fugu
modules, and checks that all loaded modules come from that snapshot. Hashes are
checked before each native stage and after the run. Source, profile, prompt
construction, fixed probes, inputs, runner, dependency versions and prepared
manifest are recorded before calls. The engine source copy stays outside tracked
deliverables; commit and hashes make it reconstructible.

The checkpoint used **`e184128979b3551ff6cb97561cd7822f4a9accd0`**, a lead-frozen
legacy engine at `/tmp/fugu-current-limits-base-engine`, solely for offline
compatibility. Its initial 1,600/600 caps are intentionally observed by tests.
It is not the improved candidate and its offline plan has
`ready_for_live_review=false`.

## Budget, stop and resume

The proposed later ceiling is **1,900 cumulative SDK attempts**, with 800 for the
first 20 cases and 1,100 for the remainder, also bounded by 1,900 overall. This
authority is inactive during the offline phase.

For the fixed 45 audits and 63 semantic units, the structural maximum is 1,323
primary requests plus 513 native retries, or 1,836 total. The first 20 contribute
at most 580 + 220 = 800; the remainder at most 743 + 293 = 1,036. The maximum
requested completion allowance at the ceiling is 7,782,400 tokens. It is not a
prediction of returned tokens or spending. Cost and remaining quota are unknown.

`RequestJournal` holds one process owner lock and serializes SDK attempts. It
persists the cumulative reservation and numbered request **before dispatch**.
Initial, native retry and failed attempts consume the same counter. Recorded
successful replies are replayed without another SDK dispatch when an interrupted
stage must be reconstructed. Completed stage outputs are cached unchanged,
including partial results and severe findings. Valid results are not rerun to
improve a score.

Quota exhaustion, authentication failure and temporary HTTP 429 have distinct
persistent classifications. Any provider error, request-contract drift or
journal write failure closes dispatch before native fallback can send another
request. Unknown provider error bodies and client credentials are never stored.
An interrupted reservation is an orphan requiring review. Resume preserves its
counter and stop latch; it does not reissue the unknown request. The runner has
no command to clear that latch or reset a budget.

All planned rows are written before dispatch. Failed/interrupted runs preserve
partial stage evidence and account for attempts in a final write. Resuming a
stopped run preserves earlier completed rows. Source/plan drift is rejected
before new requests. Any valid completed responses and unfinished work belong
in the handoff rather than a replacement run directory.

## Evidence and scoring

The later measurement directory contains:

- `plan.json`, `plan-hash.json`, `cases.json`: fixed inputs, grouping, profile,
  source/runtime hashes, prompt/probe hashes, partition limits and plan binding.
- `data-release.json`: the explicit later lead release reference and accepted
  plan hash. The reference is an audit record; the CLI does not authenticate
  queue authority. The operator must establish the actual grant before use.
- `budget.json`, `calls/NNNNN.json`: ordered messages/hashes, exact raw reply/hash,
  requested/served model, cap, finish reason, safe errors, failed latency and
  nullable token usage. No credentials or provider error bodies.
- `audits/<fingerprint>.json`: original native stage metrics, findings and
  coverage states. `journal_numbers` and `native_request_links` map native
  attempt order to the actual SDK journal. Recovery arrays are lineage references,
  not extra attempts. Logical `llm_calls` are not used as an SDK counter.
  After a stop, native error metadata may include calls denied by the observer.
  Count mismatches remain visible for review; the journal is the dispatch counter.
- `fugu.json`: every planned case, native member results, identical-input reuse,
  original expected composition outcomes, summary, SDK usage and omission/parse
  accounting. Unknown usage stays null with known subtotals and unknown counts.
- Chart PNG/SVG files and `chart-data.json`: plotted values, source hashes,
  paired/excluded IDs, versions, native thresholds and scope caveats.

The primary attack denominator includes every planned attack: detected, missed,
incomplete and unattempted are explicit segments. An incomplete row with a
retained severe finding remains visible as raw evidence but is not rewarded as
a complete primary detection. Conditional comparison is secondary and uses
exactly the same complete intersection/excluded IDs for every included tool.

Fugu description/crafted detection is any native finding of medium severity or
above. Source-composition outcomes retain the original trifecta/shadowing
expectations and matching rule; disagreements are recorded without relabeling.
Dependency cases retain raw source flags but have `detected=null` and no
reputation detection rate. Source/inference completion is distinct from
capability completion. Raw benign flags, confirmed false positives and pending
manual adjudication are separate counts. No population false-positive rate or
universal ranking follows from this small selected set.

Omission and parse totals count each distinct cached audit once, not all 54
member contexts. Missing metrics remain unknown. Mounted content characters
exclude headings; mounted/RED packet characters include them. Native call and
validation error records are separate from actual SDK dispatch counts.

## Historical references

Reused tools are dated, versioned historical executions on the same 20 inputs:

| Tool | Pinned version/commit | Native threshold and retained counts |
|---|---|---|
| fuzzd | 0.13.0 / `f739e120cd7dc253fead2a1f13668f9535e4d8a5` | Medium+ unsuppressed findings: 10/15; any findings: 11/15 |
| mcp-sec-audit | 0.1.0 / `457057a7dfda6b81622a12ee68b74f76f3fbde85` | Aggregate medium+ at score 25: 0/15; any capability flags: 12/15 |

Both retained executions flagged 0/5 constructed controls at their defined
medium thresholds. Their risk scales are not calibrated to one another.
Capability presence alone does not establish maliciousness. The loader verifies
versions/commits, retained fuzzd packet hashes and uniform mcp-sec wrapper hashes;
binary/lock/rules hashes are retained from
[setup.json](../bench/results/2026-10-02-full/competitors/setup.json).
Snyk has no measured case result in this protocol. Its earlier daily-quota stop
is preserved in the [historical report](benchmark-full.md); it is not retried.

The [retained Fugu SDK context](../bench/results/2026-10-03-current-limits/offline-checkpoint/historical-telemetry.json)
includes 1,355 requests, 611,330 prompt tokens, 437,721 completion tokens and
2,362.979 summed SDK seconds, including 7 structured retries and 52 later Super
recoveries. Historical derived bounds show mount loss on 5 distinct inputs and
RED truncation on 10. The source/profile and full-capability completion contract
differ from the new protocol. These figures are context, not measured savings
for the improved version.

## Reproduce the offline checkpoint

Run from the checkout root. Use the existing shared environment without syncing:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHON_DOTENV_DISABLED=1 UV_CACHE_DIR=/tmp/fugu-uv-cache \
  uv run --no-sync python -m pytest tests/test_current_limits.py tests/test_current_limits_charts.py \
  -q -p no:cacheprovider --tb=short
UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync ruff check --no-cache \
  bench/current_limits.py bench/current_limits_charts.py \
  tests/test_current_limits.py tests/test_current_limits_charts.py \
  bench/results/2026-10-03-current-limits/offline-checkpoint/verify.py
```

Native integration tests use harmless fixtures and a fake SDK. They require a
lead-provisioned full engine snapshot; otherwise they explicitly skip. Set
`FUGU_BENCH_TEST_ENGINE=/path/to/checked-snapshot` to test another frozen engine.
With the new profile the same native test requires every SDK request to use
4,096 tokens. The checkpoint's 41 passing tests used the legacy snapshot, with
zero skips; this does not validate the final improved engine.

The plotting environment is isolated from project dependencies. If absent, a
lead/operator can provision it with the pinned plotting dependency:

```sh
uv venv /tmp/fugu-charts-venv
uv pip install --python /tmp/fugu-charts-venv/bin/python matplotlib==3.11.2
```

The retained synthetic fixture references the original inputs by checkout-relative
paths and needs the retained historical competitor files. Regenerate its plots:

```sh
MPLCONFIGDIR=/tmp/fugu-mpl PYTHONDONTWRITEBYTECODE=1 \
  /tmp/fugu-charts-venv/bin/python bench/current_limits_charts.py \
  --source bench/results/2026-10-03-current-limits/offline-checkpoint/synthetic-fixture \
  --output /tmp/fugu-current-limits-chart-review
```

The author inspected all four rendered PNGs. The engine hash manifest, offline
preflight/plan, fixture, chart data and verification record are under
[offline-checkpoint](../bench/results/2026-10-03-current-limits/offline-checkpoint/).
Local engine copies and copied compatibility-test inputs stay under `/tmp`.
An offline artifact check is retained as `offline-checkpoint/verify.py`:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHON_DOTENV_DISABLED=1 UV_CACHE_DIR=/tmp/fugu-uv-cache \
  uv run --no-sync python bench/results/2026-10-03-current-limits/offline-checkpoint/verify.py
```

It checks the fixed input bytes, plan/code bindings, historical hashes/counts,
chart source values/nulls, PNG/SVG files and local documentation links. It also
checks the legacy engine bytes when that local snapshot is present. The native
integration tests remain the separate proof of stage execution with a fake SDK.

## Later data phase

After backend release, integration checks and independent review of the exact
production/runner commit, the lead freezes the checked engine. Rerun the native
fake tests against it, prepare the final plan and return its hash/profile/source
evidence for acceptance. Preparation alone is offline:

```sh
PYTHONDONTWRITEBYTECODE=1 UV_CACHE_DIR=/tmp/fugu-uv-cache \
  uv run --no-sync python -m bench.current_limits prepare \
  --engine-root /path/to/checked-snapshot \
  --output bench/results/2026-10-03-current-limits
```

Only a separately granted data-phase lease and exact accepted plan authorize
the following command. The owner verifies that grant before supplying these
values; the offline amendment supplies no such authority:

```sh
PYTHONDONTWRITEBYTECODE=1 UV_CACHE_DIR=/tmp/fugu-uv-cache \
  uv run --no-sync python -m bench.current_limits run \
  --engine-root /path/to/checked-snapshot \
  --output bench/results/2026-10-03-current-limits \
  --approved-plan-sha256 ACCEPTED_PLAN_SHA256 \
  --data-release-ref EXPLICIT_LATER_QUEUE_RELEASE
```

After the run, render from the actual result directory, retain every incomplete
case, manually adjudicate fresh benign flags where appropriate, inspect the
figures and obtain independent evidence review. Runtime/full-capability claims,
cost claims and a claim that these limits are optimal remain unsupported unless
separately measured. The original fresh measurement outcome is still unfinished.
