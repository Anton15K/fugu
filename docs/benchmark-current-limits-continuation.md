# Measured continuation of the current-limits benchmark

On 3 October 2026, the accepted continuation completed all 27 previously
unattempted cases with 919 SDK requests. The combined result has 39 complete
cases and the original partial case. Primary detection is **13/15 planned
malicious descriptions (86.7%)**, with one completed miss and one incomplete
case. One of five clean descriptions was flagged; independent adjudication is
pending. These are source and model-response results on the fixed curated set.

The [first interval](benchmark-current-limits.md), its 12 completed cases, one
partial case, failed request 359, and all 403 sealed parent files remain
unchanged. Independent review `qitem-20261003075455-5e493534` accepted source
`2b5e134f11ff4a1349d519dfaa2f0051c2012e1f`, the plan below, and bootstrap
`266592fe883c6a58c6671f9feff36b5a0be4d5ed4b680c494bfa58e6c2858cc6`.
The separately authenticated lead release `qitem-20261003080043-770294f3`
authorized this one child. No detector or profile change was made.

## Measured results

| Cohort | Complete / planned | Detected malicious / planned | Benign case flags / planned |
| --- | ---: | ---: | ---: |
| MCPtox descriptions | 14 / 15 | 13 / 15 | — |
| Clean descriptions | 5 / 5 | — | 1 / 5 |
| Crafted source cases | 11 / 11 | 7 / 7 | 0 / 4 |
| Composition sets | 7 / 7 | 3 / 4 | 0 / 3 |
| Dependency source controls | 2 / 2 | Outcome unavailable | Separate dependency labels |

The completed primary miss is `mcptox/mcp-simple-arxiv_9`. The incomplete case,
`mcptox/AlphaVantage_4`, retains its high advisory finding and receives no
completed detection credit. The secondary conditional primary result is 13/14
completed attacks (92.9%). The primary denominator remains all 15 planned cases.

`composition/shadow-pair` missed its expected shadowing rule even though
component findings reached medium or higher. The three trifecta sets matched
their expected rule. All three composition controls had negative composition
outcomes; two retained medium+ component findings. Composition detection uses
the scored trifecta/shadowing rules, while single-source detection uses any
medium+ finding. The raw `raw_medium_flag`, scored `detected`, and expected
composition rules remain available in the unchanged result rows.

Across the 12 benign cases, one scored case flag is pending adjudication.
Three rows have medium+ findings when composition member findings are included:
`clean/read_file`, `composition/control-ingress-egress`, and
`composition/control-private-egress`. The latter two have negative composition
outcomes. These counts answer different questions. Adjudicated FPR is
unavailable; this curated sample does not measure population FPR.

The `read_file` description only states normal file-reading behavior. Its
critical empirical finding came from mounted everyday-model replies containing
the synthetic harness canary after generated probes requested ordinary file
contents. No file tool or target filesystem ran. The retained
[manual assessment](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/evidence/benign-read-file-adjudication.json)
judges this an advisory false flag for malicious source classification against
the curated benign label. The model disclosure remains observed evidence;
independent adjudication is pending, and raw rows and adjudication fields were
not changed.

The dependency cases completed the assigned source/inference stages. Their
reputation outcomes remain unavailable because live reputation was excluded.
Crafted and composition cases remain separate from the description cohort.
This continuation samples the untouched portion of an existing benchmark; its
two intervals do not establish an independent 40-case rerun or population-wide
performance.

### Measured figures and historical comparison

- [Primary results and clean-description flags](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/charts/common-results.png)
- [Coverage of the fixed 40 cases](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/charts/cohort-coverage.png)
- [SDK attempts and known usage](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/charts/call-telemetry.png)
- [Machine-readable chart data](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/charts/chart-data.json)

All three PNGs were visually checked; their SVG counterparts parse. Captions
identify both UTC intervals, the unchanged 4,096-token profile, the historical
comparator date, the retained partial finding and pending benign judgment.

The reused comparator snapshot is `2026-10-02-full`: fuzzd 0.13.0 and
mcp-sec-audit 0.1.0. Their source/binary/rule/packet hashes remain pinned in the
existing artifacts. No comparator was rerun. The normalized primary thresholds
are any medium+ finding for Fugu, any unsuppressed medium+ finding for fuzzd,
and aggregate risk 25+ for mcp-sec-audit. Native capability flags are separate.

| Tool | Normalized detections / 15 planned attacks | Same 14 complete paired attacks | Clean-description flags |
| --- | ---: | ---: | ---: |
| Fugu, two current-profile intervals | 13 / 15; one miss, one partial | 13 / 14 | 1 / 5, pending |
| fuzzd 0.13.0, historical | 10 / 15 | 10 / 14 | 0 / 5 |
| mcp-sec-audit 0.1.0, historical | 0 / 15 | 0 / 14 | 0 / 5 |

The historical native flags were 11/15 for fuzzd and 12/15 for mcp-sec-audit;
their differing risk contracts limit interpretation of normalized results.
The paired set excludes only the original incomplete AlphaVantage case and
uses the same 14 IDs for every tool. These measurements support this dated,
fixed-input comparison. They do not establish universal superiority.

### Actual calls, usage and coverage

| Interval | UTC window, 3 October 2026 | SDK attempts | Known prompt tokens | Known completion tokens | Stop |
| --- | --- | ---: | ---: | ---: | --- |
| Original parent | 02:45:32–02:55:27 | 359 | 85,076 | 112,637 | HTTP 500 at request 359 |
| Untouched child | 08:07:02–08:35:35 | 919 | 498,335 | 307,652 | None |
| Combined | Two intervals | 1,278 | 583,411 subtotal | 420,289 subtotal | Parent stop retained by interval |

All 919 child requests returned, used the 4,096-token cap and finished with
`stop`. Child usage is known for every call: 640 requested/served
`nvidia/Nemotron-3-Ultra-550b-a55b` and 279 requested/served
`nvidia/nemotron-3-super-120b-a12b`. The numbered journal contains 50 semantic
and 869 harness requests. There were zero child provider errors, orphan
reservations, output errors, native recoveries or replay requests. No restart
or accounting recovery was needed.

The original failed request still has unknown tokens, so combined whole token
totals remain null. The 19 native call-error records belong to the original
partial run; the combined SDK ledger has one provider error. Native error or
recovery references add no SDK attempts. Summed SDK durations are 1,689.37
seconds for the child and 2,281.38 seconds across both intervals; these sums
exclude the gap between intervals. Remaining quota was not queried. No quota
exhaustion occurred in this child interval. Cost and savings were not measured.

Observed child phase counts are 194 common and 725 remainder, within caps
280/1,036. Cumulative phases are 553/800 and 725/1,100; total 1,278/1,900.
The 41 child member contexts used 32 distinct audits with nine cache reuses.
Combined coverage contains all 45 planned unique audits and 54 observed member
contexts. All 63 semantic units completed; 62,495 source characters were
submitted with zero omitted characters/files/units in the recorded metrics.
Mounted comparison coverage is 779/792; the 13 missing comparisons remain in
the original partial case. Reputation and detonation remain outside this scope.

## Accepted preparation and authority

The accepted zero-call preparation is
`bench/results/2026-10-03-current-limits/continuation-offline/prepared-v3/plan.json`.
Its canonical plan digest is
`ea8cff37184b4dd7efe06d3494643462298b398bebcb471d50ce0d6d76f32835`.
`execution_authorized` is false. The adjacent release template is also false.
These files provide review evidence and do not grant access to inference.
The previous prepared-v2 plan
`0e859af4efdda0c6f8c0ee48664486444563ca3af21a4c2cc2ea4e9bf8e74f74`
is preserved byte for byte and superseded for execution by the aggregate
accounting correction. Independent review of that candidate required rework.
The new exact plan, source and bootstrap subsequently passed independent review
before the separately authenticated data grant used here.
The earlier zero-call plan `4e5d5569…f921e` is retained locally and superseded
because the module was corrected to accept macOS's system `/tmp` alias.

## Fixed inputs and request bound

The selection follows the original 40-case order: two remaining MCPtox attacks,
five clean descriptions, 11 crafted cases, seven composition sets, and two
dependency source cases. Labels, tool packets, grouping, and expected composition
rules remain those of the original manifest. No selected audit fingerprint
overlaps an observed parent audit.

The 41 member contexts share 32 unique audits and 50 semantic units. Nine contexts
reuse the child cache. For an audit with `u` units, the primary bound is `u + 28`:
semantic requests, one RED request, and three arms over six fixed plus three
generated probes. Native recovery adds at most `u + 10`: one structured retry
per semantic unit, one RED retry, and one empty-length recovery for each of nine
Super comparisons. Thus each unique audit is bounded by `2u + 38`.

| Phase | Unique audits | Semantic units | Primary | Native recovery | New maximum | Parent + child / original cap |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Common descriptions | 7 | 7 | 203 | 77 | 280 | 639 / 800 |
| Remaining cohorts | 25 | 43 | 743 | 293 | 1,036 | 1,036 / 1,100 |
| Total | 32 | 50 | 946 | 370 | 1,316 | 1,675 / 1,900 |

The original remaining allowance is 1,541 attempts. Cache reuse is required;
counting all 41 contexts as new audits would reach 2,053 cumulative attempts.
Every initial request, native retry, error, and uncertain reservation consumes
the budget before dispatch. The SDK itself has zero retries.

The engine is frozen at `cc58a58d6cea861510980814ae2e70b7bdf24e63`, including all
37 Python files. The inherited profile uses 4,096 output tokens, 90-second
timeout, temperature 0.1, 24 semantic units, 6,000 characters per unit, and a
32,000-character complete mount/RED packet. Ultra serves semantic, RED, baseline,
and strong arms; Super serves the everyday arm. Scope is S0/S1/S2/S4 and source
composition. Target execution, detonation, live reputation, browser/HTTP work,
fresh competitors, and the refused discovery scopes remain excluded.

## Portable offline preparation

Use the existing shared environment without synchronization. The checked
snapshot is a local execution artifact and is excluded from tracked deliverables.
On this host it is `/tmp/fugu-current-limits-checked-cc58a58d6cea`.

To reconstruct it on a checkout whose source bytes match the accepted engine,
run the following from the repository root. It verifies every source before
creating a new snapshot. If any source differs, obtain the exact cc58a58 sources
through the lead's checkout procedure first.

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
  uv run --no-sync python - <<'RECONSTRUCT_ENGINE'
from pathlib import Path
from bench import current_limits as base
from bench.current_limits_continuation import load_parent

parent = load_parent()
engine_root = Path('/tmp/fugu-continuation-engine-cc58a58')
if engine_root.exists():
    raise SystemExit('Use an existing verified snapshot or a new empty path.')
blobs = {}
for name, expected in parent.plan['engine']['hashes'].items():
    path = base.ROOT / name
    if path.is_symlink():
        raise SystemExit('Source symlink rejected.')
    data = path.read_bytes()
    if base.sha(data) != expected:
        raise SystemExit('Checkout does not contain the accepted engine bytes.')
    blobs[name] = data
for name, data in blobs.items():
    destination = engine_root / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
base.write_json(engine_root / 'manifest.json', parent.plan['engine'])
base.verify_inventory(engine_root, parent.plan['engine'])
print('Verified 37 source files; zero provider requests.')
RECONSTRUCT_ENGINE
```

Prepare once into a fresh offline directory:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
  uv run --no-sync python -m bench.current_limits_continuation prepare \
  --engine-root /tmp/fugu-continuation-engine-cc58a58 \
  --prepared-dir /tmp/fugu-continuation-prepared
```

Preparation rechecks the 402 parent bindings plus its inventory, the original
manifest, all original input files, frozen source/profile/runtime, copied regular
inputs, grouping, unit counts, cache disjointness, and request bounds. It writes
`plan.json`, `plan-hash.json`, `cases.json`, a non-authorizing
`release-template.json`, and local copied `targets/`. Existing plans are preserved.
No child budget, registry, release, or SDK client is created.

The original tracked input paths must be available. Copied targets and snapshots
are local artifacts. A plan binds its prepared target paths, timestamp, runtime,
and module hash, so preparation on another path creates a new digest for review.
Do not overwrite an accepted plan to relocate its inputs.

## Authenticated measured execution

The lead owns integration, exact independent review, and data authorization.
The accepted data row was sourced from `control-lead@fugu`, addressed to
`research-security@fugu`, and claimed by that seat. Its complete body is the
prepared release template with `execution_authorized=true`, the full reviewed
commit, and the accepted review qitem reference. Every other field must match
the template exactly. A prose instruction or a qitem reference alone is rejected.
The CLI obtains both identity and the complete row through authenticated `rig`
commands before loading provider settings. Credentials stay in the application
loader, and the accepted default endpoint is enforced.

Only this child is permitted:
`bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/`.
Its parent-keyed registry lives outside it at
`bench/results/2026-10-03-current-limits/continuation-registry/708623e0fac256a4cb2810bdddc2875ba22a1ad3b16bbdb7ed39324821d3b987.json`.
An exclusive lock and permanent owner seal bind the child path, plan, release,
parent usage, models, contexts, and caps. Another directory, release, plan,
deleted registry/budget, or changed request bytes is rejected.

An open-session marker is durable before requests. Each reservation has a guard
that is cleared only after the response and ownership checkpoint persist.
Provider/auth/quota/rate errors, orphans, malformed state, failed storage, and an
unexpected owner exit close future dispatch. Restart retains counters and the
latch. Only an exactly bound successful request may be replayed; replay creates
no new SDK attempt. Terminal child rows are returned without rerunning their
analysis. The original parent's stop remains intact.

The measured invocation used the exact reviewed bootstrap, retained under
[`evidence/reviewed-bootstrap-v2.py`](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/evidence/reviewed-bootstrap-v2.py).
It authenticates the release, checks inputs/source in a separate credential-free
process, loads the project's configured credentials, then reauthenticates and
validates before dispatch. The recorded invocation was:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  uv run --no-sync python /tmp/fugu-current-limits-continuation-reviewed-bootstrap-v2.py \
  --data-release-ref qitem-20261003080043-770294f3
```

This invocation has finished. It is retained as execution provenance; another
measured phase requires separate authority and review. The released evidence
must remain sealed.

The child tree contains the accepted plan/cases/release, `budget.json`,
numbered `calls/`, native `audits/`, and a 27-row `fugu.json`. Aggregation adds
`combined.json` and `provenance.json`. The outside registry, guards, and locks are
execution state; their exact bytes are included in this phase's inventory.
A provider stop returns exit code 2 with retained partial evidence. It grants
no reset, second child, preflight call, or retry of the original error.

## Combined reporting

Offline aggregation uses the same engine and prepared plan:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
  uv run --no-sync python -m bench.current_limits_continuation aggregate \
  --engine-root /tmp/fugu-continuation-engine-cc58a58 \
  --prepared-dir bench/results/2026-10-03-current-limits/continuation-offline/prepared-v3
```

The aggregator takes a shared registry lock and verifies numbered requests
against their durable hashes and counters. It compares all durable child usage
fields with the ledger and outside registry: errors, orphans, token totals and
unknown usage, durations, models, finish reasons, phase and cumulative counts,
and the stop reason. Registry and ledger stop state must agree. An unresolved
open session or reservation guard requires owner recovery. The saved process
replay count is validated as a nonnegative integer and retained as a process
annotation; it consumes no SDK attempts and cannot be reconstructed offline.

A stop recorded after `fugu.json` publication can leave its saved accounting
stale even when the attempt count has not changed. Aggregation rejects this
state before writing `combined.json` or `provenance.json`; previously published
combined artifacts are left untouched. Through the same authorized owner path,
accounting-only recovery replaces usage and adds `accounted_utc`. It preserves
every case row and dispatches no inference when the child is stopped or already
terminal. The stopped child remains stopped. Aggregation then retains the stop
in both combined usage and the child interval. This recovery does not grant
execution authority or change the original parent's failed request or partial
case.

It emits schema 2 with protocol
`current-production-source-inference-continuation-v1`, the original 40 rows in
order, two interval records, `row_interval`, and exact parent/child result and
plan lineage. Only the 27 selected rows are replaced. The 13 carried rows,
including severe partial findings, remain structurally identical.

Usage comes from the 359 parent requests plus the child's numbered journal.
Cache hits, logical calls, native recovery references, and replay references add
no requests. The unknown usage of the original failed request keeps whole token
totals null; known subtotals remain available. Each interval retains its own
usage and dates. The provenance sidecar qualifies SDK numbers and native
alignment by interval, including the parent's 19 native errors versus one SDK
error. It does not edit the carried rows.

The chart consumer receives the original case manifest and existing comparator
directory. It verifies packet/source hashes and recomputes the same completed,
available case intersection for every tool. The original primary denominator
remains 15 attacks and five clean controls, with other cohorts separate. All
27 new cases completed, giving 39/40 complete overall because the original
partial case remains partial.

Benign raw flags, confirmed false positives, pending adjudication, partial cases,
and unattempted cases remain separate. Dependency expectations are unavailable
without live reputation. Two-interval captions are required. Cost, savings,
remaining quota, universal superiority, and population false-positive rates
have not been measured here.

## Verification and provenance

Run the scoped offline checks:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
  uv run --no-sync python -m pytest \
  tests/test_current_limits_continuation.py tests/test_current_limits.py \
  -q -p no:cacheprovider
```

The native integration fixture uses the exact frozen stages with a fake SDK.
It exercises 32 audits, nine cached contexts, semantic/RED/Super recovery,
unchanged terminal rows on restart, original 40-row aggregation, unknown usage,
and preservation of all 403 parent files. It also exercises the actual aggregate
path after a post-publication stop at the same 949-request count, rejects stale
accounting without changing existing combined artifacts, and recovers accounting
with zero new dispatches. All 27 child rows and 13 carried rows stay unchanged,
and the chart consumer retains the recovered stop and unknown whole token totals.
Its 949 fake attempts are synthetic test evidence. They are not measured
provider calls or a benchmark score.
The remaining tests cover selector drift, source/profile/runtime/input bindings,
authenticated release shape, cumulative and phase budgets, exclusive ownership,
reset rejection, crash/storage/provider stops, request hash validation, and stale
saved or ownership accounting beyond the attempt count.

The R1 offline correction passed 166 scoped tests and Ruff for the runner and
its tests. Raw fail-first, passing, recovery, preparation and binding evidence is
retained under
[`aggregate-accounting-correction/`](../bench/results/2026-10-03-current-limits/continuation-offline/aggregate-accounting-correction/).
That candidate uses the same 27 IDs, original input hashes and grouping,
37 frozen source files, profile, 41 contexts, 32 audits, 50 units, nine reuses,
and 1,316 / 1,675 / 1,900 request bound. At that offline checkpoint provider
requests were zero and the real child and registry were absent. Raw pytest logs
retain their original trailing whitespace; source and documentation whitespace
checks are separate.

The accepted parent inventory is
`63240327fc6adf050b6cefbd0340f1fb6c16700c48551bc12548b071a057783e`.
Lead packaging changed its schema-1 map to explicit schema-2 path/hash records;
the 402 bindings and all raw/data/source bytes are identical. The original
inventory digest remains
`0aae4a79a057069dfd568d6e06fe01653e046bf5a8fba9868e0257a311aa3835`,
preserved at the lead's local checkpoint
`refs/fugu-checkpoints/current-limits-evidence-0f95559`. The earlier read-only
assessment retains the normalization proof. This continuation binds schema 2
and makes no changes to either provenance version.

## Measured artifacts and offline reproduction

- [Raw 27-case child](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/fugu.json)
- [Combined 40-case result](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/combined.json)
- [Interval-qualified SDK and native provenance](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/provenance.json)
- [Ledger, row and preservation checks](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/evidence/analysis.json)
- [Authenticated source/input preflight](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/evidence/preflight.json)
- [Portable input-restoration proof](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/evidence/input-restoration.json)
- [Render commands and visual checks](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/evidence/qa.json)
- [Final offline checks](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/evidence/final-check.json)
- [Schema-2 path/SHA256 inventory](../bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/artifact-manifest.json)

The preflight/preservation checks bind 2,348 protected files and all three
owner files. The protected set includes the 403 parent files, 37 frozen engine
files, all 81 original input files, 68 prepared child input files and the
reviewed runner/chart modules. All retained hashes match. The original 13 carried rows and the new
27 child rows are structurally identical to their respective raw results.

The outside registry records 919 attempts, phases 194/725, a closed session and
no stop. Its persistent `.lock` is retained. No reservation `.guard.json`
remains. The empty child `.journal.lock` is retained as bookkeeping. The new
inventory includes every child deliverable, the exact outside registry/lock
and this report. It excludes itself; its own digest belongs in the authenticated
handoff. Engine snapshots, plotting dependencies and copied scratch inputs
remain local artifacts.

Input restoration requires the original manifest's input paths to be present;
the manifest alone is insufficient. From the repository root, copy them into a
fresh scratch directory without overwriting accepted plans, inputs or results:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
  uv run --no-sync python - <<'RESTORE_INPUTS'
import copy
import tempfile
from pathlib import Path
from bench import current_limits as base

original = base.read_json(base.FROZEN / 'cases.json')
assert base.sha((base.FROZEN / 'cases.json').read_bytes()) == base.FIXED_CASE_MANIFEST_SHA256
output = Path(tempfile.mkdtemp(prefix='fugu-current-limits-continuation-data-repro-',
                               dir='/tmp')).resolve()
copied = base.prepare_inputs(original, output, base.ROOT)
restored = copy.deepcopy(copied)
for case in restored['cases']:
    case['target'] = case.pop('original_target')
assert restored == original
for case in copied['cases']:
    assert base.input_hashes(base.case_target(case)) == case['input_sha256']
assert len(copied['cases']) == 40
print(output)
RESTORE_INPUTS
```

The retained restoration check verified all 40 cases and 81 regular files. Its
first scratch attempt hit the `/tmp` versus `/private/tmp` relative-path
assertion; that attempt remains recorded separately. Resolving the output path
and using a new scratch copy completed the check. No sealed inputs changed.

Chart regeneration uses the original immutable manifest and original input
paths, alongside the historical comparator artifacts. The scratch copy above
demonstrates restoration without changing that manifest's bytes. If a plotting
environment is absent, provision a separate one with the recorded version:

```sh
uv venv /tmp/fugu-charts-venv
uv pip install --python /tmp/fugu-charts-venv/bin/python matplotlib==3.11.2
```

Use a fresh output directory for regeneration. The accepted renderer checks
the original manifest, all packet hashes, comparator adapters, lineage and
interval accounting before rendering:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHON_DOTENV_DISABLED=1 \
  MPLCONFIGDIR=/tmp/fugu-current-limits-continuation-data-repro-mpl \
  /tmp/fugu-charts-venv/bin/python -m bench.current_limits_continuation_charts \
  --combined bench/results/2026-10-03-current-limits/continuation-cc58a58-untouched/combined.json \
  --manifest bench/results/2026-10-02-full/cases.json \
  --historical-competitors bench/results/2026-10-02-full/competitors \
  --output /tmp/fugu-current-limits-continuation-data-repro-charts
```

These input-copy and chart steps make zero provider requests and execute no
targets. SVG/PNG metadata can vary between renders; numerical chart data and
source/input bindings are the reproducible comparison.
