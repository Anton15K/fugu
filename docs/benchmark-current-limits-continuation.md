# Untouched-case continuation of the current-limits benchmark

This runner prepares one child for the 27 cases that were unattempted when the
[first interval](benchmark-current-limits.md) stopped. It keeps the original
12 completed cases, one partial case, failed request 359, and all 403 sealed
parent files unchanged. Preparation makes zero provider requests. A later run
requires independent review of the exact candidate and a separate claimed lead
data row.

The current offline candidate is
`bench/results/2026-10-03-current-limits/continuation-offline/prepared-v2/plan.json`.
Its canonical plan digest is
`0e859af4efdda0c6f8c0ee48664486444563ca3af21a4c2cc2ea4e9bf8e74f74`.
`execution_authorized` is false. The adjacent release template is also false.
These files provide review evidence and do not grant access to inference.
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

## Later authenticated data grant

The lead owns integration, exact independent review, and the later grant. Its
new data row must be sourced from `control-lead@fugu`, addressed to
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

After an explicit accepted grant, the lead supplies `FUGU_CONTINUATION_PLAN`,
`FUGU_CONTINUATION_RELEASE`, and `FUGU_CONTINUATION_PREPARED` pointing to the exact
reviewed prepared directory. This is the later run command, not an offline step:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  uv run --no-sync python -m bench.current_limits_continuation run \
  --engine-root /tmp/fugu-continuation-engine-cc58a58 \
  --prepared-dir "$FUGU_CONTINUATION_PREPARED" \
  --approved-plan-sha256 "$FUGU_CONTINUATION_PLAN" \
  --data-release-ref "$FUGU_CONTINUATION_RELEASE"
```

The planned child tree contains the accepted plan/cases/release, `budget.json`,
numbered `calls/`, native `audits/`, and a 27-row `fugu.json`. Aggregation adds
`combined.json` and `provenance.json`. The outside registry, guards, and locks are
execution state; their publication requires the later data packaging decision.
A provider stop returns exit code 2 with retained partial evidence. It grants
no reset, second child, preflight call, or retry of the original error.

## Combined reporting

Offline aggregation uses the same engine and prepared plan:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
  uv run --no-sync python -m bench.current_limits_continuation aggregate \
  --engine-root /tmp/fugu-continuation-engine-cc58a58 \
  --prepared-dir "$FUGU_CONTINUATION_PREPARED"
```

The aggregator takes a shared registry lock, verifies numbered requests against
their durable hashes and counters, and requires reconciled child accounting.
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
remains 15 attacks and five clean controls, with other cohorts separate. If all
27 new cases complete, combined completion is at most 39/40 because the original
partial case remains partial. No score is forecast by the offline plan.

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
and preservation of all 403 parent files. Its 949 fake attempts are synthetic
test evidence. They are not measured provider calls or a benchmark score.
The remaining tests cover selector drift, source/profile/runtime/input bindings,
authenticated release shape, cumulative and phase budgets, exclusive ownership,
reset rejection, crash/storage/provider stops, and request hash validation.

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
