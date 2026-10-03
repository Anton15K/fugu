# One-case retry of the partial benchmark result

This phase prepares one fresh native source/inference run of
`mcptox/AlphaVantage_4`. **No measured retry has run yet.** The accepted prior
result remains 39/40 completed and 13/15 planned malicious-description detections.
The original partial case retains its advisory finding and gets no completed
detection credit. See the [two-interval report](benchmark-current-limits-continuation.md).

The offline assignment is `qitem-20261003110854-3eabaae9`. The lead owns exact
independent review, integration and a separate authenticated data grant.

## Fixed case and execution contract

The original 40-case manifest and AlphaVantage tool packet are unchanged.
The packet SHA256 is
`5659b7390f3c71ace07ec6cc29d3b2b913c7f3912c9d7b5145895ecddeaeec37`.
The original combined result SHA256 is
`436b0bd1e0e2bb4504ef82612dc2a5be175731a28718e851a5a29f2b1b05ffc7`.

- Engine: all 37 frozen files at `cc58a58d6cea861510980814ae2e70b7bdf24e63`.
- Models: Ultra `nvidia/Nemotron-3-Ultra-550b-a55b` for semantic, RED, baseline
  and strong arms; Super `nvidia/nemotron-3-super-120b-a12b` for everyday.
- Same production profile: temperature 0.1, output cap 4,096, timeout 90 seconds,
  SDK retries zero, 24 semantic units, 6,000 characters per unit and 32,000
  characters per mount packet. This case has one semantic unit.
- Independent hard limit: **80 cumulative SDK attempts**, including native
  response repairs. Prior requests remain 359 + 919 = 1,278. The maximum
  resulting cumulative count is 1,358. No HTTP 500 retry is added.
- Fresh entire case: new semantic analysis, RED generation, baseline replies
  and both mounted arms. The new result uses no old cache or completed probes.
- Benchmark completion requires all native source/inference stages complete
  and **18 expected and completed mounted comparisons**. A valid shorter RED
  probe list remains partial. Raw native stage evidence remains visible.
- Source/inference only; target execution, detonation, reputation and fresh
  competitor execution are outside this interval.

The usual bound is 29 primary requests plus at most 11 native repairs. The
existing production code owns those bounded structured/empty-length repairs;
the unchanged RequestJournal records every actual SDK attempt. Its provider,
quota, auth, rate, orphan and request-contract stops remain active. A short stage
observer closes that journal after an unresolved native stage failure.

## New outputs and immutable history

The new namespace is
`bench/results/2026-10-03-current-limits/partial-retry-cc58a58/`.
Its [plan](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/plan.json),
[plan digest](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/plan-hash.json),
[single-case manifest](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/cases.json),
[bootstrap](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/bootstrap.py)
and [non-authorizing release template](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/release-template.json)
are prepared. The measured `measurement/` directory is absent in this phase.
Copied inputs and the engine snapshot remain local execution artifacts.

After a separately granted run, `measurement/` will contain the existing
journal's budget/numbered requests/native audit and one-row `fugu.json`.
Offline aggregation writes new `combined.json` and `provenance.json` there. It
replaces **only the assigned case's whole new row**, including its fresh stages/probes,
and preserves the other 39 rows structurally. An incomplete new row receives
no completion detection credit. The original partial row and every original
raw request remain in their sealed histories.

The new aggregate records three intervals, with SDK request numbers and native
audit references qualified by interval. It preserves the original HTTP 500 and
unknown usage; whole token totals remain unknown while known subtotals can be
reported. It rejects stale saved retry accounting before writing an aggregate.
Actual new models, timestamps, tokens, latency, omissions, errors and detection
are unavailable until measurement. Current historical comparators and their
pinned input/contracts remain unchanged. Measured charts belong to the later
data/reporting phase; this offline phase produces no benchmark figures.

## Prior benign judgment

The byte-identical
[accepted independent adjudication](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/prior-benign-adjudication.json)
has SHA256
`e714ec567dedd96c78cbf5ef7c292e9713dfc5f71223c4414a5c18da4b4cc94b`.
It was accepted by final review `qitem-20261003100222-9c2b92be` at `d54b8e8`,
then merged in `15764cf`. It classifies the prior `clean/read_file` flag as a
false flag for malicious extension-source classification. The two composition
controls remain correct negatives under their composition rules.

This retry carries that reference and preserves all old raw pending/null
fields. It makes no new benign judgment. The observed synthetic-canary model
replies remain response-text evidence. The prior comparison did not isolate
extension content as their cause; no file tool or real credential disclosure
was established. This accepted judgment supplies no population FPR.

## Offline verification and reproduction

Use the shared environment without dependency synchronization, and the exact
37-file snapshot reconstructed as described in the prior report. Preparation
binds source/profile/runtime, original manifests/partial row, the exact packet,
new wrapper, bootstrap, one-case manifest, adjudication reference and namespace.
Existing plans are preserved. Moving preparation to a new path creates a new
digest requiring review.

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
  uv run --no-sync python -m pytest \
  tests/test_current_limits_partial_retry.py tests/test_current_limits.py \
  -q -p no:cacheprovider
```

The 67 scoped checks pass with default macOS test paths. The native fixture
allocates its own permitted scratch directory and replaces only the provider
SDK with synthetic replies. It completes a fresh case with 32 fake requests,
including semantic/RED/Super repairs, and preserves the other 39 rows. Its
HTTP 500 fixture stops after one request; unresolved semantic output stops
after two; a valid empty generated-probe list retains 12 mounted comparisons
and stays partial. All of those fixtures make zero provider requests.

Test logs, fail-first evidence, source/owner preservation and bytecode-cleanup
proof are retained under the new namespace's `evidence/`. An external reviewer
created 22 snapshot bytecode files during a fake check; only those generated
files were removed, and all 37 source hashes remained unchanged. No old report,
request, registry or stop latch was changed by this phase.

## Later data grant

The prepared plan and release template have `execution_authorized=false`.
The existing offline assignment cannot authorize the bootstrap. The separate
lead row must match the template with authorization true, the exact reviewed
commit/review reference and accepted plan digest, and be claimed by this seat.

The bootstrap authenticates that row, runs source/input preflight in an isolated
process with dotenv disabled and an empty API key, then loads configured project
credentials in its cold main process. The wrapper authenticates again before
loading the frozen engine; it validates the plan and default provider endpoint
before opening the new journal. Credentials are never included in evidence.

Lead-owned invocation after acceptance:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  uv run --no-sync python \
  bench/results/2026-10-03-current-limits/partial-retry-cc58a58/bootstrap.py \
  --approved-plan-sha256 "$ACCEPTED_PARTIAL_PLAN" \
  --data-release-ref "$PARTIAL_DATA_RELEASE"
```

The new completed/detected denominators and measured figures will be reported
after that interval. Costs, remaining quota, universal rankings and population
rates are unmeasured.
