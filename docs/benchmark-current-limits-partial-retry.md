# Measured whole-case retry of the partial benchmark result

On 3 October 2026, the fresh `mcptox/AlphaVantage_4` retry completed all native
source/inference stages and **18/18 mounted comparisons**, using **29 SDK
attempts**. The combined fixed set now has **40/40 complete cases** and
**14/15 planned malicious-description detections (93.3%)**, with one completed
miss. This combines three dated intervals, including an explicitly selected
whole-case retry; it is not an independent blind rerun of all 40 cases.

The [original interval](benchmark-current-limits.md) and
[two-interval result](benchmark-current-limits-continuation.md) remain sealed.
Their original partial case, HTTP 500 and all 1,278 earlier requests are retained.
Only the assigned case's whole new row replaces its old row in the new aggregate;
the other 39 rows are structurally identical. Final measured review is pending.

## Results on the fixed curated set

| Cohort | Complete / planned | Detected malicious / planned | Benign case flags / planned |
| --- | ---: | ---: | ---: |
| MCPtox descriptions | 15 / 15 | 14 / 15 | — |
| Clean descriptions | 5 / 5 | — | 1 / 5 |
| Crafted source cases | 11 / 11 | 7 / 7 | 0 / 4 |
| Composition sets | 7 / 7 | 3 / 4 | 0 / 3 |
| Dependency source controls | 2 / 2 | Outcome unavailable | Separate dependency labels |

The remaining primary miss is `mcptox/mcp-simple-arxiv_9`.
`composition/shadow-pair` also misses its expected composition rule. The three
trifecta sets match their expected rules. Composition detection scores the
assigned trifecta/shadowing rules; single-source detection uses any medium+
finding. Raw member findings and scored case outcomes are separate.

The new AlphaVantage row has a high semantic finding for an injected instruction
and a critical raw harness finding for a synthetic-canary echo. The echo is
observed model-response text. No auditee tool or filesystem executed, and no
real secret theft is established. The model/canary baseline differences limit
causal interpretation of harness findings. Detection here is the assigned
medium+ case flag, rather than proof of executed compromise.

The 12 benign cases retain one scored case flag and two additional medium+
composition-member finding rows. The previously accepted independent judgment
classifies `clean/read_file` as a false flag for malicious extension-source
classification. Both flagged composition-member rows remain correct negative
composition outcomes. This small curated set provides no population FPR.

## Dated figures and historical comparison

- [Description detections and clean flags](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/charts/common-results.png)
- [Coverage of all 40 cases](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/charts/cohort-coverage.png)
- [SDK attempts, known tokens and durations](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/charts/call-telemetry.png)
- [Machine-readable chart data](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/charts/chart-data.json)

All three PNGs were visually checked. Their captions show the measurement date,
engine `cc58a58`, the 4,096-token cap and the source/inference scope. Exact
interval times remain in the report and chart data. SVG versions
are retained beside the PNGs. Benign flags and accepted source-classification
judgments remain distinct from their unchanged raw null adjudication fields.

The comparator snapshot remains `2026-10-02-full`; no comparator was rerun.
Pinned source/binary/rule hashes, original packets and adapters are unchanged.

| Tool and dated scope | Normalized detections / 15 planned attacks | Clean-description flags / 5 |
| --- | ---: | ---: |
| Fugu, three current-profile intervals on 3 October | 14 / 15 | 1 / 5; independently adjudicated false flag |
| fuzzd 0.13.0, historical 2 October | 10 / 15 | 0 / 5 |
| mcp-sec-audit 0.1.0, historical 2 October | 0 / 15 | 0 / 5 |

Thresholds are any medium+ finding for Fugu, any unsuppressed medium+ finding for
fuzzd, and aggregate risk 25+ for mcp-sec-audit. Historical native capability
flags were 11/15 and 12/15 respectively; these are different risk contracts.
All 15 attack IDs now form the completed paired subset. These measurements
support a dated fixed-input comparison, with no universal superiority claim.

## Actual SDK accounting and coverage

| Interval | UTC window on 3 October 2026 | SDK attempts | Known prompt tokens | Known completion tokens | Stop |
| --- | --- | ---: | ---: | ---: | --- |
| Original parent | 02:45:32–02:55:27 | 359 | 85,076 | 112,637 | HTTP 500 at request 359 |
| Untouched continuation | 08:07:02–08:35:35 | 919 | 498,335 | 307,652 | None |
| Whole-case retry | 12:12:45–12:13:29 | 29 | 6,724 | 7,636 | None |
| Combined | Three intervals | 1,307 | 590,135 subtotal | 427,925 subtotal | Original stop retained by interval |

The retry made one semantic and 28 harness SDK requests: 20 requested/served
`nvidia/Nemotron-3-Ultra-550b-a55b` and nine requested/served
`nvidia/nemotron-3-super-120b-a12b`. All 29 returned with `stop`, output cap 4,096,
and known usage. Retry provider errors, output errors, native call/parse errors,
response repairs, orphans and replays are zero. There was no restart or added
HTTP retry. The observed count is within the independent 80-attempt allowance.

Summed retry SDK duration is 44.32 seconds; combined summed duration is 2,325.70
seconds. These sums exclude gaps between intervals. The earlier HTTP 500 still
has unknown tokens, so combined whole prompt/completion totals remain null.
Historical native error records remain in the original partial evidence; the
current replacement's native error counts are zero. Costs and remaining quota
were not measured. No retry quota/provider exhaustion was observed.

The retry submitted one semantic unit containing 272 source characters. Its
mount packet was 291 characters including headings; all three generated RED
probes and six fixed probes were retained. No source characters/files/units,
mount content or generated probes were omitted in recorded retry metrics.
Effective combined coverage is 45 distinct inputs, 54 member contexts, 63/63
semantic units and 792/792 mounted comparisons. Dependency reputation and
live detonation remain outside this source/inference completion measure.

## Accepted plan, authority and immutable history

Namespace: `bench/results/2026-10-03-current-limits/partial-retry-cc58a58/`.

- [Accepted plan](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/plan.json) and [digest](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/plan-hash.json): `738c380aa2e3fcdb5910dfcecb0ee8f87a1acf065b8d396c22f0677d40084794`.
- Frozen engine: all 37 files at `cc58a58d6cea861510980814ae2e70b7bdf24e63`.
- Wrapper SHA256: `14f12e72f49fc03608c3d5689085da7242e004b6b8586b5ee7371eb53bedfdfe`.
- [Bootstrap](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/bootstrap.py) SHA256: `6c458f8acb2ff8842a401ec3f3ab593d1819df9559e2dfa38e2d8aade90723bd`.
- Exact source review: `qitem-20261003120447-25369c91`, accepted commit `7a6ed056e5e8e1ee2d220b6b7b7749fefa5eefe1`.
- Separate authenticated data grant: `qitem-20261003121116-4ba56327`, sourced by lead and claimed by research.security.

The unchanged plan fixes temperature 0.1, 4,096 output tokens, 90-second timeout,
SDK retries zero, 24 semantic units, 6,000 characters per unit and 32,000-character
mount packet. The original one-case tool packet SHA256 is
`5659b7390f3c71ace07ec6cc29d3b2b913c7f3912c9d7b5145895ecddeaeec37`.
The [single-case manifest](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/cases.json)
only relocates the exact regular copied input and records its original target.
Copied targets and the engine snapshot remain local execution artifacts.

The existing RequestJournal directly preserves the 80-attempt plan binding,
provider/auth/quota/rate/orphan stops and every native SDK attempt. Native
structured/empty-length repairs remain production-owned. Unresolved native
failure stops further dispatch. A valid short generated-probe list would remain
partial and receive no completed-detection credit. No detector tuning occurred.

The bootstrap authenticated the pure-JSON grant before an isolated credential-free
preflight, then loaded project credentials through the configured loader in its
cold process. It reauthenticated and checked source/input/profile/default
endpoint before opening the new journal. Credentials are excluded from evidence.
The actual invocation and exit-zero summary are retained in
[execution evidence](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/evidence/execution.json).
This completed interval authorizes no further run or reset.

Raw and aggregate artifacts:

- [Fresh one-case result](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/fugu.json), [SDK budget](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/budget.json), numbered `measurement/calls/` and native `measurement/audits/`.
- [Three-interval result](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/combined.json) and [provenance](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/provenance.json).
- [Measured artifact inventory](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/artifact-manifest.json).

The accepted offline inventory remains byte-identical. This report is the
explicitly granted documentation amendment; its original accepted bytes are
retained as [accepted-offline-report.md](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/evidence/accepted-offline-report.md),
and the measured inventory binds the amended report. Original parent/continuation
artifacts, accepted runtime source/plan/bootstrap and owner files remain unchanged.
The lead separately amended the CI-only test fixture; its original/new hashes
and narrow diff are recorded in measured evidence, without runtime changes.

## Accepted prior benign judgment

The [byte-identical adjudication reference](../bench/results/2026-10-03-current-limits/partial-retry-cc58a58/prior-benign-adjudication.json)
has SHA256 `e714ec567dedd96c78cbf5ef7c292e9713dfc5f71223c4414a5c18da4b4cc94b`.
It was accepted by review `qitem-20261003100222-9c2b92be` at `d54b8e8` and
merged in `15764cf`. This phase makes no new benign judgment and preserves all
raw pending/null fields. The accepted judgment identifies the ordinary
file-reading description and the same-model/canary-baseline limitation; it
preserves the observed model disclosure without asserting malicious extension
behavior or real credential theft.

## Offline verification and chart reproduction

The accepted source boundary passed 67 scoped tests and Ruff, including full
native fake-SDK success/repair, provider/native stops, short RED coverage and
39-row preservation. Those fixtures made zero provider requests. The separate
actual measurement above used 29 real SDK requests. No source/dependency/Git
changes accompanied measurement.

Aggregation is offline and uses the original accepted engine/input bindings:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 \
  PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
  uv run --no-sync python -m bench.current_limits_partial_retry aggregate \
  --engine-root /tmp/fugu-continuation-engine-cc58a58
```

For plots, use a disposable environment outside project dependencies:

```sh
uv venv /tmp/fugu-charts-venv
uv pip install --python /tmp/fugu-charts-venv/bin/python matplotlib==3.11.2
MPLCONFIGDIR=/tmp/fugu-mpl PYTHONDONTWRITEBYTECODE=1 \
  PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY='' \
  /tmp/fugu-charts-venv/bin/python \
  bench/results/2026-10-03-current-limits/partial-retry-cc58a58/measurement/render_charts.py
```

On a clean checkout, the tracked original 40-case inputs must be present for
comparator packet validation. The plotting script reads their original paths;
prepared copied targets are unnecessary for chart reproduction. Aggregation
also needs the accepted frozen engine and the one copied regular retry packet;
restore it from the original target without overwriting accepted plans/results.
Path/runtime changes require separate preparation and review for execution.
Chart reproduction makes no provider requests. Final measured review and lead
integration remain the next steps.
