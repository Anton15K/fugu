# Reliability recovery and coverage accounting

Date: 2026-10-02. This note separates frozen benchmark evidence from the current, not-yet-independently-reviewed production diff.

## Changes

The production inference client now disables implicit SDK retries and applies a 90-second per-request timeout. A stage can therefore record the requests it owns, and provider errors or timeouts remain visible in stage coverage.

Semantic analysis now tries one conservative trailing-comma repair, then makes at most one same-prompt request with a 4096-token cap when the response has no usable `findings` list. A usable list is not retried: valid findings survive malformed siblings, the unit is marked partial, and severe findings retain FAIL precedence. Harness RED probe generation follows the same repair and one-retry policy for a whole unusable response. A usable `probes` list keeps its valid strings and is not retried because of invalid siblings. If a bounded recovery still fails, the static probes remain in use and stage coverage is incomplete.

Harness Super arms retry exactly once at 4096 tokens only when the 600-token response is empty and ends with `finish_reason=length`. The retry uses the same model, messages, and temperature. Nonempty responses are retained as returned. Setup failures no longer silently run the Ultra caller in place of Super; the affected comparisons are recorded as unavailable.

Detonation now records each selected trigger's exit status. Nonzero exits, timeouts (`exit_code=None`), and missing or unexpected result records mark detonation coverage incomplete. Findings from every returned result are retained. A zero exit means only that the selected trigger returned successfully; it does not establish that all behavior in the extension was exercised. A zero-trigger stage remains skipped and does not invoke the driver.

Malformed model text is **not** retained in stage metrics. Recovery metadata contains response character count, SHA-256, the original parse error, retry outcome, and normal call usage/latency records. The separately authorized live comparison artifact retains both raw responses.

## Evidence and cost

The frozen 40-case run predates these production edits. Its initial results recorded 15/40 complete cases. The benchmark-only recovery pass retried 52 empty Super responses at 4096 tokens; all 52 returned nonempty responses and the recovered artifact records 40/40 complete cases. Those retries covered 29 contexts and added 36,121 completion tokens, 37,522 repeated prompt tokens, and 195.776 seconds total measured latency (3.765 seconds per retry on average). The frozen call ledger also contains seven structured-response retries: six semantic and one harness RED; all seven initial responses were unusable and their retries parsed successfully. These benchmark recoveries demonstrate a repairable failure mode; they do not measure the current production patch across all 40 cases.

The authorized same-prompt Super comparison used two requests to `nvidia/nemotron-3-super-120b-a12b`, capped at 600 and 4096 output tokens. Both returned nonempty responses with `finish_reason=stop`, so this pair did not reproduce the original empty-at-600 failure. The 600-token request used 271 prompt and 554 completion tokens in 3.458 seconds; the 4096-token request used 271 prompt and 855 completion tokens in 4.662 seconds. The experiment supports retrying only the demonstrated empty/truncated condition rather than paying for a larger second request after every valid response. No dollar estimate is made because token pricing was not measured here.

The raw pair and full request metadata are in [the bounded comparison artifact](../bench/results/2026-10-02-reliability/super-token-bound-20261002T122220Z.json). Frozen inputs and results remain under `bench/results/2026-10-02-full/`; the artifact check confirms that directory remained unchanged during the comparison.

The retained [trigger diagnostics](../bench/results/2026-10-02-full/chamber-trigger-diagnostics.json) are supplementary, outside the 40-case primary denominator. For `crafted/09-clean-installer`, the install trigger exited 0, while the selected Python import trigger exited 1 with `ModuleNotFoundError: No module named 'csv_tidy'`. The previous stage discarded that status and treated returned evidence as complete. The new fake-driver regressions cover that status path without starting a chamber.

## Coverage and containment limits

- If every semantic unit fails or remains unusable after its one retry, the stage fails and the verdict reports incomplete analysis. Partial valid units and valid findings survive other failed units; a hard finding still yields FAIL.
- If harness comparisons all fail, the stage fails; if some succeed, it reports partial coverage. Missing Super setup is no longer hidden by a model substitution. Existing composition coverage accounting propagates child partial/failed states to the parent verdict and persistence/SSE replay.
- The source-read preflight resolves an explicit root and rejects descendant symlinks before remote stage reads or chamber packaging. It permits the root itself to be a symlink. This is a preflight check, not race-proof isolation: a concurrently mutable local tree could change after validation.
- Detonation covers only derived triggers. A selected trigger that exits 0 is recorded as completed, but behavior outside those triggers remains unmeasured. No chamber was run for this change.
- No full paid 40-case rerun was performed after the code edits. The offline fake-driver and stage tests verify coverage behavior; the two-call live comparison is a bounded sample, not a reliability-rate estimate. SDK retries are disabled, so provider/network failures that occur before a usable response remain incomplete rather than being hidden by transport retries.

Verification used fake inference and drivers: 215 scoped tests passed, with the two Docker-backed end-to-end detonation tests deselected. Those two tests were attempted once; both stopped during image build when the sandbox denied a Buildx activity-directory write, before a chamber ran or fixture content executed. They were not retried. The verification did not invoke paid audit paths.
