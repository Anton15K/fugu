# 140-case launch prescription

Owner task: qitem-20261005095331-1a1e3054. This is a zero-call preparation artifact. The lead must integrate the released backend guard, fill the final plan hash, and separately assign authenticated data authority and both output territories before execution. A syntactically valid queue reference is a provenance parameter; it does not authenticate or grant authority. This task's queue ID is not a data grant.

## Accepted bindings

- Bootstrap: `launch.py`, SHA256 `d7937e6bee3bd56bafb14d1951af0ea4815feeab7950b5a8d25ec1152037febd`.
- Binding inventory: `bindings.json`, SHA256 `af02d71fc24b09e58a19c9f532beac52027dee7833af96a9d039bdc19c8fbda2`.
- Original 140-case manifest SHA256 `250aeeeaef812c39e5a10a7caec55bc36d79c1babb0066ce47dd80ede4c21143`.
- Existing frozen Fugu source39 at `dbc4f641bfad39f7004e64f08bf8351697f5ae7c`; explicit source and engine-manifest bindings are checked before loading.
- Final integrated runner and plan hashes are deliberately pending. `prepare` records the actual runner after lead integration; `fugu` and `competitors` require the exact accepted canonical plan hash and verify the runner bytes against it. No changing runner bytes were frozen in this task.

## Commands

These commands are a prescription, not a record of execution. Use fresh, later-assigned output paths. Existing measurement evidence must remain intact.

Lead update at10:16Z: the canonical140 Fugu plan is already frozen (hash prefix `8b737033`). Use its existing prepared output and full accepted hash in the data grant. Skip the `prepare` command below for that accepted plan; it is retained only as the initial preparation prescription. No additional plan freeze or pre-call review is requested.

```sh
cd /Users/antonkogun/dev/nebius_hack
FUGU_LAUNCH=.fugu-private/full-workflow-20261005/research/launch-preparation/launch.py
FUGU_LAUNCH_BIND=af02d71fc24b09e58a19c9f532beac52027dee7833af96a9d039bdc19c8fbda2
FUGU_NATIVE_OUTPUT=/tmp/fugu-full-workflow-backend-20261005/native140-final
FUGU_COMPETITOR_OUTPUT=/tmp/fugu-full-workflow-research-20261005/measurement-140
```

After backend release/integration, the lead can assign and prepare the native output with no credential loader or calls:

```sh
env -i PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
  UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 PYTHON_DOTENV_DISABLED=1 \
  uv run --no-sync --offline python "$FUGU_LAUNCH" prepare \
  --bindings-sha256 "$FUGU_LAUNCH_BIND" --fugu-output "$FUGU_NATIVE_OUTPUT"
```

The lead obtains `plan_sha256` from that directory's `plan-hash.json` and binds it plus this bootstrap/inventory into the later authenticated data assignment. Set `FUGU_PLAN_SHA` and `FUGU_DATA_REF` to those exact assigned values. Do not substitute the draft amendment or this preparation qitem. After claiming that later assignment, initialize all 320 supported competitor pairs before any measurement dispatch:

```sh
env -i PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
  PYTHONDONTWRITEBYTECODE=1 PYTHON_DOTENV_DISABLED=1 \
  PYTHONPATH=/Users/antonkogun/dev/nebius_hack:/tmp/fugu-full-workflow-research-20261005/sources/mcp-sec-audit/detection \
  /tmp/fugu-competitors-20261005/bin/python "$FUGU_LAUNCH" competitors --initialize-only \
  --bindings-sha256 "$FUGU_LAUNCH_BIND" --fugu-output "$FUGU_NATIVE_OUTPUT" \
  --competitor-output "$FUGU_COMPETITOR_OUTPUT" \
  --approved-plan-sha256 "${FUGU_PLAN_SHA:?accepted exact plan required}" \
  --data-release-ref "${FUGU_DATA_REF:?authenticated later data assignment required}"
```

Run Fugu in a cold process in the unchanged shared environment. The bootstrap explicitly calls the supported `dotenv.load_dotenv(project/.env, override=False)`, disables subsequent dotenv auto-discovery, calls the accepted frozen loader exactly once, then `run_frozen`. The accepted runner initializes all 140 Fugu rows before stage execution, verifies the profile/scanner/chamber prerequisites, and retains its existing journals and unavailable-chamber guard.

```sh
env -i PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
  UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHONDONTWRITEBYTECODE=1 PYTHON_DOTENV_DISABLED=1 \
  uv run --no-sync --offline python "$FUGU_LAUNCH" fugu \
  --bindings-sha256 "$FUGU_LAUNCH_BIND" --fugu-output "$FUGU_NATIVE_OUTPUT" \
  --competitor-output "$FUGU_COMPETITOR_OUTPUT" \
  --approved-plan-sha256 "$FUGU_PLAN_SHA" --data-release-ref "$FUGU_DATA_REF"
```

Then run the native competitors sequentially, in the isolated environment:

```sh
env -i PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
  PYTHONDONTWRITEBYTECODE=1 PYTHON_DOTENV_DISABLED=1 \
  PYTHONPATH=/Users/antonkogun/dev/nebius_hack:/tmp/fugu-full-workflow-research-20261005/sources/mcp-sec-audit/detection \
  /tmp/fugu-competitors-20261005/bin/python "$FUGU_LAUNCH" competitors \
  --bindings-sha256 "$FUGU_LAUNCH_BIND" --fugu-output "$FUGU_NATIVE_OUTPUT" \
  --competitor-output "$FUGU_COMPETITOR_OUTPUT" \
  --approved-plan-sha256 "$FUGU_PLAN_SHA" --data-release-ref "$FUGU_DATA_REF"
```

`uv --offline` prevents dependency downloads; it does not disable the later explicitly granted application inference/search calls.

## Native execution and accounting

Native order is fixed before observation: Sentinel100, MCP-Sec100, Cisco Skill20, Cisco MCP100, preserving original case order within each lane. Metadata lanes use the original name/description/genuine-schema packets from the same prepared targets Fugu uses. Schema absence remains absence. Source/composition cases have no supported competitor pairing; they remain in Fugu's planned140 denominator and are excluded explicitly from supported-cohort comparisons.

One existing `NativeRequestCounter` and one async lock serve both Cisco lanes. There is no new journal/subclass/registry. SDK retries are zero; Skill cap8192/temperature0/timeout120/native retries3 and MCP cap1000/temperature0.1/timeout30/native retries3 are unchanged. Native JSON schema, recognized JSON-object fallback, reasoning options and bounded native transient/empty-response recovery traverse `hosted_completion`. Every actual dispatch reserves one shared counter row before network. Native non-quota exceptions remain available to native bounded recovery; quota/auth, aggregate cap and orphan/evidence stops stay sticky. The old Fugu first-provider-error journals are unchanged. Fugu quota/auth stops are carried to both hosted competitors, and a retained competitor quota/auth stop prevents a later Fugu restart. Offline competitors remain independently useful when hosted calls stop.

Installed wheel file hashes and versions are checked through the exact isolated `site-packages` directory, avoiding MCP-Sec source-tree egg-info shadowing. Pinned source bytes and all recorded transitive versions are checked separately. MCP-Sec's wheel still lacks `detection.core`; execution uses the unchanged pinned source tree through the explicit `PYTHONPATH` above. No wheel repair is implied.

Rows are persisted before invocation. Completed, partial, failed and unavailable native rows are never automatically rerun. Interrupted `in_progress` rows become partial and receive no completion credit. Counter orphans require review, never a new namespace or counter reset. Fugu reuses only its accepted same-run cache/journal behavior. No historical outputs or detector-driven selection are used.

Hard ceilings: Fugu5400 SDK attempts in its three existing1800 journals, competitors1800 shared SDK attempts, total7200; Tavily480. Requested completion-token envelope36,864,000 is an upper bound, not token usage, spending, or a quota estimate. Actual usage retains unknown/null values. Remaining quota and cost are unknown.

## Private evidence and later export

- Fugu: `fugu.json`, `plan.json`, `cases.json`, `data-release.json`, `journals/fugu-*/`, and `search-budget.json`/`searches/` beneath the native output.
- Competitors: `competitors.json` contains safe status/flag/completeness/per-analyzer records, original input hashes and request-number links. `native/NNNN.json` retains raw native output privately. `hosted-counter/ledger.json` binds safe usage/error/options/latency metadata and exact request/response file hashes; its request/response directories stay private.
- Native stdout/stderr and logging are suppressed; the launcher reports only an exception class on failure. It never prints dotenv values, provider messages or tracebacks.
- Later public SDK metadata should use one compact record per line with context/stage/ordinal/number, requested/served model, native cap/temperature/timeout, request/options/artifact hashes, usage/nulls, finish reason, response length, latency and safe exception class/status. Export no messages, replies, source packets, authorization values, provider exception bodies or search payloads. Raw evidence remains hash-linked and private.
- Preserve incomplete/unavailable/unattempted planned rows. Later paired comparisons require matching case IDs/input hashes and complete native coverage, with planned counts and exclusions visible. Full-workflow eligibility is not an execution result.

## Verification boundary

`zero-call-proof.json` records AST/in-memory compilation, pure cohort work-list checks, 39 frozen source hashes, 385 installed native file hashes, source/transitive bindings and15 accepted file bindings. It records zero credential access, inference/search/native scanner/chamber calls or target execution. CLI help was checked in the shared environment without imports or loading credentials. This is launch preparation, not fresh inference, chamber reproduction or measured evidence. The human-selected remaining review is one final independent review of the exact combined measured result.
