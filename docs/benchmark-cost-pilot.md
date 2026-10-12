# Cost pilot owner operations

This benchmark compares the full native Fugu product with a source-and-web Ultra/Super/Ultra agent. Both use the same frozen sources, provider profile and USD2 ceiling. Fugu additionally uses its own OSV and Docker capabilities; this is not an equal-tool orchestration experiment. The total ceiling is USD10, with USD4 admitted before each pair. No implementation fake test is a measured result.

The implementation phase does not authorize a paid run, target execution, publication or native credential access by a coder. The separately assigned owner operates the following commands after independent code, truth and readiness review. Never answer native approval dialogs or bypass a denied build. Use the application worktree source and existing environment; no shared sync.

## Artifact order

`prepared-sources.json` → `prepared-inputs.json` → `preflight/preparation.json` → independent `private/readiness-review.json` → `run-plan.json` → new `admission/<unique>.json` observations. Earlier artifacts never refer to a later hash. All are immutable, exclusive-create files. Prepare/preflight/freeze issue zero paid requests.

The reviewer supplies complete source exports and independently frozen truth/proofs before preflight. The integrator supplies readiness approval after successful unpaid native smoke. Approval JSON requires schema_version1, named reviewer, exact kind and APPROVE. Truth approval binds the source inventory and truth/proof byte hashes. Code approval binds the exact engine commit/tree with no findings. Readiness binds prepared_inputs_sha256, preparation_report_sha256, truth_review_sha256 and code_approval_sha256. No measured arm creates or approves these records.

## Future assigned owner commands

```bash
PILOT_RUN=/Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/measured-run-01
PILOT_PREP=/Users/antonkogun/.local/share/drover/reports/fugu-cost-pilot-20261012/source-preparation
FUGU_NO_DOTENV=1 PYTHONPATH="$PWD/src:$PWD" uv run --no-sync python -m bench.cost_pilot prepare --root "$PILOT_RUN" --upstream-dir "$PILOT_PREP" --seed 20261012
FUGU_NO_DOTENV=1 PYTHONPATH="$PWD/src:$PWD" uv run --no-sync python -m bench.cost_pilot preflight --mode preparation --root "$PILOT_RUN" --pricing "$PILOT_RUN/private/pricing.json" --truth-review "$PILOT_RUN/private/truth-review.json" --operator-config "$PILOT_RUN/private/operator-inputs.json" --plan docs/superpowers/plans/2026-10-12-whole-system-cost-benchmark.md --engine-root "$PWD" --chamber-smoke --owner-credentials
FUGU_NO_DOTENV=1 PYTHONPATH="$PWD/src:$PWD" uv run --no-sync python -m bench.cost_pilot freeze --root "$PILOT_RUN" --preparation-report "$PILOT_RUN/preflight/preparation.json" --truth-review "$PILOT_RUN/private/truth-review.json" --readiness-review "$PILOT_RUN/private/readiness-review.json"
FUGU_NO_DOTENV=1 PYTHONPATH="$PWD/src:$PWD" uv run --no-sync python -m bench.cost_pilot preflight --mode admission --root "$PILOT_RUN" --allow-hosted --consent-id fugu-cost-pilot-usd10-native-approved --owner-credentials
FUGU_NO_DOTENV=1 PYTHONPATH="$PWD/src:$PWD" uv run --no-sync python -m bench.cost_pilot measure --root "$PILOT_RUN" --allow-hosted --consent-id fugu-cost-pilot-usd10-native-approved --cap-usd 10
FUGU_NO_DOTENV=1 PYTHONPATH="$PWD/src:$PWD" uv run --no-sync python -m bench.cost_pilot adjudicate --root "$PILOT_RUN" --review "$PILOT_RUN/private/adjudication.json"
FUGU_NO_DOTENV=1 PYTHONPATH="$PWD/src:$PWD" uv run --no-sync python -m bench.cost_pilot export --root "$PILOT_RUN" --output "$PILOT_RUN/publishable"
```

Set the preparation and admission modes explicitly. `--allow-hosted` and the exact consent ID are required for every measurement; credential presence alone never consents. No force, reroll, selective case, retry-after-orphan or fixture gate is available. Resume requires explicit `--resume` and refuses any orphan/unfinished pair; previously closed cases cannot be redispatched. Unknown errors retain the full request bound and stop both arms. All planned rows remain in terminal output, distinguishing partial attempts from unattempted cases.

## Operator and price inputs

Keep private inputs outside sources. `operator-inputs.json` includes credential_endpoint (official Nebius EU/US URL), scanner_binary_path and scanner_binary_sha256, scanner_image_digest with an immutable repository@sha256 digest, docker_base_digest and collector_digest, code_approval_path and code_approval_sha256, and native_approval_state `human_resolved` before assigned smoke. The scanner must be trusted, external to every source and run through its native network-none Docker branch. Host scanners, proxy/credential-helper Docker routes and remote Docker hosts are rejected. Existing Docker/Buildx version alone does not prove native build/run capability.

Pricing schema1 includes exactly the frozen Ultra/Super model IDs, integer microdollar rates per million input/output/cache tokens, context_tokens, billable_output_bound, verified output/reasoning/cache contracts, documented cache partition, basic_credit_bound1, Tavily microdollars per credit, zero unpriced fees, verified_at, account_verified, official endpoint and dated HTTPS authority_documents with local byte hashes. Fake authority and fixture flags never pass the owner boundary. Full-context reservation is conservative; inability to fit USD2 is a blocker, not permission to use a character heuristic. Included reasoning is billed within output totals; cached tokens are charged once. Tavily missing observed credits needs a frozen authoritative exact-one-credit success contract; errors remain unknown.

The bridge sets FUGU_NO_DOTENV before config imports and resolves only owner-authorized native storage or present environment values. Empty environment values disable fallback. Keys stay in process, outside messages/artifacts and children; after resolution the parent environment is reduced to a vetted infrastructure allowlist, then restored on exit. Original dotenv, stores, databases and unrelated research/logs are never benchmark inputs.

## Evidence and limits

Native run_cli_audit receives the complete local snapshot, full mode and detonateTrue with canonical automatic composition. Source/stage/trigger observations are passive; native verdicts, public exit codes, omissions and selected-trigger failures remain unchanged. Hosted A/B probes are not target execution. Native collectors show attempted transfers; NXDOMAIN does not prove successful HTTP delivery and filesystem paths do not prove file contents. Truth owner reproductions remain separate from measured arms.

The direct agent has exactly list_files/read_file/search_files/search_web. Reads preserve source bytes after strict UTF8 decode with opaque bound continuation inside long lines, at most200 lines and8192 serialized Unicode characters per page. Searches never become OSV queries or arbitrary fetches. Both agent roles have identical permissions, max4096 output tokens, temperature0.1, SDK retries0/timeout90 and32 outbound attempts including explicit recovery. Coverage comes from actual returned ranges, not model claims.

Exports require independent masked adjudication. Security and functional lanes, attempted/all-planned/completed denominators, unresolved claims, runtime requirements, failed request costs and unknown liability intervals remain separate. There are no claims of superiority, noninferiority or published README outcomes before measured review. Matplotlib is report-only in a separately reviewed renderer environment; no main environment dependency is added. Python3.10 syntax compatibility is checked separately from actual runtime compatibility; current fake tests use Python3.11 and POSIX ledger ownership. Windows live ledger remains unsupported.
