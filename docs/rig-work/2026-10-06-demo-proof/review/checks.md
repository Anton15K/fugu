# Independent checks and reproduction limits

Engine checkpoint `d21543e927a1b67a21eab0e2e23ef9105f66733e`; owned review `qitem-20261006-demo-proof-review`. Checks ran with `uv run --no-sync --offline`, dotenv disabled, empty provider-key overrides and bytecode disabled. All writes stayed in reviewer directories or `/tmp/fugu-demo-proof-review-20261006-*` scratch.

## Results

- 22 scoped regressions pass: `tests/test_reliability_detonation.py` and `tests/test_readme_triggers.py`. Pytest plugin autoload and cache writes were disabled, with a dedicated `TMPDIR` and `--basetemp`. Tests use fake drivers, in-memory storage or pure trigger parsing.
- Passive MarkItDown pin/hash/trigger replay passes: four files match acquisition and both roots derive zero triggers. No target module is imported.
- Synthetic matching/coverage helper passes: one HTTP, DNS and filesystem hit; critical-network/high-filesystem mapping; no-trigger PASS/static-only/caveat; whole-driver failure WARN/failed coverage.
- Retained semantic comparison, telemetry and checks reproduce byte for byte. All six source maps and three frozen engine vectors match; eleven wire prompt bindings and responses join to the measured stages. The two older calls have weaker character/source/stage bindings.
- All seven finding bodies and six original inputs were inspected. Corrected source spans, fixed selection, missing annotations, mutation rejection, conditional authority and unsupported impact claims were judged independently.
- 22 execution inventory bindings, four selected source files/acquisition and ten semantic inventory entries match. Thirteen original measurement/artifact hashes match. Exact Git baseline checks identify only the already documented older `server/app.py` difference; current 13 source/test bindings match current Git.
- All relative author-report links resolve. Python helpers pass Python 3.10 AST parsing. Seventeen author exports pass structural forbidden-payload-key checks and named credential-pattern checks, with the explicitly permitted generic first-party fixture literal distinguished.

## How these checks were isolated

The inspected author recount uses frozen first-party collection/chunk helpers in separate processes and blocks socket connections. It never constructs a provider client or runs a pipeline stage. The reviewer redirected only its temporary input directory into reviewer scratch, leaving its source, unit, prompt and comparison logic unchanged.

The synthetic helper's fixed scratch directory was likewise redirected into reviewer scratch while evaluating unchanged check logic under its original file path. No author file was edited. It called only the pure canary scanner and explicitly fake stage drivers. The only subprocesses in retained replay were trusted Python unit-binding helpers.

Reproduction needs the existing private source caches, original journals and frozen engine roots. A public checkout alone cannot reconstruct missing private originals. The scripts do not download, install or silently replace them. The author helper's existing-output refusal remains in effect.

The raw-to-stage join check was corrected to apply the frozen conversion caps (title 120, detail 600, excerpt 200), rather than incorrectly demanding full raw text equality. Its final normalized joins pass. This was a reviewer harness assumption, not a product or evidence discrepancy.

## Scope of absences

Fresh provider/search requests, scanner invocations, Docker commands/builds, target/chamber/collector processes and upstream execution were zero. `tests/test_docker_driver.py` was not imported; its module-level Docker probe is excluded. DNS collector source was read, not imported, because it binds UDP/53 and starts a receive loop. No UI change, browser, services, DB or dependency check was in this evidence boundary.

The credential-pattern check covers GitHub token/PAT forms, OpenAI-style key prefixes, AWS access-key identifiers and private-key headers. Manual export inspection complements it. Neither check proves the absence of every possible credential representation. Original source, prompt, reply, retained runtime token and unpublished issue bodies were not copied into new public artifacts.

The Buildx prerequisite retains an unverified chamber state and no detailed native denial rationale. No denied command or refused showcase discovery was retried. The independent verdict accepts that evidence limit while preserving the actual-MCP criterion as blocked.

Machine-readable proof: [checks.json](../../../../bench/results/2026-10-06-demo-proof/review/checks.json), [binding checks](../../../../bench/results/2026-10-06-demo-proof/review/binding-checks.json), [wire/export checks](../../../../bench/results/2026-10-06-demo-proof/review/independent-joins-export-checks.json), [Git/history checks](../../../../bench/results/2026-10-06-demo-proof/review/git-history-checks.json), and [selection/quote checks](../../../../bench/results/2026-10-06-demo-proof/review/selection-quote-checks.json).
