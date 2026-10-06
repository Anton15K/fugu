# Point 1: execution evidence and permitted diagnosis

**Status: partial.** This packet establishes the current trigger and coverage behavior and preserves prior authored observations. It does not fulfill the real-MCP execution criterion: no fresh chamber smoke or MarkItDown target process ran.

## Candidate and invocation readiness

I passively inspected the retained public `microsoft/markitdown` source at commit `2b61a335a4bec721144498fe425a61f23e9e3d6e`. The acquisition record pins the archive SHA-256 to `3233a8112220cf781dd10c869614f4439d6137fc752896775f308c5e22388aae`; all four selected source files match that record. The exact hashes are in [inventory.json](../../../../bench/results/2026-10-06-demo-proof/execution/inventory.json).

The package README documents the `markitdown-mcp` console command for its default STDIO server and `markitdown-mcp --http --host 127.0.0.1 --port 3001` for HTTP/SSE. Its `pyproject.toml` maps the console command to `markitdown_mcp.__main__:main` and declares Python 3.10+ plus `mcp`, `markitdown[all]`, and `requests` dependencies. The README describes conversion of file, data, and HTTP(S) URIs and says the local server runs without authentication with the caller’s privileges. Those are documented capabilities and deployment limits, not a vulnerability finding.

The current Fugu `derive_triggers` returned an empty list for both the retained repository root and `packages/markitdown-mcp`. It does not resolve this nested `pyproject.toml` console script, and the package uses a `src/markitdown_mcp` layout rather than a recognized root `main.py`, `server.py`, or `__main__.py`. Therefore this candidate does not currently reach the execution driver from either tested root. The reproducible pin and derivation check is [trigger-derivation-check.py](../../../../bench/results/2026-10-06-demo-proof/execution/trigger-derivation-check.py).

The current Docker victim image is built from `python:3.11-slim`, adds `curl` and `dnsutils`, copies the source tree, and installs the collector CA. It does not install the target package or its declared Python dependencies. This is a second readiness gap even if trigger discovery were extended. The upstream source’s own Dockerfile was not built or used.

## Chamber boundary and historical evidence

This task started from the retained 5 October plan, which records the native Docker chamber as unavailable after the known Buildx denial, with target execution false and no retry. The lease prohibits retries, alternate chamber drivers, owner mounts, and target execution, so I did not run Docker or try another route. That benchmark used engine commit `dbc4f641bfad39f7004e64f08bf8351697f5ae7c`; this diagnosis inspected the current checkout at `d21543e927a1b67a21eab0e2e23ef9105f66733e`. The older 5 October measurements are not current-engine results.

The 2 October full-capability report preserves a real Docker detonation of an **authored installer-exfil fixture**, which produced a canary hit and six HTTP flows. It reports 17 applicable Docker detonations and 28 non-applicable cases. That is historical fixture evidence, not execution of MarkItDown or evidence about this current engine. A separate retained diagnostic contains one import result with exit code 1 and `ModuleNotFoundError`; it records no canary hit, HTTP flow, or DNS query. Both source artifacts are identified and hashed in [plan.json](../../../../bench/results/2026-10-06-demo-proof/execution/plan.json) and [inventory.json](../../../../bench/results/2026-10-06-demo-proof/execution/inventory.json).

## Current coverage behavior and checks

The current stage reports selected-trigger status by trigger identity and occurrence. Nonzero exits, timeouts (`exit_code: null`), missing results, and unexpected duplicate or unselected rows mark coverage incomplete while retaining returned findings. A deterministic severe finding still takes FAIL precedence over partial coverage. The scoped regressions also verify serialized stage metrics and propagation to composition-parent member coverage. All 22 tests in `tests/test_reliability_detonation.py` and `tests/test_readme_triggers.py` passed with a fake driver or pure local parsing; no Docker-dependent test ran.

An additional synthetic check exercised HTTP, DNS, and filesystem canary matching and the corresponding critical-network/high-filesystem finding mapping. It started no collector process. The same check confirmed two user-visible limits: a no-trigger stage makes zero driver calls, reports `executed: false` and `static_only: true`, yet the aggregate verdict can be PASS with a coverage caveat; a whole-driver exception is reported as failed coverage and produces WARN. Zero derived triggers therefore do not prove safety.

Even when a selected trigger exits zero, the stage’s declared scope is `selected_triggers_only`; this is not proof that the whole application behaved correctly. The recognized entrypoint wrapper treats a three-second timeout as successful startup completion, without recording an MCP protocol handshake. The DNS collector binds UDP/53 and runs a receive loop, so it was only inspected as source and never imported or started on the host. The HTTP and DNS collector logs are shared within a chamber across selected triggers; canary matches are useful evidence of observed egress but attribution to one trigger can be ambiguous when several triggers share the same chamber canaries.

The test module `tests/test_docker_driver.py` was deliberately not invoked: module import itself calls `docker info`, and the module includes image builds and real container execution. The detailed commands, outputs, fake-only scope and invocation counts are in [checks.json](../../../../bench/results/2026-10-06-demo-proof/execution/checks.json).

## Remaining criterion and next step

The actual target/chamber/provider counts for this task are all zero. The real-MCP claim remains unproven. A follow-up needs a separately scoped source/test change that recognizes the nested Python console script and provides the required package environment, plus a chamber prerequisite permitted under the retained Buildx-denial boundary. Until both are available, the right report for this candidate is passive/static-only analysis with execution unavailable, not a clean runtime result or a demonstrated malicious action.
