# 🐡 Fugu — audit before install

**Know what you’re letting in.** Fugu helps developers review community skills,
MCP servers and plugins before granting an AI agent access to files, credentials
and tools. Submit an extension, inspect the evidence behind its verdict, and
review the checks that completed before making an install decision.

A useful report points to decoded instructions, flagged source, or observed
behavior and distinguishes direct evidence from a model’s judgment. **PASS is
limited to the performed checks; it does not certify safety.**

Built for the [Nebius × NVIDIA Global AI Hackathon](https://nebiusglobalaihackathon.devpost.com/),
Coding and Agentic Engineering track. [MIT license](LICENSE).
A public hosted demo and public YouTube video have not been published. The
repository is currently private; public judging access remains a submission task.

## Run locally

Requirements: Python 3.10+, [uv](https://docs.astral.sh/uv/), and Node
20.19+ within the Node 20 series or Node 22.12+ for the current Vite build.
Docker is optional for execution checks; without a working chamber, review the
reported coverage limits. Cloning currently requires repository access.

```sh
git clone https://github.com/Anton15K/fugu.git
cd fugu
uv sync --extra dev
cp .env.example .env
```

Set `NEBIUS_API_KEY` in your local environment/configuration to enable NVIDIA
inference on Nebius Token Factory. `TAVILY_API_KEY` is optional for reputation
queries. Keep both outside source control. Missing model credentials skip hosted
analysis rather than producing evidence that it ran.

Build the browser UI, then start the API with a dedicated development database:

```sh
cd web
npm ci
npm run build
cd ..
uv run --no-sync python -m fugu.server --port 8000 --db /tmp/fugu-dev.db
```

Open **http://127.0.0.1:8000/?mock=0** for live analysis. For frontend development,
run `npm run dev` from `web/` while the API runs; Vite proxies `/api` to port 8000.
The `/tmp` database is disposable; choose a persistent path for history you need
to retain. See [web instructions](web/README.md).

1. Select a **bundled example** to fill the source, then choose **Start audit**.
   Examples are crafted fixtures advertised by the API when available.
   Alternatively enter one Git URL or one directory on the API server.
2. Inspect the returned verdict, policy reasons and **Analysis coverage**.
   Expand a finding to see its source/exhibits and confidence tier. The full
   pipeline and event history are available below the report.
3. Reopen the existing `/audit/<id>` URL or choose a run under **Continue an
   audit**. With the same database, persisted events restore that run without
   submitting another audit.

Open **http://127.0.0.1:8000/?mock=1** and choose **Play simulated audit** for a
scripted walkthrough. Its findings, timing and verdict are labeled simulated;
no extension is fetched or analyzed. It is not a recorded real audit or
benchmark evidence. Live audit URLs reconnect to their actual server history.

## Evidence, analysis and verdicts

| Check | Purpose | Evidence boundary |
|---|---|---|
| Concealment | Decode hidden Unicode instructions | Local, deterministic |
| Static | Identify concrete source patterns | Local, deterministic |
| Semantic | Read supplied text for injection and deceptive intent | Hosted Nemotron judgment, advisory |
| Detonation | Run derived triggers with fake canaries and collectors | Configured chamber; observations limited to executed triggers/collectors |
| Harness | Compare baseline and extension-mounted responses | Hosted A/B stated-intent probes with deterministic signal checks; not a complete tool-execution loop |
| Reputation | Check package/domain context | Source-cited Tavily/OSV lookups |
| Composition | Analyze relationships in repository fan-out | Member findings and coverage; not proof every possible combination ran |

The verdict policy returns FAIL for critical findings or deterministic/empirical
highs; WARN for other high/medium findings, failed or partial analysis, or omitted
skill units; otherwise PASS. Intentional skips can accompany PASS, so read
coverage alongside severity. A target with no runnable trigger was **not
executed**. No canary hit in a bounded run does not prove harmless behavior.

## Nebius and NVIDIA integration; data flow

The [client](src/fugu/client.py) uses the OpenAI-wire-compatible SDK against the
configured Nebius Token Factory endpoint. [Configuration](src/fugu/config.py)
defaults to its EU endpoint and supports `NEBIUS_BASE_URL` overrides.

| NVIDIA model | Current role |
|---|---|
| `nvidia/Nemotron-3-Ultra-550b-a55b` | Semantic judge; harness baseline, strong mounted arm and probe generation |
| `nvidia/nemotron-3-super-120b-a12b` | Harness everyday-agent mounted arm |
| `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | Available router tier; not established as an active pipeline stage |

Token Factory provides runtime inference for the security reading and A/B
comparisons through the same client interface. Call records retain model and
usage where available; Super harness telemetry is incomplete, so universal
per-call timing/token or monetary savings claims are not supported.

Concealment and static analysis run locally. **Enabled semantic and harness
stages send selected extension text and prompts to the configured inference
provider.** Reputation sends identifiers/queries to Tavily and pinned package
lookups to OSV; Git sources are fetched remotely. Docker is the default chamber.
The optional Contree/Nebius Sandboxes driver sends target files to remote
compute when selected; live sandbox behavior has not been verified here.
Fugu is not an entirely local analysis system. Review these flows before
submitting confidential content.

## Fresh bounded evaluation

Frozen S0/S1/S2 engine, 2026-10-02; detection means any finding at least medium.
The engine predates the subsequent source-boundary and coverage fixes.

| Separate cohort | Result | Completion limits |
|---|---|---|
| MCPTox name/description attack sample | **26/30 planned detections (86.7%)** | 28 completed: 26 detected, 2 missed; 2 JSON parse failures |
| Constructed clean tool descriptions | 0/20 flagged | All completed; constructed examples |
| Cached public-skill sample | 0/19 completed flagged | 20 planned; 1 JSON parse failure; benign labels provisional |

These sets are not pooled. The results do not estimate ecosystem-wide accuracy
or false-positive rate, measure S3/S4, or establish superiority over competitors.
Comparator tools were not rerun locally and use different protocols.
Historical headline runs used label-contaminated inputs; the preserved history
is [explained here](docs/head-to-head.md#why-historical-fugu-484485-is-excluded).

[Protocol, failures and reproduction](docs/benchmark.md) ·
[Fresh chart](docs/benchmark-charts/fresh-results.svg) ·
[Raw semantic outcomes](bench/results/2026-10-02/semantic.json) ·
[Static outcomes](bench/results/2026-10-02/static.json) ·
[Input references](bench/results/2026-10-02/sources/index.json) ·
[Artifact inventory](bench/results/2026-10-02/artifact-manifest.json).
Detector reruns require separately acquired, hash-checked input caches; retained
chart regeneration is offline. Actual monetary cost and remaining quota are unknown.

## Verification and limits

From the repository root: `uv run --no-sync python -m pytest -q`. From `web/`:
`npm run build`, `npm run lint`, `npm run contract`, `npm run smoke`,
`node scripts/audit-result.mjs`, and `node scripts/edge-reducer.mjs`.
Current frontend checks pass with retained lint warnings; final integration and
independent review status is recorded in the [assessment](docs/hackathon-assessment.md).

Source preflight rejects descendant symlinks before host reads and remote payload
construction. It is not race-proof isolation of a changing source tree. Execution
coverage depends on chamber availability and trigger derivation; Docker was
unavailable for current live verification. Public deployment safety is not
established by local tests or these guards. No deployment target is assigned.

[User story, advisory rubric and readiness](docs/hackathon-assessment.md) ·
[Under-three-minute demo script](docs/demo-script.md).
