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
| Detonation | Run derived triggers with fake canaries and collectors | Configured chamber runs triggers from `/opt/target`; observations cover executed triggers/collectors only |
| Harness | Compare baseline and extension-mounted responses | Hosted A/B stated-intent probes with deterministic signal checks; not a complete tool-execution loop |
| Reputation | Check package/domain context | Source-cited Tavily/OSV lookups |
| Composition | Analyze relationships in repository fan-out | Member findings and coverage; not proof every possible combination ran |

### Optional static tool-surface scanner

The S1 stage can also run a pinned scanner over literal JSON/Python tool
definitions and `SKILL.md` instructions. It parses source without importing or
executing the audited extension. Syntax-only context marks selected comments
and literal references as informational; uncertain syntax receives no
exemption. The scanner is advisory: phrase matches need contextual review. The
existing Fugu S1 rules still run if this optional
component is absent; its metrics report the tool-surface pass as disabled.
Scanner errors or omitted surfaces mark S1 coverage incomplete.

To build and install the pinned component locally, use an existing Rust
toolchain:

```sh
uv run --no-sync python tools/build_static_rules.py
```

The build fetches the pinned source and uses `cargo build --locked --release`;
it does not install Rust. By default the scanner looks for
`src/fugu/_bin/static-rules`. Set `FUGU_STATIC_RULES_BINARY` to use another
binary, and optionally set `FUGU_STATIC_RULES_SHA256` to require its expected
SHA-256. `FUGU_STATIC_RULES_IMAGE` selects an existing trusted container image
as the scanner's isolated runtime; that invocation uses Docker with networking disabled and
read-only mounts. If no image is selected, a configured binary runs locally.
If an image is selected but Docker is unavailable, the invocation fails and
S1 coverage is marked incomplete; it does not fall back to local execution.
The application Dockerfile is configured to compile the
pinned scanner and place it at `/opt/fugu/static-rules`. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for upstream attribution and
license details.

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
comparisons through the same client interface. The 2 October full-capability
benchmark retains raw responses, model names and token usage. Dollar cost,
remaining quota and monetary savings were not measured.

Concealment and static analysis run locally. **Enabled semantic and harness
stages send selected extension text and prompts to the configured inference
provider.** Reputation sends identifiers/queries to Tavily and pinned package
lookups to OSV; Git sources are fetched remotely. Docker is the default chamber.
The optional Contree/Nebius Sandboxes driver sends target files to remote
compute when selected; live sandbox behavior has not been verified here.
Fugu is not an entirely local analysis system. Review these flows before
submitting confidential content.

## Full-workflow benchmark (5 October 2026)

On frozen workflow snapshot `dbc4f641`, Fugu completed **110/140 cases**; 30
remain partial. The four native scanner lanes completed **314/320 rows**; six
remain partial. The run recorded 4,581 SDK dispatches and 46 search calls, with
no provider errors or quota/budget stop.

The table compares primary flags on identical, completed attack inputs. The
native thresholds were fixed before measurement and differ by scanner.

| Native scanner / cohort | Complete attack pairs / planned | Fugu full-workflow flags | Native primary flags |
|---|---:|---:|---:|
| Sentinel / metadata (HIGH or CRITICAL) | 80/80 | 80/80 | 11/80 |
| MCP-Sec / metadata (risk ≥25) | 80/80 | 80/80 | 12/80 |
| Cisco MCP / metadata (native unsafe finding) | 74/80 | 74/74 | 74/74 |
| Cisco Skill / skills (HIGH or CRITICAL) | 3/10 | 2/3 | 3/3 |

MCP-Sec's secondary any-alert result is 66/80 attacks, distinct from its
12/80 primary result. Raw flags on completed clean controls were Fugu 1/19
metadata and 2/6 skills; Sentinel 2/19, MCP-Sec 0/19, Cisco MCP 0/19, and
Cisco Skill 0/6. These are unadjudicated, not population false-positive rates
(see the [full methodology and case-level results](docs/benchmark-full-workflow-20261005.md)).

![Primary flags on identical completed metadata attack and clean-control inputs](bench/results/2026-10-05-full-workflow/measurement/metadata-paired.png)

*Metadata: 80 matched attacks for Sentinel and MCP-Sec, 74 for Cisco MCP, and
19 matched controls per comparison. Intervals are Wilson 95% intervals.*

![Primary flags on identical completed skill attack and clean-control inputs](bench/results/2026-10-05-full-workflow/measurement/skills-paired.png)

*Fugu completed 3/10 planned skill attacks and 6/10 planned controls; the
matched complete intersection is n=3 attack pairs and n=6 control pairs. Cisco
Skill completed its full 20/20 lane. Intervals are Wilson 95% intervals.*

![Completion coverage for Fugu and measured native scanner lanes](bench/results/2026-10-05-full-workflow/measurement/completion-coverage.png)

*Coverage: Fugu 110 complete and 30 partial; native lanes 314 complete and
6 partial. Twenty-eight Fugu cases were chamber-limited and two had harness
coverage shortfalls. All six partial Cisco MCP rows had analyzer coverage
failures; four retain raw alerts but are excluded from complete-case scoring.*

These are clustered, previously visible convenience fixtures, not a blind or
population sample. The skill comparison is small, thresholds are not calibrated,
and no overall superiority to Cisco or broad source/composition ranking follows.
In these measured modes, source and composition have no matching native
interface; composition controls use a cross-member contract rather than a
clean-package label. A zero-trigger stage is not evidence of target execution.
The [full methodology and case-level
results](docs/benchmark-full-workflow-20261005.md) include exclusions, native
thresholds, accounting and interpretation; the [sealed measurement inventory](bench/results/2026-10-05-full-workflow/measurement/inventory.json)
binds the retained artifacts.

Historical methods: [4 October workflow integration](docs/benchmark-workflow-integration.md) ·
[3 October production-profile measurement](docs/benchmark-current-limits-partial-retry.md) ·
[2 October full-capability measurement](docs/benchmark-full.md).

## Current-source checks

Current source checks preserve the baseline S1 decision signatures and stage
status on all 45 recorded inputs. Regressions cover sensitive reads after
JavaScript regexes and escaped line breaks, Python exception operands and
comparison operands, captured names, and UTF-8 source positions. Inert comments
and simple rejection guards retain informational evidence. See the [current
source verification](bench/results/2026-10-04-integration/guard-operand-correction/README.md).

Normal configured S1 activation on an inert `SKILL.md` returned five advisory
findings with no scanner omissions or parse errors. That [installed activation
proof](bench/results/2026-10-04-integration/lead-integration-verification/installed-activation.json)
and the frozen paired results remain unchanged. Source checks do not replace
the workflow measurement. A fresh final application-image build and deployment
smoke remain unverified after the recorded Docker Buildx denial.

## Current application limits

The checked application uses a shared, immutable profile for inference and
source coverage. Its main bounds are:

| Area | Current default |
|---|---:|
| Model output | 4,096 tokens per request |
| SDK timeout / automatic SDK retries | 90 seconds / 0 |
| Semantic review | Up to 24 units, each at most 6,000 characters |
| Harness source and RED input packet | 32,000 characters, including file headings and separators |
| Generated RED probes | First 3 valid probes, at most 200 characters each |
| Materialized source tree | 512 MiB / 20,000 entries |

The SDK retry count does not include the stages’ bounded response recovery;
those requests are recorded separately. The source-tree caps are checked after
materialization and do not cap bytes transferred during a shallow Git clone.
See [production limits](docs/production-limits.md) for file caps, fixed probes,
coverage metrics, and cleanup bounds.

## Verification and limits

From the repository root: `uv run --no-sync python -m pytest -q`. From `web/`:
`npm run build`, `npm run lint`, `npm run contract`, `npm run smoke`,
`node scripts/audit-result.mjs`, and `node scripts/edge-reducer.mjs`.
The 2 October benchmark's scoped checks and independent artifact review verified
chart arithmetic, original evidence preservation and application hashes.
Current candidate verification and the advisory judging score are in the
[assessment](docs/hackathon-assessment.md).

Source preflight rejects descendant symlinks before host reads and remote payload
construction. It is not race-proof isolation of a changing source tree. Execution
coverage depends on chamber availability and trigger derivation. The 2 October
full-capability benchmark exercised the Docker chamber; remote Nebius Sandboxes
transport remains unverified. Public deployment safety is not established by
local tests or these guards. No deployment target is assigned.

[User story, advisory rubric and readiness](docs/hackathon-assessment.md) ·
[Under-three-minute demo script](docs/demo-script.md).
