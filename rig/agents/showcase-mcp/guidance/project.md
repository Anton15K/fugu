# Fugu project context for all seats

Your working directory is the repository containing `rig.yaml`. Fugu audits
third-party agent extensions through concealment decoding, static and semantic
analysis, isolated detonation, behavioral A/B testing, reputation, composition,
and an evidence-tiered verdict. The project uses Nebius Token Factory/NVIDIA
models in its application; this engineering team runs on Codex.

Read `rig/CULTURE.md` and your delivered role before any work. Read `README.md`
and the applicable code for current state; `IDEA.md` explains intent. `HANDOFF.md`
has historical scaffold paths and pending-work claims that must be checked
against current files. `BOTS.md` supplies territory, secret-handling and shared
environment rules, but the human's newer authorized Git and paid API workflow
in `rig/CULTURE.md` supersedes its blanket no-Git/offline restrictions.

## Code and evidence map

- `src/fugu/pipeline/`, `verdict.py`, `types.py`, `dedupe.py`: audit stages,
  evidence/confidence contracts, composition, verdict policy.
- `src/fugu/detonation/`: canary environment, collectors, Docker/Contree drivers.
- `src/fugu/server/`, `store/`: FastAPI/SSE jobs and SQLite/WAL persistence.
- `src/fugu/config.py`, `client.py`, `model_router.py`: application inference.
- `web/src/`: React/Vite/TypeScript/Tailwind dashboard and SSE clients.
- `tests/`, `corpus/`, `bench/`, `eval/`: hermetic checks and benchmark evidence.
- `docs/`: strategy, methodology, contracts, wild findings and deployment.

Shared contracts and dependency files require explicit lead ownership. Python
application changes remain 3.10+ compatible; use type hints and stdlib first.
This checkout contains a local SQLite database and unrelated human artifacts.
Do not modify or commit them as part of your assignment.

## Commands

```sh
uv run --no-sync pytest tests/<assigned-test-file>.py -q
uv run --no-sync pytest -q                     # lead/reviewer integration
uv run --no-sync python -m fugu.server --port 8000 --db fugu.db
```

From `web/`: `npm run build`, `npm run lint`, `npm run contract`, `npm run smoke`,
and `npm run dev`. Start application services only when the task requires them;
avoid conflicting ports or existing service instances. The rig has no managed
service startup requirement. Browser tests may need a running app; inspect their
scripts first rather than assuming every check is hermetic.

## Team addresses

| Role | Logical ID | Session |
|---|---|---|
| Lead | control.lead | control-lead@fugu |
| Backend/sandbox | build.backend | build-backend@fugu |
| Frontend/UX | build.frontend | build-frontend@fugu |
| Security/benchmarks | research.security | research-security@fugu |
| Reviewer/QA | quality.reviewer | quality-reviewer@fugu |
| Docs/release/demo | delivery.release | delivery-release@fugu |
| Showcase MCP hunter | showcase.mcp | showcase-mcp@fugu |
| Showcase skills hunter | showcase.skills | showcase-skills@fugu |
| Showcase evidence reviewer | showcase.evidence | showcase-evidence@fugu |

Derive runtime identity with `rig whoami --json`; do not infer your own role
from shared guidance or another seat's session. Load the relevant OpenRig
skills through their installed discovery path and current `rig ... --help`.
Durable handoffs go through the queue; use `rig send` for concise coordination.

At boot complete the authenticated startup challenge supplied by OpenRig.
Report your actual role, cwd, model/effort and blockers to the lead; the lead
records its own readiness. Then wait. Do not start development, benchmarks,
deployments or unsolicited backlog work merely because the seat is running.
