# Fugu Web — audit before install

React/Vite console for developers reviewing agent skills, MCP servers, and plugins.
Submit one server-local directory or Git URL, watch live checks, then inspect the
verdict, server policy reasons, coverage caveats, confidence tiers, and evidence.
Large repositories may fan out into per-extension audits on the server.

## Run locally

From the repository root, use a dedicated database for development:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python -m fugu.server --port 8000 --db /tmp/fugu-dev.db
```

From `web/`:

```sh
npm run dev                         # Vite; /api proxies to localhost:8000
npm run build                       # TypeScript + production bundle in dist/
npm run preview                     # Preview production bundle (API needs routing)
```

`GET /api/samples` advertises only two bundled corpus examples when available on
that server. Picking one fills the source; **Start audit** launches real checks.
An older or unavailable samples endpoint hides these choices. No arbitrary local
path is assumed by the browser.

## Analysis and disclosure

The current API runs full depth. Static/concealment checks run locally. Semantic
and harness analysis send extension content and prompts to the configured model
provider. Reputation queries use Tavily when configured. Detonation depends on
the configured sandbox. A verdict is limited to performed checks: **PASS is not a
safety certification**. Skips, failures, and server policy caveats appear beside
the verdict; reports missing coverage metadata say so.

`/?mock=1` opens a **simulated walkthrough** with scripted findings and timing.
No extension is fetched or analyzed. Replay results cannot invoke real per-finding
probes and are excluded from live recent-audit history. `/?mock=0` forces live
mode even if the build's VITE_MOCK environment flag is enabled.

Live runs use `POST /api/audits` and SSE at `/api/audits/:id/events`. Existing
`/audit/:id` URLs and recent history reconnect to persisted server events without
creating a new audit. Browsers without EventSource use the polling fallback.

## Verification

```sh
npm run build
npm run lint                        # Existing warnings include generated dist
npm run contract                    # 202 response parsing + polling fallback
npm run smoke                       # Scripted timeline invariants
node scripts/audit-result.mjs       # Server policy/coverage mapping + legacy payload
node scripts/edge-reducer.mjs        # Stage completion/error/replay reducer checks
```

Server sample discovery tests (from repo root):

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync pytest tests/test_server_samples.py -q
```

Browser verification should cover desktop/mobile entry, an actual bundled
sample-to-result journey, result evidence expansion, saved-run resume, replay
labels, and connection/submission failure feedback. Keep paid sample audits
bounded; replay is illustrative and is not benchmark evidence.
