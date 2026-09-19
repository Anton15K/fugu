# Fugu Web — audit console

React frontend for Fugu, the agentic security auditor for agent extensions
(skills / MCP servers / plugins). Submit an extension → watch the pipeline run
live → read the OWASP-mapped scorecard with tiered-confidence findings and
expandable evidence.

## Run (dev)

```bash
cd web
npm install
npm run dev            # http://localhost:5173, proxies /api → localhost:8000
```

The backend isn't wired up yet. Develop against the **mock replay** — a
scripted, realistic malicious-skill audit (Unicode smuggling, canary-credential
exfil in detonation, harness A/B delta, typosquat, trifecta… ~33 events, all 4
confidence tiers, FAIL verdict):

```bash
npm run dev            # then open http://localhost:5173/?mock=1
# or
MOCK=1 npm run dev     # VITE_MOCK=1 also works
```

With the FastAPI backend running on `:8000`, just drop the flag — the UI
switches to `POST /api/audits` + `GET /api/audits/:id/events` (SSE).

## Build

```bash
npm run build          # tsc -b && vite build → dist/
npx tsc --noEmit       # typecheck only
npm run preview        # serve the production build
```

## Tests

```bash
npm run smoke          # drives the mock timeline, asserts event-shape invariants
npm run contract       # fake backend; verifies 202 parse + SSE/polling client
```

## Architecture

```
src/
  lib/
    types.ts       TS mirrors of src/fugu/types.py (READ-ONLY contract)
    api.ts         submitAudit + openAuditStream (EventSource w/ reconnect,
                   fetch-polling fallback that also parses buffered SSE bodies)
    mockStream.ts  scripted audit replay; ?mock=1 | VITE_MOCK=1 | MOCK=1
    recentJobs.ts  localStorage recent-audit list (best-effort)
    utils.ts       cn() classname combiner
  components/
    ui/            hand-rolled shadcn-style primitives (cva + Tailwind 4):
                   button, card, badge, progress, table, tabs, alert, collapsible
    badges.tsx     severity chips, confidence-tier badges, status dots, verdict
  views/
    SubmitForm.tsx       source input + depth toggle + recent audits
    PipelineMonitor.tsx  stage cards (fixed order), live findings/log feed,
                         elapsed timer; exports the applyEvent state reducer
    Scorecard.tsx        verdict banner, severity counts, OWASP matrix,
                         expandable evidence (monospace excerpt + source pointer)
  App.tsx          single page, state machine: idle → running → done
```

## Backend contract (expected)

| Method | Path | Behavior |
| --- | --- | --- |
| `POST` | `/audits` | body `{source, depth}` → `202` with `{job_id}` (full `AuditJob` also accepted) |
| `GET` | `/audits/:id/events` | SSE stream of `StageEvent` (`stage_started` \| `finding` \| `stage_done` \| `verdict` \| `error` \| `log`); terminal `verdict` closes the stream |

Notes:
- The client tolerates a missing `id` field on submit responses (`job_id`
  fallback) and treats any `verdict` event as terminal.
- Polling fallback sends `Last-Event-ID` (last seen `ts`) and accepts either a
  JSON array of events or a buffered `text/event-stream` body.
- Confidence tiers render distinctly by design: **deterministic** green-solid,
  **measured** blue, **empirical** amber, **advisory** gray dashed outline.

## Stack

Vite 8 · React 19 · TypeScript (strict, no unused vars/params, noUncheckedIndexedAccess) ·
Tailwind CSS 4 (`@tailwindcss/vite`) · class-variance-authority + clsx + tailwind-merge ·
lucide-react icons.
