# LEAD NOTES — Workstream B (PipelineMonitor polish)

## Session note (2026-09-24)

### What changed
**Only `web/src/views/PipelineMonitor.tsx`** (440 → 746 lines, full rewrite of the view layer; reducer logic preserved byte-for-byte in behavior).

- **Reducer contract**: `applyEvent` / `initialPipelineState` / `PipelineState` / `PipelineMonitorProps` / `PipelineMonitor` exports unchanged in name and signature. **Two additive, view-only fields** on `PipelineState`: `stageStartedAt` / `stageEndedAt` (`Partial<Record<StageName, number>>`), folded from the same server event `ts` as `startedAt`/`finishedAt` (so SSE history replay preserves true per-stage durations). No legacy field reads them; default `{}` keeps old states valid.
- **Stage strip**: horizontal console strip, order strictly `STAGE_ORDER` / `MULTI_SOURCE_STAGE_ORDER`. Running = sky border + top scanline pulse (1.4s ease, opacity only) + live-ticking duration; done = emerald check + duration + `N ⚠` findings-yielded; error = red `failed · <duration>`; skipped = dimmed honest; idle = `—`. Connector line between cells colors by upstream status.
- **Findings ticker**: Σ findings + severity tally (`2 crit 6 high …`) + latest-finding flash line (`[stage] ▲ title`, 150ms fade-in).
- **Connection chip**: always-visible pill — `connecting…` / `live · sse` / `reconnecting #N` / `polling fallback` / `disconnected` / `complete` (+ `local replay` when events flow with no status object = mock mode).
- **Halted state** (fatal error, no verdict): red banner, clock frozen at last server ts ("halted at"), `new audit` offered, progress bar red. Detection is view-only: errored stage + nothing running, OR error naming an untracked stage key (e.g. `extraction`), OR `streamStatus.kind === "closed"` with nothing running.
- Layout: side-by-side **Evidence feed** (severity rail, badges, newest-first) + **Stream log** console (ts + stage + message) replaced the old tabs. Member strip kept, relabeled "member audits".

### Verification (all from `web/`)
- `npx tsc --noEmit` → clean.
- `npm run lint` → exit 0 (same 2 pre-existing `only-export-components` warnings on this file as baseline; nothing new).
- `npm run build` → ✓ built in 94ms.
- `node scripts/edge-reducer.mjs` → 11 passed, 0 failed.
- `npm run smoke` → SMOKE PASSED.
- **A/B equivalence harness** (scratch: `~/.hermes/profiles/nebius-hackathon/cache/scratch/wsB/ab-equivalence.mjs`): folds the real mock timelines (full/standard/composition) + 7 synthetic edge streams through BOTH the pre-edit reducer (saved copy) and the new one; asserts all 8 legacy fields deep-equal after **every event**. → ALL 87 checks passed.
- **Render harness** (`render-check.mjs`): transpiles the component with a vdom jsx stub (React-like function-component normalization), renders states folded from real mock timelines + edge fixtures; asserts stage order, cell count, duration/skipped readouts, ticker, all 6 connection-chip states, halted banner, composition layout. → ALL 45 checks passed.
- **SSE replay harness** (`live-reducer-mock.mjs`): mock timeline → SSE wire text → live-reducer-style parse → fold; server-clock elapsed + per-stage durations preserved. → PASSED.

### Design decisions
- **Additive state fields instead of derived durations**: per-stage timing must survive SSE history replay (resume/reload), so it has to live in the reducer and use server `ts`, not `Date.now()`. Additive-only keeps App.tsx and every legacy fold untouched; proven equal by the A/B harness.
- **Clock freeze on halt**: a dead run stops the elapsed timer at the last server event ts instead of ticking forever — "honest death" over "pretend-alive". `verdict`/`stage_done`/member-log paths mirror existing settle semantics exactly.
- **Composite halted heuristic**: `error` events can name untracked stages (`extraction`) while a visible stage stays `"running"` in the record — the old single-signal check would miss that; three signals (tracked-error, unknown-key-error, early-close) close all the paths I found in the edge harness.

### Risks / leftovers
- `mockStream.ts` (read-only for me) stamps **all** event `ts` at timeline-build time (`ev()` never receives `tsOffsetMs`), so in **mock mode** frozen per-stage durations fold to `0.0s` and final elapsed is ~0 (mid-run ticking is fine — wall clock). Real backend is unaffected. Suggested one-line-ish fix in mockStream: pass cumulative delay as `tsOffsetMs` in `push()`.
- No visual browser pass was possible (no Chromium backend in this environment); render verification is DOM-structural, not pixel. A quick human glance at `?mock=1` mid-run is worth 30 seconds.
- Stream-log rows use index keys on the reversed list (burst replay can emit identical ts+message lines; content keys would collide).
- Strip is `overflow-x-auto` at very narrow widths; cards are fixed 136px cells (flex-1 when ≤3 cards, i.e. multi-source).

### Contract-change requests
1. **mockStream.ts**: stamp event `ts` with cumulative script delay (pass `tsOffsetMs` through `push`/`ev`) so replayed durations are non-degenerate in mock mode. (Highest value, 5-line change, owner: whoever owns mockStream.)
2. **Optional, nice-to-have**: a `finding_count` on `stage_done` is already in the contract but the UI counts findings from `finding` events instead — fine today; if the backend ever batches findings inside `stage_done`, say so and I'll reconcile.
