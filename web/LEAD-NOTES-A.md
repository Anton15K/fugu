# Lead Notes — Workstream A (Scorecard UX polish)

## What changed

- `web/src/views/Scorecard.tsx` — rewritten presentation layer, same props contract
  (`ScorecardProps { verdict, elapsedMs }`, exported name unchanged).
- `web/src/components/finding-parts.tsx` — NEW. Subcomponents moved out of the view:
  `TierPill`, `EvidenceBlock`, `CanaryExfilPanel`, `CombinationSection` (+ its internal
  `TrifectaChain` / `ShadowingCollisions`), `FindingRow` (+ internal `DetonateButton`),
  and the exported predicate `isCanaryExfil(f)`.

## Why

Judges spend most of their demo time on the scorecard; the previous layout buried the
empirical canary-exfiltration critical inside a generic findings list and rendered
confidence tiers as tiny badges. Changes:

1. **Verdict banner** — bigger icon medallion + colored left accent bar, "AUDIT VERDICT"
   kicker, 3xl verdict word, one-line reason; FAIL additionally gets a red ring/glow.
   Elapsed + total findings moved into a single chip (Clock icon, aria-label).
2. **Canary exfil centerpiece** — critical detonation findings with canary evidence
   (`meta.canary` / `meta.canary_hits` or title match, derived from evidence shape, not
   finding ids) are hoisted out of the collapsible list into a red-glow "CONFIRMED CANARY
   EXFILTRATION" panel with an exfil-path summary line (`trigger install ▸ host ▸ canary
   matched ▸ N hits`, all parsed from evidence meta) and danger-styled exhibit blocks.
   The findings list shows a pointer note ("↑ N rendered in the forensic panel above").
3. **Tier honesty brand** — banner legend now uses oversized `TierPill`s (same color
   language as `ConfidenceBadge`: green solid / blue / amber / gray dashed) each with a
   gloss line (provable / eval-measured / observed / llm-judged) and per-tier counts.
4. **Findings grouped** — global severity-desc order preserved; split into "CRITICAL &
   HIGH" (act before install) and "MEDIUM · LOW · INFO" (review context) clusters with
   count chips and rule lines; first priority row auto-expanded.
5. **Evidence exhibits** — each snippet is a labeled block: "EXHIBIT n" + source pointer
   header (sky mono, danger=red in the canary panel) + meta chips, `whitespace-pre-wrap`
   body with `[overflow-wrap:anywhere]` so long tokens (base64, URLs) wrap instead of
   overflowing.

## Preserved (verified against old code)

Severity ordering, OWASP chips + matrix table, TrifectaChain (INGRESS→PRIVATE-DATA→EGRESS,
red-when-fired) and ShadowingCollisions rendering, DetonateButton `/probe` call + result
rendering, elapsed chip, keyboard-togglable collapsibles (native button triggers,
`aria-expanded`), all aria-labels (added several: sections, detonate, elapsed, finding
toggles). Composition section still renders nothing on single-source jobs.

## Verification (run from web/)

```
$ npx tsc --noEmit          → clean, no output
$ npm run lint              → exit 0
  src/components/finding-parts.tsx:228:17: warning react(only-export-components)  ← only new line
  (same warning class as existing PipelineMonitor.tsx/badge.tsx exports; needed so
   Scorecard + CanaryExfilPanel share one isCanaryExfil definition)
$ npm run build             → ✓ built in 157ms
  dist/assets/index-3P8P-mhE.js 324.67 kB │ gzip: 100.07 kB
```

## Risks / leftovers

- `isCanaryExfil` heuristic: `severity === "critical" && stage === "detonation"` plus
  evidence-meta or title canary match. If the backend ever emits a critical exfil from
  another stage (e.g. harness), it stays in the list (still red-glow row) rather than the
  panel — acceptable, arguably correct.
- One new oxlint fast-refresh warning (see above); matching house style.
- No visual smoke run (no server per constraints) — mock replay (`?mock=1`) exercises the
  fail path incl. the canary panel; `composition: a, b` source exercises CombinationSection.

## Contract-change requests

None. `Scorecard` props and all `@/lib/types` shapes untouched.
