/**
 * Scorecard subcomponents (Workstream A — findings UX polish).
 *
 * Everything under the verdict banner: the canary-exfiltration centerpiece
 * panel, per-finding collapsible rows with labeled evidence exhibits, the
 * composition section (trifecta chain / tool-name inventory), and the oversized
 * confidence-tier pills used in the banner legend.
 *
 * Pure presentation — data shapes come from `@/lib/types`. Every behavioral
 * affordance of the previous inline implementation is preserved: severity
 * ordering, keyboard-togglable rows (native button triggers + aria-expanded),
 * the DetonateButton chamber probe, OWASP chips, tier badges.
 */
import { FileCode, Link2, Siren, Waypoints } from "lucide-react";
import { API_BASE } from "@/lib/api";
import { useState } from "react";
import { ConfidenceBadge, OwaspChip, SeverityChip } from "@/components/badges";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import type {
  ConfidenceTier,
  EvidenceSnippet,
  Finding,
} from "@/lib/types";
import {
  TRIFECTA_LEGS,
  parseMemberEvidence,
  parseToolEvidence,
} from "@/lib/types";
import { cn } from "@/lib/utils";

/* ── severity helpers ─────────────────────────────────────────────── */

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function sevRank(sev: string): number {
  return SEV_RANK[sev] ?? 0;
}

/* ── confidence-tier legend pill (oversized, honesty brand) ───────── */

/** Same color language as ConfidenceBadge, scaled up for the banner legend:
 *  deterministic = green solid · measured = blue · empirical = amber ·
 *  advisory = gray dashed outline. Gloss states what backs the tier. */
const TIER_PILL: Record<ConfidenceTier, string> = {
  deterministic: "border-emerald-500 bg-emerald-500 text-zinc-950",
  measured: "border-blue-600 bg-blue-600/20 text-blue-300",
  empirical: "border-amber-500 bg-amber-500/15 text-amber-300",
  advisory: "border-zinc-600 border-dashed bg-transparent text-zinc-400",
};

const TIER_GLOSS: Record<ConfidenceTier, string> = {
  deterministic: "provable",
  measured: "eval-measured",
  empirical: "observed",
  advisory: "llm-judged",
};

export function TierPill({ tier, count }: { tier: ConfidenceTier; count?: number }) {
  return (
    <span className="flex flex-col items-center gap-1">
      <span
        className={cn(
          "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-xs font-bold uppercase tracking-wider",
          TIER_PILL[tier],
        )}
      >
        {tier}
        {typeof count === "number" && <span className="opacity-70">×{count}</span>}
      </span>
      <span className="font-mono text-[11px] uppercase tracking-wider text-zinc-400">
        {TIER_GLOSS[tier]}
      </span>
    </span>
  );
}

/* ── evidence exhibit ─────────────────────────────────────────────── */

/** One evidence snippet as a clearly-labeled mono block: numbered exhibit
 *  header with the source pointer, meta chips, and the excerpt body. */
export function EvidenceBlock({
  evidence,
  index,
  danger,
}: {
  evidence: EvidenceSnippet;
  index: number;
  danger?: boolean;
}) {
  const meta = Object.entries(evidence.meta ?? {});
  return (
    <div
      className={cn(
        "overflow-hidden rounded-md border bg-zinc-950",
        danger ? "border-red-900/70" : "border-zinc-800",
      )}
    >
      <div
        className={cn(
          "flex flex-wrap items-center justify-between gap-3 border-b px-3 py-1.5",
          danger ? "border-red-900/50 bg-red-950/30" : "border-zinc-800/80 bg-zinc-900/60",
        )}
      >
        <span className="flex min-w-0 items-center gap-2">
          <span className="shrink-0 font-mono text-[11px] uppercase tracking-wider text-zinc-400">
            exhibit {index + 1}
          </span>
          <code
            className={cn("truncate font-mono text-[11px]", danger ? "text-red-300" : "text-sky-400")}
            title={evidence.source}
          >
            {evidence.source}
          </code>
        </span>
        {meta.length > 0 && (
          <span className="flex min-w-0 flex-wrap items-center gap-2">
            {meta.map(([k, v]) => (
              <span
                key={k}
                className="font-mono text-[11px] text-zinc-400"
                title={`${k}=${String(v)}`}
              >
                {k}={String(v)}
              </span>
            ))}
          </span>
        )}
      </div>
      <pre className="overflow-x-auto px-3 py-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap [overflow-wrap:anywhere] text-zinc-300">
        {evidence.excerpt}
      </pre>
    </div>
  );
}

/* ── per-finding chamber probe (unchanged behavior) ───────────────── */

/** Re-runs the flagged command in a fresh canary sandbox and reports
 *  empirical results inline. */
function DetonateButton({ finding }: { finding: Finding }) {
  const [state, setState] = useState<"idle" | "running" | "done" | "error">("idle");
  const [result, setResult] = useState<{
    ok: boolean;
    trigger: string | null;
    metrics: Record<string, unknown>;
    findings: { title: string; severity: string; detail: string }[];
  } | null>(null);

  const run = async () => {
    setState("running");
    setResult(null);
    try {
      const res = await fetch(`${API_BASE}/probe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding, timeout_s: 60 }),
      });
      if (!res.ok) throw new Error(`probe failed: HTTP ${res.status}`);
      setResult(await res.json());
      setState("done");
    } catch (e) {
      setResult({ ok: false, trigger: null, metrics: { error: String(e) }, findings: [] });
      setState("error");
    }
  };

  return (
    <div className="flex flex-col items-end gap-1">
      <button
        type="button"
        onClick={() => void run()}
        disabled={state === "running"}
        title="re-run the flagged command in the canary chamber"
        aria-label="detonate: re-run the flagged command in the canary chamber"
        className="shrink-0 rounded-md border border-amber-700/60 bg-amber-950/30 px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider text-amber-300 transition-colors duration-150 hover:bg-amber-900/40 disabled:opacity-50"
      >
        {state === "running" ? "detonating…" : "detonate"}
      </button>
      {result && (
        <div className="max-w-md rounded-md border border-zinc-800 bg-zinc-950/80 p-2 text-right">
          {result.trigger && (
            <p className="font-mono text-[11px] text-zinc-500 break-all">{result.trigger}</p>
          )}
          {result.ok ? (
            <>
              <p className="font-mono text-[11px] text-zinc-400">
                canary {String(result.metrics.canary_hits ?? 0)} · flows {String(result.metrics.flows ?? 0)} · dns {String(result.metrics.dns ?? 0)}
              </p>
              {result.findings.length > 0 ? (
                result.findings.map((f, i) => (
                  <p key={i} className="font-mono text-[11px] text-red-300">
                    [{f.severity}] {f.title}
                  </p>
                ))
              ) : (
                <p className="font-mono text-[11px] text-emerald-400">No canary hits observed in this run; review coverage.</p>
              )}
            </>
          ) : (
            <p className="font-mono text-[11px] text-red-400">
              {String(result.metrics.error ?? "probe failed")}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/* ── canary-exfiltration centerpiece ──────────────────────────────── */

/** Critical detonation findings whose evidence carries canary markers —
 *  the empirical "caught it in the act" class. Detection derives from the
 *  evidence shape (meta.canary / meta.canary_hits) or the title, never
 *  from a hardcoded finding id. */
function canaryMetaHit(e: EvidenceSnippet): boolean {
  const meta = e.meta as Record<string, unknown> | undefined;
  if (!meta) return false;
  return "canary" in meta || "canary_hits" in meta;
}

/** True when the finding is the empirical canary-exfiltration class (used
 *  by the Scorecard to hoist it out of the plain findings list). */
export function isCanaryExfil(f: Finding): boolean {
  if (f.severity !== "critical" || f.stage !== "detonation") return false;
  return f.evidence.some(canaryMetaHit) || /canary|exfil/i.test(f.title);
}

/** Extracts the exfil path summary (trigger → host → canary → hits) from
 *  evidence meta so the panel leads with a one-line "how it escaped". */
function exfilPathSegments(f: Finding): string[] {
  let trigger: string | undefined;
  let host: string | undefined;
  let canary: string | undefined;
  let hits: number | undefined;
  for (const e of f.evidence) {
    const meta = e.meta as Record<string, unknown> | undefined;
    if (!meta) continue;
    if (trigger === undefined && typeof meta.trigger === "string") trigger = meta.trigger;
    if (host === undefined && typeof meta.host === "string") host = meta.host;
    if (canary === undefined && typeof meta.canary === "string") canary = meta.canary;
    if (hits === undefined && typeof meta.canary_hits === "number") hits = meta.canary_hits;
  }
  const segs: string[] = [];
  if (trigger) segs.push(`trigger ${trigger}`);
  if (host) segs.push(host);
  if (canary) segs.push(`${canary} canary matched`);
  if (hits !== undefined) segs.push(`${hits} hits`);
  return segs;
}

/** The unmissable centerpiece: red-glow panel rendering every confirmed
 *  canary exfiltration with its path summary and forensic exhibits.
 *  Returns null when no such finding exists (clean / warn audits). */
export function CanaryExfilPanel({ findings, simulated = false }: { findings: Finding[]; simulated?: boolean }) {
  const hits = findings.filter(isCanaryExfil);
  if (hits.length === 0) return null;

  return (
    <section
      aria-label={simulated ? "simulated canary exfiltration" : "reported canary exfiltration"}
      className="relative overflow-hidden rounded-xl border border-red-700/80 bg-gradient-to-b from-red-950/60 to-zinc-950 ring-1 ring-red-600/40 shadow-[0_0_60px_-12px] shadow-red-800/80"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-red-900/60 px-4 py-2.5">
        <h3 className="flex items-center gap-2 font-mono text-xs font-bold uppercase tracking-[0.2em] text-red-200">
          <Siren className="size-4 text-red-400" aria-hidden />
          {simulated ? "Simulated canary exfiltration" : "Reported canary exfiltration"}
        </h3>
        <span className="font-mono text-[11px] uppercase tracking-wider text-red-400/80">
          {simulated ? "scripted demonstration · not observed behavior" : "review the evidence and confidence tier below"}
        </span>
      </div>

      {hits.map((f, i) => {
        const segs = exfilPathSegments(f);
        return (
          <div
            key={i}
            className={cn("flex flex-col gap-3 p-4", i > 0 && "border-t border-red-900/40")}
          >
            <div className="flex flex-wrap items-center gap-2">
              <SeverityChip severity={f.severity} />
              <ConfidenceBadge tier={f.confidence} />
              <span className="text-sm font-semibold text-red-50">{f.title}</span>
            </div>

            {segs.length > 0 && (
              <p className="flex flex-wrap items-center gap-2 rounded-md border border-red-900/60 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-200">
                {segs.map((s, j) => (
                  <span key={s} className="flex items-center gap-2">
                    {j > 0 && (
                      <span aria-hidden className="select-none text-red-500">
                        ▸
                      </span>
                    )}
                    <span>{s}</span>
                  </span>
                ))}
              </p>
            )}

            <p className="text-[13px] leading-relaxed text-zinc-300">{f.detail}</p>

            <div className="flex flex-col gap-2">
              <p className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-zinc-400">
                <FileCode className="size-3" aria-hidden />
                forensic trail
              </p>
              {f.evidence.map((e, j) => (
                <EvidenceBlock key={j} evidence={e} index={j} danger />
              ))}
            </div>

            <div className="flex flex-wrap gap-1">
              {f.owasp_ids.map((id) => (
                <OwaspChip key={id} id={id} />
              ))}
            </div>
          </div>
        );
      })}
    </section>
  );
}

/* ── composition (multi-source) section — unchanged logic ─────────── */

/** A trifecta leg row parsed from `member:<slug>:<title>` evidence with
 *  meta { leg, member, strength, tier } (composition.py emits exactly this). */
interface LegRow {
  leg: string;
  memberLabel: string;
  slug: string;
  strength: string;
  tier?: string;
  excerpt: string;
}

function parseLegs(finding: Finding): LegRow[] {
  const rows: LegRow[] = [];
  for (const e of finding.evidence) {
    const parsed = parseMemberEvidence(e.source);
    if (!parsed) continue;
    const meta = e.meta as Record<string, unknown> | undefined;
    const leg = typeof meta?.leg === "string" ? meta.leg : "";
    rows.push({
      leg,
      memberLabel:
        typeof meta?.member === "string" && meta.member
          ? meta.member
          : parsed.slug,
      slug: parsed.slug,
      strength: typeof meta?.strength === "string" ? meta.strength : "",
      tier: typeof meta?.tier === "string" ? meta.tier : undefined,
      excerpt: e.excerpt,
    });
  }
  // Canonical display order INGRESS → PRIVATE-DATA → EGRESS; unknown legs last.
  const rank = new Map(TRIFECTA_LEGS.map((l, i) => [l as string, i]));
  return rows.sort(
    (a, b) => (rank.get(a.leg) ?? 99) - (rank.get(b.leg) ?? 99),
  );
}

/** The trifecta chain view: INGRESS → PRIVATE-DATA → EGRESS nodes labeled
 *  with member labels, red when this finding actually fired (severity high →
 *  "lethal" styling per the backend's severity policy). */
function TrifectaChain({ finding }: { finding: Finding }) {
  const legs = parseLegs(finding);
  const fired = sevRank(finding.severity) >= (SEV_RANK.high ?? 0);
  const nodeTheme = fired
    ? "border-red-700/80 bg-red-950/40"
    : "border-zinc-700 bg-zinc-900/60";
  const labelTheme = fired ? "text-red-300" : "text-zinc-300";
  const arrowTheme = fired ? "text-red-500" : "text-zinc-400";

  if (legs.length === 0) return null;

  return (
    <div className="flex flex-wrap items-stretch gap-1.5">
      {legs.map((l, i) => (
        <div key={`${l.leg}-${l.slug}-${i}`} className="flex items-center gap-1.5">
          {i > 0 && (
            <span
              aria-hidden
              className={cn("font-mono text-lg leading-none select-none", arrowTheme)}
            >
              →
            </span>
          )}
          <div
            className={cn(
              "flex min-w-[9rem] flex-col gap-1 rounded-lg border px-3 py-2",
              nodeTheme,
            )}
            title={l.excerpt}
          >
            <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-500">
              {l.leg || "leg"}
            </span>
            <span className={cn("truncate font-mono text-xs font-semibold", labelTheme)}>
              {l.memberLabel}
            </span>
            {l.strength && (
              <span className="font-mono text-[11px] text-zinc-500">
                {l.strength}
                {l.tier ? ` · ${l.tier}` : ""}
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/** Tool-name inventory, parsed from `tools:<name>` evidence. */
function ToolNameInventory({ finding }: { finding: Finding }) {
  const tools = finding.evidence
    .map((e) => {
      const p = parseToolEvidence(e.source);
      if (!p) return null;
      const meta = e.meta as Record<string, unknown> | undefined;
      const normalized = typeof meta?.normalized === "string" ? meta.normalized : "";
      const slug = typeof meta?.member === "string" ? meta.member : "";
      return { name: p.name, normalized, slug, excerpt: e.excerpt };
    })
    .filter((t): t is NonNullable<typeof t> => t !== null);
  if (tools.length === 0) return null;
  const normalized = tools[0]?.normalized ?? tools[0]?.name ?? "";
  return (
    <div role="group" aria-label={`${finding.title} tool name inventory`} className="flex flex-col gap-2">
      {normalized && (
        <p className="font-mono text-[11px] text-zinc-500">
          all normalize to{" "}
          <code className="rounded border border-amber-800/70 bg-amber-950/40 px-1.5 py-px text-amber-300">
            {normalized}
          </code>
        </p>
      )}
      <div className="flex flex-wrap gap-1.5">
        {tools.map((t, i) => (
          <span
            key={`${t.name}-${i}`}
            className="inline-flex items-center gap-1.5 rounded-md border border-amber-800/60 bg-amber-950/30 px-2 py-1 font-mono text-[11px] text-amber-200"
          >
            <Link2 className="size-3 shrink-0 text-amber-500/80" aria-hidden />
            {t.slug && <span className="text-zinc-500">{t.slug}/</span>}
            <span className="font-semibold">{t.name}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/** True when the finding is a trifecta (member-attributed legs). */
function isTrifectaFinding(f: Finding): boolean {
  return f.evidence.some((e) => parseMemberEvidence(e.source) !== null);
}

/** The current backend marks inventory-only normalized overlaps explicitly. */
function isNameOverlapOnly(f: Finding): boolean {
  return f.evidence.length > 0 && f.evidence.every((e) => {
    const meta = e.meta as Record<string, unknown> | undefined;
    return parseToolEvidence(e.source) !== null && meta?.interpretation === "name-overlap-only";
  });
}

/** Renders ONLY when composition findings exist (multi-source jobs). Single
 *  source verdicts render nothing — their scorecard stays exactly as today. */
export function CombinationSection({ findings }: { findings: Finding[] }) {
  const compositionFindings = findings.filter((f) => f.stage === "composition");
  if (compositionFindings.length === 0) return null;

  const trifectas = compositionFindings.filter(isTrifectaFinding);
  const toolNameFindings = compositionFindings.filter((f) =>
    !isTrifectaFinding(f) && f.evidence.some((e) => parseToolEvidence(e.source) !== null),
  );
  const nameOverlaps = toolNameFindings.filter(isNameOverlapOnly);
  const reportedToolNameFindings = toolNameFindings.filter((f) => !isNameOverlapOnly(f));
  const otherFindings = compositionFindings.filter((f) =>
    !isTrifectaFinding(f) && !toolNameFindings.includes(f),
  );
  const fired = trifectas.some((f) => sevRank(f.severity) >= (SEV_RANK.high ?? 0));

  const renderToolNameFinding = (f: Finding, i: number) => (
    <div key={`${f.title}-${i}`} className="flex flex-col gap-2 rounded-lg border border-zinc-800/70 bg-zinc-950/50 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityChip severity={f.severity} />
        <ConfidenceBadge tier={f.confidence} />
        <span className="text-[13px] font-medium text-zinc-200">{f.title}</span>
      </div>
      <ToolNameInventory finding={f} />
      <p className="text-[12px] leading-relaxed text-zinc-400">{f.detail}</p>
      <div className="flex flex-wrap gap-1">
        {f.owasp_ids.map((id) => <OwaspChip key={id} id={id} />)}
      </div>
    </div>
  );

  return (
    <div
      className={cn(
        "overflow-hidden rounded-lg border",
        fired ? "border-red-800/70 bg-red-950/20" : "border-zinc-800 bg-zinc-900/40",
      )}
    >
      <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-2.5">
        <h3 className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-zinc-400">
          <Waypoints className="size-3.5 text-zinc-500" aria-hidden />
          Combination
        </h3>
        <span className="text-[11px] text-zinc-400">
          cross-extension composition · review each member’s findings
        </span>
      </div>

      <div className="flex flex-col gap-4 p-4">
        {trifectas.length > 0 && (
          <section className="flex flex-col gap-3">
            <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
              lethal trifecta chain · ingress → private data → egress
            </p>
            {trifectas.map((f, i) => (
              <div key={i} className="flex flex-col gap-2 rounded-lg border border-zinc-800/70 bg-zinc-950/50 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityChip severity={f.severity} />
                  <ConfidenceBadge tier={f.confidence} />
                  <span className="text-[13px] font-medium text-zinc-200">{f.title}</span>
                </div>
                <TrifectaChain finding={f} />
                <p className="text-[12px] leading-relaxed text-zinc-400">{f.detail}</p>
                <div className="flex flex-wrap gap-1">
                  {f.owasp_ids.map((id) => (
                    <OwaspChip key={id} id={id} />
                  ))}
                </div>
              </div>
            ))}
          </section>
        )}

        {nameOverlaps.length > 0 && (
          <section aria-label="Tool name overlaps in source inventory" className="flex flex-col gap-3">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
                tool name overlaps · source inventory
              </p>
              <p className="mt-1 text-[11px] leading-relaxed text-zinc-400">
                Matching normalized names are a review hint. They do not establish a shared runtime namespace or which definition a client resolves.
              </p>
            </div>
            {nameOverlaps.map(renderToolNameFinding)}
          </section>
        )}

        {reportedToolNameFindings.length > 0 && (
          <section aria-label="Previously reported tool-name findings" className="flex flex-col gap-3">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
                previously reported tool-name findings
              </p>
              <p className="mt-1 text-[11px] leading-relaxed text-zinc-400">
                Original stored findings are shown as reported. Review their evidence when checking runtime behavior.
              </p>
            </div>
            {reportedToolNameFindings.map(renderToolNameFinding)}
          </section>
        )}

        {otherFindings.length > 0 && (
          <section className="flex flex-col gap-3">
            <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
              other composition findings
            </p>
            {otherFindings.map((f, i) => (
              <div key={`${f.title}-${i}`} className="flex flex-col gap-2 rounded-lg border border-zinc-800/70 bg-zinc-950/50 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityChip severity={f.severity} />
                  <ConfidenceBadge tier={f.confidence} />
                  <span className="text-[13px] font-medium text-zinc-200">{f.title}</span>
                </div>
                <p className="text-[12px] leading-relaxed text-zinc-400">{f.detail}</p>
                {f.evidence.map((e, index) => <EvidenceBlock key={`${e.source}-${index}`} evidence={e} index={index} />)}
                <div className="flex flex-wrap gap-1">
                  {f.owasp_ids.map((id) => <OwaspChip key={id} id={id} />)}
                </div>
              </div>
            ))}
          </section>
        )}
      </div>
    </div>
  );
}

/* ── findings list row ────────────────────────────────────────────── */

/** One finding: collapsible row with severity/tier badges, OWASP chips,
 *  stage tag, the DetonateButton, and labeled evidence exhibits. Keyboard
 *  toggling works natively (button trigger) with aria-expanded state. */
export function FindingRow({
  finding,
  defaultOpen,
  simulated = false,
}: {
  finding: Finding;
  defaultOpen: boolean;
  simulated?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const critical = finding.severity === "critical";
  return (
    <Collapsible
      open={open}
      onOpenChange={setOpen}
      className={cn(
        "rounded-lg border bg-zinc-900/40",
        critical
          ? "border-red-900/70 shadow-[0_0_30px_-14px] shadow-red-900/90"
          : "border-zinc-800",
      )}
    >
      <div className="flex flex-wrap items-center gap-3 p-3">
        <CollapsibleTrigger
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          aria-label={`toggle finding: ${finding.title}`}
          className="min-w-0 flex-1"
        >
          <span className="flex flex-wrap items-center gap-2">
            <SeverityChip severity={finding.severity} />
            <ConfidenceBadge tier={finding.confidence} />
            <span
              className={cn(
                "text-[13px] font-medium",
                critical ? "text-red-100" : "text-zinc-200",
              )}
            >
              {finding.title}
            </span>
            {finding.evidence.length > 0 && (
              <span className="font-mono text-[11px] text-zinc-400">
                {finding.evidence.length} exhibit{finding.evidence.length === 1 ? "" : "s"}
              </span>
            )}
          </span>
          <span className="mt-1 flex flex-wrap items-center gap-1.5 pl-1">
            {finding.owasp_ids.map((id) => (
              <OwaspChip key={id} id={id} />
            ))}
            <span className="ml-1 font-mono text-[11px] uppercase tracking-wider text-zinc-400">
              {finding.stage}
            </span>
          </span>
        </CollapsibleTrigger>
        {!simulated && <DetonateButton finding={finding} />}
      </div>
      <CollapsibleContent open={open} className="px-3 pb-3">
        <div className="border-t border-zinc-800/70 pt-3">
          <p className="text-[13px] leading-relaxed text-zinc-300">{finding.detail}</p>
          {finding.evidence.length > 0 && (
            <div className="mt-3 flex flex-col gap-2">
              <p className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-zinc-400">
                <FileCode className="size-3" aria-hidden />
                evidence
              </p>
              {finding.evidence.map((e, i) => (
                <EvidenceBlock key={i} evidence={e} index={i} />
              ))}
            </div>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}
