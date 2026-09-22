import { Link2, ShieldAlert, ShieldCheck, ShieldX, Waypoints } from "lucide-react";
import { API_BASE } from "@/lib/api";
import { useMemo, useState } from "react";
import {
  ConfidenceBadge,
  OwaspChip,
  SeverityChip,
  VerdictChip,
} from "@/components/badges";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type {
  Finding,
  Severity,
  VerdictData,
} from "@/lib/types";
import {
  OWASP_LABELS,
  SEVERITIES,
  TRIFECTA_LEGS,
  parseMemberEvidence,
  parseToolEvidence,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const verdictTheme = {
  pass: {
    border: "border-emerald-700/70",
    bg: "bg-emerald-950/40",
    text: "text-emerald-300",
    Icon: ShieldCheck,
  },
  warn: {
    border: "border-amber-700/70",
    bg: "bg-amber-950/40",
    text: "text-amber-300",
    Icon: ShieldAlert,
  },
  fail: {
    border: "border-red-700/80",
    bg: "bg-red-950/50",
    text: "text-red-300",
    Icon: ShieldX,
  },
} as const;

function countBySeverity(findings: Finding[]): Partial<Record<Severity, number>> {
  const counts: Partial<Record<Severity, number>> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

export interface ScorecardProps {
  verdict: VerdictData;
  elapsedMs: number;
}

export function Scorecard({ verdict, elapsedMs }: ScorecardProps) {
  const theme =
    verdictTheme[verdict.verdict] ??
    verdictTheme[
      (typeof verdict.verdict === "string" && verdict.verdict in verdictTheme
        ? verdict.verdict
        : "warn") as keyof typeof verdictTheme
    ];
  const { Icon } = theme;

  const severityCounts = useMemo(
    () => verdict.severity_counts ?? countBySeverity(verdict.findings),
    [verdict],
  );
  const totalFindings = verdict.findings.length;

  const categories = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of verdict.findings) {
      for (const id of f.owasp_ids) {
        const list = map.get(id) ?? [];
        list.push(f);
        map.set(id, list);
      }
    }
    const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return [...map.entries()]
      .map(([owasp_id, findings]) => ({
        owasp_id,
        label: OWASP_LABELS[owasp_id] ?? owasp_id,
        findings,
      }))
      .sort(
        (a, b) =>
          Math.max(...b.findings.map((f) => rank[f.severity] ?? 0)) -
            Math.max(...a.findings.map((f) => rank[f.severity] ?? 0)) ||
          a.owasp_id.localeCompare(b.owasp_id),
      );
  }, [verdict.findings]);

  const tiers = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of verdict.findings) counts[f.confidence] = (counts[f.confidence] ?? 0) + 1;
    return counts;
  }, [verdict.findings]);

  return (
    <div className="flex flex-col gap-4">
      {/* ── verdict banner ───────────────────────────────────────── */}
      <div
        className={cn(
          "grid-noise relative overflow-hidden rounded-xl border p-5",
          theme.border,
          theme.bg,
        )}
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <Icon className={cn("size-10 shrink-0", theme.text)} aria-hidden />
            <div>
              <div className="flex items-center gap-3">
                <h2 className={cn("font-mono text-2xl font-bold uppercase tracking-[0.25em]", theme.text)}>
                  {verdict.verdict}
                </h2>
                <VerdictChip verdict={verdict.verdict} className="hidden" />
              </div>
              <p className="mt-1 text-sm text-zinc-400">
                {verdict.verdict === "fail" &&
                  "Confirmed exfiltration or critical concealment — do not install."}
                {verdict.verdict === "warn" &&
                  "Material findings without confirmed exfil — review before install."}
                {verdict.verdict === "pass" && "No material findings in audited scope."}
              </p>
            </div>
          </div>

          {/* severity tally */}
          <div className="flex items-center gap-1.5">
            {SEVERITIES.filter((s) => (severityCounts[s] ?? 0) > 0)
              .reverse()
              .map((s) => (
                <SeverityChip
                  key={s}
                  severity={s}
                  count={severityCounts[s]}
                  className="px-2 py-1 text-[11px]"
                />
              ))}
            {totalFindings === 0 && (
              <span className="font-mono text-xs text-zinc-500">no findings</span>
            )}
          </div>
        </div>

        {/* tier legend + counts */}
        <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-zinc-800/60 pt-3">
          <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
            confidence mix
          </span>
          {(["deterministic", "measured", "empirical", "advisory"] as const).map((t) => (
            <span key={t} className="flex items-center gap-1.5">
              <ConfidenceBadge tier={t} />
              <span className="font-mono text-xs tabular-nums text-zinc-400">
                ×{tiers[t] ?? 0}
              </span>
            </span>
          ))}
          <span className="ml-auto font-mono text-[11px] text-zinc-500">
            {totalFindings} findings · {(elapsedMs / 1000).toFixed(1)}s
          </span>
        </div>
      </div>

      {/* ── OWASP matrix ─────────────────────────────────────────── */}
      <div className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900/40">
        <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-2.5">
          <h3 className="font-mono text-xs uppercase tracking-wider text-zinc-400">
            OWASP category matrix
          </h3>
          <span className="text-[10px] text-zinc-600">
            based on OWASP MCP Top 10 (v0.1 beta) + LLM Top 10 2025
          </span>
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-24">ID</TableHead>
              <TableHead>Category</TableHead>
              <TableHead className="w-40">Severity</TableHead>
              <TableHead className="w-56">Confidence</TableHead>
              <TableHead className="w-14 text-right">Findings</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {categories.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-6 text-center font-mono text-xs text-zinc-600">
                  no OWASP-mapped findings
                </TableCell>
              </TableRow>
            )}
            {categories.map((row) => {
              const sevCount = countBySeverity(row.findings);
              const tierSet = [...new Set(row.findings.map((f) => f.confidence))];
              return (
                <TableRow key={row.owasp_id}>
                  <TableCell>
                    <OwaspChip id={row.owasp_id} />
                  </TableCell>
                  <TableCell className="text-zinc-300">{row.label}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {SEVERITIES.filter((s) => (sevCount[s] ?? 0) > 0)
                        .reverse()
                        .map((s) => (
                          <SeverityChip key={s} severity={s} count={sevCount[s]} />
                        ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {tierSet.map((t) => (
                        <ConfidenceBadge key={t} tier={t} />
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-right font-mono tabular-nums text-zinc-400">
                    {row.findings.length}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>

      {/* ── Combination (composition) section — multi-source only ── */}
      <CombinationSection findings={verdict.findings} />

      {/* ── findings detail ──────────────────────────────────────── */}
      <div className="flex flex-col gap-2">
        <h3 className="px-1 font-mono text-xs uppercase tracking-wider text-zinc-400">
          Findings &amp; evidence
        </h3>
        {[...verdict.findings]
          .sort(bySeverityDesc)
          .map((f, i) => <FindingRow key={i} finding={f} defaultOpen={i === 0} />)}
        {verdict.findings.length === 0 && (
          <p className="rounded-lg border border-zinc-800 p-4 text-center font-mono text-xs text-zinc-600">
            clean — zero findings across all stages
          </p>
        )}
      </div>
    </div>
  );
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function sevRank(sev: string): number {
  return SEV_RANK[sev] ?? 0;
}

/* ── Combination section (composition findings, contracts §6) ───────── */

/** A trifecta leg row parsed from `member:<slug>:<title>` evidence with
 * meta { leg, member, strength, tier } (composition.py emits exactly this). */
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
 * with member labels, red when this finding actually fired (severity high →
 * "lethal" styling per the backend's severity policy). */
function TrifectaChain({ finding }: { finding: Finding }) {
  const legs = parseLegs(finding);
  const fired = sevRank(finding.severity) >= (SEV_RANK.high ?? 0);
  const nodeTheme = fired
    ? "border-red-700/80 bg-red-950/40"
    : "border-zinc-700 bg-zinc-900/60";
  const labelTheme = fired ? "text-red-300" : "text-zinc-300";
  const arrowTheme = fired ? "text-red-500" : "text-zinc-600";

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
            <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-zinc-500">
              {l.leg || "leg"}
            </span>
            <span className={cn("truncate font-mono text-xs font-semibold", labelTheme)}>
              {l.memberLabel}
            </span>
            {l.strength && (
              <span className="font-mono text-[10px] text-zinc-500">
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

/** Shadowing: colliding tool names across members, parsed from `tools:<name>`
 * evidence (meta { normalized, member(slug), raw }). */
function ShadowingCollisions({ finding }: { finding: Finding }) {
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
    <div className="flex flex-col gap-2">
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

/** True when the finding is a trifecta (member-attributed legs) vs shadowing
 * (tools: evidence). Derives from evidence shape, not title text. */
function isTrifectaFinding(f: Finding): boolean {
  return f.evidence.some((e) => parseMemberEvidence(e.source) !== null);
}

/** Renders ONLY when composition findings exist (multi-source jobs). Single
 * source verdicts render nothing — their scorecard stays exactly as today. */
function CombinationSection({ findings }: { findings: Finding[] }) {
  const compositionFindings = useMemo(
    () => findings.filter((f) => f.stage === "composition"),
    [findings],
  );
  if (compositionFindings.length === 0) return null;

  const trifectas = compositionFindings.filter(isTrifectaFinding);
  const shadowing = compositionFindings.filter((f) => !isTrifectaFinding(f));
  const fired = trifectas.some((f) => sevRank(f.severity) >= (SEV_RANK.high ?? 0));

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
        <span className="text-[10px] text-zinc-600">
          cross-extension composition · members are individually clean
        </span>
      </div>

      <div className="flex flex-col gap-4 p-4">
        {trifectas.length > 0 && (
          <section className="flex flex-col gap-3">
            <p className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
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

        {shadowing.length > 0 && (
          <section className="flex flex-col gap-3">
            <p className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
              tool shadowing · colliding names across members
            </p>
            {shadowing.map((f, i) => (
              <div key={i} className="flex flex-col gap-2 rounded-lg border border-zinc-800/70 bg-zinc-950/50 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityChip severity={f.severity} />
                  <ConfidenceBadge tier={f.confidence} />
                  <span className="text-[13px] font-medium text-zinc-200">{f.title}</span>
                </div>
                <ShadowingCollisions finding={f} />
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
      </div>
    </div>
  );
}

function bySeverityDesc(a: Finding, b: Finding): number {
  return (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0);
}

/** Per-finding chamber probe: re-runs the flagged command in a fresh
 *  canary sandbox and reports empirical results inline. */
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
        className="shrink-0 rounded-md border border-amber-700/60 bg-amber-950/30 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-amber-300 transition-colors hover:bg-amber-900/40 disabled:opacity-50"
      >
        {state === "running" ? "detonating…" : "detonate"}
      </button>
      {result && (
        <div className="max-w-md rounded-md border border-zinc-800 bg-zinc-950/80 p-2 text-right">
          {result.trigger && (
            <p className="font-mono text-[10px] text-zinc-500 break-all">{result.trigger}</p>
          )}
          {result.ok ? (
            <>
              <p className="font-mono text-[10px] text-zinc-400">
                canary {String(result.metrics.canary_hits ?? 0)} · flows {String(result.metrics.flows ?? 0)} · dns {String(result.metrics.dns ?? 0)}
              </p>
              {result.findings.length > 0 ? (
                result.findings.map((f, i) => (
                  <p key={i} className="font-mono text-[11px] text-red-300">
                    [{f.severity}] {f.title}
                  </p>
                ))
              ) : (
                <p className="font-mono text-[10px] text-emerald-400">no canary/egress hits — command behaved</p>
              )}
            </>
          ) : (
            <p className="font-mono text-[10px] text-red-400">
              {String(result.metrics.error ?? "probe failed")}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding, defaultOpen }: { finding: Finding; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Collapsible
      open={open}
      onOpenChange={setOpen}
      className="rounded-lg border border-zinc-800 bg-zinc-900/40"
    >
      <div className="flex items-center gap-3 p-3">
        <CollapsibleTrigger
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          className="flex-1"
        >
          <span className="flex flex-wrap items-center gap-2">
            <SeverityChip severity={finding.severity} />
            <ConfidenceBadge tier={finding.confidence} />
            <span className="text-[13px] font-medium text-zinc-200">{finding.title}</span>
          </span>
          <span className="mt-1 flex flex-wrap items-center gap-1.5 pl-1">
            {finding.owasp_ids.map((id) => (
              <OwaspChip key={id} id={id} />
            ))}
            <span className="ml-1 font-mono text-[10px] uppercase tracking-wider text-zinc-600">
              {finding.stage}
            </span>
          </span>
        </CollapsibleTrigger>
        <DetonateButton finding={finding} />
      </div>
      <CollapsibleContent open={open} className="px-3 pb-3">
        <div className="border-t border-zinc-800/70 pt-3">
          <p className="text-[13px] leading-relaxed text-zinc-300">{finding.detail}</p>
          {finding.evidence.length > 0 && (
            <div className="mt-3 flex flex-col gap-2">
              <p className="font-mono text-[10px] uppercase tracking-wider text-zinc-600">
                evidence
              </p>
              {finding.evidence.map((e, i) => (
                <div
                  key={i}
                  className="overflow-hidden rounded-md border border-zinc-800 bg-zinc-950/80"
                >
                  <div className="flex items-center justify-between gap-2 border-b border-zinc-800/80 px-3 py-1.5">
                    <code className="truncate font-mono text-[11px] text-sky-400">{e.source}</code>
                    {Object.entries(e.meta ?? {}).slice(0, 2).map(([k, v]) => (
                      <span key={k} className="shrink-0 font-mono text-[10px] text-zinc-600">
                        {k}={String(v)}
                      </span>
                    ))}
                  </div>
                  <pre className="overflow-x-auto px-3 py-2 font-mono text-[11px] leading-relaxed text-zinc-300">
                    {e.excerpt}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}
