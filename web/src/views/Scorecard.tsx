import { Clock, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { useMemo } from "react";
import {
  ConfidenceBadge,
  OwaspChip,
  SeverityChip,
} from "@/components/badges";
import {
  CanaryExfilPanel,
  CombinationSection,
  FindingRow,
  TierPill,
  isCanaryExfil,
} from "@/components/finding-parts";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type {
  ConfidenceTier,
  Finding,
  Severity,
} from "@/lib/types";
import {
  OWASP_LABELS,
  SEVERITIES,
} from "@/lib/types";
import type { AuditResult } from "@/lib/auditResult";
import { cn } from "@/lib/utils";

const verdictTheme = {
  pass: {
    border: "border-emerald-700/70",
    bg: "bg-emerald-950/40",
    text: "text-emerald-300",
    accent: "bg-emerald-500",
    iconWrap: "border border-emerald-600/40 bg-emerald-500/15",
    glow: "",
    Icon: ShieldCheck,
    reason: "No qualifying findings in completed checks. This is not a safety certification.",
  },
  warn: {
    border: "border-amber-700/70",
    bg: "bg-amber-950/40",
    text: "text-amber-300",
    accent: "bg-amber-500",
    iconWrap: "border border-amber-600/40 bg-amber-500/15",
    glow: "",
    Icon: ShieldAlert,
    reason: "Review the findings and coverage limits before installing.",
  },
  fail: {
    border: "border-red-700/80",
    bg: "bg-red-950/50",
    text: "text-red-300",
    accent: "bg-red-600",
    iconWrap: "border border-red-600/50 bg-red-600/20",
    glow: "shadow-[0_0_70px_-18px] shadow-red-700/70 ring-1 ring-red-600/30",
    Icon: ShieldX,
    reason: "Do not install until the severe findings have been investigated and resolved.",
  },
} as const;

const TIER_ORDER: ConfidenceTier[] = ["deterministic", "measured", "empirical", "advisory"];

function countBySeverity(findings: Finding[]): Partial<Record<Severity, number>> {
  const counts: Partial<Record<Severity, number>> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

export interface ScorecardProps {
  result: AuditResult;
  simulated?: boolean;
  elapsedMs: number;
}

export function Scorecard({ result, elapsedMs, simulated = false }: ScorecardProps) {
  const { verdict } = result;
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

  // Confirmed canary exfiltrations are hoisted into the forensic centerpiece
  // panel right under the banner; the findings list below skips them so the
  // worst evidence is never buried in a collapsible row.
  const canaryHits = useMemo(
    () => verdict.findings.filter(isCanaryExfil),
    [verdict.findings],
  );

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

  // Global severity-desc order preserved; split into two scan clusters so
  // judges hit "critical & high" first without reading every row.
  const ordered = useMemo(
    () =>
      [...verdict.findings]
        .filter((f) => !canaryHits.includes(f))
        .sort(
          (a, b) =>
            (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) ||
            a.stage.localeCompare(b.stage),
        ),
    [verdict.findings, canaryHits],
  );
  const priority = ordered.filter((f) => f.severity === "critical" || f.severity === "high");
  const standard = ordered.filter((f) => f.severity !== "critical" && f.severity !== "high");
  const firstOpenIdx = priority.length > 0 ? 0 : standard.length > 0 ? 0 : -1;

  return (
    <div className="scorecard flex flex-col gap-4">
      {/* ── verdict banner ───────────────────────────────────────── */}
      <section
        aria-label={`audit verdict: ${verdict.verdict}`}
        className={cn(
          "grid-noise relative overflow-hidden rounded-xl border p-5",
          theme.border,
          theme.bg,
          theme.glow,
        )}
      >
        <div className={cn("absolute inset-y-0 left-0 w-1.5", theme.accent)} aria-hidden />
        <div className="flex flex-wrap items-start justify-between gap-4 pl-2">
          <div className="flex items-center gap-4">
            <div
              className={cn(
                "flex size-14 shrink-0 items-center justify-center rounded-xl",
                theme.iconWrap,
              )}
            >
              <Icon className={cn("size-8", theme.text)} aria-hidden />
            </div>
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.3em] text-zinc-500">
                {simulated ? "simulated verdict" : "audit verdict"}
              </p>
              <h2
                className={cn(
                  "font-mono text-3xl font-bold uppercase tracking-[0.25em]",
                  theme.text,
                )}
              >
                {verdict.verdict}
              </h2>
              <p className="mt-2 max-w-2xl text-base leading-relaxed text-zinc-200">{theme.reason}</p>
              {result.reasons.length > 0 && <ul className="verdict-reasons">{result.reasons.map(reason => <li key={reason}>{reason}</li>)}</ul>}
            </div>
          </div>

          {/* severity tally + elapsed */}
          <div className="flex flex-col items-end gap-2">
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
            <span
              aria-label={`audit completed in ${(elapsedMs / 1000).toFixed(1)} seconds with ${totalFindings} findings`}
              className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700/80 bg-zinc-900/60 px-2 py-1 font-mono text-[11px] tabular-nums text-zinc-400"
            >
              <Clock className="size-3 text-zinc-500" aria-hidden />
              {(elapsedMs / 1000).toFixed(1)}s · {totalFindings} findings
            </span>
          </div>
        </div>

        <div className="coverage-panel">
          <h3>{simulated ? "Simulated evidence only" : result.staticOnly ? "Limited analysis" : "Analysis coverage"}</h3>
          {simulated ? <p>This scripted verdict demonstrates the workflow. No extension was audited and no behavior was measured.</p> : <>
            {result.coverage.length > 0 ? <><p>Some checks did not complete. Review these limits alongside the findings:</p><ul>{result.coverage.map(caveat => <li key={caveat}>{caveat}</li>)}</ul></> : <p>{result.coverageKnown ? "No coverage caveats were reported by the server. The verdict applies to the checks performed and their scope." : "The server did not supply coverage details for this report. Completed checks cannot establish unreported analysis coverage."}</p>}
            {result.staticOnly && <p>Some model or runtime checks were unavailable. Complete the missing checks before relying on this report for an install decision.</p>}
          </>}
        </div>

        {/* tier legend + counts — the honesty brand, unmissable */}
        <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-zinc-800/60 pl-2 pt-3">
          <span className="flex flex-col">
            <span className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
              confidence mix
            </span>
            <span className="font-mono text-[11px] text-zinc-400">
              how much to trust each finding
            </span>
          </span>
          {TIER_ORDER.map((t) => (
            <TierPill key={t} tier={t} count={tiers[t] ?? 0} />
          ))}
        </div>
      </section>

      {/* ── canary exfiltration centerpiece ───────────────────────── */}
      <CanaryExfilPanel findings={verdict.findings} simulated={simulated} />

      {/* ── Combination (composition) section — multi-source only ── */}
      <CombinationSection findings={verdict.findings} />

      {/* ── findings detail ──────────────────────────────────────── */}
      <section aria-label="findings and evidence" className="flex flex-col gap-2">
        <div className="flex items-baseline justify-between px-1">
          <h3 className="font-mono text-xs uppercase tracking-wider text-zinc-400">
            Findings &amp; evidence
          </h3>
          <span className="font-mono text-[11px] text-zinc-400">
            click a row to expand evidence
          </span>
        </div>

        {canaryHits.length > 0 && (
          <p className="px-1 font-mono text-[11px] text-red-400/90">
            ↑ {canaryHits.length} {simulated ? "simulated" : "reported"} canary exfiltration
            {canaryHits.length === 1 ? "" : "s"} rendered in the forensic panel above
          </p>
        )}

        {priority.length > 0 && (
          <div className="flex flex-col gap-2">
            <GroupHeader label="critical & high" hint="act before install" count={priority.length} />
            {priority.map((f, i) => (
              <FindingRow key={f.title + i} finding={f} defaultOpen={i === firstOpenIdx} simulated={simulated} />
            ))}
          </div>
        )}

        {standard.length > 0 && (
          <div className="flex flex-col gap-2">
            <GroupHeader label="medium · low · info" hint="review context" count={standard.length} />
            {standard.map((f, i) => (
              <FindingRow
                key={f.title + i}
                finding={f}
                simulated={simulated}
                defaultOpen={priority.length === 0 && i === firstOpenIdx}
              />
            ))}
          </div>
        )}

        {verdict.findings.length === 0 && (
          <p className="rounded-lg border border-zinc-800 p-4 text-center font-mono text-xs text-zinc-400">
            No findings were emitted by the completed checks. Review the analysis coverage above.
          </p>
        )}
      </section>
      {/* ── OWASP matrix ─────────────────────────────────────────── */}
      <section
        aria-label="OWASP category matrix"
        className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900/40"
      >
        <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-2.5">
          <h3 className="font-mono text-xs uppercase tracking-wider text-zinc-400">
            OWASP category matrix
          </h3>
          <span className="text-[11px] text-zinc-400">
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
                <TableCell colSpan={5} className="py-6 text-center font-mono text-xs text-zinc-400">
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
      </section>

    </div>
  );
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function GroupHeader({ label, hint, count }: { label: string; hint: string; count: number }) {
  return (
    <div className="flex items-center gap-2 px-1">
      <span className="font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">
        {label}
      </span>
      <span className="font-mono text-[11px] text-zinc-400">{hint}</span>
      <span className="rounded border border-zinc-700/80 bg-zinc-900 px-1.5 py-px font-mono text-[11px] tabular-nums text-zinc-400">
        {count}
      </span>
      <span aria-hidden className="h-px flex-1 bg-zinc-800/80" />
    </div>
  );
}
