import { cva, type VariantProps } from "class-variance-authority";
import type { ConfidenceTier, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";

/* ── Severity ───────────────────────────────────────────────────── */

const severityStyles: Record<Severity, string> = {
  info: "border-zinc-700 bg-zinc-800/60 text-zinc-400",
  low: "border-sky-800 bg-sky-950/60 text-sky-300",
  medium: "border-amber-700 bg-amber-950/60 text-amber-300",
  high: "border-orange-700 bg-orange-950/70 text-orange-300",
  critical: "border-red-600 bg-red-900/80 text-red-50",
};

export function SeverityChip({
  severity,
  count,
  className,
}: {
  severity: Severity;
  count?: number;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-px font-mono text-[10px] font-semibold uppercase tracking-wider",
        severityStyles[severity],
        className,
      )}
    >
      {severity}
      {typeof count === "number" && count > 1 && (
        <span className="opacity-70">×{count}</span>
      )}
    </span>
  );
}

/* ── Confidence tiers ───────────────────────────────────────────── */

const tierVariant: Record<
  ConfidenceTier,
  VariantProps<typeof Badge>["variant"]
> = {
  deterministic: "tierDeterministic",
  measured: "tierMeasured",
  empirical: "tierEmpirical",
  advisory: "tierAdvisory",
};

/** Deterministic = green solid · measured = blue · empirical = amber · advisory = gray dashed outline. */
export function ConfidenceBadge({ tier }: { tier: ConfidenceTier }) {
  return <Badge variant={tierVariant[tier]}>{tier}</Badge>;
}

/* ── OWASP id chip ──────────────────────────────────────────────── */

export function OwaspChip({ id }: { id: string }) {
  return (
    <span className="inline-flex items-center rounded-sm border border-zinc-700/80 bg-zinc-900 px-1.5 py-px font-mono text-[10px] font-medium tracking-wide text-zinc-400">
      {id}
    </span>
  );
}

/* ── Verdict ────────────────────────────────────────────────────── */

const verdictStyles = cva(
  "inline-flex items-center gap-2 rounded-md border px-3 py-1.5 font-mono text-sm font-bold uppercase tracking-[0.2em]",
  {
    variants: {
      verdict: {
        pass: "border-emerald-600 bg-emerald-950/60 text-emerald-300",
        warn: "border-amber-600 bg-amber-950/60 text-amber-300",
        fail: "border-red-600 bg-red-950/70 text-red-300",
        pending: "border-zinc-700 bg-zinc-900/60 text-zinc-400",
      },
    },
    defaultVariants: { verdict: "pending" },
  },
);

export function VerdictChip({
  verdict,
  className,
}: {
  verdict: "pass" | "warn" | "fail" | "pending";
  className?: string;
}) {
  return <span className={cn(verdictStyles({ verdict }), className)}>{verdict}</span>;
}

/* ── Stage status dot ───────────────────────────────────────────── */

export type StageDotState = "idle" | "running" | "done" | "error" | "skipped";

const dotStyles: Record<StageDotState, string> = {
  idle: "border-zinc-700 bg-zinc-800",
  skipped: "border-zinc-700 bg-transparent",
  running: "border-sky-500 bg-sky-400 animate-pulse-dot",
  done: "border-emerald-700 bg-emerald-500",
  error: "border-red-600 bg-red-500",
};

export function StatusDot({ state }: { state: StageDotState }) {
  return (
    <span
      aria-label={state}
      className={cn(
        "inline-block size-2.5 shrink-0 rounded-full border",
        dotStyles[state],
      )}
    />
  );
}
