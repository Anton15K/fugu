// Workstream B — PipelineMonitor: the live-run security console.
//
// Layout during an audit (1–3 min the judge watches):
//   header    job · connection chip (always visible) · elapsed clock
//   progress  thin overall bar + stage/member counter
//   strip     stage cells in STAGE_ORDER / MULTI_SOURCE_STAGE_ORDER with
//             running-pulse / done / partial / error / skipped states
//   members   multi-source child audits (parsed from parent log events)
//   ticker    findings-so-far: Σ count + severity tally + latest finding flash
//   grid      evidence feed (findings, newest first) | stream log console
//
// Reducer contract (App.tsx depends on it): findings and timing fold from
// server events, so stored SSE history preserves the same evidence and
// coverage states as a live run. Terminal settling never upgrades limited
// coverage to a completed check.
//
// Harness note: scripts/edge-reducer.mjs + live-reducer.mjs transpile THIS
// file standalone with stubbed imports — keep `@/lib/types` as the single
// value import (first position) and never deref other modules at module
// scope (icons/components are JSX-only).
import { MULTI_SOURCE_STAGE_ORDER, SEVERITIES, STAGE_META, STAGE_ORDER, parseMemberLog } from "@/lib/types";
import { Activity, CircleAlert, CircleCheck, CircleMinus, CircleX, Radio, Terminal } from "lucide-react";
import { Fragment, useEffect, useMemo, useState } from "react";
import { ConfidenceBadge, SeverityChip, StatusDot } from "@/components/badges";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import type { AuditJob, Finding, MemberInfo, StageEvent, StageName } from "@/lib/types";
import type { Severity } from "@/lib/types";
import { cn } from "@/lib/utils";
import type { StreamStatus } from "@/lib/api";

export type StageStatus = "idle" | "running" | "done" | "partial" | "error" | "skipped";

export interface PipelineState {
  stages: Record<StageName, StageStatus>;
  findings: Finding[];
  logs: { ts: string; stage?: StageName; message: string }[];
  /** Multi-source jobs: member child audits parsed from parent log events. */
  members: MemberInfo[];
  /** True once events prove this is a composition parent (member log or
   *  composition stage activity). Drives which stage cards render; never
   *  flips for single-source jobs, even after the verdict. */
  multiSource: boolean;
  currentStage: StageName | null;
  startedAt: number | null;
  finishedAt: number | null;
  /** Terminal error-event text, retained even when the bounded log rolls over. */
  failureReason: string | null;
  /** ADDITIVE view-only bookkeeping (no legacy field depends on it):
   *  server-clock per-stage timing for the duration readout, folded from
   *  event `ts` exactly like startedAt/finishedAt so SSE history replay
   *  preserves true durations instead of restarting them near zero. */
  stageStartedAt: Partial<Record<StageName, number>>;
  stageEndedAt: Partial<Record<StageName, number>>;
  /** Server-reported reasons for incomplete stage coverage, retained on replay. */
  stageCoverageReasons: Partial<Record<StageName, string>>;
}

/** Every stage key the reducer tracks. `composition` is invisible on
 * single-source jobs (multiSource stays false) but is still tracked so the
 * terminal verdict can finish it like every other key. */
const ALL_STAGE_KEYS: StageName[] = [...STAGE_ORDER, "composition"];

export function initialPipelineState(): PipelineState {
  const stages = Object.fromEntries(
    ALL_STAGE_KEYS.map((s) => [s, "idle"] as const),
  ) as Record<StageName, StageStatus>;
  return {
    stages,
    findings: [],
    logs: [],
    members: [],
    multiSource: false,
    currentStage: null,
    startedAt: null,
    finishedAt: null,
    failureReason: null,
    stageStartedAt: {},
    stageEndedAt: {},
    stageCoverageReasons: {},
  };
}

/** Stage cards to show: the single-source strip, or the parent's own two
 * cards for multi-source jobs (children run server-side; the parent's only
 * own stage is `composition`, then the verdict). */
function stageOrderFor(state: PipelineState): StageName[] {
  return state.multiSource ? MULTI_SOURCE_STAGE_ORDER : STAGE_ORDER.filter(stage => stage !== "composition");
}

/** Fold a StageEvent into pipeline state (pure). */
export function applyEvent(state: PipelineState, event: StageEvent): PipelineState {
  const next: PipelineState = {
    ...state,
    stages: { ...state.stages },
    stageStartedAt: { ...state.stageStartedAt },
    stageEndedAt: { ...state.stageEndedAt },
    stageCoverageReasons: { ...state.stageCoverageReasons },
  };
  const stage = event.data.stage as StageName | undefined;
  // Server clock is the source of truth for elapsed time: resume/reload
  // replays events whose ts predates page load, so Date.now() would restart
  // the timer near zero. All arithmetic happens on event timestamps.
  const ts = Date.parse(event.ts);
  const safeTs = Number.isFinite(ts) ? ts : Date.now();

  switch (event.type) {
    case "stage_started":
      if (stage) {
        next.stages[stage] = "running";
        next.currentStage = stage;
        next.startedAt ??= safeTs;
        // A parent's only own stage is composition; its appearance proves a
        // multi-source job (single-source pipelines never start it).
        if (stage === "composition") next.multiSource = true;
        // First start wins (duplicate stage_started is idempotent).
        if (next.stageStartedAt[stage] === undefined) next.stageStartedAt[stage] = safeTs;
      }
      break;
    case "finding": {
      const f = event.data.finding as Finding | undefined;
      if (f) next.findings = [...state.findings, f];
      break;
    }
    case "stage_done":
      if (stage) {
        const metrics = event.data.metrics as Record<string, unknown> | undefined;
        next.stages[stage] = event.data.ok === false ? "error"
          : metrics && "skipped" in metrics ? "skipped"
          : metrics?.coverage_incomplete ? "partial" : "done";
        if (metrics?.coverage_incomplete) {
          next.stageCoverageReasons[stage] = typeof metrics.coverage_incomplete === "string"
            ? metrics.coverage_incomplete : "Only part of this check completed.";
        }
        next.findings = state.findings; // count already included via finding events
        if (next.stageEndedAt[stage] === undefined) next.stageEndedAt[stage] = safeTs;
      }
      break;
    case "verdict":
      // Terminal: stages that never ran settle to "skipped" (honest state —
      // e.g. composition on single-source jobs, harness on standard-depth
      // jobs), never fake-green. An interrupted stage has no completion
      // evidence and settles into error, even when a verdict is returned.
      for (const s of ALL_STAGE_KEYS) {
        if (next.stages[s] === "done" || next.stages[s] === "partial" || next.stages[s] === "error" || next.stages[s] === "skipped") continue;
        next.stages[s] = next.stages[s] === "running" ? "error" : "skipped";
      }
      next.stages.verdict = "done";
      next.finishedAt = safeTs;
      // Freeze timing for anything that started but never got a stage_done —
      // mirrors the status settle directly above.
      for (const s of ALL_STAGE_KEYS) {
        if (next.stageStartedAt[s] !== undefined && next.stageEndedAt[s] === undefined) {
          next.stageEndedAt[s] = safeTs;
        }
      }
      break;
    case "error": {
      // Legacy semantics first: a named (even unknown-key) stage errors;
      // otherwise the current stage does.
      if (stage) next.stages[stage] = "error";
      else if (next.currentStage) next.stages[next.currentStage] = "error";
      // View-only: freeze durations at the error ts for every stage the
      // error plausibly terminalized — the named one AND the running one
      // (a fatal error may name an untracked stage like "extraction" while
      // the visible stage was mid-flight). Only stages that actually
      // started and never ended are frozen.
      const targets = new Set([stage, next.currentStage]);
      // Backend error events end the job. No interrupted check becomes green.
      for (const s of ALL_STAGE_KEYS) {
        if (next.stages[s] === "running") {
          next.stages[s] = "error";
          targets.add(s);
        }
      }
      for (const t of targets) {
        if (
          t &&
          next.stageStartedAt[t] !== undefined &&
          next.stageEndedAt[t] === undefined
        ) {
          next.stageEndedAt[t] = safeTs;
        }
      }
      const reason = event.data.error ?? event.data.message;
      next.failureReason = reason != null && String(reason).trim() ? String(reason) : null;
      next.logs = [...state.logs.slice(-40), {
        ts: event.ts,
        stage,
        message: next.failureReason ?? "The server did not supply a failure reason.",
      }];
      break;
    }
    case "log": {
      // Multi-source parent: member summaries arrive as log events carrying
      // child_job_id (contracts §6). Folding is pure and order-driven, so
      // live arrival and SSE history replay (burst at connect) build the
      // exact same member list.
      const member = parseMemberLog(event.data);
      if (member) {
        // Member child logs prove a multi-source parent and ARE its runtime:
        // they can precede the parent's own stage_started(composition), so
        // the elapsed clock must start here (server ts, like stage_started).
        next.multiSource = true;
        next.startedAt ??= safeTs;
        const i = next.members.findIndex((m) => m.childJobId === member.childJobId);
        if (i === -1) {
          next.members = [...next.members, member];
        } else {
          const prev = next.members[i] as MemberInfo;
          const merged: MemberInfo = {
            ...prev,
            status: member.status,
            // Crash follow-up logs ("runner error") repeat the child with a
            // zero count — never lose the summary's real finding count.
            findings: Math.max(prev.findings, member.findings),
          };
          next.members = [...next.members];
          next.members[i] = merged;
        }
        // The parent is actively auditing members before its own
        // stage_started(composition) fires — the running card must tick
        // from this first evidence, exactly like `startedAt` above.
        if (next.stages.composition === "idle") {
          next.stages.composition = "running";
          next.stageStartedAt.composition ??= safeTs;
        }
      }
      next.logs = [
        ...state.logs.slice(-40),
        {
          ts: event.ts,
          stage: event.data.stage as StageName | undefined,
          message: String(event.data.message ?? ""),
        },
      ];
      break;
    }
  }
  return next;
}

/* ── presentation helpers ─────────────────────────────────────────── */

function formatElapsed(ms: number): string {
  const total = Math.floor(ms / 100) / 10;
  if (total < 60) return `${total.toFixed(1)}s`;
  const m = Math.floor(total / 60);
  const s = Math.round(total % 60);
  return `${m}m${s.toString().padStart(2, "0")}s`;
}

const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-sky-400",
  info: "text-zinc-500",
};

const SEVERITY_BAR: Record<Severity, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-sky-600",
  info: "bg-zinc-600",
};

const SEVERITY_ABBR: Record<Severity, string> = {
  critical: "crit",
  high: "high",
  medium: "med",
  low: "low",
  info: "info",
};

/** Terminal glyph per stage state; running/idle keep the pulsing dot. */
function StageGlyph({ status }: { status: StageStatus }) {
  if (status === "done") {
    return <CircleCheck className="size-3.5 shrink-0 text-emerald-400" aria-hidden />;
  }
  if (status === "error") {
    return <CircleX className="size-3.5 shrink-0 text-red-400" aria-hidden />;
  }
  if (status === "partial") {
    return <CircleAlert className="size-3.5 shrink-0 text-amber-400" aria-hidden />;
  }
  if (status === "skipped") {
    return <CircleMinus className="size-3.5 shrink-0 text-zinc-400" aria-hidden />;
  }
  return <StatusDot state={status} />;
}

function connectorClass(left: StageStatus): string {
  if (left === "done") return "bg-emerald-700/80";
  if (left === "error") return "bg-red-800";
  if (left === "partial") return "bg-amber-700/80";
  if (left === "running") return "bg-sky-500";
  return "bg-zinc-800";
}

/** Honest connection status chip — connecting / live / reconnecting /
 *  degraded / disconnected / complete. Always rendered, never hidden. */
function streamChip(
  streamStatus: StreamStatus | null,
  finished: boolean,
  sawEvents: boolean,
): { label: string; dot: string; text: string; pulse: boolean; title: string } {
  if (finished) {
    return { label: "complete", dot: "bg-emerald-400", text: "text-emerald-300", pulse: false, title: "audit finished — stream closed by verdict" };
  }
  if (!streamStatus) {
    // No status object: either the real stream hasn't reported yet, or this
    // is the local mock replay (which never emits status). Events flowing
    // without a status object = replay; otherwise connecting.
    return sawEvents
      ? { label: "local replay", dot: "bg-zinc-500", text: "text-zinc-400", pulse: false, title: "mock replay — no live stream" }
      : { label: "connecting…", dot: "bg-zinc-500", text: "text-zinc-400", pulse: true, title: "opening event stream" };
  }
  switch (streamStatus.kind) {
    case "connecting":
      return { label: "connecting…", dot: "bg-sky-400", text: "text-sky-300", pulse: true, title: "opening event stream" };
    case "open":
      return { label: `live · ${streamStatus.transport}`, dot: "bg-emerald-400", text: "text-emerald-300", pulse: false, title: "event stream connected" };
    case "reconnecting":
      return { label: `reconnecting #${streamStatus.attempt}`, dot: "bg-amber-400", text: "text-amber-300", pulse: true, title: "stream dropped — retrying" };
    case "degraded":
      return { label: "polling fallback", dot: "bg-amber-400", text: "text-amber-300", pulse: false, title: `SSE unavailable — polling (${streamStatus.reason})` };
    case "closed":
      return { label: "disconnected", dot: "bg-red-400", text: "text-red-300", pulse: false, title: "stream closed before verdict" };
  }
}

export interface PipelineMonitorProps {
  job: AuditJob;
  state: PipelineState;
  streamStatus: StreamStatus | null;
  onNewAudit: () => void;
}

export function PipelineMonitor({ job, state, streamStatus, onNewAudit }: PipelineMonitorProps) {
  const [now, setNow] = useState<number>(() => Date.now());

  // A run is HALTED when it ended without a verdict: a tracked stage errored
  // and nothing is running, a fatal error named an untracked stage (leaves an
  // extraneous error key — e.g. "extraction"), or the stream closed early.
  // View-only detection — no verdict or transport state is synthesized.
  const errorKeys = (Object.keys(state.stages) as StageName[]).filter(
    (k) => state.stages[k] === "error",
  );
  const anyError = errorKeys.length > 0;
  const unknownKeyError = errorKeys.some((k) => !ALL_STAGE_KEYS.includes(k));
  const nothingRunning = !Object.values(state.stages).includes("running");
  const streamClosedEarly = streamStatus?.kind === "closed";
  const halted =
    !state.finishedAt &&
    (unknownKeyError || (anyError && nothingRunning) || (streamClosedEarly && nothingRunning));

  useEffect(() => {
    if (state.finishedAt || halted) return;
    const t = setInterval(() => setNow(Date.now()), 100);
    return () => clearInterval(t);
  }, [state.finishedAt, halted]);

  // Freeze the clock at the last server event ts when halted (honest "died
  // at T" instead of an ever-ticking clock on a dead run).
  const lastLog = state.logs.at(-1);
  const lastLogTs = lastLog ? Date.parse(lastLog.ts) : NaN;
  const clockEnd = state.finishedAt ?? (halted && Number.isFinite(lastLogTs) ? lastLogTs : now);

  const elapsed = state.startedAt ? clockEnd - state.startedAt : 0;
  const multiSource = state.multiSource;
  const stageCards = stageOrderFor(state);
  const doneCount = stageCards.filter(
    (s) =>
      state.stages[s] === "done" ||
      state.stages[s] === "partial" ||
      state.stages[s] === "error" ||
      state.stages[s] === "skipped",
  ).length;
  const completedChecks = stageCards.filter(stage => stage !== "verdict" && state.stages[stage] === "done").length;
  const partialChecks = stageCards.filter(stage => stage !== "verdict" && state.stages[stage] === "partial").length;
  const unavailableChecks = stageCards.filter(stage => stage !== "verdict" && (state.stages[stage] === "error" || state.stages[stage] === "skipped")).length;
  const progress = Math.round((doneCount / stageCards.length) * 100);
  const finished = state.finishedAt !== null;

  // Server-clock per-stage duration (ms), or null when unknown. Running
  // stages tick live against the same clock as the elapsed timer.
  const stageDuration = (stage: StageName): number | null => {
    const s = state.stageStartedAt[stage];
    const e = state.stageEndedAt[stage];
    if (typeof s !== "number") return null;
    if (typeof e === "number") return e - s;
    if (state.stages[stage] === "running" && !finished) return clockEnd - s;
    return null;
  };

  const findingsByStage = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of state.findings) m.set(f.stage, (m.get(f.stage) ?? 0) + 1);
    return m;
  }, [state.findings]);

  const severityTally = useMemo(() => {
    const t: Partial<Record<Severity, number>> = {};
    for (const f of state.findings) t[f.severity] = (t[f.severity] ?? 0) + 1;
    return t;
  }, [state.findings]);

  const feed = useMemo(
    () =>
      [...state.findings]
        .reverse()
        .slice(0, 50)
        .map((f, i) => ({ f, key: `${state.findings.length - i}` })),
    [state.findings],
  );

  const latestFinding = state.findings.at(-1);
  const membersDone = state.members.filter((m) => m.status === "done" || m.status === "failed").length;
  const sawEvents = state.logs.length > 0 || state.findings.length > 0 || state.currentStage !== null;
  const chip = streamChip(streamStatus, finished, sawEvents);
  const erroredLabels = stageCards
    .filter((s) => state.stages[s] === "error")
    .map((s) => STAGE_META[s].label);

  return (
    <div className="flex flex-col gap-4">
      {/* ── header strip ─────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <Radio
            className={cn(
              "size-4 shrink-0",
              finished
                ? "text-emerald-400"
                : halted
                  ? "text-red-400"
                  : "text-sky-400 animate-pulse-dot",
            )}
            aria-hidden
          />
          <div className="min-w-0">
            <p className="truncate font-mono text-sm text-zinc-200">{job.source}</p>
            <p className="font-mono text-[11px] text-zinc-500">
              {job.id} · {finished ? "run finished" : halted ? "analysis interrupted" : "analysis in progress"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span
            title={chip.title}
            className="inline-flex items-center gap-1.5 rounded-full border border-zinc-800 bg-zinc-950/60 px-2.5 py-1 font-mono text-[11px] tracking-wide"
          >
            <span
              className={cn(
                "inline-block size-1.5 rounded-full",
                chip.dot,
                chip.pulse && "animate-pulse-dot",
              )}
            />
            <span className={chip.text}>{chip.label}</span>
          </span>
          <div className="text-right">
            <p className="font-mono text-lg leading-none tabular-nums text-zinc-100">
              {formatElapsed(elapsed)}
            </p>
            <p className="text-[11px] uppercase tracking-wider text-zinc-400">
              {finished ? "total" : halted ? "halted at" : "elapsed"}
            </p>
          </div>
          {finished && (
            <button
              onClick={onNewAudit}
              className="rounded-md border border-zinc-700 px-3 py-1.5 font-mono text-xs text-zinc-300 transition-colors duration-150 hover:bg-zinc-800"
            >
              new audit
            </button>
          )}
        </div>
      </div>

      {/* overall progress */}
      <div className="flex items-center gap-3 px-1">
        <Progress
          value={progress}
          className="h-1 flex-1"
          indicatorClassName={finished ? partialChecks > 0 || unavailableChecks > 0 ? "bg-amber-500" : "bg-emerald-500" : halted ? "bg-red-500" : "bg-sky-500"}
        />
        <span className="font-mono text-[11px] tabular-nums text-zinc-500">
          {multiSource
            ? `${membersDone}/${state.members.length} members audited`
            : `${completedChecks}/${stageCards.length - 1} checks completed${partialChecks > 0 ? ` · ${partialChecks} partial` : ""}${unavailableChecks > 0 ? ` · ${unavailableChecks} unavailable` : ""}`}
        </span>
      </div>

      {/* ── halted banner (fatal error, no verdict) ─────────────────── */}
      {halted && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-lg border border-red-800/70 bg-red-950/30 px-4 py-3 font-mono text-xs text-red-300"
        >
          <CircleX className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <section className="min-w-0 flex-1 space-y-2">
            <p>Audit stopped without a verdict{erroredLabels.length > 0 ? ` — ${erroredLabels.join(", ")} failed` : ""}.</p>
            <p className="whitespace-pre-wrap break-words [overflow-wrap:anywhere]">{state.failureReason ?? "The server did not supply a failure reason."}</p>
            <button
              onClick={onNewAudit}
              className="rounded-md border border-red-700 px-3 py-1.5 font-mono text-xs transition-colors duration-150 hover:bg-red-950 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-300"
            >new audit</button>
          </section>
        </div>
      )}

      {!finished && !halted && <p className="text-sm leading-relaxed text-zinc-300" role="status">{state.currentStage ? `Checking ${STAGE_META[state.currentStage]?.label ?? state.currentStage}…` : "Preparing the source…"} Model and sandbox checks can take longer. You can return to this audit’s URL to reconnect.</p>}

      {/* ── stage strip ─────────────────────────────────────────────
           Order matches STAGE_ORDER / MULTI_SOURCE_STAGE_ORDER exactly.
           running = sky pulse + live ticking duration; done = duration +
           findings yielded; error = red; skipped = honest dimmed, never
           fake-green. */}
      <div className="stage-strip rounded-lg border border-zinc-800/70 bg-zinc-900/30 p-3">
        {stageCards.map((stage, i) => {
          const meta = STAGE_META[stage];
          const status = state.stages[stage];
          const active = status === "running" && !finished;
          const dur = stageDuration(stage);
          const n = findingsByStage.get(stage) ?? 0;
          const prev = i > 0 ? state.stages[stageCards[i - 1] as StageName] : null;
          return (
            <Fragment key={stage}>
              {i > 0 && (
                <span
                  aria-hidden
                  className={cn("hidden h-px w-4 shrink-0 transition-colors duration-150", connectorClass(prev as StageStatus))}
                />
              )}
              <div
                title={meta.blurb}
                role="group"
                aria-label={`${meta.label}: ${status}`}
                className={cn(
                  "stage-cell relative min-w-0 overflow-hidden rounded-lg border px-2.5 py-2 transition-colors duration-150",

                  status === "running" && "border-sky-700/70 bg-sky-950/30",
                  status === "done" && "border-zinc-800 bg-zinc-900/40",
                  status === "error" && "border-red-800/70 bg-red-950/30",
                  status === "partial" && "border-amber-800/70 bg-amber-950/30",
                  status === "skipped" && "border-zinc-800/50 bg-zinc-900/20 ",
                  status === "idle" && "border-zinc-800/60 bg-zinc-900/20 ",
                  stage === "verdict" && finished && status === "done" && "border-emerald-800/60 bg-emerald-950/20",
                )}
              >
                {active && (
                  <span className="absolute inset-x-0 top-0 h-px animate-pulse-dot bg-gradient-to-r from-transparent via-sky-400 to-transparent" />
                )}
                <div className="flex items-center gap-1.5">
                  <StageGlyph status={status} />
                  <span className="font-mono text-[11px] tabular-nums text-zinc-400">
                    S{meta.index}
                  </span>
                  <span
                    className={cn(
                      "truncate text-[12px] font-semibold",
                      active ? "text-sky-100" : "text-zinc-200",
                    )}
                  >
                    {meta.label}
                  </span>
                </div>
                <div className="mt-1 flex items-center justify-between gap-1 font-mono text-[11px] tabular-nums">
                  <span
                    className={cn(
                      status === "error" && "text-red-400",
                      status === "partial" && "text-amber-300",
                      status === "running" && "text-sky-300",
                      status === "done" && "text-zinc-500",
                      (status === "idle" || status === "skipped") && "text-zinc-400",
                    )}
                  >
                    {status === "skipped"
                      ? "skipped"
                      : status === "partial"
                        ? `partial${dur !== null ? ` · ${formatElapsed(dur)}` : ""}`
                      : status === "idle"
                        ? "—"
                        : dur !== null
                          ? status === "error"
                            ? `failed · ${formatElapsed(dur)}`
                            : formatElapsed(dur)
                          : status === "error"
                            ? "failed"
                            : "…"}
                  </span>
                  {n > 0 && (
                    <span className="rounded border border-amber-800/70 bg-amber-950/50 px-1 py-px text-[11px] text-amber-300">
                      {n} ⚠
                    </span>
                  )}
                </div>
                {status === "partial" && (
                  <p className="mt-2 break-words text-[11px] leading-relaxed text-amber-200 [overflow-wrap:anywhere]">
                    {state.stageCoverageReasons[stage] ?? "Only part of this check completed."}
                  </p>
                )}
              </div>
            </Fragment>
          );
        })}
      </div>

      {/* ── member strip (multi-source jobs only) ─────────────────────
           One row per member child audit, parsed from parent log events
           carrying child_job_id. Identical whether the events arrive live
           or as SSE history replay — the reducer folds them the same way. */}
      {multiSource && (
        <div className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900/40">
          <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-2">
            <span className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
              member audits
            </span>
            <span className="font-mono text-[11px] tabular-nums text-zinc-400">
              {state.members.length} source{state.members.length === 1 ? "" : "s"} ·{" "}
              {state.members.reduce((acc, m) => acc + m.findings, 0)} member findings
            </span>
          </div>
          <ul className="divide-y divide-zinc-800/60">
            {state.members.map((m) => (
              <li
                key={m.childJobId}
                className="flex items-center gap-3 px-4 py-1.5"
              >
                <StatusDot
                  state={
                    m.status === "done"
                      ? "done"
                      : m.status === "failed"
                        ? "error"
                        : "running"
                  }
                />
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-300">
                  {m.label}
                </span>
                {m.findings > 0 && (
                  <span className="rounded border border-amber-800/70 bg-amber-950/50 px-1.5 py-px font-mono text-[11px] text-amber-300">
                    {m.findings} ⚠
                  </span>
                )}
                <span
                  className={cn(
                    "w-14 text-right font-mono text-[11px] uppercase tracking-wider",
                    m.status === "done" && "text-emerald-400",
                    m.status === "failed" && "text-red-400",
                    (m.status === "running" || m.status === "queued") && "text-sky-400",
                  )}
                >
                  {m.status}
                </span>
              </li>
            ))}
            {state.members.length === 0 && (
              <li className="px-4 py-2 font-mono text-[11px] text-zinc-400">
                fanning out member audits…
              </li>
            )}
          </ul>
        </div>
      )}

      {/* ── findings-so-far ticker ───────────────────────────────────
           Σ count + severity tally + the latest finding, flashing in
           (150ms) each time evidence lands. */}
      <div className="flex items-center gap-3 overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900/50 px-3 py-2">
        <span className="shrink-0 font-mono text-[11px] uppercase tracking-wider text-zinc-500">
          findings
        </span>
        <span className="shrink-0 font-mono text-base font-bold leading-none tabular-nums text-amber-300">
          {state.findings.length}
        </span>
        <span className="hidden shrink-0 items-center gap-2 font-mono text-[11px] tabular-nums sm:flex">
          {[...SEVERITIES].reverse().map((sev) => {
            const c = severityTally[sev] ?? 0;
            if (c === 0) return null;
            return (
              <span key={sev} className={SEVERITY_TEXT[sev]}>
                {c} {SEVERITY_ABBR[sev]}
              </span>
            );
          })}
        </span>
        <div className="min-w-0 flex-1 text-right">
          {latestFinding ? (
            <p
              key={state.findings.length}
              title={latestFinding.detail}
              className="animate-feed-in [animation-duration:150ms] truncate font-mono text-[11px]"
            >
              <span className="text-zinc-400">[{latestFinding.stage}]</span>{" "}
              <span className={SEVERITY_TEXT[latestFinding.severity]}>▲</span>{" "}
              <span className="text-zinc-300">{latestFinding.title}</span>
            </p>
          ) : (
            <p className="truncate font-mono text-[11px] text-zinc-400">
              {halted ? "audit stopped — no findings returned" : finished ? "no findings emitted" : "listening for findings…"}
            </p>
          )}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        {/* ── evidence feed ────────────────────────────────────────── */}
        <Card className={cn("flex min-w-0 max-h-[560px] flex-col", halted ? "min-h-0 lg:min-h-[380px]" : "min-h-[380px]")}>
          <CardHeader className="space-y-0 border-b border-zinc-800/70 pb-3">
            <CardTitle className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2">
                <Activity className="size-3.5 text-zinc-500" aria-hidden />
                Evidence feed
              </span>
              <span className="font-mono text-xs tabular-nums text-zinc-500">
                {state.findings.length} total
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-y-auto p-2">
            {state.findings.length === 0 && (
              <p className="p-4 text-center font-mono text-xs text-zinc-400">
                {halted ? "audit stopped — no findings returned" : finished ? "no findings emitted" : "listening…"}
              </p>
            )}
            <ul className="flex flex-col gap-1.5">
              {feed.map(({ f, key }) => (
                <li
                  key={key}
                  className="animate-feed-in [animation-duration:150ms] flex gap-2.5 rounded-md border border-zinc-800/70 bg-zinc-900/60 p-2.5"
                >
                  <span
                    aria-hidden
                    className={cn("w-0.5 shrink-0 self-stretch rounded-full", SEVERITY_BAR[f.severity])}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
                        {f.stage}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <ConfidenceBadge tier={f.confidence} />
                        <SeverityChip severity={f.severity} />
                      </div>
                    </div>
                    <p className="mt-1.5 break-words text-[13px] font-medium leading-snug text-zinc-200 [overflow-wrap:anywhere]">
                      {f.title}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        {/* ── stream log console ───────────────────────────────────── */}
        <Card className={cn("flex min-w-0 max-h-[560px] flex-col", halted ? "min-h-0 lg:min-h-[380px]" : "min-h-[380px]")}>
          <CardHeader className="space-y-0 border-b border-zinc-800/70 pb-3">
            <CardTitle className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2">
                <Terminal className="size-3.5 text-zinc-500" aria-hidden />
                Stream log
              </span>
              <span className="font-mono text-xs tabular-nums text-zinc-500">
                {state.logs.length} lines
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-y-auto p-3">
            {state.logs.length === 0 && (
              <p className="p-4 text-center font-mono text-xs text-zinc-400">no log lines yet</p>
            )}
            <div className="font-mono text-[11px] leading-relaxed">
              {state.logs
                .slice()
                .reverse()
                .map((l, i) => (
                  <p
                    key={i}
                    className="animate-feed-in [animation-duration:150ms] break-words border-b border-zinc-900 py-0.5 [overflow-wrap:anywhere]"
                  >
                    <span className="tabular-nums text-zinc-500">{l.ts.slice(11, 19)}</span>{" "}
                    <span className="text-zinc-400">[{l.stage ?? "core"}]</span>{" "}
                    <span className="text-zinc-400">{l.message}</span>
                  </p>
                ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
