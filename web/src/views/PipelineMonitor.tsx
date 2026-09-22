import { Activity, Radio } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ConfidenceBadge, SeverityChip, StatusDot, type StageDotState } from "@/components/badges";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { AuditJob, Finding, MemberInfo, StageEvent, StageName } from "@/lib/types";
import { MULTI_SOURCE_STAGE_ORDER, STAGE_META, STAGE_ORDER, parseMemberLog } from "@/lib/types";
import { cn } from "@/lib/utils";
import type { StreamStatus } from "@/lib/api";

export type StageStatus = "idle" | "running" | "done" | "error";

export interface PipelineState {
  stages: Record<StageName, StageStatus>;
  findings: Finding[];
  logs: { ts: string; stage?: StageName; message: string }[];
  /** Multi-source jobs: member child audits parsed from parent log events. */
  members: MemberInfo[];
  /** True once events prove this is a composition parent (member log or
   * composition stage activity). Drives which stage cards render; never
   * flips for single-source jobs, even after the verdict. */
  multiSource: boolean;
  currentStage: StageName | null;
  startedAt: number | null;
  finishedAt: number | null;
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
  };
}

/** Stage cards to show: the single-source strip, or the parent's own two
 * cards for multi-source jobs (children run server-side; the parent's only
 * own stage is `composition`, then the verdict). */
function stageOrderFor(state: PipelineState): StageName[] {
  return state.multiSource ? MULTI_SOURCE_STAGE_ORDER : STAGE_ORDER;
}

/** Fold a StageEvent into pipeline state (pure). */
export function applyEvent(state: PipelineState, event: StageEvent): PipelineState {
  const next: PipelineState = { ...state, stages: { ...state.stages } };
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
      }
      break;
    case "finding": {
      const f = event.data.finding as Finding | undefined;
      if (f) next.findings = [...state.findings, f];
      break;
    }
    case "stage_done":
      if (stage) {
        next.stages[stage] = event.data.ok === false ? "error" : "done";
        next.findings = state.findings; // count already included via finding events
      }
      break;
    case "verdict":
      // Terminal: finish every stage that didn't explicitly fail or complete.
      // (The backend runs 6 stages today; cards for planned-but-unbuilt
      // stages must not stay "idle" forever after the verdict lands.)
      for (const s of ALL_STAGE_KEYS) {
        if (next.stages[s] !== "error" && next.stages[s] !== "done") next.stages[s] = "done";
      }
      next.stages.verdict = "done";
      next.finishedAt = safeTs;
      break;
    case "error":
      if (stage) next.stages[stage] = "error";
      else if (next.currentStage) next.stages[next.currentStage] = "error";
      break;
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
        // stage_started(composition) fires.
        if (next.stages.composition === "idle") next.stages.composition = "running";
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

function dotFor(status: StageStatus): StageDotState {
  return status;
}

function formatElapsed(ms: number): string {
  const total = Math.floor(ms / 100) / 10;
  if (total < 60) return `${total.toFixed(1)}s`;
  const m = Math.floor(total / 60);
  const s = Math.round(total % 60);
  return `${m}m${s.toString().padStart(2, "0")}s`;
}

export interface PipelineMonitorProps {
  job: AuditJob;
  state: PipelineState;
  streamStatus: StreamStatus | null;
  onNewAudit: () => void;
}

export function PipelineMonitor({ job, state, streamStatus, onNewAudit }: PipelineMonitorProps) {
  const [now, setNow] = useState<number>(() => Date.now());
  const [tab, setTab] = useState("feed");

  useEffect(() => {
    if (state.finishedAt) return;
    const t = setInterval(() => setNow(Date.now()), 100);
    return () => clearInterval(t);
  }, [state.finishedAt]);

  const elapsed = state.startedAt ? (state.finishedAt ?? now) - state.startedAt : 0;
  const multiSource = state.multiSource;
  const stageCards = stageOrderFor(state);
  const doneCount = stageCards.filter(
    (s) => state.stages[s] === "done" || state.stages[s] === "error",
  ).length;
  const progress = Math.round((doneCount / stageCards.length) * 100);

  const feed = useMemo(
    () =>
      [...state.findings]
        .reverse()
        .slice(0, 50)
        .map((f, i) => ({ f, key: `${state.findings.length - i}` })),
    [state.findings],
  );

  const membersDone = state.members.filter((m) => m.status === "done" || m.status === "failed").length;

  return (
    <div className="flex flex-col gap-4">
      {/* ── header strip ─────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <Radio
            className={cn(
              "size-4 shrink-0",
              state.finishedAt ? "text-emerald-400" : "text-sky-400 animate-pulse-dot",
            )}
            aria-hidden
          />
          <div className="min-w-0">
            <p className="truncate font-mono text-sm text-zinc-200">{job.source}</p>
            <p className="font-mono text-[11px] text-zinc-500">
              {job.id} · depth {job.depth}
              {streamStatus && streamStatus.kind !== "closed" && (
                <span className="ml-2 text-zinc-600">
                  · {streamStatus.transport}
                  {streamStatus.kind === "reconnecting" && ` retry#${streamStatus.attempt}`}
                  {streamStatus.kind === "degraded" && ` (${streamStatus.reason})`}
                </span>
              )}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <p className="font-mono text-lg leading-none tabular-nums text-zinc-100">
              {formatElapsed(elapsed)}
            </p>
            <p className="text-[10px] uppercase tracking-wider text-zinc-600">elapsed</p>
          </div>
          {state.finishedAt && (
            <button
              onClick={onNewAudit}
              className="rounded-md border border-zinc-700 px-3 py-1.5 font-mono text-xs text-zinc-300 transition-colors hover:bg-zinc-800"
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
          indicatorClassName={state.finishedAt ? "bg-emerald-500" : "bg-sky-500"}
        />
        <span className="font-mono text-[11px] tabular-nums text-zinc-500">
          {multiSource
            ? `${membersDone}/${state.members.length} members audited`
            : `${doneCount}/${stageCards.length} stages`}
        </span>
      </div>

      {/* ── member strip (multi-source jobs only) ─────────────────────
           One row per member child audit, parsed from parent log events
           carrying child_job_id. Identical whether the events arrive live
           or as SSE history replay — the reducer folds them the same way. */}
      {multiSource && (
        <div className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900/40">
          <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-2">
            <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
              members
            </span>
            <span className="font-mono text-[10px] tabular-nums text-zinc-600">
              {state.members.length} source{state.members.length === 1 ? "" : "s"} ·{" "}
              {state.members.reduce((n, m) => n + m.findings, 0)} member findings
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
                  <span className="rounded border border-amber-800/70 bg-amber-950/50 px-1.5 py-px font-mono text-[10px] text-amber-300">
                    {m.findings} ⚠
                  </span>
                )}
                <span
                  className={cn(
                    "w-14 text-right font-mono text-[10px] uppercase tracking-wider",
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
              <li className="px-4 py-2 font-mono text-[11px] text-zinc-600">
                fanning out member audits…
              </li>
            )}
          </ul>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        {/* ── stage cards ────────────────────────────────────────── */}
        <div className="grid gap-2 sm:grid-cols-2">
          {stageCards.map((stage) => {
            const meta = STAGE_META[stage];
            const status = state.stages[stage];
            const active = state.currentStage === stage && !state.finishedAt;
            const stageFindings = state.findings.filter((f) => f.stage === stage).length;
            return (
              <div
                key={stage}
                className={cn(
                  "relative overflow-hidden rounded-lg border bg-zinc-900/40 p-3 transition-colors",
                  status === "running" && "border-sky-700/70 bg-sky-950/20",
                  status === "done" && "border-zinc-800",
                  status === "error" && "border-red-800/70 bg-red-950/20",
                  status === "idle" && "border-zinc-800/60 opacity-60",
                )}
              >
                {active && (
                  <span className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-sky-400 to-transparent" />
                )}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <StatusDot state={dotFor(status)} />
                    <span className="font-mono text-[10px] tabular-nums text-zinc-600">
                      S{meta.index}
                    </span>
                    <span className="text-[13px] font-semibold text-zinc-200">{meta.label}</span>
                  </div>
                  {stageFindings > 0 && (
                    <span className="rounded border border-amber-800/70 bg-amber-950/50 px-1.5 py-px font-mono text-[10px] text-amber-300">
                      {stageFindings} ⚠
                    </span>
                  )}
                </div>
                <p className="mt-1.5 pl-[4.35rem] text-[11px] leading-tight text-zinc-500">
                  {meta.blurb}
                </p>
              </div>
            );
          })}
        </div>

        {/* ── live findings feed + stream log tabs ───────────────── */}
        <Card className="flex max-h-[560px] min-h-[360px] flex-col">
          <CardHeader className="space-y-2 border-b border-zinc-800/70 pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Activity className="size-3.5 text-zinc-500" aria-hidden />
                Live telemetry
              </CardTitle>
              <span className="font-mono text-xs tabular-nums text-zinc-500">
                {state.findings.length} findings
              </span>
            </div>
            <Tabs value={tab} onValueChange={setTab}>
              <TabsList>
                <TabsTrigger value="feed">findings</TabsTrigger>
                <TabsTrigger value="log">
                  log{state.logs.length > 0 && ` (${state.logs.length})`}
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </CardHeader>
          <CardContent className="flex-1 overflow-y-auto p-2">
            <Tabs value={tab} onValueChange={setTab}>
              <TabsContent value="feed">
                {state.findings.length === 0 && (
                  <p className="p-4 text-center font-mono text-xs text-zinc-600">
                    {state.finishedAt ? "no findings emitted" : "listening…"}
                  </p>
                )}
                <ul className="flex flex-col gap-1.5">
                  {feed.map(({ f, key }) => (
                    <li
                      key={key}
                      className="animate-feed-in rounded-md border border-zinc-800/70 bg-zinc-900/60 p-2.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                          {f.stage}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <ConfidenceBadge tier={f.confidence} />
                          <SeverityChip severity={f.severity} />
                        </div>
                      </div>
                      <p className="mt-1.5 text-[13px] font-medium leading-snug text-zinc-200">
                        {f.title}
                      </p>
                    </li>
                  ))}
                </ul>
              </TabsContent>
              <TabsContent value="log">
                {state.logs.length === 0 && (
                  <p className="p-4 text-center font-mono text-xs text-zinc-600">no log lines yet</p>
                )}
                <div className="font-mono text-[11px] leading-relaxed text-zinc-500">
                  {state.logs
                    .slice()
                    .reverse()
                    .map((l, i) => (
                      <p key={i} className="animate-feed-in border-b border-zinc-900 py-0.5">
                        <span className="text-zinc-700">[{l.stage ?? "core"}]</span> {l.message}
                      </p>
                    ))}
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
