"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.initialPipelineState = initialPipelineState;
exports.applyEvent = applyEvent;
exports.PipelineMonitor = PipelineMonitor;
const jsx_runtime_1 = require("react/jsx-runtime");
const lucide_react_1 = require("lucide-react");
const react_1 = require("react");
const badges_1 = require("@/components/badges");
const card_1 = require("@/components/ui/card");
const progress_1 = require("@/components/ui/progress");
const tabs_1 = require("@/components/ui/tabs");
const types_1 = require("@/lib/types");
const utils_1 = require("@/lib/utils");
function initialPipelineState() {
    const stages = Object.fromEntries(types_1.STAGE_ORDER.map((s) => [s, "idle"]));
    return {
        stages,
        findings: [],
        logs: [],
        currentStage: null,
        startedAt: null,
        finishedAt: null,
    };
}
/** Fold a StageEvent into pipeline state (pure). */
function applyEvent(state, event) {
    var _a;
    const next = { ...state, stages: { ...state.stages } };
    const stage = event.data.stage;
    switch (event.type) {
        case "stage_started":
            if (stage) {
                next.stages[stage] = "running";
                next.currentStage = stage;
                next.startedAt ?? (next.startedAt = Date.now());
            }
            break;
        case "finding": {
            const f = event.data.finding;
            if (f)
                next.findings = [...state.findings, f];
            break;
        }
        case "stage_done":
            if (stage) {
                next.stages[stage] = event.data.ok === false ? "error" : "done";
                next.findings = state.findings; // count already included via finding events
            }
            break;
        case "verdict":
            for (const s of types_1.STAGE_ORDER)
                (_a = next.stages)[s] ?? (_a[s] = "done");
            next.stages.verdict = "done";
            next.finishedAt = Date.now();
            break;
        case "error":
            if (stage)
                next.stages[stage] = "error";
            else if (next.currentStage)
                next.stages[next.currentStage] = "error";
            break;
        case "log":
            next.logs = [
                ...state.logs.slice(-40),
                {
                    ts: event.ts,
                    stage: event.data.stage,
                    message: String(event.data.message ?? ""),
                },
            ];
            break;
    }
    return next;
}
function dotFor(status) {
    return status;
}
function formatElapsed(ms) {
    const total = Math.floor(ms / 100) / 10;
    if (total < 60)
        return `${total.toFixed(1)}s`;
    const m = Math.floor(total / 60);
    const s = Math.round(total % 60);
    return `${m}m${s.toString().padStart(2, "0")}s`;
}
function PipelineMonitor({ job, state, streamStatus, onNewAudit }) {
    const [now, setNow] = (0, react_1.useState)(() => Date.now());
    const [tab, setTab] = (0, react_1.useState)("feed");
    (0, react_1.useEffect)(() => {
        if (state.finishedAt)
            return;
        const t = setInterval(() => setNow(Date.now()), 100);
        return () => clearInterval(t);
    }, [state.finishedAt]);
    const elapsed = state.startedAt ? (state.finishedAt ?? now) - state.startedAt : 0;
    const doneCount = types_1.STAGE_ORDER.filter((s) => state.stages[s] === "done" || state.stages[s] === "error").length;
    const progress = Math.round((doneCount / types_1.STAGE_ORDER.length) * 100);
    const feed = (0, react_1.useMemo)(() => [...state.findings]
        .reverse()
        .slice(0, 50)
        .map((f, i) => ({ f, key: `${state.findings.length - i}` })), [state.findings]);
    return ((0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col gap-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex flex-wrap items-center justify-between gap-3 rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex min-w-0 items-center gap-3", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Radio, { className: (0, utils_1.cn)("size-4 shrink-0", state.finishedAt ? "text-emerald-400" : "text-sky-400 animate-pulse-dot"), "aria-hidden": true }), (0, jsx_runtime_1.jsxs)("div", { className: "min-w-0", children: [(0, jsx_runtime_1.jsx)("p", { className: "truncate font-mono text-sm text-zinc-200", children: job.source }), (0, jsx_runtime_1.jsxs)("p", { className: "font-mono text-[11px] text-zinc-500", children: [job.id, " \u00B7 depth ", job.depth, streamStatus && streamStatus.kind !== "closed" && ((0, jsx_runtime_1.jsxs)("span", { className: "ml-2 text-zinc-600", children: ["\u00B7 ", streamStatus.transport, streamStatus.kind === "reconnecting" && ` retry#${streamStatus.attempt}`, streamStatus.kind === "degraded" && ` (${streamStatus.reason})`] }))] })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "text-right", children: [(0, jsx_runtime_1.jsx)("p", { className: "font-mono text-lg leading-none tabular-nums text-zinc-100", children: formatElapsed(elapsed) }), (0, jsx_runtime_1.jsx)("p", { className: "text-[10px] uppercase tracking-wider text-zinc-600", children: "elapsed" })] }), state.finishedAt && ((0, jsx_runtime_1.jsx)("button", { onClick: onNewAudit, className: "rounded-md border border-zinc-700 px-3 py-1.5 font-mono text-xs text-zinc-300 transition-colors hover:bg-zinc-800", children: "new audit" }))] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-3 px-1", children: [(0, jsx_runtime_1.jsx)(progress_1.Progress, { value: progress, className: "h-1 flex-1", indicatorClassName: state.finishedAt ? "bg-emerald-500" : "bg-sky-500" }), (0, jsx_runtime_1.jsxs)("span", { className: "font-mono text-[11px] tabular-nums text-zinc-500", children: [doneCount, "/", types_1.STAGE_ORDER.length, " stages"] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]", children: [(0, jsx_runtime_1.jsx)("div", { className: "grid gap-2 sm:grid-cols-2", children: types_1.STAGE_ORDER.map((stage) => {
                            const meta = types_1.STAGE_META[stage];
                            const status = state.stages[stage];
                            const active = state.currentStage === stage && !state.finishedAt;
                            const stageFindings = state.findings.filter((f) => f.stage === stage).length;
                            return ((0, jsx_runtime_1.jsxs)("div", { className: (0, utils_1.cn)("relative overflow-hidden rounded-lg border bg-zinc-900/40 p-3 transition-colors", status === "running" && "border-sky-700/70 bg-sky-950/20", status === "done" && "border-zinc-800", status === "error" && "border-red-800/70 bg-red-950/20", status === "idle" && "border-zinc-800/60 opacity-60"), children: [active && ((0, jsx_runtime_1.jsx)("span", { className: "absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-sky-400 to-transparent" })), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between gap-2", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(badges_1.StatusDot, { state: dotFor(status) }), (0, jsx_runtime_1.jsxs)("span", { className: "font-mono text-[10px] tabular-nums text-zinc-600", children: ["S", meta.index] }), (0, jsx_runtime_1.jsx)("span", { className: "text-[13px] font-semibold text-zinc-200", children: meta.label })] }), stageFindings > 0 && ((0, jsx_runtime_1.jsxs)("span", { className: "rounded border border-amber-800/70 bg-amber-950/50 px-1.5 py-px font-mono text-[10px] text-amber-300", children: [stageFindings, " \u26A0"] }))] }), (0, jsx_runtime_1.jsx)("p", { className: "mt-1.5 pl-[4.35rem] text-[11px] leading-tight text-zinc-500", children: meta.blurb })] }, stage));
                        }) }), (0, jsx_runtime_1.jsxs)(card_1.Card, { className: "flex max-h-[560px] min-h-[360px] flex-col", children: [(0, jsx_runtime_1.jsxs)(card_1.CardHeader, { className: "space-y-2 border-b border-zinc-800/70 pb-3", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)(card_1.CardTitle, { className: "flex items-center gap-2 text-sm", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Activity, { className: "size-3.5 text-zinc-500", "aria-hidden": true }), "Live telemetry"] }), (0, jsx_runtime_1.jsxs)("span", { className: "font-mono text-xs tabular-nums text-zinc-500", children: [state.findings.length, " findings"] })] }), (0, jsx_runtime_1.jsx)(tabs_1.Tabs, { value: tab, onValueChange: setTab, children: (0, jsx_runtime_1.jsxs)(tabs_1.TabsList, { children: [(0, jsx_runtime_1.jsx)(tabs_1.TabsTrigger, { value: "feed", children: "findings" }), (0, jsx_runtime_1.jsxs)(tabs_1.TabsTrigger, { value: "log", children: ["log", state.logs.length > 0 && ` (${state.logs.length})`] })] }) })] }), (0, jsx_runtime_1.jsx)(card_1.CardContent, { className: "flex-1 overflow-y-auto p-2", children: (0, jsx_runtime_1.jsxs)(tabs_1.Tabs, { value: tab, onValueChange: setTab, children: [(0, jsx_runtime_1.jsxs)(tabs_1.TabsContent, { value: "feed", children: [state.findings.length === 0 && ((0, jsx_runtime_1.jsx)("p", { className: "p-4 text-center font-mono text-xs text-zinc-600", children: state.finishedAt ? "no findings emitted" : "listening…" })), (0, jsx_runtime_1.jsx)("ul", { className: "flex flex-col gap-1.5", children: feed.map(({ f, key }) => ((0, jsx_runtime_1.jsxs)("li", { className: "animate-feed-in rounded-md border border-zinc-800/70 bg-zinc-900/60 p-2.5", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between gap-2", children: [(0, jsx_runtime_1.jsx)("span", { className: "font-mono text-[10px] uppercase tracking-wider text-zinc-500", children: f.stage }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-1.5", children: [(0, jsx_runtime_1.jsx)(badges_1.ConfidenceBadge, { tier: f.confidence }), (0, jsx_runtime_1.jsx)(badges_1.SeverityChip, { severity: f.severity })] })] }), (0, jsx_runtime_1.jsx)("p", { className: "mt-1.5 text-[13px] font-medium leading-snug text-zinc-200", children: f.title })] }, key))) })] }), (0, jsx_runtime_1.jsxs)(tabs_1.TabsContent, { value: "log", children: [state.logs.length === 0 && ((0, jsx_runtime_1.jsx)("p", { className: "p-4 text-center font-mono text-xs text-zinc-600", children: "no log lines yet" })), (0, jsx_runtime_1.jsx)("div", { className: "font-mono text-[11px] leading-relaxed text-zinc-500", children: state.logs
                                                        .slice()
                                                        .reverse()
                                                        .map((l, i) => ((0, jsx_runtime_1.jsxs)("p", { className: "animate-feed-in border-b border-zinc-900 py-0.5", children: [(0, jsx_runtime_1.jsxs)("span", { className: "text-zinc-700", children: ["[", l.stage ?? "core", "]"] }), " ", l.message] }, i))) })] })] }) })] })] })] }));
}
