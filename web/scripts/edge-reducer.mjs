// Edge-case streams for the live-reducer harness (synthetic but shaped
// exactly like backend jobs.py emits — see /tmp capture of a real stream).
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

const stubDir = mkdtempSync(join(tmpdir(), "fugu-red-"));
const ts = require("typescript");
const rel = (f) => readFileSync(join(process.cwd(), f), "utf8");
const trans = (src) => ts.transpileModule(src, {
  compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
}).outputText;

let monitorSrc = trans(rel("src/views/PipelineMonitor.tsx"));
const typesSrc = trans(rel("src/lib/types.ts"));
monitorSrc = monitorSrc
  .replace(/(?:var|const) jsx_runtime_1 = require\("react\/jsx-runtime"\);/m,
    "const jsx_runtime_1 = { jsx: () => null, jsxs: () => null, Fragment: () => null };")
  .replace(/require\("react"\)/g, "({ useEffect:()=>{}, useMemo:(f)=>f(), useState:(v)=>[typeof v==='function'?v():v,()=>{}] })")
  .replace(/require\("lucide-react"\)/g, "({ Activity:{}, Radio:{} })")
  .replace(/require\("@\/components\/badges"\)/g, "({ ConfidenceBadge:()=>null, SeverityChip:()=>null, StatusDot:()=>null })")
  .replace(/require\("@\/components\/ui\/card"\)/g, "({ Card:()=>null, CardContent:()=>null, CardHeader:()=>null, CardTitle:()=>null })")
  .replace(/require\("@\/components\/ui\/progress"\)/g, "({ Progress:()=>null })")
  .replace(/require\("@\/components\/ui\/tabs"\)/g, "({ Tabs:()=>null, TabsContent:()=>null, TabsList:()=>null, TabsTrigger:()=>null })")
  .replace(/require\("@\/lib\/utils"\)/g, "({ cn: (...a)=>a.filter(Boolean).join(' ') })");
monitorSrc = monitorSrc.replace(/(?:var|const) types_1 = require\("@\/lib\/types"\);/m, "var types_1 = __REAL_TYPES__;");
monitorSrc = monitorSrc.replace(/(?:var|const) \w+ = require\("@\/[\w\/-]+"\);/g, (m) => m.includes("types_1") ? m : m.replace(/require\([^)]*\)/, "{}"));

const combined = typesSrc
  + "\nconst __TYPES__ = exports;\nconst __REAL_TYPES__ = __TYPES__;\n"
  + monitorSrc
  + "\nmodule.exports = { applyEvent, initialPipelineState };";
const outFile = join(stubDir, "combined.cjs");
writeFileSync(outFile, combined);
const { applyEvent, initialPipelineState } = require(outFile);

const ev = (type, data = {}) => ({ type, job_id: "t", ts: new Date().toISOString(), data });
const F = (sev, conf, stage) => ({ severity: sev, confidence: conf, stage, owasp_ids: ["LLM01"], title: "t", detail: "d", evidence: [] });

let pass = 0, fail = 0;
const check = (name, cond) => { cond ? pass++ : fail++; console.log(`  ${cond ? "✓" : "✗"} ${name}`); };

// 1. benign PASS verdict — no findings at all
{
  let s = initialPipelineState();
  for (const st of ["concealment", "static", "semantic", "harness", "reputation", "detonation"]) {
    s = applyEvent(s, ev("stage_started", { stage: st }));
    s = applyEvent(s, ev("stage_done", { stage: st, ok: true, findings_count: 0 }));
  }
  s = applyEvent(s, ev("verdict", { status: "done", verdict: { status: "pass", severity_counts: { critical: 0 } } }));
  console.log("    stage states:", JSON.stringify(s.stages));
  check("benign: run stages done", ["concealment","static","semantic","harness","reputation","detonation","verdict"].every((k) => s.stages[k] === "done"));
  check("benign: composition skipped (single-source)", s.stages.composition === "skipped");
  check("benign: zero findings", s.findings.length === 0);
  check("benign: finishedAt set", s.finishedAt !== null);
}

// 2. stage failure mid-run (detonation ok:false) then verdict
{
  let s = initialPipelineState();
  s = applyEvent(s, ev("stage_started", { stage: "concealment" }));
  s = applyEvent(s, ev("stage_done", { stage: "concealment", ok: true }));
  s = applyEvent(s, ev("stage_started", { stage: "static" }));
  s = applyEvent(s, ev("stage_done", { stage: "static", ok: false, error: "Boom" }));
  s = applyEvent(s, ev("verdict", { status: "done", verdict: { status: "warn" } }));
  check("stage failure: static marked error", s.stages.static === "error");
  check("stage failure: verdict still completes", s.finishedAt !== null);
}

// 3. finding AFTER stage_done (out-of-order-ish; server emits per-stage)
{
  let s = initialPipelineState();
  s = applyEvent(s, ev("stage_started", { stage: "static" }));
  s = applyEvent(s, ev("stage_done", { stage: "static", ok: true, findings_count: 1 }));
  s = applyEvent(s, ev("finding", { stage: "static", finding: F("high", "deterministic", "static") }));
  check("late finding: still appended", s.findings.length === 1);
  check("late finding: stage stays done", s.stages.static === "done");
}

// 4. terminal error event (extraction failure) — UI must not hang in running
{
  let s = initialPipelineState();
  s = applyEvent(s, ev("stage_started", { stage: "concealment" }));
  s = applyEvent(s, ev("error", { error: "git clone failed", stage: "extraction" }));
  check("terminal error: interrupted stage is failed", s.stages.concealment === "error");
  check("terminal error: server failure reason retained", s.logs.at(-1)?.message === "git clone failed");
  check("terminal error: no success verdict manufactured", s.stages.verdict !== "done" && s.finishedAt === null);
}

// 5. unknown future stage name (e.g. new backend stage) — no crash
{
  let s = initialPipelineState();
  s = applyEvent(s, ev("stage_started", { stage: "composition" }));
  check("unknown stage: no crash", s !== undefined);
  // note: stage card for unknown name is simply not tracked (fixed set)
}

// 6. keepalive comment frames + duplicate events (SSE replay after reconnect)
{
  let s = initialPipelineState();
  s = applyEvent(s, ev("stage_started", { stage: "static" }));
  s = applyEvent(s, ev("stage_started", { stage: "static" })); // duplicate
  s = applyEvent(s, ev("stage_done", { stage: "static", ok: true }));
  check("duplicate stage_started: idempotent", s.stages.static === "done");
}

// Successful no-op stages are unavailable coverage, not completed checks.
{
  let s = initialPipelineState();
  s = applyEvent(s, ev("stage_started", { stage: "semantic" }));
  s = applyEvent(s, ev("stage_done", { stage: "semantic", ok: true, metrics: { skipped: "no API key" } }));
  check("skip metrics: semantic is skipped", s.stages.semantic === "skipped");
  s = applyEvent(s, ev("verdict", { verdict: { status: "pass" } }));
  check("skip metrics: terminal preserves skipped status", s.stages.semantic === "skipped");
}
// A verdict cannot prove a running stage finished without a completion event.
{
  let s = initialPipelineState();
  s = applyEvent(s, ev("stage_started", { stage: "detonation" }));
  s = applyEvent(s, ev("verdict", { verdict: { status: "warn" } }));
  check("interrupted stage: not marked completed", s.stages.detonation === "error");
}

// Reviewer R2: successful stages can still have explicitly partial coverage.
// Stored SSE history must preserve the same status, reason and valid findings.
for (const stage of ["semantic", "harness"]) {
  const reason = "1/2 semantic units completed; synthetic fake call failure";
  const finding = F("medium", "advisory", stage);
  const events = [
    ev("stage_started", { stage }),
    ev("finding", { finding }),
    ev("stage_done", { stage, ok: true, metrics: { coverage_incomplete: reason, units_completed: 1, units_total: 2 } }),
    ev("verdict", { verdict: { status: "warn", reasons: ["coverage incomplete"] } }),
  ];
  let s = events.slice(0, -1).reduce(applyEvent, initialPipelineState());
  check(`${stage} partial: not completed before verdict`, s.stages[stage] === "partial");
  s = applyEvent(s, events.at(-1));
  check(`${stage} partial: terminal preserves status and reason`, s.stages[stage] === "partial" && s.stageCoverageReasons?.[stage] === reason);
  check(`${stage} partial: valid findings retained`, s.findings.length === 1 && s.findings[0] === finding);
  const replay = JSON.parse(JSON.stringify(events)).reduce(applyEvent, initialPipelineState());
  check(`${stage} partial: stored replay retains partial coverage`, replay.stages[stage] === "partial" && replay.stageCoverageReasons?.[stage] === reason && replay.findings.length === 1);
}
// A failed stage remains failed, even when it also reports incomplete coverage.
{
  const s = applyEvent(initialPipelineState(), ev("stage_done", { stage: "semantic", ok: false, metrics: { coverage_incomplete: "no completed units" } }));
  check("partial metadata: failure takes precedence", s.stages.semantic === "error");
}

// Terminal reason is independent of the bounded forensic log, including replay/reset.
{
  const reason = '<img src=x onerror=alert(1)> ' + 'x'.repeat(2000);
  const finding = F("high", "deterministic", "static");
  let s = applyEvent(initialPipelineState(), ev("finding", { finding }));
  s = applyEvent(s, ev("error", { stage: "extraction", error: reason }));
  check("failure reason: arbitrary text retained unchanged", s.failureReason === reason);
  check("failure reason: original log agrees", s.logs.at(-1)?.message === reason);
  for (let i = 0; i < 60; i++) s = applyEvent(s, ev("log", { message: `later log ${i}` }));
  check("failure reason: survives bounded log rollover", s.failureReason === reason && s.logs.length <= 41 && !s.logs.some(l => l.message === reason));
  check("failure reason: findings retained, no terminal verdict", s.findings[0] === finding && s.finishedAt === null && s.stages.verdict !== "done");
  check("failure reason: reset clears terminal state", initialPipelineState().failureReason === null && initialPipelineState().findings.length === 0);
  const replay = [ev("error", {stage:"extraction",message:"message-only reason"})].reduce(applyEvent, initialPipelineState());
  check("failure reason: message-only replay retained", replay.failureReason === "message-only reason");
  const blank = applyEvent(initialPipelineState(), ev("error", {stage:"extraction",error:"   "}));
  check("failure reason: blank is unknown with explicit log fallback", blank.failureReason === null && blank.logs.at(-1)?.message === "The server did not supply a failure reason.");
}

console.log(`\nedge cases: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
