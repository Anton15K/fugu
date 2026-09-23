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
  // reducer: unknown stage name 'extraction' — must not throw, must mark current
  check("error event: no throw, state intact", typeof s.stages.concealment === "string");
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

console.log(`\nedge cases: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
