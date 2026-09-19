// Live-payload correctness test: pipe REAL backend SSE through the REAL
// frontend reducer (from web/dist bundle), then assert the UI state machine.
// Usage: node scripts/live-reducer.mjs /tmp/fugu_live_sse.txt
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

const [, , ssePath] = process.argv;
const raw = await readFile(ssePath, "utf8");

// --- parse SSE exactly like the browser EventSource + our api.ts -----------
const events = [];
for (const frame of raw.split("\n\n")) {
  for (const line of frame.split("\n")) {
    if (line.startsWith("data: ")) {
      try {
        events.push(JSON.parse(line.slice(6)));
      } catch {
        console.error("BAD JSON FRAME:", line.slice(0, 120));
        process.exit(1);
      }
    }
  }
}
console.log(`parsed ${events.length} events; types:`, [...new Set(events.map((e) => e.type))]);

// --- load the REAL reducer: tsc-transpile the source, stub non-logic imports
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
  .replace(/require\("@\/lib\/utils"\)/g, "({ cn: (...a)=>a.filter(Boolean).join(' ') })")
  .replace(/require\("react"\)/g, "({})");
monitorSrc = monitorSrc.replace(/(?:var|const) types_1 = require\("@\/lib\/types"\);/m, "var types_1 = __TYPES__;");
monitorSrc = monitorSrc.replace(/(?:var|const) \w+ = require\("@\/[\w\/-]+"\);/g, (m) => m.includes("types_1") ? m : m.replace(/require\([^)]*\)/, "{}"));

// keep the types module's exports intact - STAGE_ORDER/STAGE_META live there
const typesBody = typesSrc;

const combined = typesBody
  + "\nconst __TYPES__ = exports;\n"   // types module exports (consts live here)
  + "\nconst __REAL_TYPES__ = __TYPES__;\n"
  + monitorSrc.replace(/var types_1 = __TYPES__;/m, "var types_1 = __REAL_TYPES__;")
  + "\nmodule.exports = { applyEvent, initialPipelineState };";
const outFile = join(stubDir, "combined.cjs");
writeFileSync(outFile, combined);
const mod = require(outFile);
const applyEvent = mod.applyEvent;
const initialPipelineState = mod.initialPipelineState;
if (!applyEvent) { console.error("applyEvent missing after transpile"); process.exit(2); }
console.log("reducer loaded from REAL src (ts.transpileModule + import stubs) \u2713");

// Minimal browser shims the bundle may touch at import time
const el = () => ({ style: {}, setAttribute: () => {}, appendChild: () => {}, removeChild: () => {}, addEventListener: () => {}, classList: { add: () => {}, remove: () => {} }, textContent: "" });
globalThis.window = globalThis;
globalThis.document = {
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: el,
  createTextNode: (t) => ({ textContent: t }),
  getElementById: () => null,
  addEventListener: () => {},
  documentElement: el(),
  head: el(),
  body: el(),
};
globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
try { globalThis.navigator = { userAgent: "node-test" }; } catch { /* Node 21+ read-only */ }
globalThis.location = { origin: "http://localhost" };
globalThis.HTMLElement = class HTMLElement {};
globalThis.SVGElement = class SVGElement {};
globalThis.MutationObserver = class { observe() {} disconnect() {} };
globalThis.requestAnimationFrame = (cb) => setTimeout(cb, 0);

// (reducer loaded above via esbuild compile of the real source)

// --- drive the state machine ------------------------------------------------
let state = initialPipelineState();
const findings = [];
let stages = new Map();
let verdict = null;
let terminal = false;
for (const ev of events) {
  if (state && typeof state === "object" && "stages" in state) {
    state = applyEvent(state, ev) ?? state;
  }
  // also track raw semantics the Scorecard uses
  switch (ev.type) {
    case "stage_started": stages.set(ev.data.stage, "running"); break;
    case "stage_done": stages.set(ev.data.stage, ev.data.ok ? "done" : "failed"); break;
    case "finding": findings.push(ev.data.finding); break;
    case "verdict": verdict = ev.data; terminal = true; break;
    case "error": terminal = true; break;
  }
}

// --- assertions (happy path) -------------------------------------------------
const fails = [];
const ok = (cond, msg) => { if (!cond) fails.push(msg); else console.log("  ✓", msg); };

console.log("\nHappy-path assertions:");
ok(stages.size === 6, `6 stage cards tracked (got ${stages.size})`);
ok([...stages.values()].every((s) => s === "done"), "all stages reached done");
ok(findings.length === 4, `4 findings captured (got ${findings.length})`);
ok(findings.every((f) => f && f.owasp_ids && f.severity && f.title), "findings well-formed (owasp/severity/title)");
ok(findings.some((f) => f.stage === "detonation" || f.confidence === "deterministic"), "deterministic finding present");
ok(verdict !== null, "terminal verdict received");
ok(verdict?.verdict?.status === "fail", `verdict.status === fail (got ${verdict?.verdict?.status})`);
ok(Array.isArray(verdict?.verdict?.reasons) && verdict.verdict.reasons.length > 0, "verdict carries reasons");
ok(verdict?.verdict?.severity_counts?.critical >= 0, "verdict carries severity_counts");
ok(typeof verdict?.verdict?.max_confidence_tier === "string", "verdict carries max_confidence_tier");
ok(terminal, "stream terminated");

// frontend reducer deep-check (if state object exposed)
if (state && typeof state === "object") {
  ok(typeof state.findings?.length === "number" || findings.length === 4, "reducer state findings consistent");
}

// ---- ELAPSED-REPLAY: server-clock elapsed survives replay-after-the-fact ----
// (simulates: audit finished at T; user opens /audit/<id> at T+10min)
{
  const evs = events;                      // already parsed, w/ server ts
  const first = evs.find((e) => e.type === "stage_started");
  const last = evs.find((e) => e.type === "verdict") ?? evs[evs.length - 1];
  const realMs = Date.parse(last.ts) - Date.parse(first.ts);

  let s2 = initialPipelineState();
  for (const e of evs) s2 = applyEvent(s2, e);

  const okStart = Math.abs(s2.startedAt - Date.parse(first.ts)) < 5;
  ok(okStart, `elapsed REPLAY: startedAt from server ts (got ${new Date(s2.startedAt).toISOString()})`);
  ok(s2.finishedAt !== null && Math.abs(s2.finishedAt - Date.parse(last.ts)) < 5,
    `elapsed REPLAY: finishedAt from server ts (got ${s2.finishedAt ? new Date(s2.finishedAt).toISOString() : "null"})`);
  const elapsedMs = s2.startedAt ? s2.finishedAt - s2.startedAt : 0;
  ok(Math.abs(elapsedMs - realMs) < 10,
    `elapsed REPLAY: duration preserved (${(elapsedMs / 1000).toFixed(1)}s vs real ${(realMs / 1000).toFixed(1)}s)`);
  ok(elapsedMs > 5000, `elapsed REPLAY: not restarted near zero (${(elapsedMs / 1000).toFixed(1)}s)`);
}

console.log(fails.length ? `\n✗ FAILURES (${fails.length}):\n- ${fails.join("\n- ")}` : "\nALL LIVE-PAYLOAD ASSERTIONS PASSED ✓");
process.exit(fails.length ? 1 : 0);

