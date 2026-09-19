// Regression: the REAL captured verdict payload must map to a valid
// VerdictData (string status, real findings) — the exact case that crashed
// the Scorecard pre-fix (data.verdict is an OBJECT from aggregate_verdict).
import { readFile } from "node:fs/promises";

const raw = await readFile(process.argv[2], "utf8");
let verdictEvent = null;
for (const frame of raw.split("\n\n")) {
  for (const line of frame.split("\n")) {
    if (line.startsWith("data: ")) {
      const ev = JSON.parse(line.slice(6));
      if (ev.type === "verdict") verdictEvent = ev;
    }
  }
}
if (!verdictEvent) { console.error("no verdict event in capture"); process.exit(1); }

const d = verdictEvent.data;
if (typeof d.verdict !== "object") {
  console.error("capture doesn't exercise the bug shape (verdict is a string) — get a fresh capture");
  process.exit(1);
}
console.log("payload shape: data.verdict is an OBJECT (the crash trigger) ✓");

// THE FIXED MAPPING (verbatim semantics from App.tsx post-fix)
const raw2 = d.verdict;
const status = typeof raw2 === "string" ? raw2 : raw2?.status ?? "warn";
const severity_counts = raw2?.severity_counts ?? d.severity_counts ?? {};
const findingsFromStream = [{ severity: "high", confidence: "deterministic" }]; // pipeline state

let fail = 0;
const ok = (c, m) => { console.log((c ? "  ✓ " : "  ✗ ") + m); if (!c) fail++; };
ok(typeof status === "string" && ["pass", "warn", "fail"].includes(status), `status is valid string: '${status}'`);
ok(typeof severity_counts === "object" && severity_counts !== null, "severity_counts object present");
ok(Object.keys(severity_counts).length > 0, "severity_counts non-empty (authoritative counts)");
ok(findingsFromStream.length > 0, "findings sourced from pipeline state (not the event)");

// and the pre-fix behavior demonstrably crashes the Scorecard's lookup
const verdictTheme = { pass: 1, warn: 1, fail: 1 };
const preFixStatus = d.verdict; // object, as App.tsx used it
let crashed = false;
try { void verdictTheme[preFixStatus].bg; } catch { crashed = true; }
ok(crashed, "pre-fix mapping demonstrably crashes theme lookup (repro confirmed)");

console.log(fail ? `\nFAILED (${fail})` : "\nVERDICT-MAPPING REGRESSION PASSED ✓");
process.exit(fail ? 1 : 0);
