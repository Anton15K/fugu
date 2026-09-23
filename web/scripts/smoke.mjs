/**
 * Node smoke test for the mock replay: bundles the app sources with rolldown
 * (vite's bundler, already in node_modules) and drives `openMockAuditStream`
 * at high speed, asserting the event-timeline shape. Run with `npm run smoke`.
 *
 * Usage: node scripts/smoke.mjs
 */
import { build } from "rolldown";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const here = (p) => new URL(p, import.meta.url).pathname;
const tmp = mkdtempSync(join(tmpdir(), "fugu-smoke-"));
const outfile = join(tmp, "smoke-bundle.mjs");

await build({
  input: here("../src/lib/mockStream.ts"),
  output: { file: outfile, format: "esm" },
  platform: "node",
});

const { openMockAuditStream } = await import(pathToFileURL(outfile).href);
const { STAGE_ORDER } = await import(pathToFileURL(here("../src/lib/types.ts")).href);

const events = [];
const handle = openMockAuditStream("smoke-job", "full", (e) => events.push(e), {
  speed: 25,
});

await new Promise((resolve) => {
  const watchdog = setInterval(() => {
    if (events.some((e) => e.type === "verdict")) {
      clearInterval(watchdog);
      resolve(undefined);
    }
  }, 50);
  setTimeout(() => {
    clearInterval(watchdog);
    resolve(undefined);
  }, 30_000);
});
handle.close();

// ── assertions ────────────────────────────────────────────────────
const counts = { stage_started: 0, finding: 0, stage_done: 0, verdict: 0, error: 0, log: 0 };
for (const e of events) counts[e.type] += 1;

const stagesSeen = new Set(
  events.filter((e) => e.type === "stage_started").map((e) => e.data.stage),
);
const missing = STAGE_ORDER.filter((s) => !stagesSeen.has(s) && s !== "composition"); // composition legitimately skipped on single-source mock

const findings = events.filter((e) => e.type === "finding");
const critical = findings.filter((e) => e.data.finding?.severity === "critical");
const tiers = new Set(findings.map((e) => e.data.finding?.confidence));
const verdict = events.find((e) => e.type === "verdict");
const verdictFindings = verdict?.data.findings ?? [];

const problems = [];
if (events.length < 20) problems.push(`too few events: ${events.length}`);
if (counts.verdict !== 1) problems.push(`expected exactly 1 verdict, got ${counts.verdict}`);
if (counts.error !== 0) problems.push("unexpected error events");
if (missing.length > 0) problems.push(`missing stage_started for: ${missing.join(", ")}`);
if (findings.length < 10) problems.push(`too few findings: ${findings.length}`);
if (critical.length < 1) problems.push("no critical findings in scenario");
for (const t of ["deterministic", "empirical", "measured", "advisory"]) {
  if (!tiers.has(t)) problems.push(`confidence tier not exercised: ${t}`);
}
if (verdictFindings.length !== findings.length) {
  problems.push(
    `verdict carries ${verdictFindings.length} findings but stream emitted ${findings.length}`,
  );
}
const sc = verdict?.data.severity_counts;
if (!sc || (sc.critical ?? 0) < 1) problems.push("verdict severity_counts missing critical");

console.log(`events=${events.length} findings=${findings.length} stages=${stagesSeen.size}/8`);
console.log(`tier coverage: ${[...tiers].sort().join(", ")}`);
console.log(`severity_counts: ${JSON.stringify(sc)}`);

if (problems.length > 0) {
  console.error("SMOKE FAILED:");
  for (const p of problems) console.error(` - ${p}`);
  process.exit(1);
}
console.log("SMOKE PASSED ✓");
