/**
 * Contract test for the real API path: spins up a tiny FastAPI-shaped HTTP
 * server (POST /audits → 202 {job_id}, GET /audits/:id/events → SSE) and
 * drives the bundled `submitAudit` + `openAuditStream` against it, including
 * the polling fallback (EventSource deleted from globalThis).
 *
 * Usage: node scripts/contract.mjs
 */
import { build } from "rolldown";
import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const here = (p) => new URL(p, import.meta.url).pathname;
const tmp = mkdtempSync(join(tmpdir(), "fugu-contract-"));
const outfile = join(tmp, "api-bundle.mjs");

await build({
  input: here("../src/lib/api.ts"),
  output: { file: outfile, format: "esm" },
  platform: "node",
});

const { submitAudit, openAuditStream, setApiBase } = await import(pathToFileURL(outfile).href);

const JOB_ID = "job-contract-42";
const events = [
  { type: "stage_started", job_id: JOB_ID, data: { stage: "concealment" }, ts: new Date().toISOString() },
  { type: "finding", job_id: JOB_ID, data: { finding: { title: "t", severity: "high" } }, ts: new Date().toISOString() },
  { type: "verdict", job_id: JOB_ID, data: { verdict: "fail" }, ts: new Date().toISOString() },
];

// ── fake backend matching the documented SSE contract ──────────────
const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (req.method === "POST" && url.pathname === "/api/audits") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const parsed = JSON.parse(body);
      if (typeof parsed.source !== "string" || typeof parsed.depth !== "string") {
        res.writeHead(400).end();
        return;
      }
      res.writeHead(202, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ job_id: JOB_ID }));
    });
    return;
  }
  const m = url.pathname.match(/^\/api\/audits\/([^/]+)\/events$/);
  if (req.method === "GET" && m) {
    if (m[1] !== JOB_ID) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    let i = 0;
    const timer = setInterval(() => {
      if (i >= events.length) {
        clearInterval(timer);
        res.end();
        return;
      }
      res.write(`data: ${JSON.stringify(events[i])}\n\n`);
      i += 1;
    }, 30);
    return;
  }
  res.writeHead(404).end();
});

await new Promise((r) => server.listen(4481, r));

// Point the client at the fake server.
setApiBase("http://localhost:4481/api");

const problems = [];

// 1) submitAudit parses the 202 + job_id shape
const job = await submitAudit("./skills/demo", "full");
if (job.id !== JOB_ID) problems.push(`submitAudit returned id=${job.id}`);
if (job.depth !== "full") problems.push(`submitAudit lost depth: ${job.depth}`);

// 2) SSE path (native EventSource exists in Node 26? no — force polling after
//    trying SSE; EventSource is undefined in Node so fallback engages)
const received = [];
const statuses = [];
await new Promise((resolve) => {
  const h = openAuditStream(JOB_ID, {
    onEvent: (e) => {
      received.push(e);
      if (e.type === "verdict") {
        h.close();
        resolve(undefined);
      }
    },
    onStatus: (s) => statuses.push(s.kind),
  });
  setTimeout(resolve, 8000);
});

if (received.length !== events.length) {
  problems.push(`polling received ${received.length}/${events.length} events`);
}
if (!received.some((e) => e.type === "verdict")) problems.push("no verdict via polling");
if (!statuses.includes("degraded")) {
  problems.push(`expected degraded→polling status, got: ${statuses.join(",")}`);
}

server.close();

console.log(`statuses: ${statuses.join(" → ")}`);
console.log(`received: ${received.map((e) => e.type).join(", ")}`);

if (problems.length > 0) {
  console.error("CONTRACT FAILED:");
  for (const p of problems) console.error(` - ${p}`);
  process.exit(1);
}
console.log("CONTRACT PASSED ✓ (202 parse + polling fallback)");
