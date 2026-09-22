/**
 * TS mirrors of the shared Fugu contracts (`src/fugu/types.py`).
 *
 * That Python module is READ-ONLY for this workstream; these interfaces are
 * hand-kept in sync. Contract-change requests go in the workstream summary.
 */

/** OWASP MCP Top 10 (v0.1 beta) ids + LLM 2025 subset + MCP04B rug-pull drift. */
export type OwaspId =
  | "MCP01" | "MCP02" | "MCP03" | "MCP04" | "MCP04B" | "MCP05" | "MCP06"
  | "MCP07" | "MCP08" | "MCP09" | "MCP10"
  | "LLM01" | "LLM02" | "LLM03" | "LLM06";

/** Finding severity, ordered info → critical. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/**
 * How much to trust a finding (IDEA.md "tiered guarantees"):
 * - deterministic — provable for a defined codepoint/rule set (S0, canary hits)
 * - measured      — recall measured on the labeled eval corpus
 * - empirical     — observed behavior in detonation / harness A/B
 * - advisory      — LLM-judged, probabilistic
 */
export type ConfidenceTier =
  | "deterministic"
  | "measured"
  | "empirical"
  | "advisory";

/** Pipeline stages in execution order; `verdict` is terminal.
 *
 * `composition` runs only on multi-source jobs (the parent's single stage);
 * single-source jobs never emit it, so the default card strip must not
 * include it — see STAGE_ORDER / MULTI_SOURCE_STAGE_ORDER below.
 */
export type StageName =
  | "concealment"
  | "static"
  | "semantic"
  | "detonation"
  | "harness"
  | "reputation"
  | "composition"
  | "verdict";

/** Audit-job lifecycle. `queued` → `running` → `done` | `failed`. */
export type JobStatus = "queued" | "running" | "done" | "failed";

/** How much of the pipeline to run: `standard` skips the expensive stages. */
export type AuditDepth = "standard" | "full";

/** A pointer to where a finding was observed, plus a short excerpt. */
export interface EvidenceSnippet {
  /** e.g. "mitm.flow[3].body", "dns.query[7]", "file:install.sh:L12" */
  source: string;
  /** <= 500 chars, human-readable */
  excerpt: string;
  /** Free-form extras (canary id, byte offsets, …) */
  meta?: Record<string, unknown>;
}

/** One security finding produced by a stage; maps to OWASP categories. */
export interface Finding {
  /** Subset of {@link OwaspId} */
  owasp_ids: string[];
  /** One line */
  title: string;
  /** 1–5 sentences */
  detail: string;
  severity: Severity;
  confidence: ConfidenceTier;
  /** StageName that produced it */
  stage: string;
  evidence: EvidenceSnippet[];
}

/** Result of one pipeline stage. */
export interface StageResult {
  stage: string;
  ok: boolean;
  findings: Finding[];
  /** durations, counts, model calls */
  metrics?: Record<string, unknown>;
  error?: string | null;
}

/** An audit job as created by POST /audits. */
export interface AuditJob {
  /** short uuid/hex */
  id: string;
  /** local path, git url, or MCP config path */
  source: string;
  /** ISO 8601 UTC */
  created_at: string;
  status: JobStatus;
  depth: AuditDepth;
}

/**
 * SSE envelope streamed over GET /audits/:id/events. `type` drives the UI;
 * `data` is JSON-safe and its shape depends on `type` (see {@link StageEventData}).
 */
export interface StageEvent {
  type: "stage_started" | "finding" | "stage_done" | "verdict" | "error" | "log";
  job_id: string;
  data: Record<string, unknown>;
  /** ISO 8601 UTC */
  ts: string;
}

/** Union of the `data` payloads carried by {@link StageEvent}. */
export type StageEventData =
  | StageStartedData
  | FindingData
  | StageDoneData
  | VerdictData
  | ErrorData
  | LogData;

export interface StageStartedData {
  stage: StageName;
  depth: AuditDepth;
}

export interface FindingData {
  finding: Finding;
  /** Running count of findings so far (informational). */
  count?: number;
}

export interface StageDoneData {
  stage: StageName;
  ok: boolean;
  findings: number;
  metrics?: Record<string, unknown>;
  error?: string | null;
}

/** Terminal verdict; emitted once, closes the stream. */
export interface VerdictData {
  verdict: "pass" | "warn" | "fail";
  severity_counts: Partial<Record<Severity, number>>;
  findings: Finding[];
  scorecard?: VerdictScorecard;
}

/** Aggregated per-OWASP-category rollup (UI-shaped convenience). */
export interface VerdictScorecard {
  verdict: "pass" | "warn" | "fail";
  severity_counts: Partial<Record<Severity, number>>;
  categories: OwaspCategoryRow[];
}

/** One row of the OWASP matrix: category × severities present. */
export interface OwaspCategoryRow {
  owasp_id: string;
  label: string;
  findings: Finding[];
}

export interface ErrorData {
  stage?: StageName;
  message: string;
  fatal?: boolean;
}

export interface LogData {
  stage?: StageName;
  message: string;
  level?: "debug" | "info" | "warn" | "error";
}

/** LogData for multi-source (composition) parent jobs: the parent emits one
 * log per finished member child audit (§6): stage "composition", message
 * `member <label>: job <child_id> <status>, <N> findings`, plus a
 * `child_job_id` discriminator. History replay delivers the same events.
 */
export interface MemberLogData extends LogData {
  child_job_id?: string;
}

/** Human-readable names for OWASP ids (drives the scorecard matrix labels). */
export const OWASP_LABELS: Record<string, string> = {
  MCP01: "Token mismanagement / secrets",
  MCP02: "Privilege escalation / scope creep",
  MCP03: "Tool poisoning",
  MCP04: "Supply chain / rug pull",
  MCP04B: "Rug pull drift",
  MCP05: "Command injection",
  MCP06: "Intent flow subversion",
  MCP07: "AuthN/AuthZ gaps",
  MCP08: "Audit/telemetry gaps",
  MCP09: "Shadow servers",
  MCP10: "Context over-sharing",
  LLM01: "Prompt injection",
  LLM02: "Sensitive info disclosure",
  LLM03: "Supply chain",
  LLM06: "Excessive agency",
};

/** Display order of the pipeline stage cards (fixed; matches the backend).
 *
 * Cards mirror what the backend ACTUALLY runs (see build_stages()). A stage
 * that isn't implemented must never appear as a green card — that would be
 * fake coverage. `composition` is the exception: it runs ONLY on multi-source
 * jobs (contracts §6), so it lives in {@link MULTI_SOURCE_STAGE_ORDER} and is
 * spliced into the strip only when the job actually emitted composition
 * events (see {@link compositionPresent}). Single-source jobs render the
 * exact same 7 cards as before.
 */
export const STAGE_ORDER: StageName[] = [
  "concealment",
  "static",
  "semantic",
  "detonation",
  "harness",
  "reputation",
  "verdict",
];

/** Stage-card order for multi-source (composition) parent jobs. The parent
 * fans children out first (per-member child audits run the standard 6
 * stages server-side), then runs `composition` as its single own stage. */
export const MULTI_SOURCE_STAGE_ORDER: StageName[] = [
  "composition",
  "verdict",
];

/** Presentation metadata for each stage card. */
export const STAGE_META: Record<StageName, { index: number; label: string; blurb: string }> = {
  concealment: {
    index: 0,
    label: "Concealment",
    blurb: "Unicode smuggling · zero-width · bidi · homoglyphs",
  },
  static: {
    index: 1,
    label: "Static",
    blurb: "Secrets · dangerous patterns · dependency risk",
  },
  semantic: {
    index: 2,
    label: "Semantic",
    blurb: "LLM-as-judge over SKILL.md · OWASP checklist",
  },
  detonation: {
    index: 3,
    label: "Detonation",
    blurb: "Sandbox run · canary creds · egress capture",
  },
  harness: {
    index: 4,
    label: "Harness A/B",
    blurb: "Probe battery · absent vs mounted",
  },
  reputation: {
    index: 5,
    label: "Reputation",
    blurb: "Author history · CVEs · typosquats",
  },
  composition: {
    index: 6,
    label: "Composition",
    blurb: "Cross-extension trifecta · tool shadowing",
  },
  verdict: {
    index: 7,
    label: "Verdict",
    blurb: "OWASP scorecard · tiered confidence",
  },
};

/** All severities, ordered ascending for counts UI. */
export const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

/* ── Composition (multi-source jobs, contracts §6) ─────────────────── */

const JOB_STATUSES: ReadonlySet<string> = new Set([
  "queued",
  "running",
  "done",
  "failed",
]);

/**
 * Parse a parent `log` event payload into a member row, or null when the
 * payload is not a member log. Wire shape (composition_jobs.py):
 *   { stage: "composition", message: "member <label>: job <id> <status>, <N> findings",
 *     child_job_id: "<id>" }
 * Also tolerates the runner-error followup
 *   { stage: "composition", message: "member <label>: runner error (…)" }.
 *
 * Pure so both the live path and SSE history replay (events arrive in a
 * burst at connect) fold identically through applyEvent.
 */
export function parseMemberLog(data: Record<string, unknown>): MemberInfo | null {
  if (typeof data.child_job_id !== "string" || !data.child_job_id) return null;
  const message = typeof data.message === "string" ? data.message : "";
  // member <label>: job <child_id> <status>, <N> findings
  const m = /^member (.*?): job \S+ (\w+), (\d+) findings$/.exec(message);
  if (m) {
    const status = m[2] ?? "";
    return {
      label: m[1] ?? message,
      status: JOB_STATUSES.has(status) ? (status as JobStatus) : "running",
      findings: Number(m[3] ?? 0),
      childJobId: data.child_job_id,
    };
  }
  // member <label>: runner error (…) — a failed member without a parseable count
  const e = /^member (.*?): /.exec(message);
  if (e) {
    return {
      label: e[1] ?? message,
      status: "failed",
      findings: 0,
      childJobId: data.child_job_id,
    };
  }
  return null;
}

/** One member (child audit) of a multi-source job, as shown in the strip. */
export interface MemberInfo {
  label: string;
  status: JobStatus;
  findings: number;
  /** Empty while the member is still queued/running (no child log yet). */
  childJobId: string;
}

/** Split a trifecta finding's evidence sources into per-leg rows.
 * source format (composition.py): `member:<slug>:<finding-title>` with
 * meta { leg, member (label), strength, tier }. */
export const TRIFECTA_LEGS = ["INGRESS", "PRIVATE-DATA", "EGRESS"] as const;
export type TrifectaLeg = (typeof TRIFECTA_LEGS)[number];

/** Parse `member:<slug>:<title>` evidence sources (trifecta legs). */
export function parseMemberEvidence(
  source: string,
): { slug: string; title: string } | null {
  const m = /^member:([^:]+):([\s\S]+)$/.exec(source);
  return m ? { slug: m[1] ?? source, title: m[2] ?? "" } : null;
}

/** Parse `tools:<name>` evidence sources (shadowing collisions). */
export function parseToolEvidence(
  source: string,
): { name: string } | null {
  const m = /^tools:(.+)$/.exec(source);
  return m ? { name: m[1] ?? source } : null;
}
