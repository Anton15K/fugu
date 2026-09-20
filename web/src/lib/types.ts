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

/** Pipeline stages in execution order; `verdict` is terminal. */
export type StageName =
  | "concealment"
  | "static"
  | "semantic"
  | "detonation"
  | "harness"
  | "reputation"
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

/** Display order of the pipeline stages (fixed; matches the backend). */
// Cards mirror what the backend ACTUALLY runs (see build_stages()). A stage
// that isn't implemented must never appear as a green card — that would be
// fake coverage. Composition (cross-extension trifecta) is designed but not
// built; when it lands, add it back here.
export const STAGE_ORDER: StageName[] = [
  "concealment",
  "static",
  "semantic",
  "detonation",
  "harness",
  "reputation",
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
  verdict: {
    index: 7,
    label: "Verdict",
    blurb: "OWASP scorecard · tiered confidence",
  },
};

/** All severities, ordered ascending for counts UI. */
export const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
