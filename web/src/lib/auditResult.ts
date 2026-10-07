import type { Finding, VerdictData } from './types';

export interface AuditResult {
  verdict: VerdictData;
  reasons: string[];
  coverage: string[];
  staticOnly: boolean;
  coverageKnown: boolean;
  modelEvidence: ModelEvidence;
}

/** An internal allowlist, never the original metrics or SDK payload. */
export interface ModelRecord {
  requestedModel: string | null;
  servedModel: string | null;
  maxOutputTokens: number | null;
  usage: { promptTokens: number | null; completionTokens: number | null };
}
export interface ModelStage {
  stage: 'semantic' | 'harness';
  status: 'completed' | 'failed' | 'skipped' | 'partial' | 'not reported';
  illustrative: boolean;
  calls: ModelRecord[] | null;
  attempts: ModelRecord[] | null;
  limits: Record<string, number | null>;
}
export interface ModelEvidence {
  stages: ModelStage[];
  composition: boolean;
}

const object = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
const number = (value: unknown): number | null =>
  typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
const modelId = (value: unknown): string | null =>
  typeof value === 'string' && value.trim() ? value : null;

function records(value: unknown): ModelRecord[] | null {
  // A malformed list cannot establish a reliable record count; [] is recorded zero.
  if (!Array.isArray(value) || value.some(item => !object(item))) return null;
  return value.map(item => {
    const row = object(item)!;
    const usage = object(row.usage);
    return {
      requestedModel: modelId(row.requested_model),
      servedModel: modelId(row.served_model),
      maxOutputTokens: number(row.max_tokens),
      usage: {
        promptTokens: number(usage?.prompt_tokens),
        completionTokens: number(usage?.completion_tokens),
      },
    };
  });
}

function modelEvidence(stages: Record<string, unknown>[]): ModelEvidence {
  const rows: ModelStage[] = [];
  for (const name of ['semantic', 'harness'] as const) {
    const supplied = stages.filter(stage => stage.stage === name);
    for (const stage of supplied.length ? supplied : [{}]) {
      const metrics = object(stage.metrics);
      const incomplete = metrics?.coverage_incomplete;
      const partial = incomplete === true || (typeof incomplete === 'string' && !!incomplete.trim());
      const status: ModelStage['status'] = metrics && 'skipped' in metrics ? 'skipped'
        : partial ? 'partial' : stage.ok === false ? 'failed'
        : stage.ok === true ? 'completed' : 'not reported';
      const limits = object(metrics?.effective_limits);
      const keys = ['llm_max_output_tokens', 'request_timeout_seconds', 'sdk_max_retries',
        ...(name === 'semantic' ? ['semantic_max_units', 'semantic_max_chars_per_unit']
          : ['harness_mount_char_budget', 'red_probe_count', 'red_probe_max_chars'])];
      rows.push({
        stage: name, status, illustrative: metrics?.simulated === true,
        calls: records(metrics?.llm_calls), attempts: records(metrics?.request_attempts),
        limits: Object.fromEntries(keys.map(key => [key, number(limits?.[key])])),
      });
    }
  }
  return { stages: rows, composition: stages.some(stage => stage.stage === 'composition') };
}

const strings = (value: unknown): string[] => Array.isArray(value)
  ? value.filter((item): item is string => typeof item === 'string') : [];

/** Keep server policy and coverage alongside the findings emitted by SSE. */
export function mapAuditResult(data: Record<string, unknown>, findings: Finding[]): AuditResult {
  const raw = data.verdict;
  const policy = object(raw) ?? {};
  const status = typeof raw === 'string' ? raw : policy.status;
  const validStatus = status === 'pass' || status === 'fail' || status === 'warn';
  const coverage = strings(policy.coverage_caveats);
  const stages = Array.isArray(data.stages)
    ? data.stages.map(object).filter((stage): stage is Record<string, unknown> => stage !== null) : [];
  for (const stage of stages) {
    if (!stage || typeof stage.stage !== 'string') continue;
    if (stage.ok === false) coverage.push(`${stage.stage}: failed${stage.error ? ` — ${stage.error}` : ''}`);
    else {
      const metrics = object(stage.metrics);
      if (metrics && 'skipped' in metrics) coverage.push(`${stage.stage}: skipped — ${String(metrics.skipped)}`);
    }
  }
  if (!validStatus) coverage.push('Verdict status unavailable; review the returned evidence.');
  return {
    verdict: {
      verdict: validStatus ? status : 'warn',
      severity_counts: (policy.severity_counts ?? data.severity_counts ?? {}) as VerdictData['severity_counts'],
      findings,
    },
    reasons: strings(policy.reasons),
    coverage: [...new Set(coverage)],
    staticOnly: policy.static_only === true,
    coverageKnown: Array.isArray(policy.coverage_caveats),
    modelEvidence: modelEvidence(stages),
  };
}
