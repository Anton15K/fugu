import type { Finding, StageResult, VerdictData } from './types';

export interface AuditResult {
  verdict: VerdictData;
  reasons: string[];
  coverage: string[];
  staticOnly: boolean;
  coverageKnown: boolean;
}

const strings = (value: unknown): string[] => Array.isArray(value)
  ? value.filter((item): item is string => typeof item === 'string') : [];

/** Keep server policy and coverage alongside the findings emitted by SSE. */
export function mapAuditResult(data: Record<string, unknown>, findings: Finding[]): AuditResult {
  const raw = data.verdict;
  const policy = typeof raw === 'object' && raw !== null ? raw as Record<string, unknown> : {};
  const status = typeof raw === 'string' ? raw : policy.status;
  const validStatus = status === 'pass' || status === 'fail' || status === 'warn';
  const coverage = strings(policy.coverage_caveats);
  const stages = Array.isArray(data.stages) ? data.stages as StageResult[] : [];
  for (const stage of stages) {
    if (!stage || typeof stage.stage !== 'string') continue;
    if (stage.ok === false) coverage.push(`${stage.stage}: failed${stage.error ? ` — ${stage.error}` : ''}`);
    else if (stage.metrics && 'skipped' in stage.metrics) coverage.push(`${stage.stage}: skipped — ${String(stage.metrics.skipped)}`);
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
  };
}
