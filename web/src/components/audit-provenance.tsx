import type { ModelEvidence, ModelRecord } from '@/lib/auditResult';

const limitLabels: Record<string, string> = {
  llm_max_output_tokens: 'Output token cap',
  request_timeout_seconds: 'Request timeout (seconds)',
  sdk_max_retries: 'SDK retry cap',
  semantic_max_units: 'Semantic unit cap',
  semantic_max_chars_per_unit: 'Characters per semantic unit',
  harness_mount_char_budget: 'Harness mount character budget',
  red_probe_count: 'Red probe cap',
  red_probe_max_chars: 'Characters per red probe',
};

function Field({ label, value }: { label: string; value: string | number | null }) {
  return (
    <div className="min-w-0">
      <dt className="text-zinc-400">{label}</dt>
      <dd className="min-w-0 whitespace-pre-wrap [overflow-wrap:anywhere] text-zinc-200">{value ?? 'not reported'}</dd>
    </div>
  );
}

function Records({ label, rows }: { label: string; rows: ModelRecord[] | null }) {
  return (
    <details className="min-w-0 rounded border border-zinc-800">
      <summary className="cursor-pointer rounded px-3 py-2 text-zinc-300 focus-visible:outline-2 focus-visible:outline-sky-400">
        {label}: {rows?.length ?? 'not reported'}
      </summary>
      <div className="flex min-w-0 flex-col gap-3 px-3 pb-3">
        {rows === null ? <p className="text-zinc-400">Records not reported.</p>
          : rows.length === 0 ? <p className="text-zinc-400">The supplied list contains no records.</p>
            : rows.map((record, index) => (
              <dl key={index} aria-label={`${label} record ${index + 1}`} className="grid min-w-0 grid-cols-1 gap-2 border-t border-zinc-800 pt-3 sm:grid-cols-2">
                <Field label="Requested model" value={record.requestedModel} />
                <Field label="Served model" value={record.servedModel} />
                <Field label="Prompt tokens" value={record.usage.promptTokens} />
                <Field label="Completion tokens" value={record.usage.completionTokens} />
                <Field label="Recorded output token cap" value={record.maxOutputTokens} />
              </dl>
            ))}
      </div>
    </details>
  );
}

/** Disclosure of supplied records, not a reconstructed billing or execution log. */
export function AuditProvenance({ evidence, simulated = false }: { evidence: ModelEvidence; simulated?: boolean }) {
  return (
    <details aria-label="Recorded model requests" className="min-w-0 rounded-lg border border-zinc-800 bg-zinc-900/40 font-mono text-xs">
      <summary className="cursor-pointer rounded-lg px-4 py-3 font-semibold text-zinc-200 focus-visible:outline-2 focus-visible:outline-sky-400">
        Recorded model requests
        <span className="ml-2 font-normal text-zinc-400">· inspect supplied telemetry</span>
      </summary>
      <section className="flex min-w-0 flex-col gap-3 border-t border-zinc-800 p-4">
        <p className="text-zinc-400">Scope: records supplied by this audit; not a total across fan-out members. Missing fields are not reported. Record counts do not establish total retries or complete execution.</p>
        {(simulated || evidence.stages.some(stage => stage.illustrative)) && (
          <p className="text-amber-300">Illustrative simulation; these records do not demonstrate real inference.</p>
        )}
        {evidence.composition && (
          <p className="text-amber-300">Composition report: member model records and totals may be missing.</p>
        )}
        {evidence.stages.map((stage, index) => (
          <section key={`${stage.stage}-${index}`} aria-label={`${stage.stage} model records`} className="flex min-w-0 flex-col gap-2 rounded-lg border border-zinc-800 p-3">
            <h3 className="text-zinc-200">{stage.stage} <span className="text-zinc-400">· {stage.status}</span></h3>
            <Records label="Logical calls" rows={stage.calls} />
            <Records label="Request attempts" rows={stage.attempts} />
            <h4 className="mt-1 text-zinc-400">Selected recorded effective limits</h4>
            <dl className="grid min-w-0 grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {Object.entries(stage.limits).map(([key, value]) => <Field key={key} label={limitLabels[key] ?? key} value={value} />)}
            </dl>
          </section>
        ))}
      </section>
    </details>
  );
}
