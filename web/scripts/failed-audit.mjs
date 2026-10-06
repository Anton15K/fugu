// Assert the real failure view, rather than source spelling or component mocks.
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'rolldown';

const tmp = mkdtempSync(join(tmpdir(), 'fugu-failed-view-'));
const entry = join(tmp, 'view.tsx'), output = join(tmp, 'view.mjs');
writeFileSync(entry, `
import React from ${JSON.stringify(resolve('node_modules/react/index.js'))};
import { renderToStaticMarkup } from ${JSON.stringify(resolve('node_modules/react-dom/server.node.js'))};
import { PipelineMonitor, applyEvent, initialPipelineState } from ${JSON.stringify(resolve('src/views/PipelineMonitor.tsx'))};
export function failureView() {
  const state = applyEvent(initialPipelineState(), {
    type: 'error', job_id: 'missing-source', ts: '2026-10-06T12:00:01Z',
    data: {stage: 'extraction', error: 'source extraction failed: missing fixture', stage_results: []}
  });
  return renderToStaticMarkup(<PipelineMonitor
    job={{id:'missing-source',source:'/fixtures/missing',depth:'full',status:'failed',created_at:'2026-10-06T12:00:00Z'}}
    state={state} streamStatus={{kind:'closed',transport:'sse'}} onNewAudit={()=>{}} />);
}
`);
await build({ input: entry, output: { file: output, format: 'esm' }, platform: 'node',
  resolve: { alias: { '@': resolve('src'), react: resolve('node_modules/react') } }, transform: { jsx: 'react-jsx' } });
const { failureView } = await import(pathToFileURL(output).href);
const markup = failureView();
assert.match(markup, /analysis interrupted/);
assert.match(markup, /source extraction failed: missing fixture/);
assert.match(markup, /new audit/);
assert.ok(!markup.includes('listening'), 'stopped audit still says listening');
assert.doesNotMatch(markup, /run finished/);
assert.doesNotMatch(markup, /Preparing the source/);
console.log('FAILED AUDIT VIEW PASSED: failure reason, stopped empty states, retry action, no success verdict');
