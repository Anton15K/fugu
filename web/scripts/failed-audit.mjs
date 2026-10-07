// Assert the real failure view, rather than source spelling or component mocks.
import assert from 'node:assert/strict';
import { test } from 'node:test';
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
export { applyEvent, initialPipelineState };
export function renderView(state, kind = "closed") {
  return renderToStaticMarkup(<PipelineMonitor
    job={{id:"missing-source",source:"/fixtures/missing",depth:"full",status:kind === "closed" ? "failed" : "running",created_at:"2026-10-06T12:00:00Z"}}
    state={state} streamStatus={{kind,transport:"sse"}} onNewAudit={()=>{}} />);
}
export function failureView() {
  const state = applyEvent(initialPipelineState(), {
    type: 'error', job_id: 'missing-source', ts: '2026-10-06T12:00:01Z',
    data: {stage: 'extraction', error: 'source extraction failed: missing fixture', stage_results: []}
  });
  return renderView(state);
}
`);
await build({ input: entry, output: { file: output, format: 'esm' }, platform: 'node',
  resolve: { alias: { '@': resolve('src'), react: resolve('node_modules/react') } }, transform: { jsx: 'react-jsx' } });
const { failureView, renderView, applyEvent, initialPipelineState } = await import(pathToFileURL(output).href);
const event = (type, data) => ({ type, data, job_id: 'missing-source', ts: '2026-10-06T12:00:01Z' });
const alert = markup => markup.match(/<div role="alert"[^>]*>([\s\S]*?)<\/div>/)?.[1] ?? '';
const failure = reason => applyEvent(initialPipelineState(), event('error', {stage:'extraction', error:reason}));
const fallback = 'The server did not supply a failure reason.';

test('existing failure view stops without claiming a verdict', () => {
  const markup = failureView();
  assert.match(markup, /analysis interrupted/);
  assert.match(markup, /source extraction failed: missing fixture/);
  assert.match(markup, /new audit/);
  assert.ok(!markup.includes('listening'), 'stopped audit still says listening');
  assert.doesNotMatch(markup, /run finished|Preparing the source/);
});
test('primary alert contains the actual reason and recovery button', () => {
  const markup = failureView();
  assert.match(alert(markup), /source extraction failed: missing fixture/);
  assert.match(alert(markup), /<button[^>]*>new audit<\/button>/);
  assert.equal((markup.match(/source extraction failed: missing fixture/g) ?? []).length, 2, 'alert and original log agree');
});
test('closed stream without error does not promote unrelated log to failure reason', () => {
  const state = applyEvent(initialPipelineState(), event('log', {message:'job started'}));
  const markup = renderView(state);
  assert.ok(alert(markup).includes(fallback));
  assert.ok(!alert(markup).includes('job started'));
  assert.doesNotMatch(markup, /run finished/);
});
test('missing and blank server reasons have an explicit unsupplied fallback', () => {
  for (const reason of [undefined, null, '', '   ']) {
    const markup = renderView(failure(reason));
    assert.ok(alert(markup).includes(fallback));
    assert.ok(markup.includes(fallback));
  }
});
test('long HTML-looking reason is retained as text in alert and log', () => {
  const reason = '<img src=x onerror=alert(1)> ' + 'x'.repeat(2000) + ' END';
  const markup = renderView(failure(reason));
  assert.ok(alert(markup).includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(alert(markup).includes('x'.repeat(2000) + ' END'));
  assert.doesNotMatch(markup, /<img/);
});
test('failure reason survives bounded log rollover and findings stay visible', () => {
  const finding = {stage:'static',title:'Retained finding',detail:'detail',severity:'high',confidence:'deterministic',owasp_ids:[],evidence:[]};
  let state = applyEvent(initialPipelineState(), event('finding', {finding}));
  state = applyEvent(state, event('error', {stage:'static',error:'failed with retained finding'}));
  for (let i=0; i<60; i++) state = applyEvent(state, event('log', {message:'later log '+i}));
  assert.ok(state.logs.length <= 41);
  const markup = renderView(state);
  assert.match(alert(markup), /failed with retained finding/);
  assert.match(markup, /Retained finding/);
});
test('new initial state clears failure and following run and verdict retain new findings', () => {
  const stopped = failure('old failure reason');
  assert.match(alert(renderView(stopped)), /old failure reason/);
  let state = initialPipelineState();
  state = applyEvent(state, event('stage_started', {stage:'static'}));
  state = applyEvent(state, event('finding', {finding:{stage:'static',title:'Next run finding',detail:'detail',severity:'medium',confidence:'advisory',owasp_ids:[],evidence:[]}}));
  let markup = renderView(state, 'open');
  assert.equal(alert(markup), '');
  assert.doesNotMatch(markup, /old failure reason|analysis interrupted/);
  assert.match(markup, /Next run finding/);
  state = applyEvent(state, event('stage_done', {stage:'static',ok:true}));
  state = applyEvent(state, event('verdict', {verdict:{status:'warn'}}));
  markup = renderView(state);
  assert.equal(alert(markup), '');
  assert.match(markup, /run finished/);
  assert.match(markup, /Next run finding/);
});
