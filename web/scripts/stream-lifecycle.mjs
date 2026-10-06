// Exercise the production client at its transport boundary, without providers.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'rolldown';

const outfile = join(mkdtempSync(join(tmpdir(), 'fugu-stream-')), 'api.mjs');
await build({ input: new URL('../src/lib/api.ts', import.meta.url).pathname,
  output: { file: outfile, format: 'esm' }, platform: 'node' });
const { openAuditStream, setApiBase } = await import(pathToFileURL(outfile).href);
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const event = type => ({ type, job_id: 'failed-run', ts: '2026-10-06T12:00:00Z',
  data: type === 'error' ? { stage: 'extraction', error: 'source does not exist', stage_results: [] }
    : { verdict: { status: 'warn' } } });

// Node has no native browser EventSource; only the transport is doubled.
class Source {
  static CLOSED = 2;
  static instances = [];
  readyState = 0;
  constructor(url) { this.url = url; Source.instances.push(this); }
  close() { this.readyState = Source.CLOSED; }
  send(e) { this.onmessage?.({ data: JSON.stringify(e) }); }
}
function sse(t) {
  const original = globalThis.EventSource;
  Source.instances = [];
  globalThis.EventSource = Source;
  t.after(() => { globalThis.EventSource = original; });
}

for (const type of ['error', 'verdict']) {
  test(`SSE ${type} closes the transport after delivering the terminal event`, async t => {
    sse(t);
    const received = [], statuses = [];
    const h = openAuditStream('failed-run', { onEvent: e => received.push(e),
      onStatus: s => statuses.push(s.kind) });
    t.after(() => h.close());
    const source = Source.instances[0];
    source.onopen();
    source.send(event(type));
    await wait(350);
    assert.equal(source.readyState, Source.CLOSED);
    assert.deepEqual(received.map(e => e.type), [type]);
    assert.equal(statuses.at(-1), 'closed');
    const count = statuses.length;
    source.send(event('finding'));
    source.onopen();
    assert.equal(received.length, 1, 'terminal stream must ignore late events');
    assert.equal(statuses.length, count, 'terminal stream must ignore late connection callbacks');
  });
}

test('closing a stream cancels its pending reconnect', async t => {
  sse(t);
  const received = [], statuses = [];
  const h = openAuditStream('old-run', { onEvent: e => received.push(e), onStatus: s => statuses.push(s.kind) });
  t.after(() => h.close());
  const old = Source.instances[0];
  old.readyState = Source.CLOSED;
  old.onerror();
  h.close();
  const count = statuses.length;
  old.send(event('finding'));
  old.onopen();
  await wait(850);
  assert.equal(Source.instances.length, 1, 'closed audit reopened a transport');
  assert.equal(received.length, 0, 'closed audit delivered stale evidence');
  assert.equal(statuses.length, count, 'closed audit changed connection status');
});

test('an already aborted stream never connects', t => {
  sse(t);
  const controller = new AbortController();
  controller.abort();
  const h = openAuditStream('old-run', { signal: controller.signal, onEvent: () => assert.fail('event after abort') });
  h.close();
  assert.equal(Source.instances.length, 0);
});

test('polling stops after a terminal error, without replaying or requesting again', async t => {
  const original = globalThis.EventSource;
  globalThis.EventSource = undefined;
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.end(`data: ${JSON.stringify(event('error'))}\n\n`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { globalThis.EventSource = original; server.close(); });
  setApiBase(`http://127.0.0.1:${server.address().port}/api`);
  const received = [], statuses = [];
  const h = openAuditStream('failed-run', { onEvent: e => received.push(e), onStatus: s => statuses.push(s.kind) });
  t.after(() => h.close());
  await wait(1700);
  assert.equal(requests, 1, 'failed audit was polled again');
  assert.deepEqual(received.map(e => e.type), ['error']);
  assert.equal(statuses.at(-1), 'closed');
});

test('closing during a polling body read suppresses its late event and status', async t => {
  const originalSource = globalThis.EventSource, originalFetch = globalThis.fetch;
  globalThis.EventSource = undefined;
  let release;
  globalThis.fetch = async () => ({ ok: true, text: () => new Promise(resolve => { release = resolve; }) });
  t.after(() => { globalThis.EventSource = originalSource; globalThis.fetch = originalFetch; });
  const received = [], statuses = [];
  const h = openAuditStream('old-run', { onEvent: e => received.push(e), onStatus: s => statuses.push(s.kind) });
  t.after(() => h.close());
  await wait(0);
  h.close();
  const count = statuses.length;
  release(JSON.stringify([event('verdict')]));
  await wait(0);
  assert.equal(received.length, 0, 'old audit delivered a result after New audit');
  assert.equal(statuses.length, count, 'old audit changed the new audit connection status');
});
