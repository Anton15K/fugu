// Render the production Scorecard and mapper, with no component substitutes.
import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'rolldown';
const tmp=mkdtempSync(join(tmpdir(),'fugu-provenance-view-'));
after(()=>rmSync(tmp,{recursive:true,force:true}));
const entry=join(tmp,'view.tsx'),output=join(tmp,'view.mjs');
writeFileSync(entry,`
import React from ${JSON.stringify(resolve('node_modules/react/index.js'))};
import { renderToStaticMarkup } from ${JSON.stringify(resolve('node_modules/react-dom/server.node.js'))};
import { Scorecard } from ${JSON.stringify(resolve('src/views/Scorecard.tsx'))};
import { mapAuditResult } from ${JSON.stringify(resolve('src/lib/auditResult.ts'))};
export function render(data,findings=[],simulated=false){return renderToStaticMarkup(<Scorecard result={mapAuditResult(data,findings)} elapsedMs={0} simulated={simulated}/>)}
`);
await build({input:entry,output:{file:output,format:'esm'},platform:'node',resolve:{alias:{'@':resolve('src'),react:resolve('node_modules/react')}},transform:{jsx:'react-jsx'}});
const {render}=await import(pathToFileURL(output).href);
const section=markup=>{const match=markup.match(/<details[^>]*aria-label="Recorded model requests"[\s\S]*?<\/section><\/details>/);assert.ok(match,'recorded-model disclosure missing');return match[0]};
const row=(metrics,extra={})=>({stage:'semantic',ok:true,metrics,...extra});
const run=(stages,simulated=false)=>render({verdict:{status:'warn',coverage_caveats:[]},stages},[],simulated);
test('native expandable model disclosure follows verdict and findings before category matrix',()=>{
 const markup=run([]),body=section(markup);
 assert.match(body,/<summary[^>]*>Recorded model requests/);assert.doesNotMatch(body.split('<summary')[0],/\bopen/);
 assert.ok(markup.indexOf('audit verdict: warn')<markup.indexOf('findings and evidence'));
 assert.ok(markup.indexOf('findings and evidence')<markup.indexOf('aria-label="Recorded model requests"'));
 assert.ok(markup.indexOf('aria-label="Recorded model requests"')<markup.indexOf('OWASP category matrix'));
 assert.match(body,/records supplied by this audit/);assert.match(body,/not a total across fan-out members/);
});
test('actual production records display distinct IDs, counts, usage and selected bounds',()=>{
 const body=section(run([row({llm_calls:[{requested_model:'fixture/request-A',served_model:'fixture/served-B',usage:{prompt_tokens:7,completion_tokens:0},max_tokens:80}],request_attempts:[{requested_model:'fixture/request-A',served_model:null},{requested_model:'fixture/request-A',served_model:'fixture/served-B'}],effective_limits:{llm_max_output_tokens:80,request_timeout_seconds:2.5,sdk_max_retries:0,semantic_max_units:3,semantic_max_chars_per_unit:40}}),{stage:'harness',ok:true,metrics:{llm_calls:[],request_attempts:[]}}]));
 for(const text of ['semantic','harness','completed','Logical calls: 1','Request attempts: 2','Logical calls: 0','Request attempts: 0','Requested model','Served model','fixture/request-A','fixture/served-B','Prompt tokens','Completion tokens','Output token cap','Request timeout (seconds)','SDK retry cap','Semantic unit cap']) assert.ok(body.includes(text),text);
 assert.match(body,/Prompt tokens<\/dt><dd[^>]*>7<\/dd>/);assert.match(body,/Completion tokens<\/dt><dd[^>]*>0<\/dd>/);
 assert.match(body,/SDK retry cap<\/dt><dd[^>]*>0<\/dd>/);assert.match(body,/Request timeout \(seconds\)<\/dt><dd[^>]*>2.5<\/dd>/);
});
test('unknowns are explicit, requested ID never supplies served ID, legacy remains readable',()=>{
 const body=section(run([row({llm_calls:[{requested_model:'request-only',model:'legacy-model',usage:null}],request_attempts:null})]));
 assert.match(body,/Served model<\/dt><dd[^>]*>not reported<\/dd>/);assert.match(body,/Prompt tokens<\/dt><dd[^>]*>not reported<\/dd>/);
 assert.match(body,/Request attempts: not reported/);assert.doesNotMatch(body,/legacy-model/);
 assert.match(section(render({verdict:'fail'})),/Logical calls: not reported/);
});
test('failed, skipped, partial and malformed stage records remain scope limited',()=>{
 for(const [extra,metrics,label] of [[{ok:false},{},'failed'],[{},{skipped:'missing key'},'skipped'],[{ok:false},{coverage_incomplete:'raw partial reason'},'partial'],[{},'bad','completed']]) {
  const body=section(run([row(metrics,extra)]));assert.match(body,new RegExp(label));assert.match(body,/Logical calls: not reported/);assert.doesNotMatch(body,/raw partial reason/);
 }
});
test('zero and invalid numbers render independently without invented totals or costs',()=>{
 const body=section(run([row({llm_calls:[{usage:{prompt_tokens:0,completion_tokens:-1},max_tokens:Infinity}],request_attempts:[],effective_limits:{llm_max_output_tokens:NaN,sdk_max_retries:0}})]));
 assert.match(body,/Prompt tokens<\/dt><dd[^>]*>0<\/dd>/);assert.match(body,/Completion tokens<\/dt><dd[^>]*>not reported<\/dd>/);
 assert.match(body,/Output token cap<\/dt><dd[^>]*>not reported<\/dd>/);assert.match(body,/SDK retry cap<\/dt><dd[^>]*>0<\/dd>/);
 assert.doesNotMatch(body,/NaN|Infinity|cost|latency|total tokens/i);
 assert.doesNotMatch(body,/<dt>[^<]*retries[^<]*<\/dt>/i);
});
test('simulation flag and parent-only composition warn against inference and full accounting',()=>{
 for(const markup of [run([row({simulated:true})]),run([],true)]) assert.match(section(markup),/Illustrative simulation; these records do not demonstrate real inference\./);
 const body=section(run([{stage:'composition',ok:true,metrics:{llm_calls:[{requested_model:'parent-only'}]}}]));
 assert.match(body,/Composition report: member model records and totals may be missing\./);assert.doesNotMatch(body,/parent-only/);assert.match(body,/Logical calls: not reported/);
});
test('HTML-looking model IDs are text and excluded payloads do not reach markup',()=>{
 const body=section(run([row({llm_calls:[{requested_model:'<img src=x onerror=alert(1)>','served_model':'<script>unsafe()</script>',prompt:'SECRET-PROMPT',response:'SECRET-RESPONSE',error:'SECRET-ERROR',api_key:'SECRET-KEY',usage:{prompt_tokens:1,secret:'SECRET-USAGE'}}],request_attempts:[],arbitrary:'SECRET-ARBITRARY',effective_limits:{endpoint:'SECRET-ENDPOINT'}})]));
 assert.match(body,/&lt;img src=x onerror=alert\(1\)&gt;/);assert.match(body,/&lt;script&gt;unsafe\(\)&lt;\/script&gt;/);
 assert.doesNotMatch(body,/<img|<script|SECRET-/);
});
test('verdict reasons, streamed findings and coverage remain unchanged',()=>{
 const finding={stage:'static',title:'Retained finding',detail:'Original detail',severity:'high',confidence:'deterministic',owasp_ids:['LLM02'],evidence:[]};
 const markup=render({verdict:{status:'fail',reasons:['Original reason'],coverage_caveats:['Original coverage']},stages:[row({skipped:'no API key'})]},[finding]);
 for(const text of ['audit verdict: fail','Retained finding','Original reason','Original coverage','semantic: skipped — no API key']) assert.ok(markup.includes(text),text);
 section(markup);
});
