import assert from 'node:assert/strict';
import { build } from 'rolldown';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const outfile = join(mkdtempSync(join(tmpdir(), 'fugu-result-')), 'result.mjs');
await build({input:new URL('../src/lib/auditResult.ts', import.meta.url).pathname, output:{file:outfile,format:'esm'}, platform:'node'});
const { mapAuditResult } = await import(pathToFileURL(outfile).href);
const findings=[{severity:'high',confidence:'deterministic',stage:'static',title:'Credential read',detail:'d',owasp_ids:['LLM02'],evidence:[]}];
const result=mapAuditResult({verdict:{status:'fail',severity_counts:{high:1},reasons:['high-severity finding(s) with deterministic/empirical evidence'],coverage_caveats:['semantic: skipped'],static_only:true},stages:[{stage:'semantic',ok:true,metrics:{skipped:'no API key'}},{stage:'detonation',ok:false,error:'Docker unavailable'}]}, findings);
assert.equal(result.verdict.verdict,'fail');
assert.deepEqual(result.verdict.findings,findings);
assert.equal(result.reasons[0],'high-severity finding(s) with deterministic/empirical evidence');
assert.equal(result.staticOnly,true);
assert(result.coverage.some(x=>x.includes('semantic')));
assert(result.coverage.some(x=>x.includes('Docker unavailable')));
const replay=mapAuditResult({verdict:'fail',severity_counts:{high:1}},findings);
assert.equal(replay.verdict.verdict,'fail');
assert.equal(replay.coverageKnown,false);
assert.equal(mapAuditResult({verdict:{status:'pass',coverage_caveats:[],static_only:false}},[]).verdict.verdict,'pass');
assert.equal(mapAuditResult({verdict:{status:'unexpected'}},[]).verdict.verdict,'warn');
console.log('AUDIT RESULT PASSED: server reasons, incomplete coverage, streamed findings and legacy replay');

// Literal behavior expectations: neither request totals nor served IDs are inferred.
import { test, after } from 'node:test';
after(()=>rmSync(new URL('.',pathToFileURL(outfile)),{recursive:true,force:true}));
const metricRow = (metrics, extra = {}) => ({stage:'semantic',ok:true,metrics,...extra});
const unknownRecord = {requestedModel:null,servedModel:null,maxOutputTokens:null,usage:{promptTokens:null,completionTokens:null}};
const unknownLimits = {llm_max_output_tokens:null,request_timeout_seconds:null,sdk_max_retries:null,semantic_max_units:null,semantic_max_chars_per_unit:null};
const evidence = stages => mapAuditResult({verdict:'warn',stages},[]).modelEvidence;
test('production semantic and harness records keep IDs, counts, usage and effective limits distinct', () => {
  const value = evidence([metricRow({llm_calls:[{model:'legacy-label',requested_model:'request-A',served_model:'serve-B',max_tokens:80,usage:{prompt_tokens:7,completion_tokens:0}}],request_attempts:[{requested_model:'request-A',served_model:null,usage:null},{requested_model:'request-A',served_model:'serve-B',usage:{prompt_tokens:7,completion_tokens:0}}],effective_limits:{llm_max_output_tokens:80,request_timeout_seconds:2.5,sdk_max_retries:0,semantic_max_units:3,semantic_max_chars_per_unit:40}}),{stage:'harness',ok:true,metrics:{llm_calls:[],request_attempts:[],effective_limits:{llm_max_output_tokens:90,request_timeout_seconds:4,sdk_max_retries:1,harness_mount_char_budget:100,red_probe_count:2,red_probe_max_chars:20}}}]);
  assert.deepEqual(value, {composition:false,stages:[{stage:'semantic',status:'completed',illustrative:false,calls:[{requestedModel:'request-A',servedModel:'serve-B',maxOutputTokens:80,usage:{promptTokens:7,completionTokens:0}}],attempts:[{...unknownRecord,requestedModel:'request-A'},{requestedModel:'request-A',servedModel:'serve-B',maxOutputTokens:null,usage:{promptTokens:7,completionTokens:0}}],limits:{llm_max_output_tokens:80,request_timeout_seconds:2.5,sdk_max_retries:0,semantic_max_units:3,semantic_max_chars_per_unit:40}},{stage:'harness',status:'completed',illustrative:false,calls:[],attempts:[],limits:{llm_max_output_tokens:90,request_timeout_seconds:4,sdk_max_retries:1,harness_mount_char_budget:100,red_probe_count:2,red_probe_max_chars:20}}]});
});
test('allowlist excludes prompts, responses, errors, secrets, arbitrary fields and legacy inference', () => {
  const value = evidence([metricRow({llm_calls:[{model:'legacy-model',requested_model:' <b>request</b> ',served_model:null,max_tokens:0,usage:{prompt_tokens:0,completion_tokens:null,secret:'SECRET-USAGE'},prompt:'SECRET-PROMPT',response:'SECRET-RESPONSE',error:'SECRET-ERROR',api_key:'SECRET-KEY',endpoint:'SECRET-ENDPOINT',latency_s:1,cost:5}],request_attempts:[],effective_limits:{api_key:'SECRET-LIMIT'},arbitrary:'SECRET-ARBITRARY'})]);
  assert.deepEqual(value.stages[0].calls,[{requestedModel:' <b>request</b> ',servedModel:null,maxOutputTokens:0,usage:{promptTokens:0,completionTokens:null}}]);
  assert.doesNotMatch(JSON.stringify(value),/SECRET-|legacy-model|latency|cost|endpoint/);
});
test('missing or malformed stages, metrics, arrays and numeric fields are unknown', () => {
  for (const metrics of [null,undefined,4,'broken',[],{llm_calls:null,request_attempts:'broken',effective_limits:[]},{llm_calls:[null],request_attempts:[3]}]) {
    const value=evidence([metricRow(metrics)]);
    assert.equal(value.stages[0].calls,null);assert.equal(value.stages[0].attempts,null);
    assert.deepEqual(value.stages[0].limits,unknownLimits);
  }
  for (const invalid of [null,undefined,-1,NaN,Infinity,-Infinity,'0',false,{}]) {
    const value=evidence([metricRow({llm_calls:[{requested_model:typeof invalid==='string'?' ':invalid,served_model:typeof invalid==='string'?'':invalid,max_tokens:invalid,usage:{prompt_tokens:invalid,completion_tokens:invalid}}],effective_limits:{llm_max_output_tokens:invalid,request_timeout_seconds:invalid,sdk_max_retries:invalid,semantic_max_units:invalid,semantic_max_chars_per_unit:invalid}})]);
    assert.deepEqual(value.stages[0].calls,[unknownRecord]);assert.deepEqual(value.stages[0].limits,unknownLimits);
  }
  for(const stages of [null,undefined,'bad',[null,3,'bad',{stage:'static',metrics:'bad'}]]) {
    const result=evidence(stages);assert.deepEqual(result.stages.map(s=>[s.stage,s.status,s.calls,s.attempts]),[['semantic','not reported',null,null],['harness','not reported',null,null]]);
  }
});
test('real zero remains zero, blanks are unknown and legacy model never becomes served model', () => {
  const value=evidence([metricRow({llm_calls:[{model:'legacy-model',requested_model:' ',served_model:'',max_tokens:0,usage:{prompt_tokens:0,completion_tokens:0}}],request_attempts:[],effective_limits:{llm_max_output_tokens:0,request_timeout_seconds:0,sdk_max_retries:0,semantic_max_units:0,semantic_max_chars_per_unit:0}})]);
  assert.deepEqual(value.stages[0].calls,[{requestedModel:null,servedModel:null,maxOutputTokens:0,usage:{promptTokens:0,completionTokens:0}}]);
  assert.deepEqual(value.stages[0].limits,{llm_max_output_tokens:0,request_timeout_seconds:0,sdk_max_retries:0,semantic_max_units:0,semantic_max_chars_per_unit:0});
  assert.deepEqual(value.stages[0].attempts,[]);
});
test('failed, skipped, partial, unknown and simulated stage states are explicit', () => {
  const cases=[[{ok:false}, {}, 'failed'],[{}, {skipped:'no API key'},'skipped'],[{ok:false},{coverage_incomplete:'some units failed'},'partial'],[{ok:undefined},{},'not reported']];
  for(const [row,metrics,status] of cases) assert.equal(evidence([metricRow(metrics,row)]).stages[0].status,status);
  const value=evidence([metricRow({simulated:true,llm_calls:[]})]);assert.equal(value.stages[0].illustrative,true);
});
test('parent-only composition retains unknown member accounting and legacy verdict behavior', () => {
  const value=evidence([{stage:'composition',ok:true,metrics:{llm_calls:[{requested_model:'parent-only'}]}}]);
  assert.equal(value.composition,true);assert.equal(value.stages[0].calls,null);assert.equal(value.stages[1].attempts,null);
  const replay=mapAuditResult({verdict:'fail'},findings);assert.equal(replay.verdict.verdict,'fail');assert.equal(replay.verdict.findings,findings);assert.equal(replay.coverageKnown,false);
});
