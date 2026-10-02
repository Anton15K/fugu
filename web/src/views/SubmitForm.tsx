import { ArrowRight, Clock, FileSearch, FlaskConical, GitBranch, ShieldCheck } from 'lucide-react';
import { useEffect, useState } from 'react';
import { API_BASE } from '@/lib/api';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import type { AuditDepth, AuditJob } from '@/lib/types';

interface Sample { source: string; label: string; description: string }

export interface SubmitFormProps {
  onSubmit: (source: string, depth: AuditDepth) => void;
  recent: AuditJob[];
  onSelectRecent: (job: AuditJob) => void;
  onClearRecent: () => void;
  busy?: boolean;
  error?: string | null;
  mockMode: boolean;
}

export function SubmitForm({ onSubmit, recent, onSelectRecent, onClearRecent, busy = false, error = null, mockMode }: SubmitFormProps) {
  const [source, setSource] = useState('');
  const [samples, setSamples] = useState<Sample[]>([]);
  useEffect(() => {
    if (mockMode) return;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    fetch(`${API_BASE}/samples`, { signal: controller.signal })
      .then(async response => response.ok ? response.json() : null)
      .then(data => {
        if (!controller.signal.aborted && Array.isArray(data?.samples)) {
          setSamples(data.samples.filter((sample: Sample) => typeof sample?.source === 'string' && typeof sample?.label === 'string' && typeof sample?.description === 'string'));
        }
      }).catch(() => { /* Older or unavailable API: no assumed sample paths. */ })
      .finally(() => clearTimeout(timeout));
    return () => { controller.abort(); clearTimeout(timeout); };
  }, [mockMode]);
  const valid = source.trim().length >= 3;

  return (
    <div className="entry-layout">
      <section className="entry-intro" aria-labelledby="entry-title">
        <p className="eyebrow"><span className="signal-dot" /> SECURITY BEFORE INSTALL</p>
        <h1 id="entry-title">Know what you’re<br />letting <span>in.</span></h1>
        <p className="intro-copy">Your agent gets powerful tools. Its extensions deserve a closer look.</p>
        <p className="intro-detail">Audit a community skill, MCP server, or plugin before giving it access to your files, credentials, and workflows.</p>
        <div className="entry-principle"><ShieldCheck aria-hidden /><div><strong>Evidence you can inspect.</strong><p>Decoded instructions, flagged code, and observed behavior — with a confidence tier for every finding.</p></div></div>
        <ol className="journey-steps" aria-label="How an audit works">
          <li><span>01</span> Choose an extension</li><li><span>02</span> Watch the checks</li><li><span>03</span> Review before install</li>
        </ol>
      </section>

      <section className="audit-entry" aria-labelledby="submit-title">
        <div className="entry-card-header"><FileSearch aria-hidden /><p className="eyebrow">{mockMode ? 'SIMULATED WALKTHROUGH' : 'NEW AUDIT'}</p></div>
        <h2 id="submit-title">{mockMode ? 'See the evidence unfold' : 'What should Fugu inspect?'}</h2>
        <p className="entry-subtitle">{mockMode ? 'A scripted malicious-skill scenario. No source is fetched and no analysis runs.' : 'One extension or repository. Fugu inspects the source and reports what its checks found.'}</p>
        <form onSubmit={event => { event.preventDefault(); if (!busy && (mockMode || valid)) onSubmit(mockMode ? 'Simulated malicious skill · pdf-table-extractor' : source.trim(), 'full'); }}>
          {!mockMode && <>
            <label htmlFor="extension-source">Extension source</label>
            <div className="source-field"><GitBranch aria-hidden /><input id="extension-source" value={source} onChange={event => setSource(event.target.value)} placeholder="https://github.com/owner/extension" spellCheck={false} autoComplete="off" aria-describedby="source-help" required /></div>
            <p id="source-help" className="field-help">Git URL or a directory on the API server. Start with a small extension; large repositories can take longer.</p>
          </>}
          <Button type="submit" disabled={busy || (!mockMode && !valid)} className="audit-submit">{busy ? 'Starting…' : mockMode ? 'Play simulated audit' : 'Start audit'}<ArrowRight aria-hidden /></Button>
        </form>
        {error && <Alert variant="destructive" role="alert"><AlertTitle>Couldn’t start the audit</AlertTitle><AlertDescription>{error} Check the source and server connection, then try again.</AlertDescription></Alert>}
        {samples.length > 0 && !mockMode && <div className="sample-section"><p className="eyebrow">TRY A BUNDLED EXAMPLE</p><div className="sample-grid">{samples.map(sample => <button type="button" key={sample.source} disabled={busy} onClick={() => { setSource(sample.source); document.getElementById('extension-source')?.focus(); }} className="sample-choice"><span>{sample.label}<ArrowRight aria-hidden /></span><small>{sample.description}</small></button>)}</div><p className="field-help">Crafted examples available on this server. Selecting one fills the source; Start audit runs real checks.</p></div>}
        <div className="analysis-note"><p className="eyebrow">{mockMode ? 'DEMO DATA ONLY' : 'FULL ANALYSIS · COVERAGE REPORTED'}</p><p>{mockMode ? 'The findings, timing, and verdict illustrate the interface. They are not measured results for a supplied extension.' : 'Static and concealment checks run locally. Semantic and harness stages send extension content and prompts to the configured model provider. Reputation queries use Tavily when configured. Runtime checks depend on sandbox availability.'}</p><p>{mockMode ? 'Switch to live analysis to audit your own source.' : 'Unavailable or failed checks are reported with the verdict. A PASS is limited to completed checks; it does not certify safety.'}</p></div>
        <a className="replay-link" href={mockMode ? '/?mock=0' : '/?mock=1'}><FlaskConical aria-hidden />{mockMode ? 'Switch to live analysis' : 'Explore a simulated audit — no API calls'}<ArrowRight aria-hidden /></a>
      </section>
      {!mockMode && recent.length > 0 && <section className="recent-section" aria-labelledby="recent-title"><div className="flex items-center justify-between gap-3"><h2 id="recent-title">Continue an audit</h2><Button variant="ghost" onClick={onClearRecent}>Clear history</Button></div><p className="field-help">Saved on this browser. Opens the existing run without starting another audit.</p><div className="recent-list">{recent.map(job => <button key={job.id} onClick={() => onSelectRecent(job)}><Clock aria-hidden /><span><strong>{job.source}</strong><small>{new Date(job.created_at).toLocaleString()} · {job.id}</small></span><ArrowRight aria-hidden /></button>)}</div></section>}
    </div>
  );
}
