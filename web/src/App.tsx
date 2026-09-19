import { useCallback, useEffect, useRef, useState } from "react";
import { readPathJob, writePathJob, clearPathJob, rememberJobMeta } from "@/lib/sessionResume";
import { openAuditStream, submitAudit, type StreamHandle, type StreamStatus } from "@/lib/api";
import { isMockEnabled, mockSubmitAudit, openMockAuditStream } from "@/lib/mockStream";
import { loadRecentJobs, pushRecentJob, RECENT_KEY } from "@/lib/recentJobs";
import type { AuditDepth, AuditJob, StageEvent, VerdictData } from "@/lib/types";
import {
  PipelineMonitor,
  applyEvent,
  initialPipelineState,
  type PipelineState,
} from "@/views/PipelineMonitor";
import { Scorecard } from "@/views/Scorecard";
import { SubmitForm } from "@/views/SubmitForm";

type Phase = "idle" | "running" | "done";

interface VerdictInfo {
  verdict: VerdictData;
  elapsedMs: number;
}

export default function App() {
  const mock = isMockEnabled();

  const [phase, setPhase] = useState<Phase>("idle");
  const [job, setJob] = useState<AuditJob | null>(null);
  const [pipeline, setPipeline] = useState<PipelineState>(initialPipelineState);
  const [verdictInfo, setVerdictInfo] = useState<VerdictInfo | null>(null);
  const [streamStatus, setStreamStatus] = useState<StreamStatus | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recent, setRecent] = useState<AuditJob[]>(() => loadRecentJobs(RECENT_KEY));
  const [resumeJob, setResumeJob] = useState<AuditJob | null>(() => readPathJob());

  const streamRef = useRef<StreamHandle | null>(null);

  useEffect(() => () => streamRef.current?.close(), []);


  /** Fold one StageEvent into pipeline + phase state. */
  const handleEvent = useCallback((event: StageEvent) => {
    setPipeline((prev) => {
      const next = applyEvent(prev, event);
      if (event.type === "verdict") {
        // Backend shape: { verdict: {status, severity_counts, reasons, ...},
        //                 severity_counts, total_findings, stages } — the
        // document lives in data.verdict; findings come from the stream
        // (pipeline state), NOT from the verdict event.
        const d = event.data as {
          verdict?: { status?: string; severity_counts?: VerdictData["severity_counts"] };
          severity_counts?: VerdictData["severity_counts"];
        };
        const raw = d.verdict;
        const status =
          typeof raw === "string" ? raw : (raw?.status as VerdictData["verdict"]) ?? "warn";
        setVerdictInfo({
          verdict: {
            verdict: status,
            severity_counts: raw?.severity_counts ?? d.severity_counts ?? {},
            findings: next.findings,
          },
          // Final elapsed is frozen at finish from SERVER timestamps —
          // never recomputed on re-render, so reloading an old audit keeps
          // its true duration instead of restarting the clock.
          elapsedMs: next.startedAt ? (next.finishedAt ?? next.startedAt) - next.startedAt : 0,
        });
        setPhase("done");
      } else if (event.type === "error" && event.data.fatal) {
        setPhase("done");
      }
      return next;
    });
  }, []);

  // Per-audit URL resume: /audit/<id> reconnects to that run. The backend
  // replays the full persisted event stream over SSE, so returning to the
  // URL any time - window closed mid-run, even after a server restart -
  // restores the exact pipeline state instead of restarting from zero.
  const resumeAudit = useCallback((job: AuditJob) => {
    streamRef.current?.close();
    setSubmitError(null);
    setJob(job);
    setPipeline(initialPipelineState());
    setVerdictInfo(null);
    setPhase("running");
    streamRef.current = openAuditStream(job.id, {
      onEvent: handleEvent,
      onStatus: setStreamStatus,
    });
  }, [handleEvent]);

  useEffect(() => {
    if (resumeJob) {
      resumeAudit(resumeJob);
      setResumeJob(null);
    }
  }, [resumeJob, resumeAudit]);


  const startAudit = useCallback(
    async (source: string, depth: AuditDepth) => {
      streamRef.current?.close();
      streamRef.current = null;
      setSubmitError(null);
      setBusy(true);
      try {
        const created = mock
          ? await mockSubmitAudit(source, depth)
          : await submitAudit(source, depth);
        if (!mock) { writePathJob(created.id); rememberJobMeta(created); }
        setJob(created);
        pushRecentJob(RECENT_KEY, created, setRecent);
        setPipeline(initialPipelineState());
        setVerdictInfo(null);
        setPhase("running");
        streamRef.current = mock
          ? openMockAuditStream(created.id, depth, handleEvent)
          : openAuditStream(created.id, {
              onEvent: handleEvent,
              onStatus: setStreamStatus,
            });
      } catch (err) {
        setSubmitError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
    },
    [mock, handleEvent],
  );

  const resetToIdle = useCallback(() => {
    streamRef.current?.close();
    streamRef.current = null;
    clearPathJob();
    setPhase("idle");
    setJob(null);
    setVerdictInfo(null);
    setPipeline(initialPipelineState());
    setStreamStatus(null);
  }, []);

  const clearRecent = useCallback(() => {
    localStorage.removeItem(RECENT_KEY);
    setRecent([]);
  }, []);

  // Browser navigation (back/forward) drives the view: the URL is the
  // single source of truth. '/' = home; '/audit/<id>' = that audit,
  // resumed from the server's persisted event history.
  const homeFromHistory = useCallback(() => {
    streamRef.current?.close();
    streamRef.current = null;
    setPhase("idle");
    setJob(null);
    setVerdictInfo(null);
    setPipeline(initialPipelineState());
    setStreamStatus(null);
  }, []);

  useEffect(() => {
    const onPopState = () => {
      const routeJob = readPathJob();
      if (routeJob) {
        resumeAudit(routeJob);
      } else {
        homeFromHistory();
      };
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, [resumeAudit, homeFromHistory]);

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-10 border-b border-zinc-800/80 bg-zinc-950/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3">
          <button
            type="button"
            onClick={resetToIdle}
            aria-label="Fugu home — new audit"
            title="new audit"
            className="flex items-center gap-3 rounded-md px-1 py-0.5 transition-colors hover:bg-zinc-800/60"
          >
            <span className="text-xl" role="img" aria-label="fugu">
              🐡
            </span>
            <div className="text-left">
              <h1 className="font-mono text-sm font-bold tracking-[0.3em] text-zinc-100">
                FUGU
              </h1>
              <p className="font-mono text-[10px] text-zinc-500">
                agent-extension security auditor
              </p>
            </div>
          </button>
          <div className="flex items-center gap-3 font-mono text-[11px] text-zinc-500">
            <span className={mock ? "text-amber-400" : "text-emerald-400"}>
              {mock ? "mock replay" : "live api"}
            </span>
            <span className="text-zinc-700">|</span>
            <span>OWASP MCP β + LLM 2025</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6">
        {phase === "idle" && (
          <SubmitForm
            onSubmit={(s, d) => void startAudit(s, d)}
            recent={recent}
            onSelectRecent={(j) => {
              // Open the EXISTING audit (server replays its persisted
              // events) — never create a duplicate job for the same source.
              writePathJob(j.id);
              rememberJobMeta(j);
              resumeAudit(j);
            }}
            onClearRecent={clearRecent}
            busy={busy}
            error={submitError}
            mockMode={mock}
          />
        )}

        {phase === "running" && job && (
          <PipelineMonitor
            job={job}
            state={pipeline}
            streamStatus={streamStatus}
            onNewAudit={resetToIdle}
          />
        )}

        {phase === "done" && job && verdictInfo && (
          <div className="flex flex-col gap-6">
            <PipelineMonitor
              job={job}
              state={pipeline}
              streamStatus={streamStatus}
              onNewAudit={resetToIdle}
            />
            <Scorecard verdict={verdictInfo.verdict} elapsedMs={verdictInfo.elapsedMs} />
          </div>
        )}

        {phase === "done" && !verdictInfo && job && (
          <PipelineMonitor
            job={job}
            state={pipeline}
            streamStatus={streamStatus}
            onNewAudit={resetToIdle}
          />
        )}
      </main>

      <footer className="border-t border-zinc-800/60 py-4">
        <p className="text-center font-mono text-[10px] text-zinc-600">
          evidence, not vibes · deterministic / measured / empirical / advisory
        </p>
      </footer>
    </div>
  );
}
