/**
 * API client for the Fugu backend (FastAPI on :8000, proxied as /api in dev).
 *
 * Contract (backend not built yet — mocked by `lib/mockStream.ts`):
 *   POST /audits            { source, depth } → 202 { job_id }
 *   GET  /audits/:id/events → SSE of StageEvent objects
 *
 * `openAuditStream` prefers native EventSource with transparent reconnect;
 * if SSE is unavailable or repeatedly fails it falls back to fetch polling
 * of the same endpoint (Last-Event-ID aware when the server sends it).
 */
import type { AuditDepth, AuditJob, StageEvent } from "./types";

/** Where to send requests. Relative by default; override for tests/deploy. */
export let API_BASE = "/api";

/** Point the client at a different backend origin (e.g. behind a gateway). */
export function setApiBase(base: string): void {
  API_BASE = base;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export interface SubmitOptions {
  signal?: AbortSignal;
}

/** Submit a new audit; resolves to the created job (202 + job resource). */
export async function submitAudit(
  source: string,
  depth: AuditDepth,
  opts: SubmitOptions = {},
): Promise<AuditJob> {
  const res = await fetch(`${API_BASE}/audits`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source, depth }),
    signal: opts.signal,
  });
  if (!res.ok) {
    throw new ApiError(res.status, `submit failed: HTTP ${res.status}`);
  }
  const body: unknown = await res.json();
  // Backend returns at minimum { job_id }; treat a full AuditJob as a bonus.
  if (isAuditJob(body)) return body;
  if (
    typeof body === "object" &&
    body !== null &&
    typeof (body as { job_id?: unknown }).job_id === "string"
  ) {
    const job = body as { job_id: string; source?: string; depth?: string };
    return {
      id: job.job_id,
      source: job.source ?? source,
      created_at: new Date().toISOString(),
      status: "queued",
      depth: (job.depth as AuditJob["depth"]) ?? depth,
    };
  }
  throw new ApiError(res.status, "submit succeeded but response had no job_id");
}

function isAuditJob(v: unknown): v is AuditJob {
  if (typeof v !== "object" || v === null) return false;
  const j = v as Record<string, unknown>;
  return (
    typeof j.id === "string" &&
    typeof j.source === "string" &&
    typeof j.created_at === "string" &&
    typeof j.status === "string"
  );
}

/** Handle returned by {@link openAuditStream}; call `close()` to stop. */
export interface StreamHandle {
  close(): void;
}

export interface StreamOptions {
  /** Called on every parsed StageEvent. */
  onEvent: (event: StageEvent) => void;
  /** Connection lifecycle; defaults console-log transport changes. */
  onStatus?: (status: StreamStatus) => void;
  signal?: AbortSignal;
}

export type StreamStatus =
  | { kind: "connecting"; transport: "sse" | "polling" }
  | { kind: "open"; transport: "sse" | "polling" }
  | { kind: "reconnecting"; attempt: number; transport: "sse" }
  | { kind: "degraded"; transport: "polling"; reason: string }
  | { kind: "closed"; transport: "sse" | "polling" };

const MAX_SSE_FAILURES = 3;
const POLL_INTERVAL_MS = 1_500;
const RECONNECT_BASE_MS = 800;

/**
 * Open the event stream for a job. Never rejects: errors surface as
 * `error` StageEvents via onEvent and through onStatus. Stream ends after
 * a `verdict` event (terminal) — call close() anyway to be safe.
 */
export function openAuditStream(
  jobId: string,
  opts: StreamOptions,
): StreamHandle {
  const controllers = new Set<() => void>();

  const stop = () => {
    controllers.forEach((fn) => fn());
    controllers.clear();
  };

  const handle: StreamHandle = {
    close() {
      stop();
      opts.onStatus?.({ kind: "closed", transport: "sse" });
    },
  };

  if (opts.signal) {
    opts.signal.addEventListener(
      "abort",
      () => handle.close(),
      { once: true },
    );
  }

  runSse(jobId, opts, controllers, 0).catch(() => {
    /* runSse handles its own errors */
  });

  return handle;
}

async function runSse(
  jobId: string,
  opts: StreamOptions,
  controllers: Set<() => void>,
  failures: number,
): Promise<void> {
  if (opts.signal?.aborted) return;
  opts.onStatus?.({ kind: "connecting", transport: "sse" });

  const url = `${API_BASE}/audits/${encodeURIComponent(jobId)}/events`;

  if (typeof EventSource !== "undefined") {
    const es = new EventSource(url);
    let sawEvent = false;
    let terminal = false;

    const teardown = () => {
      es.close();
      controllers.delete(teardown);
    };
    controllers.add(teardown);

    const retryOrFallback = (reason: string) => {
      teardown();
      if (terminal || opts.signal?.aborted) return;
      const attempt = failures + 1;
      if (attempt >= MAX_SSE_FAILURES) {
        fallbackToPolling(jobId, opts, controllers, reason);
        return;
      }
      opts.onStatus?.({ kind: "reconnecting", attempt, transport: "sse" });
      const delay = RECONNECT_BASE_MS * 2 ** (attempt - 1);
      setTimeout(() => {
        if (!opts.signal?.aborted) {
          runSse(jobId, opts, controllers, attempt).catch(() => {});
        }
      }, delay);
    };

    es.onopen = () => {
      sawEvent = true;
      failures = 0;
      opts.onStatus?.({ kind: "open", transport: "sse" });
    };

    es.onmessage = (msg: MessageEvent<string>) => {
      sawEvent = true;
      const event = parseEvent(msg.data);
      if (event) opts.onEvent(event);
      if (event?.type === "verdict") {
        terminal = true;
        // Server closes the stream after verdict; give it a beat then close.
        setTimeout(teardown, 300);
      }
    };

    es.onerror = () => {
      // EventSource auto-reconnects while `readyState === CONNECTING`; if the
      // server errored without us ever connecting, escalate ourselves.
      if (es.readyState === EventSource.CLOSED) {
        retryOrFallback("connection closed");
      } else if (!sawEvent) {
        retryOrFallback("sse error before first event");
      }
      // else: browser is reconnecting on its own — leave it alone.
    };

    return;
  }

  // No native EventSource (SSR / ancient browser): degrade immediately.
  fallbackToPolling(jobId, opts, controllers, "EventSource unavailable");
}

function parseEvent(raw: string): StageEvent | null {
  try {
    const v: unknown = JSON.parse(raw);
    if (typeof v !== "object" || v === null) return null;
    const e = v as Record<string, unknown>;
    if (typeof e.type !== "string" || typeof e.job_id !== "string") return null;
    return {
      type: e.type as StageEvent["type"],
      job_id: e.job_id,
      data: (e.data as Record<string, unknown>) ?? {},
      ts: typeof e.ts === "string" ? e.ts : new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

/** Parse a poll response: a JSON array of events, or raw SSE text. */
function parseBatch(text: string): StageEvent[] {
  const trimmed = text.trim();
  if (trimmed.startsWith("[")) {
    try {
      const arr: unknown = JSON.parse(trimmed);
      if (Array.isArray(arr)) {
        return arr.map((v) => parseEvent(JSON.stringify(v))).filter(
          (e): e is StageEvent => e !== null,
        );
      }
    } catch {
      /* fall through to SSE parsing */
    }
  }
  // SSE framing: `data: {...}\n\n` lines, possibly several in one body.
  return trimmed
    .split(/\n\n|\r\n\r\n/)
    .flatMap((frame) =>
      frame
        .split(/\n|\r\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trim()),
    )
    .map(parseEvent)
    .filter((e): e is StageEvent => e !== null);
}

async function fallbackToPolling(
  jobId: string,
  opts: StreamOptions,
  controllers: Set<() => void>,
  reason: string,
): Promise<void> {
  opts.onStatus?.({ kind: "degraded", transport: "polling", reason });

  const ctrl = new AbortController();
  const teardown = () => ctrl.abort();
  controllers.add(teardown);
  if (opts.signal) {
    if (opts.signal.aborted) {
      teardown();
      return;
    }
    opts.signal.addEventListener("abort", teardown, { once: true });
  }

  const url = `${API_BASE}/audits/${encodeURIComponent(jobId)}/events`;
  let cursor: string | undefined;

  const tick = async () => {
    while (!ctrl.signal.aborted) {
      try {
        const headers: Record<string, string> = { Accept: "application/json, text/event-stream" };
        if (cursor) headers["Last-Event-ID"] = cursor;
        const res = await fetch(url, { headers, signal: ctrl.signal });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        // The endpoint is normally SSE; accept either a JSON batch of events
        // or a buffered text/event-stream body parsed frame by frame.
        const text = await res.text();
        const events = parseBatch(text);
        for (const event of events) {
          cursor = event.ts;
          opts.onEvent(event);
        }
        if (events.some((e) => e.type === "verdict")) return;
      } catch (err) {
        if (ctrl.signal.aborted) return;
        // Transient poll failure — keep trying on the next tick.
        console.warn("[fugu] poll failed", err);
      }
      await sleep(POLL_INTERVAL_MS, ctrl.signal);
    }
  };

  tick().finally(() => {
    controllers.delete(teardown);
    opts.onStatus?.({ kind: "closed", transport: "polling" });
  });
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        resolve();
      },
      { once: true },
    );
  });
}
