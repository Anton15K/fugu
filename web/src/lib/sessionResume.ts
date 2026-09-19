/**
 * Per-audit URL resume: `/audit/<jobId>` is the canonical address of one
 * audit run (a real route — the backend's SPA fallback serves the app on
 * it). The backend is the source of truth: the job runs server-side with
 * no client attached, its full event stream is persisted (SQLite) and
 * replayed over SSE, so opening the URL any time — mid-run, after the
 * window was closed, even after a server restart — restores the exact state.
 */

import type { AuditJob } from "./types";

const ROUTE = /^\/audit\/([a-z0-9-]+)/i;

export function readPathJob(): AuditJob | null {
  try {
    const m = ROUTE.exec(location.pathname);
    const id = m?.[1];
    if (!id) return null;
    const metaRaw = sessionStorage.getItem(`fugu.job.${id}`);
    if (metaRaw) {
      try {
        const j = JSON.parse(metaRaw) as { id?: unknown; source?: unknown };
        if (typeof j?.id === "string" && typeof j?.source === "string") {
          return {
            id: j.id,
            source: j.source,
            created_at: new Date().toISOString(),
            status: "running",
            depth: "standard",
          };
        }
      } catch { /* corrupted meta — fall through to minimal job */ }
    }
    return {
      id,
      source: "resumed audit",
      created_at: new Date().toISOString(),
      status: "running",
      depth: "standard",
    };
  } catch {
    return null;
  }
}

export function writePathJob(id: string): void {
  try {
    history.pushState(null, "", `/audit/${id}`);
  } catch { /* non-browser context */ }
}

export function rememberJobMeta(job: {
  id: string;
  source: string;
}): void {
  try {
    sessionStorage.setItem(
      `fugu.job.${job.id}`,
      JSON.stringify({ id: job.id, source: job.source }),
    );
  } catch { /* storage unavailable */ }
}

export function clearPathJob(): void {
  try {
    if (ROUTE.test(location.pathname)) {
      history.replaceState(null, "", "/");
    }
  } catch { /* non-browser context */ }
}
