import type { AuditJob } from "./types";

/**
 * Recent-audit history in localStorage (best-effort; failures are swallowed
 * so a corrupted entry can never brick the UI).
 */

export const RECENT_KEY = "fugu.recent-audits";
const MAX_ENTRIES = 8;

export function loadRecentJobs(key: string): AuditJob[] {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (j): j is AuditJob =>
        typeof j === "object" &&
        j !== null &&
        typeof (j as AuditJob).id === "string" &&
        typeof (j as AuditJob).source === "string",
    );
  } catch {
    return [];
  }
}

export function pushRecentJob(
  key: string,
  job: AuditJob,
  set: (updater: (prev: AuditJob[]) => AuditJob[]) => void,
): void {
  set((prev) => {
    // dedupe by source; newest first
    const next = [job, ...prev.filter((j) => j.source !== job.source)].slice(
      0,
      MAX_ENTRIES,
    );
    try {
      localStorage.setItem(key, JSON.stringify(next));
    } catch {
      /* storage full / private mode — history just won't persist */
    }
    return next;
  });
}
