import { Clock, FileArchive, GitBranch, Globe, HardDrive, Terminal } from "lucide-react";
import { useMemo, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { AuditDepth, AuditJob } from "@/lib/types";
import { cn } from "@/lib/utils";

const SET_AUDIT_PRESET = [
  "https://github.com/brooksy4503/rss-agent-viewer",
  "https://github.com/rookie-ricardo/erduo-skills",
  "https://github.com/vapiai/skills",
].join(", ");

const SOURCE_PRESETS: { label: string; value: string }[] = [
  { label: "local skill", value: "./skills/pdf-table-extractor" },
  { label: "git url", value: "https://github.com/anthropics/skills" },
  { label: "mcp config", value: "mcp://stdio:npx -y @modelcontextprotocol/server-github" },
  { label: "set audit", value: SET_AUDIT_PRESET },
];

function sourceIcon(source: string) {
  if (source.startsWith("http")) {
    return source.includes("github.com")
      ? <GitBranch className="size-3.5 text-zinc-500" aria-hidden />
      : <Globe className="size-3.5 text-zinc-500" aria-hidden />;
  }
  if (source.startsWith("mcp://")) {
    return <Terminal className="size-3.5 text-zinc-500" aria-hidden />;
  }
  if (source.endsWith(".zip")) {
    return <FileArchive className="size-3.5 text-zinc-500" aria-hidden />;
  }
  return <HardDrive className="size-3.5 text-zinc-500" aria-hidden />;
}

function relativeTime(iso: string): string {
  const delta = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(delta / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export interface SubmitFormProps {
  onSubmit: (source: string, depth: AuditDepth) => void;
  recent: AuditJob[];
  onSelectRecent: (job: AuditJob) => void;
  onClearRecent: () => void;
  busy?: boolean;
  error?: string | null;
  mockMode: boolean;
}

export function SubmitForm({
  onSubmit,
  recent,
  onSelectRecent,
  onClearRecent,
  busy = false,
  error = null,
  mockMode,
}: SubmitFormProps) {
  const [source, setSource] = useState("");
  const [depth, setDepth] = useState<AuditDepth>("standard");

  const trimmed = source.trim();
  const valid = useMemo(() => trimmed.length >= 3, [trimmed]);

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-5">
      <Card className="grid-noise">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            Submit extension for audit
          </CardTitle>
          <CardDescription>
            Skills (SKILL.md) · MCP servers · plugins — local path, git URL, or
            MCP config
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (valid && !busy) onSubmit(trimmed, depth);
            }}
          >
            <div className="flex gap-2">
              <div className="relative flex-1">
                <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 font-mono text-sm text-zinc-600 select-none">
                  fugu audit
                </span>
                <input
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="./skills/my-skill  (or a, b, c — 2+ sources = set audit)"
                  spellCheck={false}
                  autoComplete="off"
                  aria-label="Extension source"
                  className="h-11 w-full rounded-md border border-zinc-700 bg-zinc-950/70 pl-[7rem] pr-3 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-600"
                />
              </div>
              <Button type="submit" disabled={!valid || busy} className="h-11 px-5 font-mono text-[13px]">
                {busy ? "submitting…" : "audit →"}
              </Button>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {SOURCE_PRESETS.map((p) => (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => setSource(p.value)}
                  className="rounded border border-zinc-800 bg-zinc-900/50 px-2 py-1 font-mono text-[11px] text-zinc-500 transition-colors hover:border-zinc-600 hover:text-zinc-300"
                >
                  {p.label}
                </button>
              ))}
            </div>

            <div className="flex items-center justify-between gap-4 border-t border-zinc-800/70 pt-3">
              <div className="flex items-center gap-1 rounded-lg border border-zinc-800 bg-zinc-900/70 p-1">
                {(["standard", "full"] as const).map((d) => (
                  <button
                    key={d}
                    type="button"
                    aria-pressed={depth === d}
                    onClick={() => setDepth(d)}
                    className={cn(
                      "rounded-md px-3 py-1 font-mono text-xs transition-colors",
                      depth === d
                        ? "bg-zinc-700/80 text-zinc-50"
                        : "text-zinc-500 hover:text-zinc-300",
                    )}
                  >
                    {d}
                  </button>
                ))}
              </div>
              <p className="text-[11px] leading-tight text-zinc-500">
                {depth === "full"
                  ? "all stages incl. harness A/B probe battery (~2 min)"
                  : "skips harness A/B · fastest path to verdict"}
              </p>
            </div>
          </form>

          {error && (
            <Alert variant="destructive">
              <AlertTitle>Submission failed</AlertTitle>
              <AlertDescription className="font-mono">{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {recent.length > 0 && (
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="text-sm text-zinc-300">Recent audits</CardTitle>
            <Button variant="ghost" size="sm" onClick={onClearRecent} className="h-6 px-2 text-[11px] text-zinc-500">
              clear
            </Button>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            {recent.map((job) => (
              <button
                key={job.id}
                onClick={() => onSelectRecent(job)}
                className="group flex items-center gap-3 rounded-md border border-transparent px-2 py-1.5 text-left transition-colors hover:border-zinc-800 hover:bg-zinc-800/30"
              >
                {sourceIcon(job.source)}
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-300">
                  {job.source}
                </span>
                <span className="font-mono text-[10px] text-zinc-600">{job.id.slice(0, 10)}</span>
                <span
                  className={cn(
                    "rounded border px-1.5 py-px font-mono text-[10px] uppercase",
                    job.status === "done" && "border-emerald-800 text-emerald-400",
                    job.status === "failed" && "border-red-800 text-red-400",
                    (job.status === "queued" || job.status === "running") &&
                      "border-zinc-700 text-zinc-400",
                  )}
                >
                  {job.status}
                </span>
                <span className="flex items-center gap-1 text-[10px] text-zinc-600">
                  <Clock className="size-3" aria-hidden />
                  {relativeTime(job.created_at)}
                </span>
              </button>
            ))}
          </CardContent>
        </Card>
      )}

      {mockMode && (
        <p className="text-center font-mono text-[11px] text-zinc-600">
          mock mode — replaying a scripted audit (backend not connected)
        </p>
      )}
    </div>
  );
}
