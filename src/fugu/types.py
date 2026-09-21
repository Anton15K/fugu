"""Shared contracts for the Fugu audit pipeline.

READ-ONLY for bot workstreams: adapt around these types, never edit them.
Change requests go in your workstream summary; the tech lead evolves them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

# --- OWASP taxonomy -----------------------------------------------------------
# MCP01..MCP10 from the OWASP MCP Top 10 (2025 release; verified against
# github.com/OWASP/www-project-mcp-top-10 — MCP03=Tool Poisoning incl.
# shadowing, MCP07=AuthN/AuthZ, MCP09=Shadow MCP Servers, MCP10=Context
# Injection & Over-Sharing); LLMxx from the OWASP
# Top 10 for LLM Applications 2025. MCP04B is our rug-pull-drift extension.
OWASP_IDS = (
    "MCP01", "MCP02", "MCP03", "MCP04", "MCP04B", "MCP05", "MCP06",
    "MCP07", "MCP08", "MCP09", "MCP10",
    "LLM01", "LLM02", "LLM03", "LLM06",
)

Severity = Literal["info", "low", "medium", "high", "critical"]
ConfidenceTier = Literal["deterministic", "measured", "empirical", "advisory"]
StageName = Literal[
    "concealment", "static", "semantic", "detonation",
    "harness", "reputation", "composition", "verdict",
]

# Confidence tiers (see IDEA.md "tiered guarantees"):
#   deterministic – provable for a defined codepoint/rule set (S0, canary hits)
#   measured      – recall measured on the labeled eval corpus
#   empirical     – observed behavior in detonation / harness A/B
#   advisory      – LLM-judged, probabilistic


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"


# --- Findings -----------------------------------------------------------------
@dataclass
class EvidenceSnippet:
    """A pointer to where a finding was observed, plus a short excerpt."""
    source: str                    # e.g. "mitm.flow[3].body", "dns.query[7]", "file:install.sh:L12"
    excerpt: str                   # <= 500 chars, human-readable
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    owasp_ids: list[str]           # subset of OWASP_IDS
    title: str                     # one line
    detail: str                    # 1-5 sentences
    severity: Severity
    confidence: ConfidenceTier
    stage: str                     # StageName that produced it
    evidence: list[EvidenceSnippet] = field(default_factory=list)


# --- Detonation evidence (Stage 3) ---------------------------------------------
@dataclass
class FlowRecord:
    """One captured outbound HTTP(S) request (MITM proxy view)."""
    host: str
    method: str
    path: str
    body: str = ""
    ts: str = ""


@dataclass
class DnsRecord:
    """One captured DNS query."""
    query: str
    ts: str = ""


@dataclass
class DetonationEvidence:
    trigger: str                   # which trigger ran, e.g. "install", "import", "invoke"
    exit_code: int | None
    duration_s: float
    flows: list[FlowRecord] = field(default_factory=list)
    dns: list[DnsRecord] = field(default_factory=list)
    fs_changes: list[str] = field(default_factory=list)   # docker-diff style lines
    canary_hits: list[EvidenceSnippet] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)  # cpu/mem/io if available


# --- Jobs, stages, events -------------------------------------------------------
@dataclass
class AuditJob:
    id: str                        # short uuid/hex
    source: str                    # local path, git url, or MCP config path
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: JobStatus = JobStatus.queued
    depth: Literal["standard", "full"] = "standard"


@dataclass
class StageResult:
    stage: str                     # StageName
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)  # durations, counts, model calls
    error: str | None = None


@dataclass
class StageEvent:
    """SSE envelope. `type` drives the UI; `data` is JSON-safe."""
    type: Literal["stage_started", "finding", "stage_done", "verdict", "error", "log"]
    job_id: str
    data: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
