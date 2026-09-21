"""Cross-stage finding deduplication.

Independent stages legitimately overlap: the same fetch-and-run instruction
in a README is flagged by the static rule ``install_script_fetch`` AND by the
semantic judge; a detonated trigger's egress echoes its static HIGH. A report
full of near-identical rows reads as noise and inflates severity counts, so
before findings reach the verdict (and the UI) we drop findings that are
*subsumed* by a strictly stronger finding about the same concrete artifact.

Subsumption contract (conservative by design):

1. Extract high-specificity evidence tokens from each finding: http(s) URLs,
   shell command prefixes (curl|wget|bash|pip/npm/python invocations), and
   file paths from evidence snippet sources (``file:README.md:L24``).
2. A finding A SUBSUMES weaker finding B when:
   - A's confidence tier strictly outranks B's (deterministic > empirical >
     measured > advisory — mirrors ``verdict._TIER_RANK``), AND
   - A and B share at least one high-specificity token (same URL / same
     command / same file), AND
   - B is advisory or measured (weaker evidence classes only).
3. Never drop deterministic/empirical findings: two deterministic hits on the
   same file are DIFFERENT evidence (e.g. distinct rules) and both belong in
   the report. Empirical rows carry chamber observations that must survive.

The result: one authoritative row per concrete artifact, carrying the
strongest evidence tier, with the weaker echo noted in A's detail only if
identical in spirit (kept simple: not merged; dropped as redundant).
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from fugu.types import Finding

_TIER_RANK = {"deterministic": 3, "empirical": 2, "measured": 1, "advisory": 0}

_URL_RE = re.compile(r"https?://[^\s`\"'<>|]+", re.I)
_CMD_RE = re.compile(
    r"\b(?:curl|wget|bash|sh|pip3?|npm|npx|python3?|node)\b[^\n`\"']{0,120}", re.I
)
_FILE_RE = re.compile(r"\bfile:([^\s:|]+)(?::L\d+)?")
_PATHISH_RE = re.compile(
    r"(?:^|[\s`(\[])((?:\.{0,2}/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]{2,60})(?:$|[\s)`\],.])"
)
# tokens too generic to fingerprint on
_STOP_TOKENS = {
    "http", "https", "example.com", "example.org", "localhost",
    "github.com", "npmjs.com", "pypi.org", "sh", "bash", "env", "tmp",
}
_DROPABLE_TIERS = {"advisory", "measured"}

_FILE_WEIGHTS = (".py", ".md", ".json", ".sh", ".ts", ".js", ".toml", ".yaml", ".yml")


def _tokens(finding: Finding) -> set[str]:
    """High-specificity tokens identifying the concrete artifact."""
    toks: set[str] = set()
    blobs = [finding.title, finding.detail]
    for ev in finding.evidence:
        blobs.append(ev.source)
        if ev.excerpt:
            blobs.append(ev.excerpt)
        for v in (ev.meta or {}).values():
            if isinstance(v, str):
                blobs.append(v)
    blob = " \n ".join(blobs)

    for m in _URL_RE.finditer(blob):
        u = m.group(0).rstrip(".,;)`'")
        host_path = urlsplit(u)
        tok = f"{host_path.netloc.lower()}{host_path.path.rstrip('/')}"
        if tok and host_path.netloc.lower() not in _STOP_TOKENS:
            toks.add(f"url:{tok}")

    for m in _CMD_RE.finditer(blob):
        cmd = m.group(0).strip()
        # trim at command separators (pipes/semicolons end the command; the
        # next segment is a different command) and canonicalize whitespace
        cmd = re.split(r"[|;]", cmd)[0]
        cmd = re.sub(r"\s+", " ", cmd)[:60].lower().strip()
        if len(cmd) > 8:
            toks.add(f"cmd:{cmd}")

    for m in _FILE_RE.finditer(blob):
        p = m.group(1).lower()
        if p not in _STOP_TOKENS and not p.startswith(("osv.dev", "tavily")):
            toks.add(f"file:{p}")

    return toks


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop weaker (advisory/measured) findings subsumed by stronger ones.

    Order-stable: surviving findings keep their input order. A finding with
    no tokens is never dropped (nothing anchors the subsumption).
    """
    # index of strong findings' tokens, in first-seen order
    strong_tokens: list[set[str]] = []
    strong_tiers: list[int] = []
    indexed: list[tuple[Finding, set[str], int]] = []
    out: list[Finding] = []
    dropped = 0

    for f in findings:
        toks = _tokens(f)
        tier = _TIER_RANK.get(f.confidence, 0)
        subsumed = False
        if toks and f.confidence in _DROPABLE_TIERS:
            for i, stoks in enumerate(strong_tokens):
                if strong_tiers[i] > tier and toks & stoks:
                    subsumed = True
                    break
        if subsumed:
            dropped += 1
            continue
        out.append(f)
        if toks and tier >= 2:  # deterministic / empirical index for later drops
            strong_tokens.append(toks)
            strong_tiers.append(tier)

    return out


__all__ = ["dedupe_findings"]
