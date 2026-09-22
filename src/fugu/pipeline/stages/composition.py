"""Stage 6 (S6) - composition: capability mapping + pure detectors.

Detects the *lethal trifecta* across an installed SET of extensions
(untrusted-content ingress + private-data access + egress channel, split
across >= 2 individually-clean extensions) and cross-extension tool
shadowing.  The insight (Willison's "lethal trifecta", CompoSkill arXiv
2608.16246): the risk is a PATH-level property of the installed portfolio,
invisible to any single-extension audit.

Three layers, all deterministic (no LLM):

1.  :func:`map_capabilities` - folds one member's findings + tool names
    into ``Capability`` facts (taxonomy: legs INGRESS / PRIVATE-DATA /
    EGRESS / EXEC, modifiers INJECTION-CARRIER / AGENT-INFLUENCE /
    DEFENSE-GAP).  Strength derives from the contributing finding's
    confidence tier (deterministic|empirical -> strong, measured ->
    medium, advisory -> weak), with two contract-fixed overrides:
    detonation unexpected-egress -> EGRESS medium, tool-verb ingress ->
    INGRESS medium.
2.  :func:`detect_trifecta` - minimal combos of 2-3 DISTINCT extensions
    covering INGRESS + PRIVATE-DATA + EGRESS; supersets and combos with a
    redundant member pruned; ranked by leg-strength sum (+3 when an
    ingress-providing member is a carrier/influence node); emits <= 5.
3.  :func:`detect_shadowing` - normalized tool-name index across members;
    one finding per collision group (>= 2 distinct members).

Signal -> capability mapping (docs/s6-contracts.md section 2; rule ids
verified against ``static_scan.py`` STATIC_RULES and the finding titles in
``harness.py`` / ``docker_driver.py`` - ``tests/test_composition_core.py``
asserts the literals never drift):

===========================  =====================================
Signal                       Capability
===========================  =====================================
static env_harvest /         PRIVATE-DATA strong
  sensitive_path_access
static curl_raw_ip /         EGRESS (+EXEC one notch down)
  curl_pipe_shell /
  install_script_fetch
static npm_install_hook /    EXEC
  setup_py_subprocess /
  base64_decode_exec
static skill_injection_      INJECTION-CARRIER
  phrase / tool_description_
  injection
concealment (any family)     INJECTION-CARRIER strong
semantic owasp LLM01/MCP03/  INJECTION-CARRIER weak
  MCP06
detonation canary exfil      EGRESS + PRIVATE-DATA strong
detonation canary on disk    PRIVATE-DATA strong
detonation unexpected        EGRESS medium (fixed override)
  egress
harness (any finding)        AGENT-INFLUENCE (tier-derived)
tool names/docs matching     INGRESS medium (fixed)
  fetch|get|read|web|url|rss
===========================  =====================================

Honesty rules (frozen contract): bare weak-leg co-existence with no
carrier -> severity low / confidence advisory (hygiene note); all-advisory
legs -> severity at most medium and WARN-level wording, never FAIL-level.
Trifecta with >= 1 strong leg -> severity high, confidence taken from the
strongest contributing tier but capped at ``measured`` (composition is a
combination judgement, never deterministic proof).  OWASP: trifecta ->
MCP03 + MCP06 + LLM02 (+MCP07/MCP10 only when a selected leg's own
evidence carries them); shadowing -> MCP03 (NOT MCP09 - that is Shadow
MCP *Servers*, a different class).

The runner (server composition_jobs) injects members via the attribute
contract ``stage._member_results: list[MemberResult]`` before ``run``.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path

from fugu.types import AuditJob, EvidenceSnippet, Finding, StageResult

__all__ = [
    "Capability",
    "ExtensionNode",
    "MemberResult",
    "CompositionStage",
    "map_capabilities",
    "detect_trifecta",
    "detect_shadowing",
    "normalize_tool_name",
    "build_node",
]

# --- taxonomy (plain strings; NO enum added to types.py) ------------------------
LEG_KINDS = ("INGRESS", "PRIVATE-DATA", "EGRESS", "EXEC")
TRIFECTA_LEGS = ("INGRESS", "PRIVATE-DATA", "EGRESS")
MODIFIER_KINDS = ("INJECTION-CARRIER", "AGENT-INFLUENCE", "DEFENSE-GAP")

STRENGTH_ORDER = ("weak", "medium", "strong")
_STRENGTH_VALUE = {"weak": 1, "medium": 2, "strong": 3}
_CARRIER_OR_INFLUENCE = ("INJECTION-CARRIER", "AGENT-INFLUENCE")

# tier -> strength (docs/s6-contracts.md section 1)
_TIER_STRENGTH = {
    "deterministic": "strong",
    "empirical": "strong",
    "measured": "medium",
    "advisory": "weak",
}

# tier ranking for the confidence cap ("at most measured")
_TIER_RANK = {"advisory": 0, "measured": 1, "empirical": 2, "deterministic": 3}
_CAP_AT_MEASURED = {
    "deterministic": "measured",
    "empirical": "measured",
    "measured": "measured",
    "advisory": "advisory",
}

MAX_TRIFECTA_FINDINGS = 5

# --- static rule ids (verified against static_scan.STATIC_RULES; a unit
# test asserts membership so renames fail loudly instead of silently
# dropping capabilities) -------------------------------------------------------
_RULE_PRIVATE_DATA = ("env_harvest", "sensitive_path_access")
_RULE_EGRESS_EXEC = ("curl_raw_ip", "curl_pipe_shell", "install_script_fetch")
_RULE_EXEC = ("npm_install_hook", "setup_py_subprocess", "base64_decode_exec")
_RULE_CARRIER = ("skill_injection_phrase", "tool_description_injection")

# Title-substring fallbacks for findings that arrive without evidence
# meta["rule"] (stub children / unit fixtures).  Keys are lowercased
# substrings of the real S1 finding titles.
_TITLE_PRIVATE_DATA = ("environment-variable harvesting", "credential files")
_TITLE_EGRESS_EXEC = ("raw ip", "piped into a shell", "remote install script")
_TITLE_EXEC = ("install-time hook", "setup.py shells out", "base64-decode")
_TITLE_CARRIER = ("instruction-hijack", "injection phrasing")

# Semantic-stage findings carrying any of these owasp ids are carriers.
_SEMANTIC_CARRIER_OWASP = ("LLM01", "MCP03", "MCP06")

# Detonation finding titles (docker_driver.evidence_to_findings).
_DET_EXFIL_MARKERS = ("canary credential exfiltrated",)
_DET_PERSIST_MARKERS = ("canary credential persisted",)
_DET_EGRESS_MARKERS = ("unexpected network egress",)

# Ingress inventory: tool names/docs matching these verbs (word-bounded so
# "readme" does not match "read"; "_"/"-" count as boundaries).
_TOOL_VERB_RE = re.compile(r"(?:^|[^a-z0-9])(fetch|get|read|web|url|rss)(?:[^a-z0-9]|$)")

# --- deterministic text-scan layer (code files only) ----------------------------
# Findings-only mapping cannot see individually-CLEAN members - exactly the
# population composition audits (docs/s6-plan.md 1a always intended a direct
# deterministic inventory). Code patterns, never SKILL.md prose (prose words
# like "read-only" would false-positive; prose judgement is the semantic
# stage's job). Strength medium: the pattern match is provable, the
# capability inference (env read => private-data reach) is a heuristic, so a
# text-scan-only chain stays at medium severity / measured confidence.
_TEXT_SCAN_MAX_FILES = 200
_TEXT_SCAN_MAX_BYTES = 262_144
_CODE_SUFFIXES = (".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".mjs", ".pyw")

# env-var READS (not definitions) in code
_ENV_READ_RE = re.compile(
    r"os\.environ\.get\(|os\.getenv\(|os\.environ\[|process\.env\.|getenv\s*\("
)
# well-known sensitive locations referenced in code
_SENSITIVE_PATH_RE = re.compile(
    r"~/\.(?:ssh|aws|config|gitconfig|npmrc|netrc|gnupg|kube)|\bid_rsa\b|\.netrc\b|/\.ssh/|credentials\.json"
)
# python outbound-POST markers
_PY_POST_RE = re.compile(
    r"method=[\"']POST[\"']|requests\.post\(|httpx\.post\(|aiohttp\.(?:ClientSession|post)"
)
# python generic fetch markers (GET-shaped unless POST context in same file)
_PY_FETCH_RE = re.compile(
    r"urllib\.request\.urlopen\(|requests\.get\(|httpx\.get\(|urllib\.request\.Request\("
)
# python urllib Request carrying a body (POST semantics)
_PY_REQUEST_DATA_RE = re.compile(r"urllib\.request\.Request[\s\S]{0,400}?data\s*=")
_SHELL_CURL_RE = re.compile(r"\bcurl\b")
_SHELL_POST_FLAGS_RE = re.compile(r"-X\s*POST|--data\b|--data-|-d\s+|--json\b|-F\s+|-T\s+")


# --- data model (lives HERE, not in types.py - frozen contract section 1) ------
@dataclass
class Capability:
    """One capability fact about an extension node."""

    kind: str                          # a LEG_KINDS or MODIFIER_KINDS string
    strength: str                      # "strong" | "medium" | "weak"
    source_finding_title: str          # finding title or "tool surface: ..." pseudo-title
    evidence: EvidenceSnippet          # provenance; meta["tier"] carries the source tier


@dataclass
class ExtensionNode:
    """Per-member capability node the detectors reason over."""

    label: str
    slug: str
    capabilities: list[Capability] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class MemberResult:
    """One child audit's harvestable outcome (built by the runner)."""

    label: str
    slug: str
    findings: list[Finding] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    target_dir: Path | None = None


# --- capability mapper (pure) ---------------------------------------------------
def _tier_of(finding: Finding) -> str:
    return getattr(finding, "confidence", "advisory") or "advisory"


def _strength_for(finding: Finding) -> str:
    return _TIER_STRENGTH.get(_tier_of(finding), "weak")


def _downgrade(strength: str) -> str:
    """One notch down (strong -> medium); used for implied secondary legs."""
    return {"strong": "medium", "medium": "medium", "weak": "weak"}[strength]


def _cap_evidence(finding: Finding, rule: str | None) -> EvidenceSnippet:
    """Provenance snippet for a finding-derived capability."""
    ev = finding.evidence[0] if finding.evidence else None
    meta: dict = {
        "tier": _tier_of(finding),
        "severity": getattr(finding, "severity", None),
        "stage": getattr(finding, "stage", None),
    }
    if rule:
        meta["rule"] = rule
    return EvidenceSnippet(
        source=ev.source if ev else f"finding:{finding.title}",
        excerpt=(ev.excerpt if ev else finding.detail)[:500],
        meta=meta,
    )


def _rule_of(finding: Finding) -> str | None:
    for ev in finding.evidence:
        rule = ev.meta.get("rule")
        if rule:
            return str(rule)
    return None


def _map_static_finding(finding: Finding) -> list[tuple[str, str, str | None]]:
    """(kind, strength, rule) triples for one static-stage finding."""
    rule = _rule_of(finding)
    title = finding.title.lower()
    out: list[tuple[str, str, str | None]] = []

    def hit(rules: tuple[str, ...], titles: tuple[str, ...]) -> bool:
        return (rule in rules) if rule else any(t in title for t in titles)

    base = _strength_for(finding)
    if hit(_RULE_PRIVATE_DATA, _TITLE_PRIVATE_DATA):
        out.append(("PRIVATE-DATA", base, rule))
    if hit(_RULE_EGRESS_EXEC, _TITLE_EGRESS_EXEC):
        # curl-to-raw-IP / curl-pipe-shell / install-script fetch: the
        # egress leg is the primary fact; EXEC is implied, one notch down.
        out.append(("EGRESS", base, rule))
        out.append(("EXEC", _downgrade(base), rule))
    if hit(_RULE_EXEC, _TITLE_EXEC):
        out.append(("EXEC", base, rule))
    if hit(_RULE_CARRIER, _TITLE_CARRIER):
        out.append(("INJECTION-CARRIER", base, rule))
    return out


def _map_finding(finding: Finding) -> list[Capability]:
    stage = getattr(finding, "stage", "")
    title = finding.title.lower()
    owasp = list(getattr(finding, "owasp_ids", []) or [])
    caps: list[Capability] = []

    if stage == "static":
        for kind, strength, rule in _map_static_finding(finding):
            caps.append(Capability(kind, strength, finding.title, _cap_evidence(finding, rule)))
    elif stage == "concealment":
        # Any concealment family: hidden codepoints are a carrier for
        # smuggled instructions (payload families escalate on their own in
        # S0; here the carrier fact is what composition needs).
        caps.append(
            Capability("INJECTION-CARRIER", _strength_for(finding), finding.title,
                       _cap_evidence(finding, None))
        )
    elif stage == "semantic":
        if any(o in _SEMANTIC_CARRIER_OWASP for o in owasp):
            caps.append(
                Capability("INJECTION-CARRIER", _strength_for(finding), finding.title,
                           _cap_evidence(finding, None))
            )
    elif stage == "detonation":
        if any(m in title for m in _DET_EXFIL_MARKERS) or (
            "LLM02" in owasp and "MCP01" in owasp and "exfiltrat" in title
        ):
            for kind in ("EGRESS", "PRIVATE-DATA"):
                caps.append(
                    Capability(kind, "strong", finding.title, _cap_evidence(finding, None))
                )
        elif any(m in title for m in _DET_PERSIST_MARKERS):
            caps.append(
                Capability("PRIVATE-DATA", "strong", finding.title, _cap_evidence(finding, None))
            )
        elif any(m in title for m in _DET_EGRESS_MARKERS) or "MCP07" in owasp:
            caps.append(
                Capability("EGRESS", "medium", finding.title, _cap_evidence(finding, None))
            )
    elif stage == "harness":
        # disclose/target/sensitive/directive signals: the extension
        # demonstrably steers a mounted agent (AGENT-INFLUENCE modifier).
        caps.append(
            Capability("AGENT-INFLUENCE", _strength_for(finding), finding.title,
                       _cap_evidence(finding, None))
        )
    return caps


def _ingress_from_tools(tool_names: list[str]) -> list[Capability]:
    """Tool surface matching fetch|get|read|web|url|rss -> INGRESS medium."""
    matched: list[str] = []
    for name in tool_names or []:
        low = str(name).lower()
        if _TOOL_VERB_RE.search(low):
            matched.append(str(name))
    if not matched:
        return []
    pseudo_title = "tool surface: " + ", ".join(matched[:5])
    return [
        Capability(
            kind="INGRESS",
            strength="medium",
            source_finding_title=pseudo_title,
            evidence=EvidenceSnippet(
                source=f"tools:{matched[0]}",
                excerpt=f"tool names matching ingress verbs: {', '.join(matched[:8])}"[:500],
                meta={"tier": "measured", "tools": matched[:20]},
            ),
        )
    ]


def _scan_member_tree(target_dir: Path | None) -> list[tuple[Path, str]]:
    """Bounded walk of code files under the member's extracted tree."""
    if target_dir is None:
        return []
    out: list[tuple[Path, str]] = []
    try:
        for path in sorted(target_dir.rglob("*")):
            if len(out) >= _TEXT_SCAN_MAX_FILES:
                break
            if not path.is_file() or path.suffix not in _CODE_SUFFIXES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[:_TEXT_SCAN_MAX_BYTES]
            except OSError:
                continue
            out.append((path, text))
    except OSError:
        pass
    return out


def _capabilities_from_code_scan(
    files: list[tuple[Path, str]],
) -> list[Capability]:
    """Deterministic code-pattern inventory for individually-clean members.

    File-level for python (a POST anywhere in the file colours the whole
    file's fetches as POST-capable; single-file members make this exact),
    line-level for shell curl (a curl line is egress only when it carries
    POST-ish flags or a data body). INGRESS comes from generic fetch calls
    in files with no POST semantics - the pull-content-in side of the
    trifecta, distinct from the push-out egress leg.
    """
    caps: list[Capability] = []

    def cap(kind: str, title: str, src: str, excerpt: str) -> Capability:
        return Capability(
            kind=kind,
            strength="medium",
            source_finding_title=title,
            evidence=EvidenceSnippet(
                source=src,
                excerpt=excerpt[:500],
                meta={"tier": "measured", "scanner": "text-scan"},
            ),
        )

    for path, text in files:
        py = path.suffix == ".py"
        rel = path.name
        if py:
            if _ENV_READ_RE.search(text) or _SENSITIVE_PATH_RE.search(text):
                caps.append(cap(
                    "PRIVATE-DATA",
                    f"reads environment variables / sensitive paths ({rel})",
                    f"file:{rel}",
                    next(
                        (m.group(0) for m in [
                            _ENV_READ_RE.search(text), _SENSITIVE_PATH_RE.search(text)
                        ] if m),
                        "",
                    ),
                ))
            post = bool(_PY_POST_RE.search(text) or _PY_REQUEST_DATA_RE.search(text))
            if post:
                caps.append(cap(
                    "EGRESS",
                    f"outbound HTTP POST in code ({rel})",
                    f"file:{rel}",
                    next(
                        (m.group(0) for m in [
                            _PY_POST_RE.search(text), _PY_REQUEST_DATA_RE.search(text)
                        ] if m),
                        "",
                    ),
                ))
            elif _PY_FETCH_RE.search(text):
                caps.append(cap(
                    "INGRESS",
                    f"fetches remote content in code ({rel})",
                    f"file:{rel}",
                    _PY_FETCH_RE.search(text).group(0),  # type: ignore[union-attr]
                ))
        else:
            # shell: line-level curl analysis
            for line_no, line in enumerate(text.splitlines(), 1):
                if not _SHELL_CURL_RE.search(line):
                    continue
                post = bool(_SHELL_POST_FLAGS_RE.search(line))
                kind = "EGRESS" if post else "INGRESS"
                caps.append(cap(
                    kind,
                    f"{'outbound POST' if post else 'curl fetch'} in {rel}:L{line_no}",
                    f"file:{rel}:L{line_no}",
                    line.strip()[:200],
                ))
    return caps


def map_capabilities(
    findings: list[Finding],
    tool_names: list[str],
    target_dir: Path | None = None,
) -> list[Capability]:
    """Fold one member's findings + tool names + code scan into capabilities.

    Deterministic, order-preserving: capabilities appear in finding order
    (static rules emit primary leg before implied secondary), then the
    tool-surface ingress capability, then the text-scan inventory.  Exact
    duplicates (same kind, strength and source title) are dropped.
    """
    caps: list[Capability] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings or []:
        for cap_ in _map_finding(finding):
            key = (cap_.kind, cap_.strength, cap_.source_finding_title)
            if key in seen:
                continue
            seen.add(key)
            caps.append(cap_)
    caps.extend(_ingress_from_tools(tool_names or []))
    for cap_ in _capabilities_from_code_scan(_scan_member_tree(target_dir)):
        key = (cap_.kind, cap_.strength, cap_.source_finding_title)
        if key in seen:
            continue
        seen.add(key)
        caps.append(cap_)
    return caps


def build_node(member: MemberResult) -> ExtensionNode:
    """MemberResult -> ExtensionNode (pure convenience over map_capabilities)."""
    return ExtensionNode(
        label=member.label,
        slug=member.slug,
        capabilities=map_capabilities(member.findings, member.tool_names, member.target_dir),
        tool_names=list(member.tool_names or []),
        findings=list(member.findings or []),
    )


# --- node-level views used by detectors ------------------------------------------
def _best_by_kind(node: ExtensionNode) -> dict[str, Capability]:
    """Strongest capability per kind (ties -> first in declaration order)."""
    best: dict[str, Capability] = {}
    for cap in node.capabilities:
        cur = best.get(cap.kind)
        if cur is None or _STRENGTH_VALUE[cap.strength] > _STRENGTH_VALUE[cur.strength]:
            best[cap.kind] = cap
    return best


def _has_modifier(node: ExtensionNode, kinds: tuple[str, ...]) -> bool:
    return any(cap.kind in kinds for cap in node.capabilities)


# --- tool-name normalization (frozen contract section 2) -------------------------
def normalize_tool_name(name: str) -> str:
    """lowercase; strip ``mcp__server__`` style prefixes; collapse non-alphanumerics.

    MCP qualified-name convention (``mcp__<server>__<tool>`` and the bare
    ``<server>__<tool>`` form) puts the tool identity in the LAST
    double-underscore segment, so that segment is the normalized identity:
    ``mcp__fs__read_file``, ``fs__read_file`` and ``read-file`` all
    normalize to ``readfile``.
    """
    s = str(name).strip().lower()
    if "__" in s:
        tail = s.rsplit("__", 1)[-1]
        s = tail if tail else s
    return re.sub(r"[^a-z0-9]+", "", s)


# --- trifecta detector (pure) ------------------------------------------------------
def _covers(combo: tuple[ExtensionNode, ...]) -> bool:
    union: set[str] = set()
    for node in combo:
        union.update(_best_by_kind(node))
    return all(leg in union for leg in TRIFECTA_LEGS)


def _is_minimal(combo: tuple[ExtensionNode, ...]) -> bool:
    """No member is redundant: removing ANY member must break coverage.

    This single check prunes supersets (a 3-combo whose 2-subset covers)
    and refuses single self-sufficient extensions dressed up with clean
    neighbours (removing the neighbour keeps coverage -> non-minimal).
    """
    for i in range(len(combo)):
        rest = combo[:i] + combo[i + 1 :]
        if _covers(rest):
            return False
    return True


def _selected_legs(
    combo: tuple[ExtensionNode, ...],
) -> dict[str, tuple[ExtensionNode, Capability]]:
    """Per trifecta leg: the strongest contributing (node, capability)."""
    picked: dict[str, tuple[ExtensionNode, Capability]] = {}
    for leg in TRIFECTA_LEGS:
        for node in combo:
            cap = _best_by_kind(node).get(leg)
            if cap is None:
                continue
            cur = picked.get(leg)
            if cur is None or _STRENGTH_VALUE[cap.strength] > _STRENGTH_VALUE[cur[1].strength]:
                picked[leg] = (node, cap)
    return picked


def detect_trifecta(nodes: list[ExtensionNode]) -> list[Finding]:
    """Minimal cross-extension INGRESS + PRIVATE-DATA + EGRESS combos (pure).

    Combos of 2-3 DISTINCT leg-bearing extensions; every member must
    contribute (minimality); ranked by leg-strength sum with +3 when an
    ingress-providing member is INJECTION-CARRIER or AGENT-INFLUENCE;
    at most ``MAX_TRIFECTA_FINDINGS`` findings, deterministic order.
    """
    legged = [n for n in nodes if any(k in _best_by_kind(n) for k in TRIFECTA_LEGS)]
    candidates: list[tuple[ExtensionNode, ...]] = []
    for size in (2, 3):
        for combo in combinations(legged, size):
            if _covers(combo) and _is_minimal(combo):
                candidates.append(combo)

    scored: list[tuple[int, tuple[str, ...], tuple[ExtensionNode, ...]]] = []
    for combo in candidates:
        legs = _selected_legs(combo)
        score = sum(_STRENGTH_VALUE[legs[leg][1].strength] for leg in TRIFECTA_LEGS)
        if any(
            "INGRESS" in _best_by_kind(node) and _has_modifier(node, _CARRIER_OR_INFLUENCE)
            for node in combo
        ):
            score += 3
        scored.append((score, tuple(sorted(n.slug for n in combo)), combo))
    scored.sort(key=lambda t: (-t[0], t[1]))

    findings: list[Finding] = []
    for _score, _slugs, combo in scored[:MAX_TRIFECTA_FINDINGS]:
        finding = _trifecta_finding(combo)
        if finding is not None:
            findings.append(finding)
    return findings


def _trifecta_finding(combo: tuple[ExtensionNode, ...]) -> Finding | None:
    legs = _selected_legs(combo)
    if len(legs) != len(TRIFECTA_LEGS):  # defensive; _covers guarantees this
        return None

    # Canonical member order: role order (ingress provider, private-data
    # provider, egress provider, then any extra members by slug), members
    # deduped.  Makes findings identical under any input permutation.
    ordered: list[ExtensionNode] = []
    seen_slugs: set[str] = set()
    for leg in TRIFECTA_LEGS:
        n = legs[leg][0]
        if n.slug not in seen_slugs:
            seen_slugs.add(n.slug)
            ordered.append(n)
    for n in sorted(combo, key=lambda x: x.slug):
        if n.slug not in seen_slugs:
            seen_slugs.add(n.slug)
            ordered.append(n)
    combo = tuple(ordered)

    labels = [n.label for n in combo]
    strengths = {leg: legs[leg][1].strength for leg in TRIFECTA_LEGS}
    tiers = [legs[leg][1].evidence.meta.get("tier", "advisory") for leg in TRIFECTA_LEGS]
    has_strong = any(s == "strong" for s in strengths.values())
    all_weak = all(s == "weak" for s in strengths.values())
    has_carrier = any(_has_modifier(n, _CARRIER_OR_INFLUENCE) for n in combo)

    evidence = [
        EvidenceSnippet(
            source=f"member:{legs[leg][0].slug}:{legs[leg][1].source_finding_title}",
            excerpt=legs[leg][1].evidence.excerpt[:500],
            meta={
                "leg": leg,
                "member": legs[leg][0].label,
                "strength": legs[leg][1].strength,
                "tier": legs[leg][1].evidence.meta.get("tier"),
            },
        )
        for leg in TRIFECTA_LEGS
    ]

    chain = " -> ".join(
        f"{leg.lower().replace('private-data', 'private data')} via "
        f"{legs[leg][0].label} ({strengths[leg]})"
        for leg in TRIFECTA_LEGS
    )

    # OWASP: base trio; +MCP07/MCP10 only where a selected leg's own
    # finding carries them (e.g. egress leg sourced from detonation's
    # unexpected-egress finding).
    owasp = ["MCP03", "MCP06", "LLM02"]
    leg_owasp: set[str] = set()
    for leg in TRIFECTA_LEGS:
        node, cap = legs[leg]
        for f in node.findings:
            if f.title == cap.source_finding_title:
                leg_owasp.update(f.owasp_ids)
                break
    for extra in ("MCP07", "MCP10"):
        if extra in leg_owasp and extra not in owasp:
            owasp.append(extra)

    if has_strong:
        severity = "high"
        confidence = "measured"  # strongest tier capped at measured
        title = f"Lethal trifecta across installed set ({', '.join(labels)})"
        detail = (
            f"Composition chain: {chain}. Each member is individually unremarkable, "
            "but installed together they form Willison's lethal trifecta - untrusted "
            "content can flow in, private data can be reached, and an egress channel "
            "exists to carry it out. No single-extension audit can see this path; "
            "review whether the combination is intended."
        )
    elif all_weak and not has_carrier:
        severity = "low"
        confidence = "advisory"
        title = f"Weak trifecta legs co-exist ({', '.join(labels)}) - hygiene note"
        detail = (
            f"Hygiene note: advisory-tier capabilities co-exist across the installed "
            f"set ({chain}) but no injection carrier or agent-influence signal "
            "connects them. This is a WARN-level note for reviewers, not proof of "
            "an attack path."
        )
    else:
        severity = "medium"
        confidence = (
            "measured" if any(_TIER_RANK.get(t, 0) >= _TIER_RANK["measured"] for t in tiers)
            else "advisory"
        )
        title = f"Potential trifecta across installed set ({', '.join(labels)})"
        warn = (
            " WARN-level: every leg rests on advisory evidence only."
            if all_weak
            else ""
        )
        detail = (
            f"Composition chain: {chain}. The three legs are covered only at "
            f"medium-or-weaker strength, so this is a review prompt rather than a "
            f"confirmed exfiltration path.{warn} The chain is a property of the "
            "installed set, not of any single member."
        )

    return Finding(
        owasp_ids=owasp,
        title=title,
        detail=detail,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        stage="composition",
        evidence=evidence,
    )


# --- shadowing detector (pure) -------------------------------------------------------
def detect_shadowing(nodes: list[ExtensionNode]) -> list[Finding]:
    """Cross-extension normalized tool-name collisions (pure).

    One finding per collision group (same normalized name defined by >= 2
    DISTINCT members).  Collisions within a single member are S1's
    ``mcp_duplicate_tool_names`` territory, not composition.  Severity
    medium; high when any colliding member is an INJECTION-CARRIER (in a
    collision group without install order, a carrier member is exactly
    the tool-poisoning shape OWASP MCP03 describes).
    """
    index: dict[str, dict[str, tuple[str, str]]] = {}  # norm -> slug -> (label, raw name)
    for node in nodes:
        seen_raw: set[str] = set()
        for raw in node.tool_names or []:
            name = str(raw)
            if name in seen_raw:
                continue
            seen_raw.add(name)
            norm = normalize_tool_name(name)
            if not norm:
                continue
            index.setdefault(norm, {})[node.slug] = (node.label, name)

    findings: list[Finding] = []
    for norm in sorted(k for k, v in index.items() if len(v) >= 2):
        members = index[norm]
        by_node = {n.slug: n for n in nodes}
        ordered = [by_node[slug] for slug in members if slug in by_node]
        carrier = [n for n in ordered if _has_modifier(n, ("INJECTION-CARRIER",))]
        severity = "high" if carrier else "medium"
        labels = [members[n.slug][0] for n in ordered]
        names = [members[n.slug][1] for n in ordered]
        evidence = [
            EvidenceSnippet(
                source=f"tools:{members[n.slug][1]}",
                excerpt=(
                    f"tool {members[n.slug][1]!r} in member {members[n.slug][0]!r} "
                    f"normalizes to {norm!r}"
                )[:500],
                meta={"normalized": norm, "member": n.slug, "raw": members[n.slug][1]},
            )
            for n in ordered
        ]
        carrier_note = (
            f" Member '{carrier[0].label}' is an injection carrier, so the collision "
            "is a plausible tool-poisoning setup rather than an accident."
            if carrier
            else " No colliding member is an injection carrier."
        )
        findings.append(
            Finding(
                owasp_ids=["MCP03"],
                title=f"Cross-extension tool shadowing: '{norm}' defined by {len(ordered)} members",
                detail=(
                    f"Tool names {', '.join(repr(n) for n in names)} (members "
                    f"{', '.join(labels)}) all normalize to '{norm}'. A client that "
                    "mounts both extensions resolves the same tool name ambiguously - "
                    "the later-mounted definition silently shadows the other, and the "
                    "calling agent cannot tell which implementation it reached."
                    f"{carrier_note}"
                ),
                severity=severity,  # type: ignore[arg-type]
                confidence="deterministic",
                stage="composition",
                evidence=evidence,
            )
        )
    return findings


# --- the stage -----------------------------------------------------------------------
class CompositionStage:
    """S6 - capability composition over multiple member audits.

    Implements the Stage protocol (``name`` + ``async run(job, target)``).
    The runner injects the member harvest via the attribute contract
    ``stage._member_results: list[MemberResult]`` before calling ``run``;
    missing/empty members means a single-source job and the stage no-ops.
    """

    name = "composition"

    # Runner (composition_jobs) sets this attribute before run; None/empty
    # means a single-source job and the stage no-ops. Class default is None
    # (never a shared mutable list).
    _member_results: list[MemberResult] | None = None

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        t0 = time.perf_counter()
        members = list(getattr(self, "_member_results", None) or [])
        if not members:
            return StageResult(
                stage=self.name,
                ok=True,
                metrics={"skipped": "single-source job"},
            )
        try:
            nodes = [build_node(m) for m in members]
            findings = detect_trifecta(nodes) + detect_shadowing(nodes)
        except Exception as exc:  # noqa: BLE001 - stage must not raise
            return StageResult(stage=self.name, ok=False, error=f"{type(exc).__name__}: {exc}")

        cap_counts: dict[str, int] = {}
        for node in nodes:
            for cap in node.capabilities:
                cap_counts[cap.kind] = cap_counts.get(cap.kind, 0) + 1
        return StageResult(
            stage=self.name,
            ok=True,
            findings=findings,
            metrics={
                "members": len(nodes),
                "capabilities": cap_counts,
                "trifectas": sum(1 for f in findings if "MCP06" in f.owasp_ids),
                "shadowing": sum(1 for f in findings if f.owasp_ids == ["MCP03"]),
                "duration_s": round(time.perf_counter() - t0, 4),
            },
        )
