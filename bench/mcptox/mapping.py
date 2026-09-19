"""Category -> OWASP mapping for MCPTox risk categories (arXiv 2508.14925).

MCPTox labels every attack instance with one of 11 ``security risk``
categories (their ``attack_scopes`` list) and one of 3 attack paradigms:

  Template-1  explicit-trigger function hijack   (poisoned tool, when called,
              openly instructs the agent to run a *different* tool first)
  Template-2  implicit-trigger function hijack    (hidden rule + plausible
              justification; malicious action performed by a legit tool)
  Template-3  implicit-trigger parameter tampering (arguments of the legit
              tool call are silently rewritten, e.g. path -> ~/.ssh/id_rsa)

Fugu reports OWASP ids (``fugu.types.OWASP_IDS``: MCP01..MCP10 + MCP04B +
LLM01/02/03/06). The mapping below converts each MCPTox category to the ids
a fugu *manifest* should expect from a correct detector. It encodes what the
poisoned description DOES, not merely the category name:

  every category    -> LLM01 (prompt injection) + MCP03 (tool poisoning):
                       the attack vector itself is a poisoned description.
  Template-3 cases  -> + MCP06 (intent flow subversion): the description
                       overrides the user's stated intent ("priority is
                       higher than the user's query").
  outcome categories add the id matching the intended harm.

Documented unmappable ids:
  MCP04/MCP04B/LLM03 (supply chain, rug pull): MCPTox poisons *descriptions*
      on live real servers - there is no dependency/packaging/drift signal
      in a case. Not expected, never mapped.
  MCP05 (command injection): no shell/eval sink is added; the malicious
      action is executed by legitimate tools. Not expected, never mapped.
  MCP07 (authn/authz gaps), MCP08 (audit gaps), MCP09 (shadowing),
      MCP10 (context over-sharing): architectural properties of a server,
      absent from a description-only attack. Never mapped.
  "Other" (4/1312 cases): upstream catch-all; we map it to the
      always-present vector ids only and mark it unmappable-beyond-vector.
"""
from __future__ import annotations

# Vector ids present in EVERY tool-poisoning case regardless of category.
VECTOR_IDS: tuple[str, ...] = ("LLM01", "MCP03")

# Ids added when the attack rewrites what the user asked for (Template-3
# shape: "automatically modify the ... argument regardless of the original").
INTENT_OVERRIDE_IDS: tuple[str, ...] = ("MCP06",)

# Per-category outcome ids (beyond the vector ids).
CATEGORY_OUTCOME_IDS: dict[str, tuple[str, ...]] = {
    "Credential Leakage": ("MCP01",),          # credentials read/moved/leaked
    "Privacy Leakage": ("LLM02",),             # private data disclosed
    "Message Hijacking": ("MCP06",),           # output/recipient redirected
    "Code Injection": ("MCP05",),              # JS/script injected via evaluate
    "Data Tampering": ("LLM06",),              # destructive write w/o consent
    "Instruction Tampering": ("MCP06",),       # agent instructions overridden
    "Information Manipulation": ("MCP06",),    # fabricated/altered answers
    "Financial Loss": ("LLM06",),              # unwanted payment action
    "Service Disruption": ("LLM06",),          # service disabled/degraded
    "Infrastructure Damage": ("LLM06",),       # infra destroyed/disabled
    # "Other" intentionally absent: catch-all, vector ids only (see module doc).
}

# Full expected-id sets, precomputed for manifest writing and tests.
CATEGORY_TO_OWASP: dict[str, tuple[str, ...]] = {
    cat: tuple(dict.fromkeys(VECTOR_IDS + outcome))
    for cat, outcome in CATEGORY_OUTCOME_IDS.items()
}

# The 11 upstream categories (their order, from response_all.json attack_scopes).
ALL_CATEGORIES: tuple[str, ...] = (
    "Credential Leakage", "Privacy Leakage", "Message Hijacking",
    "Code Injection", "Data Tampering", "Instruction Tampering",
    "Information Manipulation", "Financial Loss", "Service Disruption",
    "Infrastructure Damage", "Other",
)

# Categories with no outcome id beyond the poisoning vector (documented
# unmappable-beyond-vector); kept explicit for report generation.
UNMAPPABLE_BEYOND_VECTOR: tuple[str, ...] = ("Other",)


def expected_owasp_ids(category: str, paradigm: str | None = None) -> list[str]:
    """Expected fugu OWASP ids for one MCPTox case.

    ``paradigm`` ("Template-1" | "Template-2" | "Template-3") adds MCP06 for
    the intent-override shapes (Template-3 rewrites arguments; Template-2
    hijacks the call flow against the user's request). Unknown categories
    (e.g. upstream typos) fall back to the vector ids alone.
    """
    ids = list(CATEGORY_TO_OWASP.get(category, VECTOR_IDS))
    if paradigm in ("Template-2", "Template-3"):
        for oid in INTENT_OVERRIDE_IDS:
            if oid not in ids:
                ids.append(oid)
    return ids


__all__ = [
    "VECTOR_IDS",
    "INTENT_OVERRIDE_IDS",
    "CATEGORY_OUTCOME_IDS",
    "CATEGORY_TO_OWASP",
    "ALL_CATEGORIES",
    "UNMAPPABLE_BEYOND_VECTOR",
    "expected_owasp_ids",
]
