"""Unit tests for the S6 composition core.

Hermetic: pure functions + the stage with attribute-injected members; no
server, no LLM, no docker. Asserts capability and verdict boundaries from
docs/s6-contracts.md sections 1-2:

* mapper per producer (static rule ids verified against the real
  STATIC_RULES so renames fail loudly; concealment/semantic/detonation/
  harness; tool-verb ingress),
* trifecta: distinctness, minimality, superset pruning, single-ext
  non-reporting, ranking, <= 5 emitted,
* honesty rules (weak co-existence -> low/advisory; all-advisory legs ->
  at most medium, WARN wording),
* severity policy + OWASP ids (MCP03+MCP06+LLM02, +MCP07 from leg
  evidence),
* tool-name overlap notes: normalization, grouping, and no unsupported
  claim of runtime namespace or client resolution,
* stage protocol: skip path, member injection, never raises,
* evidence source formats ``member:<slug>:<title>`` / ``tools:<name>``,
* 50-node performance sanity (< 1s).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fugu.pipeline.base import Stage  # noqa: E402
from fugu.pipeline.stages.composition import (  # noqa: E402
    Capability,
    CompositionStage,
    ExtensionNode,
    MemberResult,
    build_node,
    detect_shadowing,
    detect_trifecta,
    map_capabilities,
    normalize_tool_name,
)
from fugu.pipeline.stages.static_scan import STATIC_RULES  # noqa: E402
from fugu.types import AuditJob, EvidenceSnippet, Finding  # noqa: E402


# --- helpers ---------------------------------------------------------------------
def ev(tier: str, rule: str | None = None) -> list[EvidenceSnippet]:
    meta = {"tier": tier}
    if rule:
        meta["rule"] = rule
    return [EvidenceSnippet(source=f"file:x.py:L1", excerpt="x", meta=meta)]


def static_finding(title: str, rule: str | None, *, tier: str = "deterministic",
                   severity: str = "high", owasp: list[str] | None = None) -> Finding:
    return Finding(
        owasp_ids=owasp or ["MCP05", "LLM01"],
        title=title,
        detail="d",
        severity=severity,  # type: ignore[arg-type]
        confidence=tier,  # type: ignore[arg-type]
        stage="static",
        evidence=ev(tier, rule),
    )


def node(slug: str, findings: list[Finding] | None = None,
         tools: list[str] | None = None) -> ExtensionNode:
    return build_node(MemberResult(label=slug, slug=slug, findings=findings or [],
                                   tool_names=tools or []))


def member(slug: str, findings: list[Finding] | None = None,
           tools: list[str] | None = None) -> MemberResult:
    return MemberResult(label=slug, slug=slug, findings=findings or [], tool_names=tools or [])


INGRESS_TOOLS = ["fetch_page", "get_web_content"]              # fetch/get/web verbs
PRIVATE_RULE = "env_harvest"                                    # PRIVATE-DATA
EGRESS_RULE = "curl_raw_ip"                                     # EGRESS(+EXEC)


# --- producer-literal guard ----------------------------------------------------------
RULE_IDS = {r.rule_id for r in STATIC_RULES}


@pytest.mark.parametrize("rule", [
    "env_harvest", "sensitive_path_access", "curl_raw_ip", "curl_pipe_shell",
    "install_script_fetch", "npm_install_hook", "setup_py_subprocess",
    "base64_decode_exec", "skill_injection_phrase", "tool_description_injection",
])
def test_rule_ids_exist_in_static_scan(rule: str) -> None:
    """The rule literals the mapper keys on are the REAL S1 rule ids."""
    assert rule in RULE_IDS


# --- mapper: static --------------------------------------------------------------
def test_static_private_data_rules() -> None:
    for rule in ("env_harvest", "sensitive_path_access"):
        caps = map_capabilities(
            [static_finding(f"T in a.py", rule)], []
        )
        assert [(c.kind, c.strength) for c in caps] == [("PRIVATE-DATA", "strong")]


def test_static_egress_rules_carry_exec_one_notch_down() -> None:
    for rule in ("curl_raw_ip", "curl_pipe_shell", "install_script_fetch"):
        caps = map_capabilities([static_finding(f"T in a.py", rule)], [])
        assert [(c.kind, c.strength) for c in caps] == [("EGRESS", "strong"), ("EXEC", "medium")]


def test_static_exec_rules() -> None:
    for rule in ("npm_install_hook", "setup_py_subprocess", "base64_decode_exec"):
        caps = map_capabilities([static_finding(f"T in a.py", rule)], [])
        assert [(c.kind, c.strength) for c in caps] == [("EXEC", "strong")]


def test_static_carrier_rules() -> None:
    for rule in ("skill_injection_phrase", "tool_description_injection"):
        caps = map_capabilities([static_finding(f"T in a.md", rule)], [])
        assert [(c.kind, c.strength) for c in caps] == [("INJECTION-CARRIER", "strong")]


def test_static_tier_to_strength_mapping() -> None:
    tiers = [("deterministic", "strong"), ("empirical", "strong"),
             ("measured", "medium"), ("advisory", "weak")]
    for tier, strength in tiers:
        caps = map_capabilities([static_finding("T in a.py", "env_harvest", tier=tier)], [])
        assert caps[0].strength == strength


def test_static_title_fallback_without_rule_meta() -> None:
    """Findings without evidence meta['rule'] (stub children) still map via titles."""
    f = Finding(owasp_ids=["MCP01", "LLM02"], title="Environment-variable harvesting in x.py",
                detail="d", severity="high", confidence="deterministic", stage="static",
                evidence=[EvidenceSnippet(source="file:x.py:L1", excerpt="x",
                                          meta={"tier": "deterministic"})])
    caps = map_capabilities([f], [])
    assert [(c.kind, c.strength) for c in caps] == [("PRIVATE-DATA", "strong")]


def test_static_unmapped_rule_yields_nothing() -> None:
    caps = map_capabilities([static_finding("T in a.py", "typosquat_hint")], [])
    assert caps == []


# --- mapper: other producers --------------------------------------------------------
def test_concealment_maps_carrier_strong() -> None:
    f = Finding(owasp_ids=["LLM01", "MCP03"], title="Unicode Tags-block smuggling in a.md",
                detail="d", severity="critical", confidence="deterministic",
                stage="concealment", evidence=ev("deterministic"))
    assert [(c.kind, c.strength) for c in map_capabilities([f], [])] == [
        ("INJECTION-CARRIER", "strong")
    ]


def test_semantic_carrier_owasp_weak() -> None:
    for owasp in (["LLM01"], ["MCP03"], ["MCP06"], ["MCP06", "LLM01"]):
        f = Finding(owasp_ids=owasp, title="Suspicious directives", detail="d",
                    severity="medium", confidence="advisory", stage="semantic",
                    evidence=ev("advisory"))
        assert [(c.kind, c.strength) for c in map_capabilities([f], [])] == [
            ("INJECTION-CARRIER", "weak")
        ]
    # unrelated owasp ids map to nothing
    f = Finding(owasp_ids=["MCP04"], title="x", detail="d", severity="low",
                confidence="advisory", stage="semantic", evidence=ev("advisory"))
    assert map_capabilities([f], []) == []


def test_detonation_canary_exfil_maps_egress_and_private_strong() -> None:
    f = Finding(owasp_ids=["LLM02", "MCP01"],
                title="Canary credential exfiltrated over the network",
                detail="d", severity="critical", confidence="deterministic",
                stage="detonation", evidence=ev("deterministic"))
    assert [(c.kind, c.strength) for c in map_capabilities([f], [])] == [
        ("EGRESS", "strong"), ("PRIVATE-DATA", "strong")
    ]


def test_detonation_persist_maps_private_strong() -> None:
    f = Finding(owasp_ids=["MCP01"], title="Canary credential persisted to disk",
                detail="d", severity="high", confidence="deterministic",
                stage="detonation", evidence=ev("deterministic"))
    assert [(c.kind, c.strength) for c in map_capabilities([f], [])] == [
        ("PRIVATE-DATA", "strong")
    ]


def test_detonation_unexpected_egress_is_medium_regardless_of_tier() -> None:
    for tier in ("empirical", "deterministic"):  # contract: EGRESS medium, fixed
        f = Finding(owasp_ids=["MCP07", "LLM02"],
                    title="Unexpected network egress during trigger execution",
                    detail="d", severity="medium", confidence=tier,  # type: ignore[arg-type]
                    stage="detonation", evidence=ev(tier))
        assert [(c.kind, c.strength) for c in map_capabilities([f], [])] == [
            ("EGRESS", "medium")
        ]


def test_harness_finding_maps_agent_influence() -> None:
    for title in (
        "Agent disclosed the canary secret under extension influence",
        "Agent attempted to access the canary secret on the extension's behalf",
        "Agent reached for sensitive resources only when extension mounted",
        "Agent adopted the extension's embedded directives",
    ):
        f = Finding(owasp_ids=["MCP06", "LLM01"], title=title, detail="d",
                    severity="high", confidence="empirical", stage="harness",
                    evidence=ev("empirical"))
        assert [(c.kind, c.strength) for c in map_capabilities([f], [])] == [
            ("AGENT-INFLUENCE", "strong")
        ]


def test_tool_verb_ingress_medium() -> None:
    for tools in (["fetch_page"], ["read_file"], ["web_search"], ["url_loader"],
                  ["get_feed"], ["rss_reader"], ["MCP__news__Fetch_Headlines"]):
        caps = map_capabilities([], tools)
        assert [(c.kind, c.strength) for c in caps] == [("INGRESS", "medium")], tools


def test_tool_verb_requires_word_boundary() -> None:
    # "readme", "targeting" must NOT match the read/get verbs
    assert map_capabilities([], ["readme_writer", "targeting", "progress"]) == []


def test_mapper_drops_exact_duplicates_and_preserves_order() -> None:
    f1 = static_finding("T in a.py", "env_harvest")
    caps = map_capabilities([f1, f1], [])
    assert len(caps) == 1
    f2 = static_finding("T in b.py", "env_harvest")  # different title kept
    assert len(map_capabilities([f1, f2], [])) == 2


def test_capability_evidence_carries_source_meta() -> None:
    caps = map_capabilities([static_finding("T in a.py", "env_harvest")], [])
    assert caps[0].evidence.meta["rule"] == "env_harvest"
    assert caps[0].evidence.meta["tier"] == "deterministic"
    assert caps[0].evidence.source == "file:x.py:L1"


# --- trifecta: structure ---------------------------------------------------------------
def _canon_trifecta_nodes() -> list[ExtensionNode]:
    return [
        node("web-digest", tools=INGRESS_TOOLS),
        node("notes-lookup", findings=[static_finding("T in n.py", PRIVATE_RULE)]),
        node("status-poster", findings=[static_finding("T in s.py", EGRESS_RULE)]),
    ]


def test_canonical_trifecta_fires() -> None:
    findings = detect_trifecta(_canon_trifecta_nodes())
    assert len(findings) == 1
    f = findings[0]
    assert f.stage == "composition"
    assert f.owasp_ids[:3] == ["MCP03", "MCP06", "LLM02"]
    assert f.severity == "high"          # strong legs present
    assert f.confidence == "measured"    # capped at measured
    assert len(f.evidence) == 3
    legs = {e.meta["leg"] for e in f.evidence}
    assert legs == {"INGRESS", "PRIVATE-DATA", "EGRESS"}
    for e in f.evidence:
        assert e.source.startswith("member:")
        # format member:<slug>:<finding-title>
        rest = e.source[len("member:"):]
        slug, _, title = rest.partition(":")
        assert slug and title


def test_trifecta_is_order_invariant_in_membership() -> None:
    import itertools as it

    base = _canon_trifecta_nodes()
    titles = {detect_trifecta(list(p))[0].title for p in it.permutations(base)}
    # canonical member ordering makes every permutation produce the same finding
    assert len(titles) == 1
    assert all("web-digest" in t and "notes-lookup" in t and "status-poster" in t for t in titles)


def test_trifecta_requires_all_three_legs() -> None:
    assert detect_trifecta([
        node("a", tools=INGRESS_TOOLS),
        node("b", findings=[static_finding("T in b.py", PRIVATE_RULE)]),
    ]) == []  # no egress
    assert detect_trifecta([
        node("b", findings=[static_finding("T in b.py", PRIVATE_RULE)]),
        node("c", findings=[static_finding("T in c.py", EGRESS_RULE)]),
    ]) == []  # no ingress


def test_trifecta_requires_two_distinct_extensions() -> None:
    # single self-sufficient extension + clean neighbours: never cross-extension
    solo = node("solo", findings=[
        static_finding("T in a.py", PRIVATE_RULE),
        static_finding("T in a.py", EGRESS_RULE),
    ], tools=INGRESS_TOOLS)
    clean = [node(f"clean{i}") for i in range(3)]
    assert detect_trifecta([solo, *clean]) == []


def test_trifecta_supersets_pruned() -> None:
    # 2-combo (a,b) covers; 3-combo (a,b,c) is a superset -> only one finding
    a = node("a", tools=INGRESS_TOOLS)
    b = node("b", findings=[
        static_finding("T in b.py", PRIVATE_RULE),
        static_finding("T in b.py", EGRESS_RULE),
    ])
    c = node("c", findings=[static_finding("T in c.py", PRIVATE_RULE)])
    findings = detect_trifecta([a, b, c])
    assert len(findings) == 1
    labels = findings[0].title.split("(", 1)[1].rstrip(")").split(", ")
    assert labels == ["a", "b"]

def test_trifecta_redundant_member_pruned() -> None:
    # c duplicates a leg already covered by a+b; combo (a,b,c) is non-minimal
    a = node("a", tools=INGRESS_TOOLS)
    b = node("b", findings=[static_finding("T in b.py", EGRESS_RULE)])
    c = node("c", findings=[static_finding("T in c.py", PRIVATE_RULE)])
    d = node("d", findings=[static_finding("T in d.py", PRIVATE_RULE)])  # redundant
    findings = detect_trifecta([a, b, c, d])
    # (a,b,c) and (a,b,d) are both minimal 3-combos (no 2-subset covers):
    # that is correct enumeration, not a pruning failure - but no combo
    # contains BOTH c and d.
    assert 1 <= len(findings) <= 2
    for f in findings:
        labels = f.title.split("(", 1)[1].rstrip(")").split(", ")
        assert not ("c" in labels and "d" in labels)
        assert set(labels) <= {"a", "b", "c", "d"}


def test_trifecta_ranks_carrier_ingress_first_and_caps_at_five() -> None:
    def unit(i: int, *, carrier: bool = False) -> list[ExtensionNode]:
        ingress = node(f"in{i}", tools=INGRESS_TOOLS)
        if carrier:
            ingress = build_node(member(
                f"in{i}",
                [static_finding(f"IJ in m{i}.md", "skill_injection_phrase")],
                INGRESS_TOOLS,
            ))
        return [
            ingress,
            node(f"pd{i}", findings=[static_finding(f"T in p{i}.py", PRIVATE_RULE)]),
            node(f"eg{i}", findings=[static_finding(f"T in e{i}.py", EGRESS_RULE)]),
        ]

    nodes: list[ExtensionNode] = []
    for i in range(8):
        nodes.extend(unit(i, carrier=(i == 0)))
    findings = detect_trifecta(nodes)
    assert len(findings) == 5  # <= 5 emitted
    assert "in0" in findings[0].title  # carrier combo outranks plain ones


def test_trifecta_two_extension_combo() -> None:
    a = node("a", tools=INGRESS_TOOLS)  # ingress only
    b = node("b", findings=[
        static_finding("T in b.py", PRIVATE_RULE),
        static_finding("T in b.py", EGRESS_RULE),
    ])
    findings = detect_trifecta([a, b])
    assert len(findings) == 1
    f = findings[0]
    assert "a" in f.title and "b" in f.title
    assert f.severity == "high"


# --- trifecta: honesty rules -----------------------------------------------------------
def _weak_private() -> Finding:
    return Finding(owasp_ids=["MCP01", "LLM02"], title="Advisory private access",
                   detail="d", severity="low", confidence="advisory", stage="semantic",
                   evidence=ev("advisory"))


def test_weak_coexistence_without_carrier_is_low_advisory() -> None:
    # all three legs advisory-tier (weak) with no carrier anywhere
    ing = ExtensionNode(label="ing", slug="ing", capabilities=[
        Capability("INGRESS", "weak", "advisory ingress", EvidenceSnippet(
            source="semantic:x", excerpt="x", meta={"tier": "advisory"}))
    ])
    priv = ExtensionNode(label="priv", slug="priv", capabilities=[
        Capability("PRIVATE-DATA", "weak", "advisory private", EvidenceSnippet(
            source="semantic:y", excerpt="y", meta={"tier": "advisory"}))
    ])
    egr = ExtensionNode(label="egr", slug="egr", capabilities=[
        Capability("EGRESS", "weak", "advisory egress", EvidenceSnippet(
            source="semantic:z", excerpt="z", meta={"tier": "advisory"}))
    ])
    findings = detect_trifecta([ing, priv, egr])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "low"
    assert f.confidence == "advisory"
    assert "hygiene" in f.title.lower()


def test_all_advisory_legs_max_medium_and_warn_wording() -> None:
    # weak ingress+carrier (static advisory), weak private, weak egress:
    # carrier present -> not the low path, but all legs advisory -> <= medium
    ing = build_node(member("ing", [Finding(
        owasp_ids=["LLM01", "MCP06"],
        title="Instruction-hijack phrase in documentation in a.md",
        detail="d", severity="high", confidence="advisory", stage="static",
        evidence=ev("advisory", "skill_injection_phrase"),
    )], []))
    # carrier rule maps only to INJECTION-CARRIER; give it weak ingress too
    ing.capabilities.append(Capability("INGRESS", "weak", "advisory ingress", EvidenceSnippet(
        source="semantic:x", excerpt="x", meta={"tier": "advisory"})))
    priv = ExtensionNode(label="priv", slug="priv", capabilities=[
        Capability("PRIVATE-DATA", "weak", "advisory private", EvidenceSnippet(
            source="semantic:y", excerpt="y", meta={"tier": "advisory"}))
    ])
    egr = ExtensionNode(label="egr", slug="egr", capabilities=[
        Capability("EGRESS", "weak", "advisory egress", EvidenceSnippet(
            source="semantic:z", excerpt="z", meta={"tier": "advisory"}))
    ])
    findings = detect_trifecta([ing, priv, egr])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert f.confidence == "advisory"
    assert "WARN-level" in f.detail  # reads as WARN, never FAIL


def test_medium_confidence_when_any_leg_measured_or_better() -> None:
    # semantic measured-tier private finding -> PRIVATE-DATA medium; rest weak
    ing = ExtensionNode(label="ing", slug="ing", capabilities=[
        Capability("INGRESS", "weak", "w", EvidenceSnippet(
            source="s", excerpt="s", meta={"tier": "advisory"}))
    ])
    priv = ExtensionNode(label="priv", slug="priv", capabilities=[
        Capability("PRIVATE-DATA", "medium", "m", EvidenceSnippet(
            source="s", excerpt="s", meta={"tier": "measured"}))
    ])
    egr = ExtensionNode(label="egr", slug="egr", capabilities=[
        Capability("EGRESS", "weak", "w", EvidenceSnippet(
            source="s", excerpt="s", meta={"tier": "advisory"}))
    ])
    f = detect_trifecta([ing, priv, egr])[0]
    assert f.severity == "medium"
    assert f.confidence == "measured"


def test_trifecta_severity_policy_high_only_with_strong_leg() -> None:
    # all-medium legs (measured tier static findings) -> medium severity
    med = static_finding("T in a.py", PRIVATE_RULE, tier="measured")
    nodes = [
        ExtensionNode(label="i", slug="i", capabilities=[
            Capability("INGRESS", "medium", "m", EvidenceSnippet(
                source="s", excerpt="s", meta={"tier": "measured"}))]),
        build_node(member("p", [med])),
        ExtensionNode(label="e", slug="e", capabilities=[
            Capability("EGRESS", "medium", "m", EvidenceSnippet(
                source="s", excerpt="s", meta={"tier": "measured"}))]),
    ]
    f = detect_trifecta(nodes)[0]
    assert f.severity == "medium"


def test_trifecta_owasp_extras_from_leg_evidence() -> None:
    # detonation unexpected-egress leg carries MCP07 -> finding gains MCP07
    ing = ExtensionNode(label="i", slug="i", capabilities=[
        Capability("INGRESS", "medium", "tools", EvidenceSnippet(
            source="s", excerpt="s", meta={"tier": "measured"}))])
    priv = ExtensionNode(label="p", slug="p", capabilities=[
        Capability("PRIVATE-DATA", "strong", "x", EvidenceSnippet(
            source="s", excerpt="s", meta={"tier": "deterministic"}))])
    egr_f = Finding(owasp_ids=["MCP07", "LLM02"],
                    title="Unexpected network egress during trigger execution",
                    detail="d", severity="medium", confidence="empirical",
                    stage="detonation", evidence=ev("empirical"))
    egr = build_node(member("e", [egr_f]))
    f = detect_trifecta([ing, priv, egr])[0]
    assert "MCP07" in f.owasp_ids
    assert "MCP10" not in f.owasp_ids


# --- shadowing -------------------------------------------------------------------------
def test_normalize_tool_name() -> None:
    assert normalize_tool_name("MCP__fs__read_file") == "readfile"
    assert normalize_tool_name("fs__read_file") == "readfile"
    assert normalize_tool_name("read-file") == "readfile"
    assert normalize_tool_name("Read.File") == "readfile"
    assert normalize_tool_name("mcp__weather__GET_forecast") == "getforecast"
    assert normalize_tool_name("  web__search ") == "search"
    assert normalize_tool_name("") == ""


def test_name_overlap_basic_grouping_is_informational() -> None:
    nodes = [
        node("fs", tools=["read_file", "list_dir"]),
        node("fs-enhanced", tools=["mcp__fs__Read-File", "stat"]),
        node("helper", tools=["search"]),
    ]
    findings = detect_shadowing(nodes)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_ids == []
    assert f.severity == "info"
    assert f.confidence == "advisory"
    assert "does not establish" in f.detail
    assert "actual integration" in f.detail
    assert len(f.evidence) == 2
    assert all(e.source.startswith("tools:") for e in f.evidence)
    assert all(e.meta["interpretation"] == "name-overlap-only" for e in f.evidence)


def test_shadowing_within_one_member_is_not_composition() -> None:
    nodes = [node("solo", tools=["read_file", "read-file", "READ_FILE"])]
    assert detect_shadowing(nodes) == []


def test_name_overlap_does_not_escalate_from_unresolved_carrier_context() -> None:
    carrier = build_node(member("evil", [
        static_finding("IJ in a.md", "skill_injection_phrase")
    ], ["read_file"]))
    clean = node("clean", tools=["read_file"])
    findings = detect_shadowing([carrier, clean])
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].confidence == "advisory"
    assert findings[0].owasp_ids == []
    assert "security impact" in findings[0].detail
    assert any(cap.kind == "INJECTION-CARRIER" for cap in carrier.capabilities)


def test_shadowing_no_collisions_no_findings() -> None:
    assert detect_shadowing([
        node("a", tools=["fetch_url"]),
        node("b", tools=["fetch_rss"]),
    ]) == []
    assert detect_shadowing([node("a"), node("b")]) == []


def test_shadowing_one_finding_per_collision_group_deterministic_order() -> None:
    nodes = [
        node("a", tools=["z_tool", "b_tool"]),
        node("b", tools=["b-tool", "a_tool"]),
        node("c", tools=["z-tool"]),
    ]
    findings = detect_shadowing(nodes)
    assert len(findings) == 2
    norms = [f.title.split("'")[1] for f in findings]
    assert norms == sorted(norms)  # btool before ztool


def test_import_alias_post_forms_map_to_measured_egress(tmp_path: Path) -> None:
    cases = [
        ("import requests as client\nclient.post('https://example.test', json={})\n", "client.post"),
        ("from httpx import post as publish\npublish('https://example.test', json={})\n", "publish("),
    ]
    for index, (source, marker) in enumerate(cases):
        target = tmp_path / str(index)
        target.mkdir()
        (target / "sender.py").write_text(source, encoding="utf-8")
        caps = map_capabilities([], [], target_dir=target)
        egress = [cap for cap in caps if cap.kind == "EGRESS"]
        assert len(egress) == 1
        assert egress[0].strength == "medium"
        assert marker in egress[0].evidence.excerpt


def test_malformed_python_alias_source_is_not_executed_or_guessed(tmp_path: Path) -> None:
    target = tmp_path / "bad"
    target.mkdir()
    (target / "sender.py").write_text(
        "import requests as client\nclient.post(\n", encoding="utf-8"
    )
    assert [cap for cap in map_capabilities([], [], target_dir=target) if cap.kind == "EGRESS"] == []


@pytest.mark.parametrize(
    "source",
    [
        "def configure():\n    import requests as transport\n"
        "def report(transport):\n    transport.post('local-category', {})\n",
        "import requests as transport\n"
        "def report(transport):\n    transport.post('local-category', {})\n",
        "import requests as transport\n"
        "transport = make_local_transport()\n"
        "transport.post('local-category', {})\n",
    ],
    ids=["import-does-not-leak-between-functions", "parameter-shadows-module-import", "module-alias-reassigned"],
)
def test_shadowed_or_rebound_names_are_not_guessed_as_http_aliases(
    tmp_path: Path, source: str
) -> None:
    target = tmp_path / "shadowed"
    target.mkdir()
    (target / "sender.py").write_text(source, encoding="utf-8")

    caps = map_capabilities([], [], target_dir=target)

    assert not any(cap.kind == "EGRESS" for cap in caps)


# --- stage ------------------------------------------------------------------------------
def test_stage_implements_protocol() -> None:
    stage = CompositionStage()
    assert isinstance(stage, Stage)
    assert stage.name == "composition"


def _run_stage(stage: CompositionStage) -> object:
    import asyncio

    return asyncio.run(stage.run(AuditJob(id="t", source="composition:a,b"), Path("/tmp")))


def test_stage_skips_without_members() -> None:
    res = _run_stage(CompositionStage())
    assert res.ok is True  # type: ignore[attr-defined]
    assert res.metrics == {"skipped": "single-source job"}  # type: ignore[attr-defined]
    assert res.findings == []  # type: ignore[attr-defined]
    # attribute set but empty list -> same skip
    stage = CompositionStage()
    stage._member_results = []
    res2 = _run_stage(stage)
    assert res2.metrics == {"skipped": "single-source job"}  # type: ignore[attr-defined]


def test_stage_via_attribute_injection() -> None:
    stage = CompositionStage()
    stage._member_results = [
        member("web-digest", tools=INGRESS_TOOLS),
        member("notes-lookup", [static_finding("T in n.py", PRIVATE_RULE)]),
        member("status-poster", [static_finding("T in s.py", EGRESS_RULE)]),
    ]
    res = _run_stage(stage)
    assert res.ok is True  # type: ignore[attr-defined]
    assert len(res.findings) == 1  # type: ignore[attr-defined]
    assert res.findings[0].stage == "composition"  # type: ignore[attr-defined]
    m = res.metrics  # type: ignore[attr-defined]
    assert m["members"] == 3
    assert m["trifectas"] == 1
    assert m["capabilities"]["INGRESS"] >= 1
    assert m["capabilities"]["PRIVATE-DATA"] >= 1


def test_stage_reports_name_overlap_as_metric_not_shadowing() -> None:
    stage = CompositionStage()
    stage._member_results = [
        member("one", tools=["fetch_record"]),
        member("two", tools=["fetch_record"]),
    ]
    result = _run_stage(stage)
    assert result.metrics["tool_name_overlaps"] == 1  # type: ignore[attr-defined]
    assert result.metrics["shadowing"] == 0  # type: ignore[attr-defined]
    assert len(result.findings) == 1  # type: ignore[attr-defined]
    assert result.findings[0].severity == "info"  # type: ignore[attr-defined]
    assert result.findings[0].owasp_ids == []  # type: ignore[attr-defined]


def test_stage_class_default_not_shared_mutable() -> None:
    s1, s2 = CompositionStage(), CompositionStage()
    s1._member_results = [member("a")]
    assert not s2._member_results


def test_stage_never_raises_on_hostile_members() -> None:
    class BadMember:
        label = "x"
        slug = "x"

        @property
        def findings(self):
            raise RuntimeError("boom")

        tool_names: list = []

    stage = CompositionStage()
    stage._member_results = [BadMember()]  # type: ignore[list-item]
    res = _run_stage(stage)
    assert res.ok is False  # type: ignore[attr-defined]
    assert "RuntimeError" in res.error  # type: ignore[attr-defined]


# --- performance -------------------------------------------------------------------------
def test_fifty_nodes_under_one_second() -> None:
    nodes: list[ExtensionNode] = []
    for i in range(50):
        nodes.append(build_node(member(
            f"ext{i}",
            [
                static_finding(f"T in a{i}.py", PRIVATE_RULE),
                static_finding(f"IJ in m{i}.md", "skill_injection_phrase"),
            ],
            [f"tool_{i % 7}", f"shared_tool_{i % 5}"],
        )))
    t0 = time.perf_counter()
    tri = detect_trifecta(nodes)
    sha = detect_shadowing(nodes)
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0, f"50-node detection took {elapsed:.3f}s"
    assert len(tri) <= 5
    assert len(sha) >= 1  # shared_tool groups collide across members
