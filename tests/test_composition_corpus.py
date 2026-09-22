"""S6 composition corpus tests (workstream W2).

Ground-truth checks for ``corpus/composition/`` — attack + control SETS of
individually-clean extensions (docs/s6-contracts.md §4):

* set.json schema validity for every set, via the REAL loader
  (``eval.loader.load_set_specs``) plus corpus-local extras;
* HARD PRECONDITION: every member of every set (attack AND control) is
  individually clean — ``run_audit(member, include_detonation=False,
  include_semantic=False, include_harness=False, include_reputation=False)``
  yields NO high/critical finding;
* required sets exist: canonical trifecta, shuffled order, dilution,
  shadowing, and >=3 controls covering ingress+egress / private+egress /
  self-sufficient-single + clean neighbors;
* shared member copies are byte-identical across sets (drift guard);
* structural leg coverage: trifecta sets split INGRESS / PRIVATE-DATA /
  EGRESS across distinct members; controls deliberately miss one leg or
  keep all legs inside ONE member;
* shadow-pair members collide on normalized tool names; no other set does
  (``expected.shadowing`` iff a cross-member collision exists).

Hermetic: NEBIUS_API_KEY / TAVILY_API_KEY are stripped for the audit
fixture, so no live stage can fire regardless of the ambient shell.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from eval.loader import load_set_specs  # noqa: E402
from fugu.pipeline.assemble import run_audit  # noqa: E402
from fugu.pipeline.stages.static_scan import _TOOL_NAME_RE  # noqa: E402
from fugu.types import Finding  # noqa: E402

SETS_ROOT = _PROJECT_ROOT / "corpus" / "composition"

TRIFECTA_SETS = ("trifecta-canonical", "trifecta-shuffled", "trifecta-diluted")
CANONICAL_MEMBERS = {"web-digest", "notes-lookup", "status-poster"}
DILUTION_MEMBERS = {"weather-lookup", "unit-convert"}
REQUIRED_ATTACK_SETS = set(TRIFECTA_SETS) | {"shadow-pair"}
MIN_CONTROL_SETS = 3

# Conservative text markers for the three trifecta legs. Deliberately
# narrower than the fugu static rules: they assert the corpus carries the
# MILD signal text a capability mapper harvests, not a static finding.
INGRESS_MARKERS = ("urllib.request", "urlopen", "httpx", "requests.get", "fetch", "rss", "feed")
PRIVATE_MARKERS = ("os.environ", "os.getenv", "process.env", "Path.home", "~/.")
EGRESS_MARKERS = ("curl", "wget", 'method="POST"', "webhook")


# --- helpers -----------------------------------------------------------------


def _iter_member_dirs() -> list[tuple[str, str, Path]]:
    """(set-name, member-name, path) for every member of every set."""
    out: list[tuple[str, str, Path]] = []
    for spec in load_set_specs(SETS_ROOT):
        for member in spec.members:
            out.append((spec.name, member.dir, spec.path / member.dir))
    return out


def _member_text(member_dir: Path) -> str:
    chunks: list[str] = []
    for f in sorted(member_dir.rglob("*")):
        if f.is_file() and "__pycache__" not in f.parts:
            try:
                chunks.append(f.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    return "\n".join(chunks)


def _legs(member_dir: Path) -> set[str]:
    text = _member_text(member_dir)
    legs: set[str] = set()
    if any(m in text for m in INGRESS_MARKERS):
        legs.add("INGRESS")
    if any(m in text for m in PRIVATE_MARKERS):
        legs.add("PRIVATE-DATA")
    if any(m in text for m in EGRESS_MARKERS):
        legs.add("EGRESS")
    return legs


def _normalize_tool_name(name: str) -> str:
    """Contract §2 normalization: lowercase, strip mcp__server__ prefixes,
    collapse non-alphanumerics."""
    n = name.lower().strip()
    while "__" in n:
        n = n.split("__", 1)[1]
    return re.sub(r"[^a-z0-9]", "", n)


def _tool_names(member_dir: Path) -> set[str]:
    """Harvest tool names the way composition plumbing does (contracts §3):
    the static_scan tool-name regex over the member's text files."""
    names: set[str] = set()
    for f in sorted(member_dir.rglob("*")):
        if not f.is_file() or "__pycache__" in f.parts:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _TOOL_NAME_RE.finditer(text):
            names.add(_normalize_tool_name(m.group(1)))
    return names


def _dir_fingerprint(member_dir: Path) -> str:
    """Content hash over every file in a member dir (drift guard)."""
    h = hashlib.sha256()
    for f in sorted(member_dir.rglob("*")):
        if f.is_file() and "__pycache__" not in f.parts:
            h.update(str(f.relative_to(member_dir)).encode())
            h.update(b"\0")
            h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()


@pytest.fixture(scope="module")
def specs() -> list:
    return load_set_specs(SETS_ROOT)


@pytest.fixture(scope="module")
def audit_cache() -> dict[Path, list[Finding]]:
    """run_audit (concealment+static only) once per unique member dir.

    Live-stage keys are stripped so the fixture is hermetic even when the
    ambient shell exports them.
    """
    unique = {path for _, _, path in _iter_member_dirs()}
    saved = {k: os.environ.pop(k, None) for k in ("NEBIUS_API_KEY", "TAVILY_API_KEY")}
    try:
        cache: dict[Path, list[Finding]] = {}
        for path in sorted(unique):
            cache[path.resolve()] = run_audit(
                path,
                include_detonation=False,
                include_semantic=False,
                include_harness=False,
                include_reputation=False,
            )
        return cache
    finally:
        for key, val in saved.items():
            if val is not None:
                os.environ[key] = val


# --- schema + required sets ----------------------------------------------------


def test_every_set_json_is_schema_valid(specs) -> None:
    """The real loader enforces §4: 2..8 members, dirs exist, expected
    keys present with boolean values, kind in {attack, control}."""
    assert len(specs) >= 5, f"expected >=5 sets, found {len(specs)}"
    for spec in specs:
        assert 2 <= len(spec.members) <= 8, f"{spec.name}: member count {len(spec.members)}"
        assert spec.path.name == spec.name, (
            f"set dir {spec.path.name} does not match set.json name {spec.name!r}"
        )
        for member in spec.members:
            member_dir = spec.path / member.dir
            assert member_dir.is_dir(), f"{spec.name}: missing member dir {member.dir}"
            files = [f for f in member_dir.rglob("*") if f.is_file()]
            assert files, f"{spec.name}/{member.dir}: member dir is empty"
            # plausible mini-extension: SKILL.md and/or server/code shape
            names = {f.name for f in files}
            assert "SKILL.md" in names or any(
                n.endswith((".py", ".js", ".ts", ".sh")) for n in names
            ), f"{spec.name}/{member.dir}: not a plausible extension shape: {sorted(names)}"


def test_required_sets_present(specs) -> None:
    names = {s.name for s in specs}
    missing = REQUIRED_ATTACK_SETS - names
    assert not missing, f"missing required attack sets: {sorted(missing)}"
    controls = [s for s in specs if s.kind == "control"]
    assert len(controls) >= MIN_CONTROL_SETS, (
        f"expected >={MIN_CONTROL_SETS} control sets, found {len(controls)}"
    )
    by_name = {s.name: s for s in specs}
    # trifecta attack sets must expect a trifecta and no shadowing
    for name in TRIFECTA_SETS:
        assert by_name[name].expected == {"trifecta": True, "shadowing": False}, name
    assert by_name["shadow-pair"].expected == {"trifecta": False, "shadowing": True}
    for c in controls:
        assert c.expected == {"trifecta": False, "shadowing": False}, c.name


def test_trifecta_variants_share_members_differently(specs) -> None:
    by_name = {s.name: s for s in specs}
    canonical = [m.dir for m in by_name["trifecta-canonical"].members]
    shuffled = [m.dir for m in by_name["trifecta-shuffled"].members]
    diluted = [m.dir for m in by_name["trifecta-diluted"].members]

    assert set(canonical) == CANONICAL_MEMBERS, canonical
    assert set(shuffled) == CANONICAL_MEMBERS, shuffled
    assert shuffled != canonical, "shuffled variant must list members in a different order"
    assert set(diluted) == CANONICAL_MEMBERS | DILUTION_MEMBERS, diluted
    assert len(diluted) == 5, diluted


# --- hard precondition: individual cleanliness ---------------------------------


def test_every_member_individually_clean(audit_cache) -> None:
    """§4 precondition, attack AND control members: static+concealment only,
    no high/critical finding for any member alone."""
    offenders: list[str] = []
    counts: dict[str, int] = {}
    for set_name, member_name, path in _iter_member_dirs():
        findings = audit_cache[path.resolve()]
        counts[f"{set_name}/{member_name}"] = len(findings)
        for f in findings:
            if f.severity in ("high", "critical"):
                offenders.append(f"{set_name}/{member_name}: [{f.severity}] {f.title}")
    assert not offenders, "members with high/critical findings:\n" + "\n".join(offenders)


def test_audit_cache_ran_offline_stages_only(audit_cache) -> None:
    """The precondition audit must be deterministic stages only."""
    stages: set[str] = set()
    for findings in audit_cache.values():
        stages.update(f.stage for f in findings)
    assert stages <= {"concealment", "static"}, f"unexpected live stages ran: {stages}"


def test_control_members_individually_clean(specs, audit_cache) -> None:
    """Explicit control-set pass of the same precondition (FP guards must
    not sneak in high/critical singles either)."""
    for spec in specs:
        if spec.kind != "control":
            continue
        for member in spec.members:
            findings = audit_cache[(spec.path / member.dir).resolve()]
            hi = [f"{f.severity}:{f.title}" for f in findings if f.severity in ("high", "critical")]
            assert not hi, f"{spec.name}/{member.dir}: {hi}"


# --- drift guard: shared member copies stay identical --------------------------


def test_shared_members_byte_identical_across_sets(specs) -> None:
    seen: dict[str, tuple[str, str]] = {}  # member name -> (set, fingerprint)
    for spec in specs:
        for member in spec.members:
            fp = _dir_fingerprint(spec.path / member.dir)
            if member.dir in seen:
                first_set, first_fp = seen[member.dir]
                assert fp == first_fp, (
                    f"member {member.dir!r} drifted: {first_set} vs {spec.name} "
                    f"({_dir_fingerprint.__name__} mismatch)"
                )
            else:
                seen[member.dir] = (spec.name, fp)
    # the shared pool is real: the canonical trio + deploy-notify are each
    # referenced by more than one set, and the pool is sizeable
    sets_per_member: dict[str, int] = {}
    for spec in specs:
        for member in spec.members:
            sets_per_member[member.dir] = sets_per_member.get(member.dir, 0) + 1
    shared = {name for name, n in sets_per_member.items() if n >= 2}
    assert {"web-digest", "notes-lookup", "status-poster", "deploy-notify"} <= shared, (
        f"expected the canonical trio + deploy-notify to be shared across sets: {sorted(shared)}"
    )
    assert len(sets_per_member) >= 12, f"expected >=12 distinct members, found {len(sets_per_member)}"


# --- leg structure: attacks split legs, controls miss or internalize -----------


def test_attack_trifecta_sets_split_legs_across_members(specs) -> None:
    by_name = {s.name: s for s in specs}
    for name in TRIFECTA_SETS:
        spec = by_name[name]
        legs_by_member = {m.dir: _legs(spec.path / m.dir) for m in spec.members}
        all_legs: set[str] = set()
        for legs in legs_by_member.values():
            all_legs |= legs
        assert {"INGRESS", "PRIVATE-DATA", "EGRESS"} <= all_legs, (
            f"{name}: union must cover the trifecta, got {sorted(all_legs)} ({legs_by_member})"
        )
        carriers = [m for m, legs in legs_by_member.items() if len(legs) == 3]
        assert not carriers, (
            f"{name}: members carrying ALL THREE legs alone defeat the split: {carriers}"
        )
        covering = {m for m, legs in legs_by_member.items() if legs}
        assert len(covering) >= 2, f"{name}: legs must be split across >=2 members"


def test_control_sets_miss_or_internalize_legs(specs) -> None:
    by_name = {s.name: s for s in specs}
    # ingress + egress, NO private-data anywhere
    ie = by_name["control-ingress-egress"]
    for m in ie.members:
        assert "PRIVATE-DATA" not in _legs(ie.path / m.dir), f"{m.dir} leaks a private-data leg"
    ie_legs = set().union(*(_legs(ie.path / m.dir) for m in ie.members))
    assert {"INGRESS", "EGRESS"} <= ie_legs, ie_legs

    # private + egress, NO ingress anywhere
    pe = by_name["control-private-egress"]
    for m in pe.members:
        assert "INGRESS" not in _legs(pe.path / m.dir), f"{m.dir} leaks an ingress leg"
    pe_legs = set().union(*(_legs(pe.path / m.dir) for m in pe.members))
    assert {"PRIVATE-DATA", "EGRESS"} <= pe_legs, pe_legs

    # self-sufficient single extension + clean neighbors: exactly one
    # member carries legs (all three, internally), the rest carry none
    ss = by_name["control-self-sufficient"]
    legs_by_member = {m.dir: _legs(ss.path / m.dir) for m in ss.members}
    carriers = {m for m, legs in legs_by_member.items() if legs}
    assert len(carriers) == 1, f"exactly one member should carry legs: {legs_by_member}"
    assert legs_by_member[carriers.pop()] == {"INGRESS", "PRIVATE-DATA", "EGRESS"}


# --- shadowing ------------------------------------------------------------------


def test_shadow_pair_collides_on_normalized_tool_names(specs) -> None:
    by_name = {s.name: s for s in specs}
    spec = by_name["shadow-pair"]
    names_by_member = {m.dir: _tool_names(spec.path / m.dir) for m in spec.members}
    fs, fse = names_by_member["filesystem"], names_by_member["filesystem-enhanced"]
    collision = fs & fse
    assert collision, f"filesystem pair must collide: {sorted(fs)} vs {sorted(fse)}"
    assert {"readfile", "listdir"} <= collision, collision
    # help-docs is the clean neighbor: no cross-collision with either
    for other in ("filesystem", "filesystem-enhanced"):
        assert not (names_by_member["help-docs"] & names_by_member[other]), (
            f"help-docs unexpectedly collides with {other}"
        )


def test_shadowing_expected_iff_cross_member_collision(specs) -> None:
    """expected.shadowing <=> some normalized tool name appears in >=2
    distinct members of the set (corpus-wide invariant)."""
    for spec in specs:
        owners: dict[str, set[str]] = {}
        for m in spec.members:
            for tool in _tool_names(spec.path / m.dir):
                owners.setdefault(tool, set()).add(m.dir)
        collisions = {t for t, dirs in owners.items() if len(dirs) >= 2}
        assert bool(collisions) == spec.expected_shadowing, (
            f"{spec.name}: collisions={sorted(collisions)} but expected.shadowing="
            f"{spec.expected_shadowing}"
        )


def test_canonical_trio_tool_names_are_leg_signal_carriers(specs) -> None:
    """The ingress member's tool names carry fetch/read verbs (the
    capability-mapper ingress inventory input, contracts §2)."""
    by_name = {s.name: s for s in specs}
    spec = by_name["trifecta-canonical"]
    web_tools = _tool_names(spec.path / "web-digest")
    assert {"fetchurl", "readrss"} <= web_tools, sorted(web_tools)
