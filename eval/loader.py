"""Corpus loader for the Fugu eval harness.

A corpus is a directory of samples. Each sample is an immediate
sub-directory containing a ``manifest.json`` that carries the ground
truth:

    {
      "name": "hidden-unicode-instructions",      # required, unique, str
      "kind": "malicious" | "benign",             # required
      "expected_owasp_ids": ["LLM01", "MCP03"],   # list[str]; [] for benign
      "description": "...",                       # optional, ignored
      "source": "crafted" | "mcptox" | "...",     # optional, ignored
      "notes": "..."                              # optional, ignored
    }

Validation policy (deliberate):

* Structural violations (missing/invalid ``name`` or ``kind``, non-list
  ``expected_owasp_ids``, duplicate sample names, unreadable JSON) raise
  :class:`ManifestError` — the schema is ours, so it must hold.
* Unknown OWASP ids and semantic oddities (malicious with no labels,
  benign with labels, duplicate ids inside the list) only *warn*; they are
  returned in the warnings list so a corpus can carry taxonomy extensions
  without breaking the harness.

The OWASP taxonomy is imported from ``fugu.types.OWASP_IDS`` (read-only
shared contract) — never copied, so the eval never drifts from the
pipeline's taxonomy.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fugu.types import OWASP_IDS

MANIFEST_FILENAME = "manifest.json"
VALID_KINDS = ("malicious", "benign")

SET_FILENAME = "set.json"
VALID_SET_KINDS = ("attack", "control")
MIN_SET_MEMBERS = 2
MAX_SET_MEMBERS = 8


class ManifestError(ValueError):
    """A manifest violates the documented corpus schema."""


class SetSpecError(ValueError):
    """A composition set.json violates the documented set schema."""


@dataclass(frozen=True)
class Sample:
    """One labeled corpus sample: its location plus parsed manifest."""

    path: Path
    manifest: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.manifest.get("name", ""))

    @property
    def kind(self) -> str:
        return str(self.manifest.get("kind", ""))

    @property
    def expected_ids(self) -> list[str]:
        """Expected OWASP ids, de-duplicated, order preserved."""
        ids = self.manifest.get("expected_owasp_ids", [])
        if not isinstance(ids, list):
            return []
        return list(dict.fromkeys(str(i) for i in ids))


def fixtures_dir() -> Path:
    """Built-in fallback corpus shipped with the eval harness itself."""
    return Path(__file__).resolve().parent / "fixtures"


def _validate_manifest(
    dir_path: Path, data: Any, seen_names: set[str]
) -> list[str]:
    """Validate one parsed manifest; raise ManifestError on schema breaks.

    Returns the list of soft warnings for this sample.
    """
    warnings: list[str] = []
    where = dir_path.name

    if not isinstance(data, dict):
        raise ManifestError(f"{where}: manifest.json must be a JSON object")

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ManifestError(f"{where}: manifest 'name' must be a non-empty string")
    if name in seen_names:
        raise ManifestError(
            f"{where}: duplicate sample name {name!r} "
            f"(prediction keys are sample names — they must be unique)"
        )
    seen_names.add(name)

    kind = data.get("kind")
    if kind not in VALID_KINDS:
        raise ManifestError(
            f"{name}: 'kind' must be one of {VALID_KINDS}, got {kind!r}"
        )

    ids = data.get("expected_owasp_ids")
    if ids is None:
        warnings.append(f"{name}: manifest has no 'expected_owasp_ids' key; treating as []")
        ids = []
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        raise ManifestError(
            f"{name}: 'expected_owasp_ids' must be a list of strings, got {ids!r}"
        )

    if len(set(ids)) != len(ids):
        warnings.append(f"{name}: duplicate ids in expected_owasp_ids (de-duplicated)")
    for owasp_id in dict.fromkeys(ids):
        if owasp_id not in OWASP_IDS:
            warnings.append(
                f"{name}: expected id {owasp_id!r} is not in fugu.types.OWASP_IDS "
                f"(kept; it will show up as an unknown id in the metrics)"
            )

    if kind == "malicious" and not ids:
        warnings.append(f"{name}: kind=malicious but expected_owasp_ids is empty")
    if kind == "benign" and ids:
        warnings.append(f"{name}: kind=benign but expected_owasp_ids is non-empty {ids!r}")

    return warnings


def load_corpus(corpus_dir: str | Path) -> tuple[list[Sample], list[str]]:
    """Load every valid sample under ``corpus_dir``.

    Returns ``(samples, warnings)``. Samples are sorted by name for
    deterministic output. Sub-directories without a ``manifest.json``
    produce a warning and are skipped; hidden dirs (starting with ``.``
    or ``__``) are skipped silently.
    """
    corpus = Path(corpus_dir)
    if not corpus.is_dir():
        raise ManifestError(f"corpus directory not found: {corpus}")

    samples: list[Sample] = []
    warnings: list[str] = []
    seen_names: set[str] = set()

    for entry in sorted(corpus.iterdir()):
        if not entry.is_dir() or entry.name.startswith((".", "__")):
            continue
        manifest_path = entry / MANIFEST_FILENAME
        if not manifest_path.is_file():
            warnings.append(f"{entry.name}: no {MANIFEST_FILENAME}, skipped")
            continue
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError(f"{entry.name}: cannot parse {MANIFEST_FILENAME}: {exc}") from exc
        warnings.extend(_validate_manifest(entry, data, seen_names))
        samples.append(Sample(path=entry.resolve(), manifest=data))

    return samples, warnings


# --- composition sets --------------------------------------------------------


@dataclass(frozen=True)
class SetMember:
    """One extension directory inside a composition set."""

    dir: str
    label: str


@dataclass(frozen=True)
class SetSpec:
    """A composition eval set: 2..8 member extensions audited together.

    Mirrors ``set.json`` (docs/s6-contracts.md §4/§5). ``expected`` carries
    the ground-truth composition verdicts: whether the UNION of members
    completes the lethal trifecta (ingress + private-data + egress split
    across extensions) and whether cross-extension tool shadowing fires.
    """

    name: str
    kind: str  # "attack" | "control"
    description: str
    members: list[SetMember]
    expected_trifecta: bool
    expected_shadowing: bool
    path: Path  # the set directory (set.json's parent)

    @property
    def expected(self) -> dict[str, bool]:
        """Expected composition verdicts as a plain dict (matches set.json)."""
        return {"trifecta": self.expected_trifecta, "shadowing": self.expected_shadowing}


def _validate_set_spec(set_path: Path, data: Any) -> SetSpec:
    """Validate one parsed set.json; raise SetSpecError on schema breaks.

    Strict by contract (§5): the set schema is ours and 2..8 members with
    existing dirs is a hard precondition — no soft-warning path here.
    """
    where = str(set_path)

    if not isinstance(data, dict):
        raise SetSpecError(f"{where}: set.json must be a JSON object")

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise SetSpecError(f"{where}: 'name' must be a non-empty string")

    kind = data.get("kind")
    if kind not in VALID_SET_KINDS:
        raise SetSpecError(
            f"{where}: 'kind' must be one of {VALID_SET_KINDS}, got {kind!r}"
        )

    description = data.get("description", "")
    if not isinstance(description, str):
        raise SetSpecError(f"{where}: 'description' must be a string")

    raw_members = data.get("members")
    if not isinstance(raw_members, list) or not (
        MIN_SET_MEMBERS <= len(raw_members) <= MAX_SET_MEMBERS
    ):
        raise SetSpecError(
            f"{where}: 'members' must be a list of {MIN_SET_MEMBERS}..{MAX_SET_MEMBERS} "
            f"member objects, got {raw_members!r}"
        )

    members: list[SetMember] = []
    for i, member in enumerate(raw_members):
        if not isinstance(member, dict) or "dir" not in member:
            raise SetSpecError(
                f"{where}: members[{i}] must be an object with 'dir' and 'label', got {member!r}"
            )
        member_dir = member["dir"]
        label = member.get("label", member_dir)
        if not isinstance(member_dir, str) or not member_dir.strip():
            raise SetSpecError(
                f"{where}: members[{i}].dir must be a non-empty string, got {member_dir!r}"
            )
        if not isinstance(label, str) or not label.strip():
            raise SetSpecError(
                f"{where}: members[{i}].label must be a non-empty string, got {label!r}"
            )
        if member_dir in {m.dir for m in members}:
            raise SetSpecError(f"{where}: duplicate member dir {member_dir!r}")
        resolved = set_path.parent / member_dir
        if not resolved.is_dir():
            raise SetSpecError(
                f"{where}: member dir {member_dir!r} does not exist "
                f"(expected {resolved})"
            )
        members.append(SetMember(dir=member_dir, label=label))

    expected = data.get("expected")
    if not isinstance(expected, dict):
        raise SetSpecError(
            f"{where}: 'expected' must be an object with boolean "
            f"'trifecta' and 'shadowing' keys, got {expected!r}"
        )
    missing = [k for k in ("trifecta", "shadowing") if k not in expected]
    if missing:
        raise SetSpecError(f"{where}: 'expected' is missing key(s): {', '.join(missing)}")
    for key in ("trifecta", "shadowing"):
        if not isinstance(expected[key], bool):
            raise SetSpecError(
                f"{where}: 'expected.{key}' must be a boolean, got {expected[key]!r}"
            )

    return SetSpec(
        name=name,
        kind=kind,
        description=description,
        members=members,
        expected_trifecta=expected["trifecta"],
        expected_shadowing=expected["shadowing"],
        path=set_path.parent.resolve(),
    )


def load_set_specs(root: str | Path) -> list[SetSpec]:
    """Load every composition set under ``root`` (``root/<set>/set.json``).

    Sets are sorted by name for deterministic output. Sub-directories
    without a ``set.json`` are skipped silently (a set root may also hold
    shared files); hidden dirs (starting with ``.`` or ``__``) are skipped
    too. Malformed set.json raises :class:`SetSpecError` naming the file.
    """
    sets_root = Path(root)
    if not sets_root.is_dir():
        raise SetSpecError(f"sets directory not found: {sets_root}")

    specs: list[SetSpec] = []
    seen_names: set[str] = set()

    for entry in sorted(sets_root.iterdir()):
        if not entry.is_dir() or entry.name.startswith((".", "__")):
            continue
        set_path = entry / SET_FILENAME
        if not set_path.is_file():
            continue
        try:
            data = json.loads(set_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SetSpecError(f"{set_path}: cannot parse {SET_FILENAME}: {exc}") from exc
        spec = _validate_set_spec(set_path, data)
        if spec.name in seen_names:
            raise SetSpecError(f"{set_path}: duplicate set name {spec.name!r}")
        seen_names.add(spec.name)
        specs.append(spec)

    return specs
