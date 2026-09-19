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


class ManifestError(ValueError):
    """A manifest violates the documented corpus schema."""


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
