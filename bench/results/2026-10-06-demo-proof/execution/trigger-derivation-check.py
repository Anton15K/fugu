"""Read-only trigger and source-pin check for the retained MarkItDown MCP.

This script parses the public acquisition manifest and uses only Fugu's pure
trigger derivation. It does not import, install, or execute the retained source.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "src"))

from fugu.detonation.triggers import derive_triggers  # noqa: E402

SOURCE_ROOT = Path("/tmp/fugu-wild-sources-20261002/microsoft--markitdown")
ACQUISITION = REPO_ROOT / "bench/results/2026-10-02-wild-audit/acquisition.json"
SOURCE_URL = "https://github.com/microsoft/markitdown"
SELECTED_FILES = (
    "README.md",
    "packages/markitdown-mcp/README.md",
    "packages/markitdown-mcp/pyproject.toml",
    "packages/markitdown-mcp/src/markitdown_mcp/__main__.py",
)


def _find_markitdown_record(value: object) -> dict[str, object] | None:
    if isinstance(value, dict):
        if value.get("repository") == "microsoft/markitdown" and "files_sha256" in value:
            return value
        for child in value.values():
            found = _find_markitdown_record(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_markitdown_record(child)
            if found is not None:
                return found
    return None


manifest = json.loads(ACQUISITION.read_text())
record = _find_markitdown_record(manifest)
assert record is not None
file_hashes = record["files_sha256"]
assert isinstance(file_hashes, dict)
matches = {
    name: hashlib.sha256((SOURCE_ROOT / name).read_bytes()).hexdigest()
    == file_hashes[name]
    for name in SELECTED_FILES
}
assert all(matches.values()), matches

package_root = SOURCE_ROOT / "packages/markitdown-mcp"
result = {
    "source_commit": record["commit"],
    "archive_sha256": record["archive_sha256"],
    "selected_files_match_acquisition": matches,
    "derived_triggers": {
        "repository_root": derive_triggers(SOURCE_ROOT, source=SOURCE_URL),
        "mcp_package_root": derive_triggers(package_root, source=SOURCE_URL),
    },
    "target_source_imported_or_executed": False,
}
print(json.dumps(result, sort_keys=True))
