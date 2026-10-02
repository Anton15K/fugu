"""Conservative host-read boundary for extension sources.

The explicit source root may be a symlink; resolve it once as the anchor.
Reject all descendant symlinks, including internal and broken links, before
reading source text or constructing remote payloads. This is a preflight
check, not race-proof isolation of a concurrently mutable local tree.
"""
from __future__ import annotations

import os
from pathlib import Path


class SourceSafetyError(ValueError):
    """The supplied source cannot be safely read under the source policy."""


def validate_source_tree(target: Path) -> Path:
    """Return the resolved anchor after checking descendants without reads."""
    root = Path(target).resolve(strict=True)
    if root.is_file():
        return root

    def unreadable(exc: OSError) -> None:
        raise SourceSafetyError("source tree cannot be inspected safely") from exc

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            if path.is_symlink():
                rel = path.relative_to(root).as_posix()
                raise SourceSafetyError(
                    f"source contains descendant symlink '{rel}'; remove the link "
                    "or audit a directory containing regular files only"
                )
    return root
