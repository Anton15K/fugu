"""Host-read boundary for extension sources.

Direct pipeline readers reject descendant symlinks. Intake may instead inspect
links against the fully resolved source anchor and materialize only safe file
links into an owned regular-file snapshot before any reader sees the source.
This preflight is not race-proof isolation of a concurrently mutable local tree.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


class SourceSafetyError(ValueError):
    """The supplied source cannot be safely read under the source policy."""


_MAX_SYMLINK_RESOLUTION_HOPS = 128


@dataclass(frozen=True)
class SourceLinkTarget:
    """A validated, in-anchor regular-file target for one descendant link."""

    link_path: str
    link_target: str
    resolved_path: Path
    resolved_repo_path: str


def _lexical_link_target(
    root: Path, link: Path, raw_target: str
) -> tuple[Path, os.stat_result]:
    """Walk original target components without following links or leaving root."""
    target = Path(raw_target)
    raw_path = raw_target.replace(os.altsep, os.sep) if os.altsep else raw_target
    raw_components = raw_path.split(os.sep)
    requires_directory = raw_components[-1] in ("", ".")
    rel = link.relative_to(root).as_posix()
    if target.is_absolute():
        # Require the raw absolute spelling to start at the resolved anchor.
        # Checking it lexically avoids touching parent paths outside that anchor.
        if target.parts[: len(root.parts)] != root.parts:
            raise SourceSafetyError(f"source symlink '{rel}' escapes source root")
        components = target.parts[len(root.parts) :]
        current = root
    else:
        components = target.parts
        current = link.parent
        try:
            current.relative_to(root)
        except ValueError as exc:
            raise SourceSafetyError(f"source symlink '{rel}' escapes source root") from exc

    try:
        info = os.lstat(current)
    except OSError as exc:
        raise SourceSafetyError(f"source symlink '{rel}' cannot be inspected") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise SourceSafetyError(f"source symlink '{rel}' has a non-directory base")

    for index, part in enumerate(components):
        if part in ("", "."):
            continue
        if part == "..":
            if current == root:
                raise SourceSafetyError(f"source symlink '{rel}' escapes source root")
            if not stat.S_ISDIR(info.st_mode):
                raise SourceSafetyError(
                    f"source symlink '{rel}' traverses a non-directory path component"
                )
            current = current.parent
            try:
                info = os.lstat(current)
            except OSError as exc:
                raise SourceSafetyError(
                    f"source symlink '{rel}' cannot be inspected"
                ) from exc
            continue

        candidate = current / part
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise SourceSafetyError(f"source symlink '{rel}' escapes source root") from exc
        try:
            info = os.lstat(candidate)
        except FileNotFoundError as exc:
            missing = candidate.relative_to(root).as_posix()
            raise SourceSafetyError(
                f"source contains broken symlink '{rel}' at target component '{missing}'"
            ) from exc
        except OSError as exc:
            raise SourceSafetyError(f"source symlink '{rel}' cannot be inspected") from exc

        remaining = any(next_part not in ("", ".") for next_part in components[index + 1 :])
        if stat.S_ISLNK(info.st_mode):
            if remaining:
                raise SourceSafetyError(
                    f"source contains chained symlink '{rel}' through a path component"
                )
            return candidate, info
        if remaining and not stat.S_ISDIR(info.st_mode):
            component = candidate.relative_to(root).as_posix()
            raise SourceSafetyError(
                f"source symlink '{rel}' traverses non-directory target component '{component}'"
            )
        current = candidate

    if requires_directory and not stat.S_ISDIR(info.st_mode):
        raise SourceSafetyError(
            f"source symlink '{rel}' requires a directory target"
        )
    return current, info


def _resolve_file_link(root: Path, link: Path) -> SourceLinkTarget:
    rel = link.relative_to(root).as_posix()
    current_link = link
    seen: set[str] = set()

    # Chained links are rejected regardless of where they end. Walk only a
    # bounded amount of link metadata so hostile chains cannot exhaust the
    # Python call stack or make preflight unbounded.
    for hop in range(_MAX_SYMLINK_RESOLUTION_HOPS):
        current_rel = current_link.relative_to(root).as_posix()
        if current_rel in seen:
            raise SourceSafetyError(f"source contains cyclic symlink '{current_rel}'")
        seen.add(current_rel)
        try:
            raw_target = os.readlink(current_link)
        except OSError as exc:
            raise SourceSafetyError(
                f"source symlink '{current_rel}' cannot be inspected"
            ) from exc

        candidate, info = _lexical_link_target(root, current_link, raw_target)
        candidate_rel = candidate.relative_to(root)
        next_link: Path | None = None
        if stat.S_ISLNK(info.st_mode):
            next_link = candidate

        if next_link is not None:
            next_rel = next_link.relative_to(root).as_posix()
            if next_rel in seen:
                raise SourceSafetyError(f"source contains cyclic symlink '{next_rel}'")
            if hop + 1 == _MAX_SYMLINK_RESOLUTION_HOPS:
                raise SourceSafetyError(
                    f"source contains chained symlink '{rel}' (resolution limit exceeded)"
                )
            current_link = next_link
            continue

        if info is None or not stat.S_ISREG(info.st_mode):
            raise SourceSafetyError(f"source contains directory symlink '{current_rel}'")
        if hop:
            raise SourceSafetyError(f"source contains chained symlink '{rel}'")

        return SourceLinkTarget(
            link_path=rel,
            link_target=raw_target,
            resolved_path=candidate,
            resolved_repo_path=candidate_rel.as_posix(),
        )

    raise SourceSafetyError(
        f"source contains chained symlink '{rel}' (resolution limit exceeded)"
    )


def inspect_source_tree(target: Path) -> tuple[Path, dict[str, SourceLinkTarget]]:
    """Resolve the explicit root and validate every descendant without file reads.

    Internal, direct links to regular files are returned for extraction-time
    materialization. Escaping, broken, cyclic, directory, chained and special
    file entries fail closed. The root itself may be a symlink.
    """
    root = Path(target).resolve(strict=True)
    if root.is_file():
        return root, {}
    if not root.is_dir():
        raise SourceSafetyError("source root is not a regular file or directory")

    links: dict[str, SourceLinkTarget] = {}

    def unreadable(exc: OSError) -> None:
        raise SourceSafetyError("source tree cannot be inspected safely") from exc

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        dirs.sort()
        files.sort()
        for name in sorted(dirs + files):
            path = Path(directory) / name
            try:
                info = os.lstat(path)
            except OSError as exc:
                raise SourceSafetyError("source tree cannot be inspected safely") from exc
            if stat.S_ISLNK(info.st_mode):
                link = _resolve_file_link(root, path)
                links[link.link_path] = link
            elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                rel = path.relative_to(root).as_posix()
                raise SourceSafetyError(f"source contains unsupported special file '{rel}'")
    return root, links


def validate_source_tree(target: Path) -> Path:
    """Return the resolved anchor after rejecting all descendant symlinks.

    Keep this strict for stages invoked directly on unmaterialized paths. Normal
    intake calls :func:`inspect_source_tree` and hands stages an owned snapshot.
    """
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
                    "or use extraction-time source materialization"
                )
    return root
