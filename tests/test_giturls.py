"""giturls: pasted web-UI URL normalization (tree/blob views -> repo+ref+subpath).

Hermetic, pure-function tests: no network, no git.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from fugu.server.giturls import extract_git_parts
from fugu.server.jobs import _resolve_audit_subdir, ExtractionError


# --- URL parsing ------------------------------------------------------------------


def test_repo_root_unchanged() -> None:
    assert extract_git_parts("https://github.com/acme/evil-skill") == (
        "https://github.com/acme/evil-skill",
        "",
        "",
    )


def test_tree_view_with_subpath() -> None:
    # The exact shape a user pastes from the GitHub file browser.
    assert extract_git_parts(
        "https://github.com/mattpocock/skills/tree/main/skills/engineering/tdd"
    ) == (
        "https://github.com/mattpocock/skills",
        "main",
        "skills/engineering/tdd",
    )


def test_tree_view_ref_only() -> None:
    assert extract_git_parts("https://github.com/acme/repo/tree/main") == (
        "https://github.com/acme/repo",
        "main",
        "",
    )


def test_blob_view_file() -> None:
    assert extract_git_parts(
        "https://github.com/acme/repo/blob/main/SKILL.md"
    ) == ("https://github.com/acme/repo", "main", "SKILL.md")


def test_git_tail_stripped() -> None:
    assert extract_git_parts(
        "https://github.com/acme/repo.git/tree/main/skills/tdd"
    ) == ("https://github.com/acme/repo", "main", "skills/tdd")


def test_gitlab_legacy_separator() -> None:
    assert extract_git_parts(
        "https://gitlab.com/acme/repo/-/tree/main/skills/tdd"
    ) == ("https://gitlab.com/acme/repo", "main", "skills/tdd")


def test_deep_branch_ref_first_segment_only() -> None:
    # "release/1.2" style refs: first attempt takes single-segment ref; the
    # extract_source retry loop handles the slash-ref case at clone time.
    parts = extract_git_parts(
        "https://github.com/acme/repo/tree/release/1.2/skills"
    )
    assert parts == ("https://github.com/acme/repo", "release", "1.2/skills")


def test_non_github_host_still_works() -> None:
    assert extract_git_parts("https://bitbucket.org/acme/repo/tree/dev/x") == (
        "https://bitbucket.org/acme/repo",
        "dev",
        "x",
    )


def test_not_a_repo_url_returns_none() -> None:
    assert extract_git_parts("git@github.com:acme/repo.git") is None  # ssh remote
    assert extract_git_parts("/tmp/local/dir") is None  # local path
    assert extract_git_parts("https://github.com") is None  # bare host
    assert extract_git_parts("") is None


# --- subpath resolution ---------------------------------------------------------------


def test_resolve_subdir_found(tmp_path: Path) -> None:
    (tmp_path / "skills" / "tdd").mkdir(parents=True)
    got = _resolve_audit_subdir(
        tmp_path, "skills/tdd", source_display="https://x/y/tree/main/skills/tdd"
    )
    assert got == (tmp_path / "skills" / "tdd").resolve()


def test_resolve_subdir_empty_is_root(tmp_path: Path) -> None:
    assert (
        _resolve_audit_subdir(tmp_path, "", source_display="https://x/y")
        == tmp_path
    )


def test_resolve_subdir_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(ExtractionError, match="no 'skills/missing' path"):
        _resolve_audit_subdir(
            tmp_path, "skills/missing", source_display="https://x/y/tree/main/skills/missing"
        )


def test_resolve_subdir_escape_raises(tmp_path: Path) -> None:
    with pytest.raises(ExtractionError, match="escapes the repository"):
        _resolve_audit_subdir(
            tmp_path, "../outside", source_display="https://x/y/tree/main/../outside"
        )
