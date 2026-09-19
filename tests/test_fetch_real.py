"""Hermetic unit tests for bench/fetch_real.py wrapping logic.

No network, no git: builds tiny fake repos on disk (tmp_path) and asserts
how ``wrap_samples`` discovers skills per layout, applies caps and the
2 MB size ceiling, skips non-skill dirs, and writes schema-valid
manifest.fugu.json entries (keys required by eval/loader + run_bench).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from bench.fetch_real import (  # noqa: E402
    MAX_PER_SOURCE,
    MAX_SKILL_BYTES,
    Source,
    discover_skill_dirs,
    wrap_samples,
)


def _make_skill(parent: Path, name: str, body: str = "# skill\n", filler_kb: int = 0) -> Path:
    d = parent / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(body)
    if filler_kb:
        (d / "blob.bin").write_bytes(b"\0" * filler_kb * 1024)
    return d


@pytest.fixture
def skills_dir_repo(tmp_path: Path) -> Path:
    """Repo shaped like anthropics/skills or obra/superpowers."""
    repo = tmp_path / "skills_dir_repo"
    (repo / "skills").mkdir(parents=True)
    _make_skill(repo / "skills", "alpha")
    _make_skill(repo / "skills", "beta")
    (repo / "skills" / "not-a-skill").mkdir()          # no SKILL.md -> skipped
    (repo / "README.md").write_text("# repo\n")
    return repo


@pytest.fixture
def root_layout_repo(tmp_path: Path) -> Path:
    """Repo shaped like claude-office-skills/skills (skills at root)."""
    repo = tmp_path / "root_repo"
    repo.mkdir()
    _make_skill(repo, "invoice-writer")
    _make_skill(repo, "contract-review")
    (repo / "_shared").mkdir()                          # underscore prefix -> skipped
    (repo / ".github").mkdir()                          # dot prefix -> skipped
    (repo / "LICENSE").write_text("MIT")
    return repo


# --- discovery ---------------------------------------------------------------

def test_discover_skills_dir_layout(skills_dir_repo: Path) -> None:
    cfg = Source(url="https://example.com/repo", layout="skills_dir", subdir="skills")
    found = discover_skill_dirs(skills_dir_repo, cfg)
    assert [d.name for d in found] == ["alpha", "beta"]


def test_discover_root_layout(root_layout_repo: Path) -> None:
    cfg = Source(url="https://example.com/repo", layout="root")
    found = discover_skill_dirs(root_layout_repo, cfg)
    assert [d.name for d in found] == ["contract-review", "invoice-writer"]


def test_discover_include_allowlist(skills_dir_repo: Path) -> None:
    cfg = Source(url="u", layout="skills_dir", subdir="skills", include=("beta",))
    assert [d.name for d in discover_skill_dirs(skills_dir_repo, cfg)] == ["beta"]


def test_discover_missing_subdir(tmp_path: Path) -> None:
    cfg = Source(url="u", layout="skills_dir", subdir="nope")
    assert discover_skill_dirs(tmp_path, cfg) == []


# --- wrapping ----------------------------------------------------------------

def test_wrap_writes_manifests(skills_dir_repo: Path, tmp_path: Path) -> None:
    cfg = Source(url="https://example.com/repo", layout="skills_dir", subdir="skills")
    out = tmp_path / "out"
    n = wrap_samples(skills_dir_repo, "testsrc", cfg, out_root=out)
    assert n == 2
    for skill in ("alpha", "beta"):
        sample = out / skill
        assert (sample / "SKILL.md").is_file()
        m = json.loads((sample / "manifest.fugu.json").read_text())
        assert m["name"] == f"real-testsrc-{skill}"
        assert m["kind"] == "benign"
        assert m["expected_owasp_ids"] == []
        assert "description" in m and m["provenance"] == "real"


def test_wrap_names_unique_across_sources(skills_dir_repo: Path, tmp_path: Path) -> None:
    """Same skill name from two sources must not collide in run_bench keys."""
    cfg = Source(url="u", layout="skills_dir", subdir="skills")
    a = wrap_samples(skills_dir_repo, "srcA", cfg, out_root=tmp_path / "a")
    b = wrap_samples(skills_dir_repo, "srcB", cfg, out_root=tmp_path / "b")
    names = set()
    for root in (tmp_path / "a", tmp_path / "b"):
        for mf in root.glob("*/manifest.fugu.json"):
            names.add(json.loads(mf.read_text())["name"])
    assert a == b == 2
    assert len(names) == 4  # real-srcA-{alpha,beta} + real-srcB-{alpha,beta}


def test_wrap_cap(skills_dir_repo: Path, tmp_path: Path) -> None:
    cfg = Source(url="u", layout="skills_dir", subdir="skills")
    out = tmp_path / "out"
    n = wrap_samples(skills_dir_repo, "capped", cfg, cap=1, out_root=out)
    assert n == 1
    assert len(list(out.iterdir())) == 1


def test_wrap_skips_oversized_skill(tmp_path: Path) -> None:
    repo = tmp_path / "big"
    (repo / "skills").mkdir(parents=True)
    _make_skill(repo / "skills", "small")
    _make_skill(repo / "skills", "huge", filler_kb=(MAX_SKILL_BYTES // 1024) + 1)
    cfg = Source(url="u", layout="skills_dir", subdir="skills")
    out = tmp_path / "out"
    n = wrap_samples(repo, "big", cfg, out_root=out)
    assert n == 1
    assert (out / "small" / "manifest.fugu.json").is_file()
    assert not (out / "huge").exists()


def test_wrap_recreates_out_root(skills_dir_repo: Path, tmp_path: Path) -> None:
    cfg = Source(url="u", layout="skills_dir", subdir="skills")
    out = tmp_path / "out"
    out.mkdir()
    (out / "stale").mkdir()
    wrap_samples(skills_dir_repo, "again", cfg, out_root=out)
    assert not (out / "stale").exists()
    assert len(list(out.iterdir())) == 2


def test_default_cap_constant() -> None:
    assert MAX_PER_SOURCE == 25
    assert MAX_SKILL_BYTES == 2 * 1024 * 1024


# --- real SOURCES registry sanity (no network) --------------------------------

def test_sources_registry_shape() -> None:
    from bench.fetch_real import SOURCES

    assert "anthropic-skills" in SOURCES
    for name, cfg in SOURCES.items():
        assert cfg.url.startswith("https://github.com/"), name
        assert cfg.layout in ("skills_dir", "root"), name
        assert name != "anthropics"  # third-party, not the vendor itself
    third_party = [n for n in SOURCES if n != "anthropic-skills"]
    assert len(third_party) >= 2, "expansion requires >=2 third-party sources"
