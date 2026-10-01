from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def installer():
    path = Path(__file__).resolve().parents[1] / "rig" / "setup.py"
    assert path.is_file(), "The rig profile installer does not exist yet"
    spec = importlib.util.spec_from_file_location("fugu_rig_setup", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.install_profiles


@pytest.fixture
def profiles(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("fugu-rig-high", "fugu-rig-medium"):
        (source / f"{name}.config.toml").write_text('sandbox_mode = "workspace-write"\n')
    return source


def test_preserves_defaults_and_is_idempotent(installer, profiles, tmp_path):
    target = tmp_path / "codex"
    target.mkdir()
    defaults = target / "config.toml"
    defaults.write_text('model = "operator-choice"\n')
    installer(profiles, target)
    installed = target / "fugu-rig-high.config.toml"
    first = installed.stat().st_mtime_ns
    installer(profiles, target)
    assert installed.stat().st_mtime_ns == first
    assert defaults.read_text() == 'model = "operator-choice"\n'
    assert (target / "fugu-rig-medium.config.toml").is_file()


def test_conflict_is_detected_before_installing_any_file(installer, profiles, tmp_path):
    target = tmp_path / "codex"
    target.mkdir()
    conflict = target / "fugu-rig-medium.config.toml"
    conflict.write_text('model = "existing-choice"\n')
    with pytest.raises(ValueError):
        installer(profiles, target)
    assert not (target / "fugu-rig-high.config.toml").exists()
    assert conflict.read_text() == 'model = "existing-choice"\n'


def test_malformed_source_writes_nothing(installer, profiles, tmp_path):
    target = tmp_path / "codex"
    (profiles / "fugu-rig-medium.config.toml").write_text("invalid = [\n")
    with pytest.raises(ValueError):
        installer(profiles, target)
    assert not target.exists()


def test_symlinked_destination_is_not_followed(installer, profiles, tmp_path):
    target = tmp_path / "codex"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("preserve me")
    (target / "fugu-rig-high.config.toml").symlink_to(outside)
    with pytest.raises(ValueError):
        installer(profiles, target)
    assert outside.read_text() == "preserve me"
    assert not (target / "fugu-rig-medium.config.toml").exists()
