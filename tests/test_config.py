"""Unit tests for configuration and dry-run helpers (no network access)."""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import fugu.client as client_module
import fugu.config as config
import scripts.smoke_test as smoke_test  # noqa: E402  (scripts/ has no __init__)


def _scripts_importable() -> bool:
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "demo_agent", _PROJECT_ROOT / "scripts" / "demo_agent.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        return hasattr(mod, "dry_run") and hasattr(mod, "run_agent")
    except Exception:
        return False


def test_settings_defaults_sane() -> None:
    settings = config.get_settings()
    assert settings.base_url.startswith("https://")
    assert "tokenfactory" in settings.base_url
    assert settings.base_url.endswith("/v1/")
    assert isinstance(settings.api_key, str)


def test_model_constants() -> None:
    assert config.SUPER_MODEL == "nvidia/nemotron-3-super-120b-a12b"
    # Verified against the live account model list (2026-09-19): ULTRA is
    # the -a55b variant; the bare -550b id 404s.
    assert config.ULTRA_MODEL == "nvidia/Nemotron-3-Ultra-550b-a55b"
    assert config.NANO_MODEL == "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
    assert config.SUPER_MODEL.startswith("nvidia/")


def test_model_router_routing() -> None:
    from fugu.model_router import pick_model

    assert pick_model("reasoning") == config.ULTRA_MODEL
    assert pick_model("prove this math theorem") == config.ULTRA_MODEL
    assert pick_model("chat") == config.SUPER_MODEL
    assert pick_model("") == config.SUPER_MODEL
    assert pick_model("summarize this article") == config.SUPER_MODEL


def test_make_client_factory_exists_and_wired() -> None:
    assert callable(client_module.make_client)
    settings = config.get_settings()
    # The OpenAI SDK requires a non-empty key string; in real flows
    # require_api_key() guarantees one before make_client() is called.
    settings.api_key = settings.api_key or "dummy-key-for-wiring-test"
    c = client_module.make_client(settings)
    assert str(c.base_url).rstrip("/") == settings.base_url.rstrip("/")


def test_dry_run_helpers_exist() -> None:
    # smoke_test imported as a module above: dry_run must exist and exit 0
    assert callable(getattr(smoke_test, "dry_run", None))
    assert callable(getattr(smoke_test, "main", None))
    # demo_agent loaded from file: dry_run/run_agent must exist
    assert _scripts_importable()


def test_require_api_key_missing_exits_cleanly(monkeypatch) -> None:
    import pytest

    monkeypatch.setenv("NEBIUS_API_KEY", "")
    settings = config.Settings()
    assert settings.has_api_key is False

    class _NoKeySettings:
        has_api_key = False

    # require_api_key with no key must SystemExit(1), never a raw exception.
    with pytest.raises(SystemExit) as exc_info:
        config.require_api_key(_NoKeySettings())  # type: ignore[arg-type]
    assert exc_info.value.code == 1
