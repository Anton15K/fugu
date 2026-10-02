"""Tests for bounded model-client defaults."""
from __future__ import annotations

from types import SimpleNamespace

import fugu.client as client_module


def test_make_client_bounds_timeout_and_disables_hidden_sdk_retries(monkeypatch):
    received = {}

    def fake_openai(**kwargs):
        received.update(kwargs)
        return object()

    monkeypatch.setattr(client_module, "OpenAI", fake_openai)
    settings = SimpleNamespace(base_url="https://example.invalid/v1/", api_key="synthetic-test-key")

    result = client_module.make_client(settings)

    assert result is not None
    assert received["base_url"] == settings.base_url
    assert received["api_key"] == settings.api_key
    assert received["max_retries"] == 0
    assert received["timeout"] == 90
