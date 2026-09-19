"""Configuration for the Nebius Token Factory client.

Loads settings from the environment (a local `.env` file is honoured via
python-dotenv) and exposes the constants used across the project.
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()  # reads .env from the working directory, if present

# --- Nebius Token Factory endpoints ---------------------------------------
# Official base URLs (OpenAI-wire-compatible). Override with NEBIUS_BASE_URL.
BASE_URL_EU = "https://api.tokenfactory.nebius.com/v1/"
BASE_URL_US = "https://api.tokenfactory.us-central1.nebius.com/v1/"
DEFAULT_BASE_URL = BASE_URL_EU

# --- NVIDIA open source model IDs available on Token Factory ---------------
# Do NOT hardcode more model IDs here: call client.models.list()
# (GET /models) at runtime to discover the full catalogue.
#
# nemotron-3-super-120b-a12b: MoE "Super" tier - ~1M token context, native
#   function/tool calling, fast and cheap. Default for everyday calls.
# nemotron-3-ultra-550b: "Ultra" tier - heavy reasoning model. Use when answer
#   quality on hard problems matters more than latency/cost.
SUPER_MODEL = "nvidia/nemotron-3-super-120b-a12b"
ULTRA_MODEL = "nvidia/nemotron-3-ultra-550b"


class Settings:
    """Simple env-backed settings holder."""

    def __init__(self) -> None:
        self.base_url: str = (
            os.environ.get("NEBIUS_BASE_URL", DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
        )
        # Key may be empty at scaffold time; require_api_key() guards real calls.
        self.api_key: str = os.environ.get("NEBIUS_API_KEY", "").strip()

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)


def get_settings() -> Settings:
    """Return a fresh Settings instance (re-reads the environment)."""
    return Settings()


def require_api_key(settings: Settings | None = None) -> str:
    """Return the Nebius API key or exit with a friendly, actionable error.

    Never raises a raw stack trace at the user: prints clear instructions
    and exits with code 1.
    """
    settings = settings or get_settings()
    if settings.has_api_key:
        return settings.api_key
    print(
        "ERROR: NEBIUS_API_KEY is not set.\n"
        "\n"
        "  1. Copy .env.example to .env\n"
        "       cp .env.example .env\n"
        "  2. Put your Nebius Token Factory API key in it:\n"
        "       NEBIUS_API_KEY=your-key-here\n"
        "  3. Run this command again.\n"
        "\n"
        "Tip: use --dry-run to validate the setup without a key.",
        file=sys.stderr,
    )
    sys.exit(1)
