"""Configuration for the Nebius Token Factory client.

Loads settings from the environment (a local `.env` file is honoured via
python-dotenv) and exposes the constants used across the project.
"""

from __future__ import annotations

import os
import sys
from dataclasses import asdict, dataclass

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
NANO_MODEL = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
SUPER_MODEL = "nvidia/nemotron-3-super-120b-a12b"
ULTRA_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"


@dataclass(frozen=True)
class ProductionLimits:
    """Immutable, shared defaults for bounded production audit work."""

    llm_max_output_tokens: int = 4_096
    request_timeout_seconds: int = 90
    sdk_max_retries: int = 0
    semantic_max_units: int = 24
    semantic_max_chars_per_unit: int = 6_000
    semantic_max_file_bytes: int = 2_000_000
    semantic_max_files: int = 2_000
    harness_max_file_bytes: int = 2_000_000
    harness_max_files: int = 50
    harness_mount_char_budget: int = 32_000
    harness_standard_static_probes: int = 3
    harness_full_static_probes: int = 6
    red_probe_count: int = 3
    red_probe_max_chars: int = 200
    source_max_bytes: int = 512 * 1024 * 1024
    source_max_entries: int = 20_000
    git_clone_timeout_seconds: int = 120
    fanout_max_units: int = 24

    def to_dict(self) -> dict[str, int]:
        """Return the safe, JSON-serializable effective profile."""
        return asdict(self)


DEFAULT_PRODUCTION_LIMITS = ProductionLimits()


def get_production_limits() -> ProductionLimits:
    """Return the immutable production limits used by default pipeline paths."""
    return DEFAULT_PRODUCTION_LIMITS


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
