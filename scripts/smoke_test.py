"""Smoke test for the Nebius Token Factory wiring.

Usage:
    uv run python scripts/smoke_test.py            # real calls (needs key)
    uv run python scripts/smoke_test.py --dry-run  # config/imports only

The dry run validates configuration and imports and prints exactly what it
WOULD call - no network, no API key required, always exits 0 on success.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make repo-root imports work when running from the project root.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.client import make_client  # noqa: E402
from app.config import SUPER_MODEL, get_settings, require_api_key  # noqa: E402
from app.model_router import pick_model  # noqa: E402

SMOKE_PROMPT = "Reply with exactly: Token Factory smoke test OK"


def dry_run() -> int:
    settings = get_settings()
    print("DRY RUN - validating configuration and imports (no network calls)")
    print(f"  base_url  = {settings.base_url}")
    print(f"  api_key   = {'<set>' if settings.has_api_key else '<NOT SET (ok for dry run)>'}")
    print(f"  imports   = app.client.make_client, app.config, app.model_router OK")
    print()
    print("WOULD call:")
    print(f"  1) client.models.list()")
    print(f"     -> GET {settings.base_url}models  (Authorization: Bearer <NEBIUS_API_KEY>)")
    print(f"  2) client.chat.completions.create(")
    print(f"        model={SUPER_MODEL!r},")
    print(f"        messages=[{{'role': 'user', 'content': {SMOKE_PROMPT!r}}}],")
    print(f"     )")
    print(f"     -> POST {settings.base_url}chat/completions")
    print(f"  routed model for task 'chat'      -> {pick_model('chat')}")
    print(f"  routed model for task 'reasoning' -> {pick_model('reasoning')}")
    print()
    print("Dry run OK.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate config/imports and print what would be called; no network",
    )
    args = parser.parse_args()

    if args.dry_run:
        return dry_run()

    # Real run: friendly error + exit 1 if the key is missing.
    require_api_key()
    settings = get_settings()
    print(f"Base URL: {settings.base_url}")
    print()
    print("[1/2] Listing models (client.models.list()) ...")
    client = make_client(settings)
    models = [m.id for m in client.models.list()]
    print(f"  {len(models)} models available, e.g.: {models[:5]}")

    print()
    print(f"[2/2] Chat completion via {SUPER_MODEL} ...")
    completion = client.chat.completions.create(
        model=SUPER_MODEL,
        messages=[{"role": "user", "content": SMOKE_PROMPT}],
    )
    reply = completion.choices[0].message.content or ""
    print(f"  reply: {reply.strip()!r}")
    print()
    print("Smoke test OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
