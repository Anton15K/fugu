"""OpenAI SDK client wired to the Nebius Token Factory inference API.

The Token Factory API is wire-compatible with the OpenAI API, so we reuse the
official `openai` Python SDK and simply swap the endpoint:

    client = OpenAI(base_url="https://api.tokenfactory.nebius.com/v1/",
                    api_key=os.environ["NEBIUS_API_KEY"])

Every SDK feature (chat.completions, models.list, tools/function calling,
streaming) then works unchanged against Nebius-hosted NVIDIA models.
"""

from __future__ import annotations

from openai import OpenAI

from fugu.config import Settings, get_settings


def make_client(settings: Settings | None = None) -> OpenAI:
    """Return a bounded, single-request client pointed at Nebius Token Factory.

    Pipeline stages own response-level retry decisions so failed calls stay
    visible in coverage metrics. Disable implicit SDK retries and bound each
    request to the same 90-second timeout used by the full-capability runner.
    """
    settings = settings or get_settings()
    return OpenAI(
        base_url=settings.base_url,
        api_key=settings.api_key,
        max_retries=0,
        timeout=90,
    )
