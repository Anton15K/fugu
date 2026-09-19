"""Minimal FastAPI skeleton exposing Token Factory backed endpoints.

Run (from the project root, after `uv sync`):

    uv run uvicorn src.app.api:app --reload

This module path (src.app.api) works because the project root is on
sys.path when launching uvicorn from there; the installed package path
is `app` (see pyproject hatch config).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running both as installed package (app.api) and from repo root
# (src.app.api) without installing in editable mode.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from app.client import make_client
    from app.config import SUPER_MODEL, get_settings
    from app.model_router import pick_model
except ImportError:  # pragma: no cover - fallback for src.app.api invocation
    from src.app.client import make_client  # type: ignore
    from src.app.config import SUPER_MODEL, get_settings  # type: ignore
    from src.app.model_router import pick_model  # type: ignore

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Nebius Hackathon API",
    description="Minimal API skeleton backed by Nebius Token Factory "
    "(NVIDIA Nemotron open source models).",
    version="0.1.0",
)


class ChatRequest(BaseModel):
    message: str
    task: str = ""  # routed via model_router.pick_model when provided


class ChatResponse(BaseModel):
    reply: str
    model: str


@app.get("/health")
def health() -> dict:
    """Liveness probe; also reports whether an API key is configured."""
    settings = get_settings()
    return {
        "status": "ok",
        "base_url": settings.base_url,
        "api_key_configured": settings.has_api_key,
    }


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    """One-shot chat completion through Nebius Token Factory."""
    from app.config import require_api_key

    require_api_key()
    model = pick_model(req.task) if req.task else SUPER_MODEL
    client = make_client()
    completion = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": req.message}],
    )
    reply = completion.choices[0].message.content or ""
    return ChatResponse(reply=reply, model=model)
