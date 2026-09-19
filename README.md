# <PROJECT TITLE> — Nebius x NVIDIA Global AI Hackathon

> **Status: scaffold.** Track not chosen yet; this repo will be fleshed out as
> the idea develops. Placeholder sections below are marked TODO.

## What it is

TODO: one-paragraph description of the project (track-agnostic for now).

Built for the [Nebius x NVIDIA Global AI Hackathon](https://docs.tokenfactory.nebius.com/)
on top of the **Nebius Token Factory** inference API running **NVIDIA open
source models** (the Nemotron family).

## Setup

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone <repo-url>
cd nebius_hack
uv venv
uv sync --extra dev
```

## Configuration

Copy the example env file and add your Nebius Token Factory API key:

```bash
cp .env.example .env
# then edit .env:
#   NEBIUS_API_KEY=...      (required for real API calls)
#   NEBIUS_BASE_URL=...     (optional; EU endpoint by default)
```

`.env` is gitignored — never commit real keys.

## Run

```bash
# 1. Smoke test: validate wiring without a key
uv run python scripts/smoke_test.py --dry-run

# 2. Smoke test: real Token Factory calls (needs NEBIUS_API_KEY)
uv run python scripts/smoke_test.py

# 3. Demo tool-calling agent (needs NEBIUS_API_KEY)
uv run python scripts/demo_agent.py "What time is it right now, in UTC?"
uv run python scripts/demo_agent.py --task reasoning "Plan a 3-step experiment"  # routes to Ultra

# 4. API server
uv run uvicorn src.app.api:app --reload
# GET  http://127.0.0.1:8000/health
# POST http://127.0.0.1:8000/chat  {"message": "hello"}
```

## NVIDIA open source models used

All inference runs on **NVIDIA open source models** served by Nebius Token
Factory:

| Model | Tier | When to use |
|---|---|---|
| `nvidia/nemotron-3-super-120b-a12b` | Super (MoE) | Default: fast everyday calls, ~1M context, native function calling |
| `nvidia/nemotron-3-ultra-550b` | Ultra | Heavy reasoning when quality matters more than latency/cost |

Model selection is centralized in `src/app/model_router.py`. The full model
catalogue is discovered at runtime via `client.models.list()` — never
hardcoded.

## Nebius Token Factory usage

The Token Factory API (`https://api.tokenfactory.nebius.com/v1/`) is
wire-compatible with the OpenAI API, so this project uses the official
`openai` Python SDK with the base URL and key swapped:

```python
from app.client import make_client

client = make_client()  # OpenAI(base_url=NEBIUS_BASE_URL, api_key=NEBIUS_API_KEY)
completion = client.chat.completions.create(model="nvidia/nemotron-3-super-120b-a12b", ...)
```

- Docs: https://docs.tokenfactory.nebius.com/llms.txt
- Cookbook: https://github.com/nebius/token-factory-cookbook

## Project structure

```
├── pyproject.toml          # uv-managed project + deps
├── .env.example            # env template (NEBIUS_API_KEY, NEBIUS_BASE_URL)
├── LICENSE                 # MIT
├── README.md
├── src/app/
│   ├── config.py           # env loading, base URLs, model IDs, require_api_key()
│   ├── client.py           # make_client(): OpenAI SDK wired to Token Factory
│   ├── model_router.py     # pick_model(task): Super vs Ultra routing
│   └── api.py              # FastAPI skeleton (/health, /chat)
├── scripts/
│   ├── smoke_test.py       # models.list + chat completion; --dry-run mode
│   └── demo_agent.py       # minimal tool-calling agent loop; --dry-run mode
└── tests/
    └── test_config.py      # config/router/dry-run unit tests (no network)
```

## License

[MIT](LICENSE) © 2026 Nebius Hackathon Team
