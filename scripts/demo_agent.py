"""Minimal tool-calling agent loop against Nebius Token Factory.

Demonstrates native function calling with an NVIDIA Nemotron model via the
OpenAI-compatible Token Factory API. One demo tool is provided
(get_current_time); the loop runs until the model produces a final answer
with no further tool calls.

Usage:
    uv run python scripts/demo_agent.py "what time is it?"
    uv run python scripts/demo_agent.py --task reasoning "..."  # routes to ULTRA
    uv run python scripts/demo_agent.py --dry-run "what time is it?"
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.client import make_client  # noqa: E402
from app.config import get_settings, require_api_key  # noqa: E402
from app.model_router import pick_model  # noqa: E402

MAX_TURNS = 6  # safety cap on tool-call round trips

# --- Demo tool definition (OpenAI tools format) ---------------------------
DEMO_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_current_time",
            "description": "Get the current date and time in UTC, ISO-8601 format.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tz_offset_hours": {
                        "type": "integer",
                        "description": "Optional timezone offset from UTC in hours (e.g. 4 for UTC+4). Defaults to 0.",
                    },
                },
                "required": [],
            },
        },
    }
]


def get_current_time(tz_offset_hours: int = 0) -> str:
    """Demo tool: current time as ISO-8601 in the given UTC offset."""
    tz = timezone(timedelta(hours=tz_offset_hours))
    return datetime.now(tz).isoformat()


TOOL_IMPLEMENTATIONS = {"get_current_time": get_current_time}


def dry_run(user_message: str, task: str) -> int:
    settings = get_settings()
    model = pick_model(task)
    print("DRY RUN - validating configuration and imports (no network calls)")
    print(f"  base_url = {settings.base_url}")
    print(f"  api_key  = {'<set>' if settings.has_api_key else '<NOT SET (ok for dry run)>'}")
    print(f"  imports  = app.client.make_client, app.config, app.model_router OK")
    print()
    print("WOULD run an agent loop with:")
    print(f"  model        = {model!r}  (task={task!r})")
    print(f"  user message = {user_message!r}")
    print(f"  tools        = {[t['function']['name'] for t in DEMO_TOOLS]}")
    print(f"  max turns    = {MAX_TURNS}")
    print(f"  endpoint     = POST {settings.base_url}chat/completions")
    print()
    print("Dry run OK.")
    return 0


def run_agent(user_message: str, task: str) -> int:
    require_api_key()
    settings = get_settings()
    model = pick_model(task)
    client = make_client(settings)

    messages = [
        {
            "role": "system",
            "content": "You are a helpful agent. Use the provided tools when they "
            "help answer the user's request; otherwise answer directly.",
        },
        {"role": "user", "content": user_message},
    ]

    print(f"Model: {model}")
    print(f"User : {user_message}")
    for turn in range(1, MAX_TURNS + 1):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=DEMO_TOOLS,
        )
        msg = response.choices[0].message
        tool_calls = getattr(msg, "tool_calls", None) or []

        if not tool_calls:
            print(f"\nAgent: {msg.content}")
            return 0

        messages.append(
            {
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in tool_calls
                ],
            }
        )
        for tc in tool_calls:
            name = tc.function.name
            try:
                kwargs = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                kwargs = {}
            fn = TOOL_IMPLEMENTATIONS.get(name)
            result = fn(**kwargs) if fn else json.dumps({"error": f"unknown tool {name!r}"})
            print(f"[turn {turn}] tool {name}({kwargs}) -> {result}")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": str(result),
                }
            )

    print("\nAgent: (stopped: reached max tool turns)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("message", nargs="?", default="What time is it right now, in UTC?")
    parser.add_argument(
        "--task",
        default="chat",
        help="task descriptor for model routing (e.g. 'chat' or 'reasoning')",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate config/imports and print what would be called; no network",
    )
    args = parser.parse_args()

    if args.dry_run:
        return dry_run(args.message, args.task)
    return run_agent(args.message, args.task)


if __name__ == "__main__":
    sys.exit(main())
