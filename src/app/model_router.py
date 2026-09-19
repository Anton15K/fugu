"""Model routing across NVIDIA Nemotron models on Nebius Token Factory.

Hackathon cost/latency guidance:

- ULTRA (nvidia/nemotron-3-ultra-550b): the heavy-reasoning tier. Best for
  genuinely hard problems - long multi-step reasoning, complex analysis -
  where answer quality justifies higher latency and cost.
- SUPER (nvidia/nemotron-3-super-120b-a12b): MoE "everyday" tier with ~1M
  token context and native function calling. Fast and cheap; the right
  default for chat, tool-calling agents, summarisation and bulk work.

Rule of thumb: start with SUPER; escalate to ULTRA only when SUPER's answer
quality is insufficient for the task.
"""

from __future__ import annotations

from app.config import SUPER_MODEL, ULTRA_MODEL

# Task keywords that signal "serious reasoning" -> ULTRA tier.
_REASONING_TASKS = {
    "reasoning",
    "math",
    "mathematics",
    "logic",
    "analysis",
    "prove",
    "proof",
    "research",
    "planning",
    "puzzle",
}


def pick_model(task: str = "") -> str:
    """Pick a Token Factory model ID for a task.

    Args:
        task: short free-text task descriptor (e.g. "reasoning", "chat",
            "summarize this article"). Matched case-insensitively against
            known reasoning keywords.

    Returns:
        ULTRA_MODEL for reasoning-heavy tasks, SUPER_MODEL otherwise.
    """
    normalized = (task or "").strip().lower()
    if any(keyword in normalized for keyword in _REASONING_TASKS):
        return ULTRA_MODEL
    return SUPER_MODEL
