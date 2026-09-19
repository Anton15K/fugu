# HANDOFF — Nebius x NVIDIA Global AI Hackathon project
> Written 2026-09-19 by the research/setup session. Read this first in a new session.

## Mission of the next session
Idea is LOCKED (Fugu — see IDEA.md) and the core mechanism is spike-validated. Next: confirm open decisions below, then build the MVP pipeline (stages 0–5) on the existing scaffold, with the Docker detonation driver from `spikes/001-canary-egress/` promoted into `src/` and the Sandboxes driver added when beta access lands.

## Hard facts (verified, don't re-research)
- **Deadline: Oct 30, 2026, 10:00 AM PDT** (submit on Devpost; ~6 weeks left as of Sep 19)
- Judging (equally weighted): Technological Implementation · Design ("complete product, not a PoC") · Potential Impact · Quality of the Idea. Stage 1 is pass/fail fit-to-track.
- **Core requirement**: runtime call to Token Factory inference API (or Nebius AI Cloud deploy) + ≥1 NVIDIA open source model.
- Submission needs: public repo w/ license visible at top, README, **working demo URL**, **≤3-min YouTube video** w/ narration on Nebius+NVIDIA usage, feedback section, English.
- Prizes: $20k/$10k/$6k overall; Jetson Orin Nano per track; $3k Best Use of Tavily (needs runtime Tavily call); 20× $500 city awards.
- Full details: `RESEARCH.md` (tracks, rules, prizes, criteria, strategy notes). Raw sources: `research/`.

## Current state (updated 2026-09-19, evening)
- Scaffold at `~/Desktop/nebius_hack` — git repo (commit 72ec100, main), MIT LICENSE, README skeleton.
- **API verified working**: `nvidia/nemotron-3-super-120b-a12b` chat + native tool calling (`get_current_time` agent loop) + FastAPI `/chat` all tested end-to-end.
- 24 models on the account incl. Qwen3-235B-A22B, gpt-oss-120b, gemma-3-27b, Qwen3-Embedding-8B.
- `NEBIUS_API_KEY` is in `.env` (gitignored) — **never print it or paste it in chat**.
- **IDEA LOCKED (see IDEA.md)**: agentic OWASP-mapped security auditor for agent skills/MCP/plugins ("Fugu" working name). Track 1 (Coding & Agentic) recommended, not yet formally confirmed by user.
- **Spike 001 VALIDATED**: local Docker detonation chamber — canary env vars + mitmproxy (lazy strategy) + stdlib DNS collector caught all 3 exfil vectors. `spikes/001-canary-egress/` (README verdict + RUN_OUTPUT.txt + evidence JSONLs). Driver interface defined; Sandboxes driver swaps in when access lands.
- **Sandboxes beta access: form submitted** by user 2026-09-19 (request text in `docs/sandbox-access-request.md`); free during beta. Python SDK: `contree-sdk`/`contree_client.httpx`.

## Decisions
- [x] **Track: 1 — Coding and Agentic Engineering** (decided 2026-09-19)
- [ ] Effort level / hours per week (MVP scope in IDEA.md assumes ~60–80 h total)
- [ ] Frontend ownership (agent builds React UI vs user builds)
- [ ] Name (Fugu / Canary / other)

## Existing stack (working, keep unless there's a reason to change)
Python 3.11 + uv (pip is missing/PEP 668 — always use `uv run`), OpenAI SDK → Token Factory (`https://api.tokenfactory.nebius.com/v1/`), FastAPI + uvicorn, pytest.
Layout: `src/app/{config,client,model_router,api}.py`, `scripts/{smoke_test,demo_agent}.py`, `tests/`.
Key commands: `uv run python scripts/smoke_test.py [--dry-run]`, `uv run uvicorn src.app.api:app --reload`, `uv run pytest -q`. Docker 28.4 present (Docker Desktop) — needed for the local detonation driver.

## Candidate directions (historical — idea now locked, see IDEA.md)
1. **Coding & Agentic Engineering** — agents that write/run/test code in **Token Factory Sandboxes**; distinctive infra angle, fewer teams will use Sandboxes well. Fits the existing Python agent scaffold.
2. **Best Apps & Agents** — broadest fit; winning hook could be **model routing** (Nemotron Ultra for reasoning ↔ Super/Nano for cheap/fast) since the scaffold already has `model_router.py`. Tavily integration adds $3k bonus eligibility.
3. **Personal AI** — mentions Hermes Agent, NemoClaw, OpenShell explicitly; "always-on private assistant with memory/skills" — note: this chat runtime IS Hermes, possible meta angle + insider knowledge.
4. **Physical AI** — highest barrier (hardware video requirement ≥1 min), skip unless user has robots/IoT.
