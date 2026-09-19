# BOTS.md — operating guide for autonomous workstreams on Fugu

> You are one of several autonomous agents working IN PARALLEL in the same
> working tree at `/Users/antonkogun/Desktop/nebius_hack`. A tech lead (the
> orchestrating agent) reviews and commits all work. You do NOT use git.

## Project (60-second version)
Fugu = agentic security auditor for third-party agent extensions (skills /
MCP servers / plugins), Nebius x NVIDIA hackathon, Track 1. Pipeline stages:
S0 concealment (Unicode smuggling) → S1 static → S2 semantic (LLM, not yours)
→ S3 detonation (sandbox w/ canary creds + egress capture) → S4 harness A/B
→ S5 reputation → composition → verdict. Every finding maps to OWASP ids
(MCP01–10, LLM01/02/03/06) and carries a confidence tier
(deterministic / measured / empirical / advisory). Read `IDEA.md` for the
full spec and `HANDOFF.md` for state. Validated spike: `spikes/001-canary-egress/`.

## Hard rules
1. **Territory only.** Create/modify files ONLY inside your assigned
   territory (listed in your task). Everything else is read-only.
2. **Shared contracts are read-only**: `src/fugu/types.py`,
   `src/fugu/pipeline/base.py`. Need a change? Note it in your summary and
   code around it with a local adapter.
3. **No git commands** (no commit/branch/checkout/stash). The lead commits.
4. **No edits** to `pyproject.toml`, `.gitignore`, `uv.lock`. Missing dep?
   Document it in your summary; use stdlib otherwise.
5. **Offline.** Never read or print `.env`, never call the Nebius/Token
   Factory API or any LLM API, no MCPTox/HuggingFace downloads. (npm for
   the web workstream is the one exception — registry access is fine.)
6. **Run commands with** `uv run --no-sync ...` (shared venv; avoid
   re-syncing while siblings work). Frontend: plain `npm`/`npx` inside `web/`.
7. **Tests**: iterate with YOUR test files only
   (`uv run --no-sync pytest tests/<your files> -q`). Do not run the full
   suite; the lead integrates.
8. **No destructive ops** outside your territory (no rm -rf of shared dirs,
   no docker prune). Docker is available for the detonation workstream:
   reuse learnings from `spikes/001-canary-egress/` (mitmproxy needs
   `--set connection_strategy=lazy`; capture on the `request` hook, not
   `response`; victim image must trust the MITM CA).
9. Python 3.10+ compatible (`from __future__ import annotations`), stdlib
   first, type hints, small focused modules. Match existing code style in
   `src/fugu/`.
10. **You cannot ask questions.** Make reasonable assumptions, document
    every one in your summary.

## Verification bar (your work is done when…)
- All your tests pass via `uv run --no-sync pytest <your tests> -q`.
- Frontend: `npm run build` and `npx tsc --noEmit` both clean.
- No files touched outside your territory (the lead will check `git status`).
- Summary includes: files created/changed, test output tail, assumptions,
  risks/leftovers, and any contract-change requests.
