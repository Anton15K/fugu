# Nebius x NVIDIA Global AI Hackathon — Research Summary

> Source: https://nebiusglobalaihackathon.devpost.com (live rules page + archived overview, verified 2026-09-18)
> Local copies: `research/devpost_home.html` (archive 2026-08-29), `research/rules_text.txt` (live)

## Key dates

| Milestone | Date |
|---|---|
| Submission period | Aug 26 – **Oct 30, 2026, 10:00 AM PDT** (hard deadline) |
| Judging period | Dec 1 – Dec 15, 2026 |
| Winners announced | ~Jan 11, 2027 |

**~6 weeks left** as of Sep 18.

## Core requirement (applies to ALL tracks)

A working software application that:
1. **Runs on Nebius Token Factory or Nebius AI Cloud** — meaning it makes a *runtime call* to the Token Factory inference API, **or** is deployed/run on Nebius AI Cloud compute (Serverless Jobs, Serverless Endpoints, or DevPods).
2. **Uses at least one NVIDIA open source model** (Nemotron family, GROOT, Cosmos, Sonic...).

Projects may be new, or pre-existing projects **significantly updated** after Aug 26, 2026 (must explain what changed).

## The 4 tracks

### 1. Coding and Agentic Engineering
Build coding agents and developer tools: agents that **write, run, and test code in Token Factory Sandboxes**.

### 2. Best Apps and Agents
Any app or agent people would actually use — productivity tool, copilot, self-running workflow. Power it with **Nemotron models via Token Factory**: Nemotron 3 Ultra for deep reasoning, Nano/Super for fast everyday calls. Serverless Endpoints/Jobs encouraged but not required.

### 3. Personal AI
An **always-on, private assistant**: persistent memory, reusable skills, user-chosen tools, acts across daily workflows. Tools mentioned: **NVIDIA NemoClaw, OpenShell, Hermes Agent, Nebius Serverless**. Data stays under user control.

### 4. Physical AI
Embodied/edge agents — robotics, IoT, on-device intelligence — powered by Nemotron, GROOT, Cosmos, Sonic, coordinated through an agent runtime. Serverless Jobs for simulations/synthetic data/policy eval; Serverless Endpoints for real-time inference. **Demo video must include ≥1 min of actual hardware/robot operating** (or key app modules if no hardware).

## Prizes ($50,000+ total)

| Prize | Reward | Winners |
|---|---|---|
| Grand Prize | $20,000 | 1 |
| 2nd Place | $10,000 | 1 |
| 3rd Place | $6,000 | 1 |
| Each of 4 Track Winners | NVIDIA Jetson Orin Nano | 1 each |
| Best Use of Tavily | $3,000 (needs runtime Tavily API call) | 1 |
| City Winner Awards | $500 × 20 cities (Builders & Brews events) | 20 |
| Most Valuable Feedback | $100 + NVIDIA swag | 10 |

Note: a project can win max **1 Overall OR 1 Track award, plus 1 Bonus award**.

## Acceptance criteria — submission checklist

- [ ] Working project meeting the core requirement (above) + track requirements
- [ ] Track selected at submission
- [ ] Text description: what, why, how it works
- [ ] **URL to a working demo / hosted app / test build** (not required for Physical AI; judges get free access — include credentials if private)
- [ ] **Demo video ≤ 3 minutes**, public on YouTube, with audio explaining how you used Token Factory + NVIDIA models (Physical AI: ≥1 min hardware footage). No copyrighted music/trademarks.
- [ ] **Public repo** (GitHub/GitLab/Bitbucket) with:
  - Open source license file (Apache 2.0 / MIT / MPL 2.0) **visible at top of repo page**
  - README with setup + run instructions
  - Explicitly highlights NVIDIA model usage, where Token Factory accelerated workflow, other Nebius tools used
- [ ] Feedback section on Token Factory / AI Cloud / NVIDIA tools (also 10× $100 prizes)
- [ ] If pre-existing: written explanation of significant updates during the submission period
- [ ] All materials in English (or with English translation)
- [ ] Original work, solely owned by entrant, no sponsor funding/preferential support

## Judging (two stages)

**Stage One (pass/fail):** baseline viability — genuinely fits the track's stated goal and really applies the required APIs (not a superficial rebrand of an unrelated idea).

**Stage Two (equally weighted):**
1. **Technological Implementation** — how well built; how effectively it uses Token Factory/AI Cloud + Nemotron/NVIDIA OSS models
2. **Design** — complete, coherent product experience, *not just a technical PoC*
3. **Potential Impact** — credible, specific case for solving a real problem for a real audience
4. **Quality of the Idea** — creative, non-obvious use of the tech; genuine understanding of the problem space

Ties broken by highest score in the first applicable criterion.

## Eligibility

Age of majority + not in excluded regions (Brazil, Quebec, Russia, Crimea, Cuba, Iran, North Korea, US-sanctioned countries). Finland is fine. Individuals, teams, and organizations all OK; one person may be on multiple teams. 7,081 participants already registered.

## Setup — what we need to do

1. **Join the hackathon** on Devpost (free account): click "Join hackathon" at nebiusglobalaihackathon.devpost.com
2. **Claim $25 Token Factory credits**: https://nebius.com/promo-code with activation code **`NEBIUS-DEVPOST-GLOBAL26`**
3. **Join Nebius Builders Program** (free): https://dev.nebius.com/builders → another $25 credits + Tavily credits + Nebius Academy, training, office hours, builder community
4. **Create Token Factory account**: https://tokenfactory.nebius.com (Google/GitHub login) → generate API key
5. **Dev environment** — Token Factory is OpenAI-wire-compatible:
   ```python
   from openai import OpenAI
   client = OpenAI(
       base_url="https://api.tokenfactory.nebius.com/v1/",  # EU region
       api_key=os.environ["NEBIUS_API_KEY"],
   )
   ```
   - Default model: `nvidia/nemotron-3-super-120b-a12b` (MoE, ~1M ctx, native function calling)
   - Heavy reasoning: `nemotron-3-ultra-550b`; fast/cheap: Nano variants
   - US region base URL: `https://api.tokenfactory.us-central1.nebius.com/v1/`
6. **Cookbook / examples**: https://github.com/nebius/token-factory-cookbook (agents, RAG, function calling, LiteLLM/LangChain wiring)
7. **Docs index**: https://docs.tokenfactory.nebius.com/llms.txt
8. **Nebius Discord**: https://discord.gg/ZdC3rXMJH
9. Optional: Tavily API key (for the $3k Best Use of Tavily prize — needs a functional runtime call)
10. Optional: attend a Builders & Brews city event for extra credits + community (Stockholm Sep 18, Amsterdam Sep 25, Berlin Sep 29, Paris Oct 1 — full list: luma.com/builderandbrews). Attending is NOT required for the $500 City Winner award — submissions associated with a participating city are considered.

## Strategic notes

- Judges score "Design: complete product experience, not just a PoC" — budget time for UX polish, not only the agent loop.
- "Technological Implementation" explicitly rewards *effective* use of Token Factory/Nemotron — show a real architecture (e.g., model routing Ultra↔Nano, Sandboxes, Serverless Jobs), and document it in the README.
- The demo video (≤3 min, YouTube, with narration about Nebius usage) is a hard requirement — script and record it early, don't leave it for the last day.
- Repo hygiene (license visible at top, good README) is a checklist item — easy points.
- Feedback section is both an acceptance item and a prize category — write it thoughtfully.
