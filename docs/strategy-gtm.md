# GTM + Narrative Strategy (2026-09-19, research bot, partial-but-complete)

## Story hierarchy
- **One-liner:** "Static scanners read the label — Fugu tastes the food: it detonates AI-agent skills and MCP servers in an isolated chamber seeded with canary credentials, and hands you the evidence of what they actually did."
- **Positioning (pressure-tested):** "They read the label, we taste the food" is fair ONLY vs static tools (Heimdall, mcpscan, MCPShield). NOT fully fair to Snyk Agent Scan (it does launch stdio servers to read descriptions) — so say "static scanners"/"label-readers", **never name Snyk in that line**. Our defensible delta = SAST-vs-DAST: they probe descriptions, we detonate behavior with canaries and hand over captured exhibits (full HTTPS bodies, DNS, fs diffs); local-only execution (no SNYK_TOKEN, nothing leaves the machine).
- Alternates: "Agent Scan tells you what a skill *says* it does. Fugu shows you what it *did*." / "Antivirus learned to sandbox-and-detonate twenty years ago. Agent extensions never got that." / "Proof, not vibes." / "Every skill is innocent until detonated."

## Naming — IMPORTANT FINDING
**Keep FUGU for the hackathon; re-evaluate before any commercial launch.** Collision found: **Sakana AI launched a "Fugu" AI model family in 2026, including Fugu-Cyber** (cybersecurity LLM) — adjacent-category confusion risk in AI security. Also a dormant classic macOS SFTP client named Fugu (different class). **Canary is disqualified** (Thinkst Canary/canarytokens owns that mindshare — and our core technique IS canary credentials). Clean fallback: **Taster**; dark horse: **Cordon** (cordon bleu + "cordon off" containment). Plan: run as Fugu now, proper trademark search before paid product, Taster as pivot.

## Personas (ranked by pain)
1. **Power user, 50 installed skills** (Claude Code/Cursor/Windsurf) — no tooling exists for them; watches for: one-command audit of their real config dir, a scary live catch, near-zero FPs on legit skills ("no crying wolf"), readable evidence.
2. **Enterprise AppSec with agent fleets** — budgeted, needs audit-survivable evidence + OWASP mapping + local/air-gapped execution (Snyk's cloud token is a blocker for them).
3. **Registry/marketplace operator** — trust is the product; wants batch API, per-listing badges, drift detection.
4. **Hobbyist tinkerer** — lowest pain, highest virality (the "whoa" moment).

## Market signals (for README Impact section)
- 10,000+ active public MCP servers (Anthropic, Dec 2025); ~9,652 registry records; 15,900 GitHub repos tagged mcp-server (May 2026); 17-23K by trackers mid-2026
- ~427M/month combined MCP SDK downloads by Jul 2026 (npm ~156M, PyPI mcp ~271M, fastmcp ~93M)
- 41% of software orgs in MCP production (Stacklok 2026); security = #1 blocker to broader adoption (Zuplo); 72% expect usage to increase
- MCP donated to Linux Foundation Agentic AI Foundation (Dec 2025), ~190 members
- 30+ MCP CVEs in one 60-day window 2026 (~43% command injection); 492 exposed servers w/o auth; 9% of 7,029 public servers ship high/critical issues (static-visible only)
- Agentic-AI security market: $1.65B (2026) → $13.5B (2032), 42% CAGR
- CI-gating demand proven: multiple static-only GitHub Actions exist (truecopy, AgentAvow, Heimdall — which explicitly never executes); nobody ships canary detonation

## Post-hackathon wedge
CLI first (`uvx fugu-audit@latest`, ride the uvx snyk-agent-scan pattern) → GitHub Action CI gate (demand proven, all competitors static-only) → registry trust-badges/batch API tier. First customers: (1) YC-stage agent-marketplace startup (buys scoring API), (2) AI-forward enterprise platform team rolling out Claude Code/Copilot to 500+ engineers, (3) MCP registry operator wanting differentiated trust score + drift detection.

## 3-min video script (outline)
- 0:00-0:15 HOOK: terminal, normal-looking skill installs clean; split-screen — "every static scanner says clean" vs Fugu chamber live: canary AWS key fires, raw HTTPS POST scrolls, DNS lookup. Text: "This skill passed every label-reader. It stole credentials in 9 seconds."
- 0:15-0:45 PROBLEM: agents install third-party brains (numbers above); poisoning hides in descriptions the model reads but you don't; Unicode tricks defeat grep; delayed triggers defeat review. "Reading labels didn't work for food. Someone has to taste it." Fugu = licensed taster.
- 0:45-1:30 HOW IT WORKS: same skill into chamber (canaries: fake AWS keys, ~/.ssh bait, decoy .env); three evidence lanes fill live (network/DNS/fs); decode layer unwraps Unicode deterministically; Nemotron judge confirms intent; harness A/B flips behavior.
- 1:30-2:10 SCORECARD + FP-KILL: OWASP tiered-confidence card with exhibit links; then a scary-LOOKING but benign skill returns LOW with reasoning. "Evidence, not vibes. And no crying wolf."
- 2:10-2:35 WHY WE WIN: label-readers vs detonation evidence; 100% local; CLI/CI/registry wedge slide.
- 2:35-3:00 CLOSE: one-liner big; repo + demo URL + QR; verdict stamp — "Distrust and verify." CTA: "Audit your ~/.claude before your skills audit you."
