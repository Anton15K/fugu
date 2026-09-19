# Competitive Landscape (2026-09-19, research bot — verified via 5 searches + 4 extracts)

## Moat verdict (the important part)
**Execution-based analysis of MCP servers is NO LONGER uniquely ours.** SandScope/MCP-SandboxScan (SCORED'26 — WASM/WASI detonation + source-to-sink dataflow), Meta's MCPGuard-Dynamic (eBPF syscall sandbox, 82-case benchmark), and an NYIT Docker+eBPF audit sandbox all execute/instrument MCP servers at runtime.

**But the moat survives in a narrower form.** Every dynamic competitor is either an early academic artifact (SandScope: 0 stars, alpha, Rust toolchain) or a runtime DEFENSE proxy rather than a pre-install AUDITOR (MCPGuard, MCP Pulse). None do **canary-token detonation**, none do deterministic Unicode decoding, none integrate an LLM-judge + A/B harness, and — critical — **the skills side has NO dynamic auditor at all**.

**Refined claim (use this everywhere):** "execution-based canary detonation for agent SKILLS + integrated judge/harness pipeline" — NOT "execution-based analysis" (contestable). Update README/video/pitch accordingly. Speed matters: the window is closing on both fronts.

## Threat board

| Threat | Level | What they do | Our counter |
|---|---|---|---|
| **AgentSec (semiotic-ai)** | HIGH | `npx agentsec` grades skills A–F on OWASP Agentic Skills Top 10 across Claude Code, Codex, OpenClaw, **even Hermes** — near-identical deliverable FORMAT; static-only | Beat on METHOD not format: live canary exfil their static grades cannot see; publish A/B harness numbers; match their CLI polish |
| **Snyk Agent Scan + ToxicSkills** | HIGH | Commercial scale; ToxicSkills found 1,467 malicious payloads on ClawHub; 36% of skills carry injection | Specialist depth: dynamic + deterministic Unicode + local-only (no cloud token); cite scanner-reliability gaps (Rethinking MCP Security paper found scanners unreliable) |
| **SandScope (SCORED'26)** | MED | WASM/WASI sandbox execution + env/file/network→LLM-output dataflow detection | Cover skills+MCP (they're MCP-only), canary ground truth vs string heuristics, LLM-judge triage, no-Rust usability |
| **MCPSafe.org** | MED | Registry-integrated scanning, grades, embeddable badges, paid tiers — owns the badge distribution channel | Ship registry-grade dynamic badges via our API; target ClawHub/skills.sh they don't cover; partner option |
| **MCPGuard-Dynamic (Meta)** | MED | eBPF enforcement proxy w/ per-tool capability policies — big-lab validation of runtime approach; if pivoted to pre-install auditing it leapfrogs us | Differentiate auditing vs enforcement; auto-derived canary evidence vs their manual JSON policies. WATCH. |
| Socket (for MCP) | MED | Commercial static package analysis, agent-callable pre-install | They'd need a sandbox feature to match; position complementary |
| MCP Pulse ($299/mo) | MED | Runtime gateway: call blocking, SSRF detection, audit logs | We're pre-install verdicts, not call-time enforcement; can consume their logs as signals |
| MCPfinder | LOW | Cross-registry provenance confidence scores | Metadata vs behavior gap; integration partner |
| SkillSecurer (arXiv 2609.14079) | LOW | Detection + patching of prompt injection in skills | Text-level only; cite as related work |
| Rethinking MCP Security (arXiv 2607.11086) | LOW (opportunity) | Study: existing MCP security scanners unreliable/inconsistent | **Cite as evidence FOR dynamic analysis**; benchmark to beat on recall |
| Registries (official/Smithery/PulseMCP/mcp.so) | LOW (opportunity) | Identity/provenance metadata only — official registry does namespace verification, NO code scanning | Pitch Fugu as the dynamic-scanning badge backend before MCPSafe locks the niche |

## Actions derived
1. Rewrite differentiation language per refined moat claim (README, IDEA.md, pitch).
2. Add "Rethinking MCP Security" + SandScope as related-work citations — turns competitors into motivation.
3. Registry-badge API moves up the post-hackathon wedge list (MCPSafe is moving).
4. AgentSec proves the A-F + OWASP format has demand — validates our scorecard design; our edge must be the METHOD + evidence depth.
