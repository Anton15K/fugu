# Tech-Gap Review — SOTA vs Fugu (2026-09-19, research bot, partial-but-complete)

> Source: delegation research bot (429-killed at final step; full JSON recovered from partial output).
> Key papers found: CASCADE (arXiv 2604.17125 — cascaded regex→embedding→LLM detection, 95.9% precision / 61% recall where regex-only collapses on paraphrase), MindGuard (graph anomaly, 94-99% precision), MCPTox (AAAI).

## Verdict summary
SOTA converges on a **cascaded architecture** (regex pre-filter → embedding/semantic tier → LLM vetting → runtime behavior checks) — maps well onto our S0/S1 + Nemotron judge + detonation. Our main gap: **regex-only static tier**. MCPTox is an *agent-robustness* benchmark (ASR, refused-rate), not a scanner benchmark — keep labeled-corpus P/R as headline, repurpose MCPTox's 1,312 cases as free labeled positives.

## Gap list (build / don't build)

| Gap | Effort | Judging impact | Call |
|---|---|---|---|
| **AST tier (tree-sitter, Py+JS/TS, ~15-20 taint rules: exec/eval, subprocess, child_process, raw sockets, dynamic imports, b64→exec chains)** as S1.5 between regex and judge | 3-5d | High — upgrades perception from "grep script" to "lightweight semgrep"; catches aliased imports, multiline calls, string-built identifiers | **BUILD** |
| **Embedding anomaly detection for tool descriptions** (outlier vs benign-corpus centroid + length/UI-mismatch signals) | 2-3d | Med-high — novel-detection story regex can't have; feeds judge as feature | **BUILD** (Qwen3-Embedding-8B already on account) |
| **Capability manifest** (declared egress[]/fs_read[]/fs_write[]/env[]/exec flag) **diffed vs detonation observations** | 3-4d | High-for-effort — "declared minus observed" delta = the single most legible judge artifact; turns the chamber into a lie detector | **BUILD** |
| Sigstore-for-MCP signing infrastructure | 15d+ | Low (no ecosystem standard, no adopters) | **DON'T BUILD** — do the *verify* side only: SHA-256 pin tool definitions, re-hash on update (rug-pull drift), display third-party signatures when present (1-2d) |
| MCPTox as primary metric | — | Wrong instrument | **DON'T** — keep P/R headline; DO download the 1,312 cases as labeled positives; add detection-ASR + benign-FPR to harness report |
| **LLM-judge calibration** (judges systematically overconfident, ECE 39-74 reported) | 3-4d | High — unknown-FPR judge is our weakest claim | **BUILD**: self-consistency k=5 @ temp 0.7 + vote-fraction confidence; Nano/Super/Ultra tier disagreement = escalate; ~200 human-labeled calibration set; report ECE + FPR separately |
| Raw-socket egress evasion | eBPF 10d+ / namespace 1-2d | Low direct, high if it bites in demo | **DON'T BUILD eBPF** — DO fail-closed network namespace: iptables REDIRECT all TCP to proxy, block non-TCP except allowlisted DNS; document residual risk |

## Weak-spot defenses (for README threat-model section)
1. Raw-socket evasion → fail-closed namespace (above); document as sandbox property.
2. Judge FPs → self-consistency voting; unanimous-benign = auto-clear; split = escalate tier; persistent split = human-review queue.
3. Judge calibration → fixed 200-sample calibration set; ECE + benign-FPR as first-class metrics.
4. Judge-prompt gaming (injection aimed at the auditor) → S0/S1 run BEFORE judge sees text; strip imperative markers; tool text never sets the rubric.
5. Regex bypass → cascade tiers + per-tier ablation table in eval (shows the cascade matters).
6. Rug pulls → hash-pin at first scan, re-verify on update/reconnect; manifest delta + re-detonation on version change.
7. Corpus label noise → dual-annotate, track inter-annotation agreement, adjudicate disagreements.
8. Benchmark overfitting → private hold-out of paraphrased + hand-written payloads; final numbers reported once on it.
