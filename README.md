# 🐡 Fugu — the detonation chamber for AI-agent extensions

**Static scanners read the label. Fugu tastes the food.**

Fugu is an agentic security auditor for third-party AI-agent extensions — skills (SKILL.md), MCP servers, plugins. Before you install that shiny community skill, Fugu audits it four independent ways and hands you an OWASP-mapped, evidence-backed verdict. Not a score. Not vibes. Exhibits.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![tests](https://img.shields.io/badge/tests-184%20passed-brightgreen)]()

> Built for the [Nebius × NVIDIA Global AI Hackathon](https://nebiusglobalaihackathon.devpost.com) · Track 1: Coding & Agentic Engineering
> Demo: *(URL — coming with deploy)* · Video: *(≤3 min, coming)*

---

## The problem

AI agents are installing third-party brains at scale — 10,000+ public MCP servers, ~427M monthly SDK downloads, thousands of community skills. The attack surface is real:

- **Scanners cry wolf.** A 2026 ecosystem study ([MCPZoo, arXiv 2607.11086](https://arxiv.org/abs/2607.11086)) found existing security scanners flag **96.89% of MCP servers as risky** — and manual validation showed **fewer than half of those alerts are true positives**. A tool that flags everything trains you to ignore it.
- **Agents don't refuse attacks.** [MCPTox (AAAI-26)](https://arxiv.org/abs/2508.14925) measured tool-poisoning attack success up to **72.8%** across 20 agents, with a best refusal rate of **<3%**.
- **Static-only analysis misses behavior.** Descriptions that misrepresent code, payloads that only fire at runtime, instructions hidden from human eyes in Unicode.

Fugu answers with the pattern antivirus learned 20 years ago: **detonate it and watch what it does** — plus the discipline the field lacks: published, provenance-split, manually-adjudicated numbers.

## What Fugu does

Drop a skill or MCP server in; Fugu runs four independent analysis engines and produces a tiered-confidence scorecard:

| Stage | Engine | What it catches | Confidence tier |
|---|---|---|---|
| **S0 Concealment** | deterministic Unicode decoder | ASCII smuggling (U+E0000–7F), zero-width binary, bidi Trojan Source, variation-selector payloads — **decoded as evidence** | deterministic |
| **S1 Static** | 18 rule families | secrets, env harvesting, curl→shell, credential-file access, typosquats, rug-pull phrasing, MCP annotation/smell checks | deterministic |
| **S2 Semantic** | Nemotron Ultra LLM-judge via Token Factory | paraphrased injections, deceptive descriptions, intent-vs-text gaps — every finding localized with verbatim excerpt | advisory |
| **S3 Detonation** | isolated chamber (Docker today, Nebius Sandboxes driver) | runtime exfiltration: the extension runs in a network-instrumented sandbox seeded with **canary credentials** (fake AWS keys, tokens); any canary byte leaving via HTTPS body, DNS label, or file write = **critical, with forensic evidence** | deterministic |
| **S4 Harness** | red/blue/verifier A/B on two Nemotron tiers | does the extension actually **hijack an agent?** The same benign probes run against a baseline agent and an agent with the extension mounted; trajectory diff = measured behavioral poisoning | empirical |
| **S5 Reputation** | Tavily | adverse web reputation for packages/domains, source-cited | advisory |

Then one verdict policy: **FAIL** on critical or hard-evidence highs · **WARN** on advisory highs/mediums · **PASS** — and a static-only PASS says so explicitly.

## Benchmark results

Full methodology + raw JSON: [`bench/results/`](bench/results) · harness: `python -m bench.run_bench`

| Evaluation | Result | Field context |
|---|---|---|
| **MCPTox attack detection** (field's benchmark, AAAI-26; n=160 stratified, strict severity contract) | **160/160 — 100%**, all 11 categories | no competing auditor publishes a number on this benchmark |
| Static-only on MCPTox (n=1,312, full corpus) | 9% — *by design*: paraphrase detection is the LLM tier's job; the 9%→100% delta is the cascade architecture quantified | |
| **Real-world benign skills** (n=76, 4 public repos incl. Anthropic, obra/superpowers, community packs) | **0 static false positives**; semantic 3 flags → manually adjudicated: 1 true bug, 2 severity FPs (fixed) | field: 96.89% flagged / <50% true |
| **Random registry draw** (skills.sh, seed 20260920, 25 of 2,862 skills) | 1 flag → adjudicated **true positive** | MCPZoo-comparable methodology, no ground truth |
| Crafted corpus (6 attacks / 4 benign) | 6/6 detected · 0/4 FPs | internal consistency |

### Found in the wild

- **A deceptive-behavior bug in Anthropic's production `docx` skill** (timeout reported as success in `accept_changes.py`) — found by the unsupervised LLM judge reading cold code during a benchmark run; independently corroborates defect #1 of [anthropics/skills#1770](https://github.com/anthropics/skills/issues/1770) (still open). Details: [`docs/wild-findings.md`](docs/wild-findings.md).
- **A live `curl … | bash` install** in a randomly drawn registry skill — exactly the fetch-and-exec pattern an install-time auditor exists to catch.

### Methodology (why you can trust the numbers)

- **Provenance-split reporting** — crafted and real-world results are never pooled ([CASCADE, arXiv 2604.17125](https://arxiv.org/abs/2604.17125), shows synthetic corpora inflate recall).
- **Explicit aggregation convention** — "detected" = any finding ≥ medium, stated up front.
- **Manual adjudication** — every real-world flag was hand-verified; our first semantic run flagged 17% of benign skills, adjudication found the judge defect + our own harness bug, we fixed both and re-measured to 4%. The mistake and the fix are both committed.
- **Reproducible draws** — seeded random sampling from a 2,862-skill catalog union; pinned, SHA-verified MCPTox source.

## Quickstart

Requires Python 3.10+, [uv](https://docs.astral.sh/uv/), Docker (for detonation). Node 20+ for the web UI.

```bash
git clone <repo-url> && cd fugu
uv sync --extra dev
cp .env.example .env        # add NEBIUS_API_KEY (Token Factory); TAVILY_API_KEY optional
```

```bash
# API server + web UI (SSE live pipeline, scorecard)
uv run python -m fugu.server --port 8000 --db fugu.db   # persistence via SQLite

# web UI
cd web && npm install && npm run dev    # http://localhost:5173 (proxies /api)
# or serve built SPA from the server: npm run build  (dist/ auto-mounted at /)

# one-shot audit (CLI path shared with eval harness)
uv run python -c "from fugu.pipeline import run_audit; \
  [print(f.severity, f.owasp_ids, f.title) for f in run_audit('corpus/03-env-harvest-installer')]"

# reproduce the benchmark (static, free, offline)
uv run python -m bench.fetch_real          # clone public skill repos (gitignored)
uv run python -m bench.run_bench           # writes docs/benchmark.md

# tests (hermetic — no network, no keys)
uv run pytest -q                           # 184 passed
```

Try the demo samples: `corpus/01-hidden-instructions-skill` (caught three independent ways), `corpus/03-env-harvest-installer` (canary exfiltration → critical), `corpus/07-clean-skill` (passes).

## Nebius Token Factory + NVIDIA models

All inference runs on **NVIDIA open-source Nemotron models** served by the [Nebius Token Factory](https://docs.tokenfactory.nebius.com/) (OpenAI-wire-compatible API):

| Model | Role in Fugu |
|---|---|
| `nvidia/Nemotron-3-Ultra-550b-a55b` | S2 security judge — deep reasoning over untrusted content, strict severity contract |
| `nvidia/nemotron-3-super-120b-a12b` | S4 harness "everyday agent" arm + red probe generation (models what real deployed agents run) |
| `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | bulk triage tier (router-ready) |

**Where Nebius accelerated the workflow:** one wire-compatible endpoint powers the whole LLM side — the judge, both harness arms, and the red probe generator — with per-call logging (model/latency/tokens) recorded into every audit's stage metrics (`llm_calls`). Detonation runs in an isolated chamber (Docker driver today; the Nebius Sandboxes driver is written against the same interface pending our beta access). Analysis is 100% local: nothing you audit leaves your machine — unlike cloud-scoring scanners.

Model routing: `src/fugu/model_router.py` (explicit nano/super/ultra tiers). A finding from our own harness: **Ultra-550b resists naive skill injections that hijack Super-120b** — susceptibility is a property of (model × framing), which is why S4 tests two tiers.

## Repository layout

```
src/fugu/
├── pipeline/stages/    # S0 concealment · S1 static · S2 semantic · S4 harness · S5 reputation
├── detonation/         # canary env, mitm+DNS collectors, Docker driver, evidence→findings
├── server/             # FastAPI + SSE job runner, JobStore (+ SQLite persistence)
├── store/              # sqlite WAL persistence (jobs/events/findings)
├── verdict.py          # tiered verdict policy (shared by server/CLI/eval)
└── types.py            # contracts: Finding, evidence tiers, OWASP ids
corpus/                 # 10 labeled samples (6 attacks / 4 benign)
bench/                  # benchmark harness: MCPTox adapter, real-world fetch, random draw
eval/                   # precision/recall harness, selfcheck
web/                    # React+Vite+TS+Tailwind dashboard
tests/                  # 184 hermetic tests
docs/                   # strategy, methodology, wild-findings citation sheet
```

## Honest limitations

- Detonation captures proxy-aware HTTP(S) + DNS; raw-socket egress is a documented residual risk (fail-closed hardening planned).
- S4 harness is single-turn stated-intent (a tool-loop harness is next); results are framing-dependent — measured, not hidden.
- The real-world set is skill-shaped; a server-heavy MCP corpus is the next expansion.
- Reputation (S5) needs a `TAVILY_API_KEY` to activate; it no-ops cleanly without.

## License

[MIT](LICENSE) © 2026 — built by a solo developer and a team of AI agents on Nebius Token Factory.
