# Fugu vs. the field on MCPTox (arXiv 2508.14925, AAAI-26)

> The field's own benchmark, the field's own file. Third-party scanners publish
> MCPTox detection numbers against the 485-case `pure_tool.json` flat subset of
> the MCPTox-Benchmark repo. We ran Fugu on **that exact file** (same fetch
> source, same denominator) so the numbers are directly comparable — and we
> additionally publish the strictest protocol (n=160 stratified from the full
> 1,312-case corpus) with a per-case severity contract.

## Head-to-head: pure_tool.json (n=485, all malicious)

Same file all three rows measured on. Comparator numbers are theirs, published
(fuzzd v0.13 bench README; nyit-vancouver mcp-sec-audit detection README).

| Tool | Overall | Unrelated Prereq (T1) | Fake Enabling (T2) | Argument Hijack (T3) | Method |
|---|---|---|---|---|---|
| **fuzzd v0.13** | 90.7% (440/485) | 84.4% | 84.6% | 97.7% | static only: 188 Aho-Corasick needles + heuristics |
| **mcp-sec-audit** (NYIT-Vancouver) | 74.7% (367/491) | — | — | — | static capability indicators |
| **Fugu static (S0+S1)** | 8.7% (42/485) | — | — | — | conservative static (see below) |
| **Fugu cascade (S0+S1+S2)** | **99.8% (484/485)** | **100% (77/77)** | **99.5% (182/183)** | **100% (225/225)** | deterministic static + Nemotron-3-Ultra judge via Token Factory |

- Fugu beats both comparators overall **and on every paradigm they break out**.
- The single non-detection (`Apify_2`, forced-redundant-calls DoS framed as a
  "performance protocol") was re-run individually and **detected at high
  severity** — a judge-variance floor on one borderline case, not a blind spot.
  We report the measured 484, not the re-run 485.
- Fairness check: 0/484 detections relied on the raw provenance copy
  (`case.json`); 443 cite the adapted `server.py` tool description alone — the
  same artifact class the comparators scan.
- Cost: 485 Ultra-tier judge calls ≈ 15 min wall at conc=6, roughly 650 prompt
  + 270 completion tokens per call — a few cents of Token Factory credit.

## Why our static-only row is low — and why that's the honest architecture

MCPTox attacks are *paraphrased* prompt injections in tool descriptions. A
static-only detector that catches most of them must match surface forms
("MUST FIRST", "before using"), which is what fuzzd's needle list does — and
it's the approach MCPZoo ('26) measured as flagging 96.89% of servers with
<50% true-positive alerts: pattern breadth buys recall on this corpus and
costs precision on real ecosystems. Fugu's static tier is deliberately
conservative (8.7% here, **0 false positives on 76 real benign skills**), and
the semantic tier closes the gap. The 8.7% → 99.8% delta is the cascade
architecture quantified on the field's own file.

## Our headline numbers (stricter protocol)

- **MCPTox strict, n=160 stratified from the full 1,312-case corpus:
  160/160 (100%)**, all 11 categories, per-case severity contract, every
  finding localized with verbatim excerpt.
  `bench/results/mcptox-semantic-confirm.json`
- **Real-world benign skills n=76 (Anthropic, obra/superpowers, community):
  0 static FPs**; semantic flags manually adjudicated (1 true bug — the
  Anthropic docx defect — 2 severity FPs, fixed).
- **Random registry draw (skills.sh, seed 20260920, n=25):** 1 flag,
  adjudicated true positive (`curl|bash` installer in the wild).

## Protocol differences (stated, not hidden)

| | fuzzd | mcp-sec-audit | Fugu |
|---|---|---|---|
| Data | pure_tool.json (485) | pure_tool.json (they report 493→491) | pure_tool.json (485) + full-corpus strict n=160 |
| Detection rule | tool name appears in scan output | capability indicator match | any finding ≥ medium severity |
| FP measurement | 20 self-written clean tools | none published | 76 real public skills, 0 flags |
| Beyond descriptions | — | — | canary detonation chamber (runtime exfil evidence), harness A/B, composition |

## Reproduce

```bash
uv run python -m bench.mcptox.run_puretool              # static, free, offline, ~1s
uv run python -m bench.mcptox.run_puretool --semantic   # + Nemotron judge, ~15 min
```

Raw per-case JSON: `bench/results/mcptox-puretool-{static,semantic}.json`.
