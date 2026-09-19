# Fugu benchmark report

Mode: **static S0+S1** · Generated: 2026-09-19 19:55 · Tool: `python -m bench.run_bench`

Provenance-split results (CASCADE 2604.17125: pooled crafted+real numbers inflate; we never pool):

| Provenance set | n (mal/ben) | Attack detection | Benign flag rate | Info-only on benign | avg s/audit |
|---|---|---|---|---|---|
| crafted (corpus/) | 10 (6/4) | 6/6 (100%) | 0/4 (0%) | 0 | 0.0 |
| real (public skills, n=19) | 19 (0/19) | n/a | 0/19 (0%) | 0 | 0.1 |

Field context (published, not our measurements):

| Source | Finding | Number |
|---|---|---|
| MCPZoo '26 (2607.11086) | share of servers flagged risky by existing scanners | 96.89% |
| MCPZoo '26 (2607.11086) | TRUE-positive rate of sampled scanner alerts (manual validation) | <50% |
| MCPTox AAAI-26 (2508.14925) | max tool-poisoning attack success rate across 20 agents | 72.8% |
| MCPTox AAAI-26 (2508.14925) | best refusal rate against tool poisoning | <3% |
| Registry census '26 (2609.10962) | tools omitting optional safety annotations | 58.8% |
| SkillSecurer '26 (2609.14079) | skills.sh skills with latent injection vulnerabilities | >17% |
