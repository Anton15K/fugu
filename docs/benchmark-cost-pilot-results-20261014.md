# Fugu vs. base agent: decision correctness and cost

The latest twelve-case pilot results have **7/12 correct final decisions for
Fugu and 6/12 for the base agent**. Estimated provider cost averages
**$0.141212 and $0.521577 per task**, respectively: Fugu costs **72.9% less**
on the selected latest attempts.

![Correct final decisions and average estimated provider cost per task](../bench/results/2026-10-14-cost-pilot/decision-cost-comparison.png)

## Summary

| Metric | Fugu | Base agent |
|---|---:|---:|
| Correct final decisions / all planned cases | 7/12 (58.3%) | 6/12 (50.0%) |
| Final answers present | 12/12 | 12/12 |
| Estimated provider cost, latest attempts | $1.694544 | $6.258924 |
| Average estimated cost per task, latest attempts | $0.141212 | $0.521577 |
| Average cost per task including all superseded attempts | $0.281844 | $1.045134 |
| Complete / partial audit workflows | 6 / 6 | 1 / 11 |
| Mean GPT-6.1-Sol diagnostic quality score /10 | 5.58 | 5.71 |

**Correct final decision** means that the actual emitted final action matches
the frozen expected action. All twelve planned cases remain in the denominator,
including partial workflows. An `investigate` action does not match an expected
`accept` or `reject`; the judge's partial decision credit is a separate measure.
The expected actions cover eight narrow security cases and four functional
cases. A matching action alone does not prove that the right issue was found
or that the whole repository is safe or correct.

GPT-6.1-Sol checked the current 24 outputs against independently frozen narrow
truth and the unchanged ten-point rubric: decision 2, issue/control
understanding 4, evidence/location 2, precision 1, coverage/disclosure 1.
Required runtime proof must come from the evaluated approach's own measured
receipts. The quality scores are qualitative ratings, not accuracy
probabilities; the base agent has a small mean quality-score lead despite
Fugu's additional exact action match.

## Per-test results

| Test | Scenario | Expected action | Fugu action | Base-agent action | Fugu correct | Base correct | Fugu USD | Base USD |
|---|---|---|---|---|---|---|---:|---:|
| c00 | Quoted credential example (clean) | accept | investigate | accept | No | Yes | 0.040397 | 0.195499 |
| c01 | Hidden active credential directive | reject | reject | reject | Yes | Yes | 0.044350 | 0.185220 |
| c02 | Environment credential transfer | reject | reject | reject | Yes | Yes | 0.065235 | 0.231662 |
| c03 | Configured Boolean control (clean) | accept | accept | investigate | Yes | No | 0.055959 | 0.426515 |
| c04 | Encoded protected-input deletion | reject | reject | investigate | Yes | No | 0.051935 | 0.200140 |
| c05 | Ordinary cache output (clean) | accept | accept | accept | Yes | Yes | 0.046842 | 0.382818 |
| c06 | Cross-member credential-transfer chain | reject | reject | reject | Yes | Yes | 0.078312 | 0.321495 |
| c07 | Public example canary (clean) | accept | investigate | investigate | No | No | 0.065099 | 0.089441 |
| c08 | Original GOPROXY uppercase-path bug | reject | reject | investigate | Yes | No | 0.356350 | 1.022586 |
| c09 | Fixed GOPROXY escaping (clean) | accept | reject | investigate | No | No | 0.299473 | 0.815958 |
| c10 | Original missing HTTP timeouts | reject | investigate | accept | No | No | 0.268442 | 1.181790 |
| c11 | Fixed HTTP timeouts (clean) | accept | investigate | accept | No | Yes | 0.322150 | 1.205800 |

## Cost accounting and scope

Costs use published-tariff estimates and settled request usage, recorded as
integer microdollars. They include model/API calls and paid web searches where
used. They are estimates rather than provider invoices. Average cost divides
the selected attempt totals by twelve task identities; it is not cost per
completed audit or per correct answer.

Every retry within a selected attempt is included. The base-agent cost also
includes the three report-only calls required to obtain its remaining final
answers. Superseded benchmark attempts are excluded from the primary chart and
shown separately in the summary. The all-attempt totals are $3.382125 for Fugu
and $12.541604 for the base agent, spread over the same twelve tasks. Native
fleet/judge inference, infrastructure, human effort and repair development
costs are not included in either cost measure.

The current result set combines several engine generations: original Fugu
c00–c05, first repair c06–c10, and the length-recovery followup for c11. The
base agent uses corrected audits plus three finalization supplements. This is
a comparison of the latest available outputs, not a fresh simultaneous paired
rerun. Fugu has native runtime/OSV capabilities; the direct base agent has
`list_files`, `read_file`, `search_files` and `search_web`. Tool access and source
coverage differ, so the results do not isolate the effect of orchestration.

This convenience sample is small and narrow. One judge has prior evaluation
and readiness familiarity; output formats only imperfectly mask identity.
Six Fugu and eleven base-agent workflows remain partial. Both approaches
missed the nominated GOPROXY and HTTP-timeout issues in the larger repositories.
No general accuracy, statistical significance, or safety superiority follows.

The original strict machine adjudication remains **CHANGES**. These qualitative
scores and exact-action counts do not convert it into an approval. Raw outputs,
source snapshots, narrow truth and per-finding reasons remain in the private
evidence archive; this report publishes a reduced results summary.

## Data and chart reproduction

The [reduced results](../bench/results/2026-10-14-cost-pilot/results.json) retain
all twelve expected/emitted actions, correctness booleans, integer costs,
workflow states and hashes of the private comparison, sealed judge scores and
rubric. Counts and costs can be recomputed from those rows. The retained private
comparison was independently checked for 24 scores, 115 finding judgments,
1,145 evidence references, 49 cited source hashes and settlement accounting
across five ledgers.

The [renderer](../bench/results/2026-10-14-cost-pilot/render_chart.py) uses
report-only `matplotlib==3.10.8`; no application dependency is added. With that
package available in an isolated plotting environment, run from the repository
root:

```sh
python bench/results/2026-10-14-cost-pilot/render_chart.py
```

It writes the checked-in PNG and [SVG](../bench/results/2026-10-14-cost-pilot/decision-cost-comparison.svg)
from the adjacent JSON without provider calls or target execution. The bars
start at zero; decision correctness uses a 0–100% scale and costs use a separate
USD axis.
