---
# fugu-drover-mtzq
title: Add current decision-correctness and cost comparison to README
status: completed
type: task
priority: normal
created_at: 2026-10-14T08:56:57Z
updated_at: 2026-10-14T09:05:08Z
---

Human requested a chart and README report showing correct final decisions and average cost/task.

- [x] Add two-panel PNG/SVG chart for 7/12 vs 6/12 correct decisions and USD0.141212 vs USD0.521577 per task.
- [x] Add README summary/table/image/link, preserving all previous README content under explicit paired handoff with fugu-codex-coder's completed claim.
- [x] Add detailed twelve-case report, reduced JSON results with private-evidence hashes, cost inclusions/exclusions, partial-audit counts, judge-score distinction and limitations.
- [x] Reuse existing isolated report-only matplotlib 3.10.8 environment; add no application dependency.
- [x] Validate counts/costs/provenance, visual PNG layout, deterministic SVG/PNG rerender, source syntax and every new documentation link; git diff --check passes.

Files: README.md; docs/benchmark-cost-pilot-results-20261014.md; bench/results/2026-10-14-cost-pilot/{results.json,render_chart.py,decision-cost-comparison.png,decision-cost-comparison.svg}.
Branch: fleet/fugu-codex-truth-reviewer-readme-cost-chart-20261014 based on local main 32d34176a4c32ae7853711b048c253f2fad7439b. Documentation-only: no application behavior or dependency changes; no provider calls, target execution, main mutation or push.
