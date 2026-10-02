# Evidence and input provenance

This directory retains the frozen 40-case evaluation, original responses and audits, bounded recovery, final charts and independent checks. `draft-charts`, `layout-pilot` and chart-development logs are local previews and are not published.

The original and recovered JSON results, all raw inference calls, reputation search outputs, audit/member outputs, frozen targets and chamber diagnostics are retained. `reporting.json` records the agreed reporting interpretation separately from measured alert counts. The charts can be regenerated offline without acquiring the original complete external corpora.

External inputs retain their upstream attribution:

- MCPTox: [MCPTox-Benchmark](https://github.com/zhiqiangwang4/MCPTox-Benchmark), `pure_tool.json`, hash recorded in `cases.json`. Fifteen selected tool descriptions are retained in numeric target directories; the full external dataset is not included.
- Constructed clean tool descriptions: [fuzzd clean_tools.json at f739e120](https://github.com/ksek87/fuzzd/blob/f739e120cd7dc253fead2a1f13668f9535e4d8a5/bench/clean_tools.json), SHA-256 `38b8fbf265e49147a6865836d1eff3796278625599ee47f3ffb2eb7b5f037348`. Five selected descriptions are retained, not the complete source fixture.
- Authored source/composition fixtures: this repository's `corpus/`, with evaluation manifests excluded from detector inputs.
- Dependency probes: constructed exact-version manifests; vulnerability assertions come from the actual OSV/Tavily responses, not their frozen labels.

External benchmark material is attributed to its upstream authors; its inclusion does not assert ownership or relicense that material under Fugu's code license. Competitor source commits, versions, wrappers and execution environments are recorded in `competitors/setup.json`; their source repositories are not vendored.

To rebuild the selection in a new output directory, acquire the source corpora and verify the `source_hashes` in `cases.json`. The earlier [clean-fixture acquisition instructions](../../../docs/benchmark.md#clean-tool-fixture-prerequisite) show the pinned download. Existing cached `pure_tool.json` must match the frozen hash; mutable upstream `main` is not sufficient replication evidence. Keep the original manifest and targets intact. Never run paid benchmark commands into this preserved evidence directory.

Only synthetic canaries are retained. Secret-value scanning covered proposed task files before publication. SQLite state, owner logs, credentials, local tool configuration and unrelated artifacts are excluded from the commit.
