# Benchmark packaging handoff

Owner research.security; packaging assignment qitem-20261002071617-dc15cd58.
Original benchmark assignment qitem-20261002064041-10e299bf.
Packaging verification complete; writer lease released with queue handoff.
No API calls or detector runs were made during this correction. No Git,
shared environment, .gitignore or production src changes by this seat.

## Integration inventory

Use bench/results/2026-10-02/artifact-manifest.json as the explicit deliverable
list and hash manifest. The manifest itself is one additional deliverable.
Its exclusion list explicitly names all seven copied third-party README/CLI/Cargo
files, the copied clean-tools fixture, the ignored replacement fixture cache,
the engine execution copy and bytecode caches. These may remain locally but
must not be staged. Full third-party docs and fixture bytes are not distributed.

sources/index.json retains pinned commit URLs, acquisition hashes and extracted
numeric claims, marking each underlying third-party source as not distributed.
Historical local paths in measured results remain unchanged as provenance.

## Runner and reproduction changes

bench/fresh_benchmark.py now defaults to bench/real/fuzzd-cache/clean_tools.json
and accepts --clean-tools PATH. The same pinned SHA-256 is required at any path.
Missing/hash-mismatched inputs fail clearly; no automatic download. The reports
include the exact pinned curl download plus independent shasum prerequisite.
The necessary local fixture was copied into the already ignored bench/real cache.

measured-runner.py preserves the original runner source and matches its hash
recorded by the measured runs. Current changes affect input-cache resolution
and verification only; measured static/live/pilot JSON and source-hashes.json
are byte-for-byte unchanged. No new detector performance claim is made.

## Verification

- Scoped tests: 8 passed, including actionable missing/mismatch cases and verified cache load.
- CLI help exposes --clean-tools; local pinned fixture validation returned 20 entries.
- Offline plotting succeeded using only static.json, semantic.json and sources/index.json
  in a temporary directory, producing 2 SVGs and 2 PNGs. No source docs, fixture or engine needed.
- Measured runner hash matches; measured JSON/source-hash files preserved; report links resolve.
- Original final charts were visually reviewed and are unchanged. Primary bar 26/30=86.7%
  retains explicit two-miss/two-incomplete segments; comparator claims are not ranked.

## Benchmark result retained

Static: 1,904 completed cases; crafted attacks 7/7, crafted benign 0/4, MCPTox
pure 41/485, full 120/1,312, constructed clean 0/20, public skills 0/76.
Live: 26 detections of 30 planned attacks, 2 completed misses, 2 parse failures;
clean descriptions 0/20; public skills 0/19 completed plus 1 parse failure.
Final 111 calls; cumulative including discarded pilot <=139 attempts, under 210.
Remaining quota and monetary cost unknown. No S3/S4 or zero-population-FPR claim.
Frozen detector baseline 25a7a4e85bc219ea03da20fd34a09826449c0a9b predates backend fixes.

Historical 484/485 and strict 160 semantic runs exposed benchmark labels; raw
artifacts retained but excluded from blind-evaluation claims. mcp-sec-audit's
pinned READMEs conflict (367/491=74.7% versus 94.7%/491); unresolved. Local
competitor binaries were not run. See docs/benchmark.md and docs/head-to-head.md.

Next owner control.lead: independent review and integration using explicit paths.
