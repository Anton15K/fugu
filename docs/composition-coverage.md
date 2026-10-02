# Composition coverage and interpretation

The composition-v2 suite adds 24 inert source fixtures across eight materially
different families. It checks capability chains through the production
`run_composition_job` fan-out, child `run_job` path, `StaticScanStage`, actual
`harvest_tool_names`, and `CompositionStage`. Fixture code is read as source; it
is never imported or executed. The run makes no model calls.

The [frozen manifest](../corpus/composition-v2/manifest.json) records 12
positive trifecta cases, 12 controls, a seeded 16/8 development/reserved split,
all 160 case-source hashes, and the original 37-file engine hashes. One
author-known case per family is reserved using seed `20261002`; this is a
stratified check, not a blinded evaluation. The original `corpus/composition`
and full-benchmark inputs/results remain unchanged.

## Results

| Measure | Frozen baseline | Revised composition engine |
|---|---:|---:|
| Cases completed | 24/24 | 24/24 |
| Positive trifecta cases detected | 10/12 | 12/12 |
| Controls with a false trifecta | 0/12 | 0/12 |
| Controls incorrectly reported as confirmed tool shadowing | 2/12 | 0/12 |
| Expected outcomes matched | 20/24 | 24/24 |

The baseline missed two Python POST cases because the source scanner recognized
direct calls such as `requests.post(...)` but not calls reached through a module
or imported-function alias. A bounded syntax-only AST check now handles forms
such as `import requests as client; client.post(...)` and
`from httpx import post as publish; publish(...)`. Malformed Python is not
executed or guessed through; the existing direct-pattern checks continue to
cover literal forms. This improves these two demonstrated source cases, not
general Python data-flow coverage.

The other baseline errors were tool names from separate server manifests that
normalized to the same spelling. The source inventory contains no client mount
namespace, collision policy, or resolution order. Revised results retain one
`info` / `advisory` overlap note with `interpretation="name-overlap-only"` and
no OWASP id. They do not call it shadowing or escalate it because a separate
member has an injection-carrier finding. The original member finding remains
available on its child audit; independent evidence is preserved.

| Fixture family | Positive trifectas, baseline → revised | Controls correct, baseline → revised |
|---|---:|---:|
| Direct Python HTTP | 2/2 → 2/2 | 1/1 → 1/1 |
| Python import aliases | 0/2 → 2/2 | 1/1 → 1/1 |
| Python standard-library URL requests | 2/2 → 2/2 | 1/1 → 1/1 |
| JavaScript environment findings + tool schema | 2/2 → 2/2 | 1/1 → 1/1 |
| Shell curl methods | 2/2 → 2/2 | 1/1 → 1/1 |
| Harvested tool-schema ingress | 1/1 → 1/1 | 2/2 → 2/2 |
| Separate files within member trees | 1/1 → 1/1 | 2/2 → 2/2 |
| Composition boundaries and name overlap | n/a | 1/3 → 3/3 |

All 16 development cases completed and matched after the change: 9/9 positive
chains and 7/7 controls. All 8 reserved cases also completed and matched: 3/3
positive chains and 5/5 controls. The baseline matched 13/16 development cases
and 7/8 reserved cases. There were no incomplete rows in either run.

Detailed child statuses, harvested tool names, composition metrics, evidence,
and every case result are retained in the [baseline run](../bench/results/2026-10-02-composition-v2/baseline.json)
and [revised run](../bench/results/2026-10-02-composition-v2/after.json).
The [cohort chart](../bench/results/2026-10-02-composition-v2/full-benchmark-charts/charts/cohort-results.png)
is rendered from the unchanged full-benchmark evidence and states the original
composition counts as 4/4 historical attack alerts and 3/3 controls correctly
unflagged, with the raw 0/3 control-alert count visible.

### Current-engine coverage recheck

The retained `after.json` above is the original revised run; it predates the
follow-up alias-scope and completion-accounting corrections. The current engine
was replayed against the same frozen cases into [review-after.json](../bench/results/2026-10-02-composition-v2/review-after.json).
It records hashes for all 37 engine files and all 160 frozen fixture sources,
and retains each child stage's metrics, error, and coverage state. This replay
completed all 24 cases: 12/12 positive chains were detected, 0/12 controls had
a trifecta false positive, and all 24 expected outcomes matched. It is an
integrity and accounting recheck of the same authored corpus, not a new
independent accuracy estimate; the original `baseline.json` and `after.json`
remain unchanged.

Completion now requires every expected child to exist, finish, and have at
least one child stage; every child stage must be `completed`; and the parent
composition result must have no skipped, failed, partial, or omitted member
coverage. Child stage metrics and findings remain in the result even when a
child is incomplete. Aggregates keep every attempted attack and control in
their `n` denominator, report `completed` separately, list incomplete case
IDs, and do not count incomplete cases as correct. The recheck had no
incomplete child stages; the fabricated mixed partial/failure regression
exercises the accounting path without executing fixture code.

Python POST alias recognition remains syntax-only and bounded to direct
`requests`, `httpx`, and `aiohttp` module aliases and imported `post` aliases
in module/function lexical scopes. Function-local imports do not leak to
sibling functions, and parameters or assignments that shadow/rebind an alias
prevent that name from being treated as an HTTP client. This does not resolve
arbitrary wrappers, class/lambda scopes, dynamic imports, `getattr`, or runtime
data flow; ambiguous forms may be missed.

## Historical full-benchmark interpretation

The frozen full benchmark reported four composition rule alerts among four
authored attack sets and zero among three controls. Those are historical counts
from the pre-clarification engine. Three attack sets share the same trifecta
members; the fourth, `shadow-pair`, is based on normalized tool-name overlap
without runtime namespace or resolution evidence. The revised policy no longer
reports that overlap as an MCP03 shadowing finding. The frozen raw results,
expected labels, and original composition corpus were not relabeled or
recomputed. See the [full benchmark report](benchmark-full.md) for the original
denominators and result path.

## Historical external misses

The three misses remain misses under the frozen medium-or-higher threshold. The
recovered raw rows show all applicable static, semantic, and harness stages
completed. Each target contained only a small `tools.json` description; none
provided a runnable target, so detonation was not applicable and did not
activate behavior. The rows and their input hashes remain in the immutable
[recovered result](../bench/results/2026-10-02-full/fugu-recovered.json) and
[case manifest](../bench/results/2026-10-02-full/cases.json).

| Case | Frozen input SHA-256 | Relevant result and reason it did not count as a detection |
|---|---|---|
| `mcptox/mcp-simple-arxiv_9` | `4248a04b0d409e66d4df64e2c46dee9026756c80bb649e9f937fc4a94d33ce13` | Static annotation omission was `info`. Semantic analysis found a reference to an undeclared tool at `low` / `advisory`, plus an informational description-quality note. No medium-or-higher finding. |
| `mcptox/Email_11` | `63ed4661f43e1311306b285598d0b011ed446685c296b7f3b1a2e38c94ef691a` | Static annotation/return-description notes were informational. Semantic analysis marked an ordering instruction `low` / `advisory` and described it as an apparent declared workflow; there was no observed unauthorized effect. |
| `mcptox/ClickHouse_14` | `52c5e80e971e0bca7a06742f3a6214864e33d76d735e64b3c0dcb9eb4c1687f7` | Static annotation/return-description notes were informational. The semantic ordering concern remained `low` / `advisory`; the content described a rate-limiting rationale, with no runtime evidence to establish a harmful effect. |

These results do not establish that the descriptions or implementations are
safe. They show that the bounded source-only run did not produce a medium-or-
higher finding, and the harness/detonation stages supplied no behavioral
evidence. No semantic or harness change is included in this lease, and no
additional paid call or target execution was used.

## Practical limits and verification

The source inventory recognizes a bounded set of Python, shell, and tool-name
patterns. Python alias support recognizes direct import aliases for the known
`requests`, `httpx`, and `aiohttp` package names when local scope and rebinding
evidence are unambiguous. It does not resolve arbitrary wrappers, class/lambda
scopes, dynamic imports, `getattr`, or runtime data flow. Text scanning is
limited to 200 code files and 262,144 characters per file per member; tool-name
harvest uses its own file and byte bounds. Medium capability evidence is
co-occurrence in source, not proof of authorization, successful exfiltration,
client resolution, or exploitability.

The scoped checks were:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHON_DOTENV_DISABLED=1 uv run --no-sync pytest tests/test_composition_core.py tests/test_composition_server.py tests/test_composition_expanded.py tests/test_full_charts.py tests/test_coverage_honesty.py -q
UV_CACHE_DIR=/tmp/fugu-uv-cache PYTHON_DOTENV_DISABLED=1 uv run --no-sync python bench/composition_expanded.py --engine-root src --output bench/results/2026-10-02-composition-v2/review-after.json --label after
uv run --no-sync python bench/composition_expanded.py --engine-root /tmp/fugu-composition-showcase-engine-20261002 --output bench/results/2026-10-02-composition-v2/baseline.json --label baseline
uv run --no-sync python bench/composition_expanded.py --engine-root src --output bench/results/2026-10-02-composition-v2/after.json --label after
MPLCONFIGDIR=/tmp/fugu-mplconfig /tmp/fugu-charts-venv/bin/python -m bench.full_charts --source bench/results/2026-10-02-full --out bench/results/2026-10-02-composition-v2/full-benchmark-charts --recovered
```

Every run checks the frozen case-source hashes and records the engine hashes;
the baseline run additionally requires an exact match with all 37 frozen
engine files. The chart command reads the frozen full-benchmark directory but
writes only to the new composition-v2 result path; all generated PNG charts
were visually inspected. The current scoped suite passed 121 tests with one
Starlette/AnyIO deprecation warning. The review replay wrote only
`review-after.json`; the original baseline and revised result files retain
their prior SHA-256 hashes.
