# Production inference and coverage limits

Fugu uses one immutable default profile for production inference and source
coverage bounds. `get_production_limits()` returns the same frozen
`ProductionLimits` value used by default pipeline callers, and
`to_dict()` exposes its effective values for audit metrics and offline
measurement tools. Constructors accept a profile for hermetic tests; callers
should not tune limits per case.

| Area | Default bound |
| --- | ---: |
| Output tokens per model request | 4,096 |
| SDK request timeout | 90 seconds |
| SDK retries | 0 |
| Semantic review units | 24 |
| Semantic unit size | 6,000 characters |
| Semantic file size / file count | 2,000,000 bytes / 2,000 files |
| Harness file size / file count | 2,000,000 bytes / 50 files |
| Harness mounted source packet | 32,000 characters |
| Fixed harness probes | 3 standard / 6 full |
| Generated RED probes | first 3 valid probes, at most 200 characters each |
| Extracted source tree | 512 MiB / 20,000 entries |
| Git clone timeout | 120 seconds per attempt |
| Automatic skill fan-out | at most 24 units |

The serialized profile is additive stage metadata under `effective_limits`.
Both inference stages also record `llm_calls` for successful responses and
`request_attempts` once per underlying SDK request, including each request in
the bounded Super recovery. `llm_calls` remains a logical-call summary and is
not an attempt counter. A successful empty response is recorded once; the
subsequent response-validation error affects `call_errors` and coverage, not
the SDK request count. Attempt metadata includes requested and served model
where available, output cap, finish
reason, response character count and SHA-256, latency, and usage. Unknown
usage remains `null`; it is not reported as zero. Malformed completion text
is represented by its hash, character count, and original parse error; raw
malformed text is not retained in these attempt records. One bounded recovery
may retry an unusable whole response at the same output cap. A usable findings
list is not retried just because one sibling item is malformed.

Semantic text is split without dropping characters. Chunks prefer original
line boundaries and split a single overlong line when needed; concatenating
the chunks reproduces the source text, and no chunk exceeds 6,000 characters.
At most 24 resulting units are submitted. Metrics report source, unit,
submitted, and omitted character counts; total/completed/partial/omitted unit
counts; file collection counts; and request attempts. Findings from valid
items in a partly malformed response are retained, while the unit is marked
incomplete. This preserves severe evidence and the normal FAIL precedence.

Harness mounting ranks collected text files and limits the complete mounted
packet, including file headings and separators, to 32,000 characters. RED
probe generation receives that same packet. The enclosing prompt text is
outside the source-packet budget. Only the first three nonempty string probes
are scheduled, each truncated to 200 characters. Full depth therefore runs
up to six fixed and three generated probes; standard depth runs up to three
fixed and three generated probes. With all nine full-depth probes available,
the harness makes one RED request and up to 27 primary baseline/mounted
requests. Metrics report mounted and omitted source characters, source files
omitted by collection or packet limits, RED input size, generated and omitted
probe counts, and generated probe characters omitted.

Partial exposure or unusable requests set `coverage_incomplete` in semantic
or harness metrics. The server persists these metrics through job results,
GET/SSE replay, and automatic composition's parent member-coverage records.
Automatic fan-out accepts `FUGU_FANOUT_MAX` values from 1 through 24; absent
or invalid values fall back to 24. Units beyond the cap retain their exact
names and count in parent coverage metadata and verdict caveats. A clean result
with incomplete coverage is not evidence that the source is safe. When no API
key is configured, semantic and harness explicitly skip inference; their
offline no-op is not a security assessment.

Local sources and selected Git materializations are checked against the
512 MiB and 20,000-entry limits. These checks apply to the materialized tree;
they do not cap bytes already transferred while a shallow Git clone is being
created. Each clone attempt has its own 120-second timeout, and failed
materializations are cleaned up. Slashed Git refs keep the existing maximum
of two clone attempts.

The API accepts `standard` for compatibility, but currently normalizes it to
`full`; the request does not select a smaller stage set. Offline assembly can
exclude detonation and reputation explicitly as shown below. A zero exit from
a selected trigger, or zero findings from text analysis, only describes the
bounded work that completed and does not prove complete application behavior.

## Offline assembly sanity check

This check uses a temporary plain-text fixture, makes no provider requests,
and does not execute target content. It verifies the effective profile and
that production assembly can run with detonation and reputation excluded.

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python - <<'PY'
import asyncio
import json
import os
import tempfile
from pathlib import Path

# Force the application inference stages onto their documented offline path.
os.environ["NEBIUS_API_KEY"] = ""

from fugu.config import get_production_limits
from fugu.pipeline.assemble import build_stages, run_stages
from fugu.types import AuditJob, JobStatus

limits = get_production_limits()
stages = build_stages(include_detonation=False, include_reputation=False)
assert [stage.name for stage in stages] == [
    "concealment", "static", "semantic", "harness"
]

with tempfile.TemporaryDirectory(prefix="fugu-limits-check-") as temporary:
    target = Path(temporary) / "sample"
    target.mkdir()
    (target / "SKILL.md").write_text(
        "# Offline sample\n\nSummarize a public document in plain language.\n",
        encoding="utf-8",
    )
    job = AuditJob(
        id="offline-limits-check",
        source=str(target),
        status=JobStatus.running,
    )
    results = asyncio.run(run_stages(job, target, stages))

assert [result.stage for result in results] == [
    "concealment", "static", "semantic", "harness"
]
assert results[2].metrics.get("skipped") == (
    "no NEBIUS_API_KEY; semantic stage offline"
)
assert results[3].metrics.get("skipped") == (
    "no NEBIUS_API_KEY; harness offline"
)
print(json.dumps({"effective_limits": limits.to_dict(),
                  "stages": [result.stage for result in results]}, sort_keys=True))
PY
```
