# Fugu developer reference

Technical details supporting the [jury README](../README.md). These are
configuration and verification notes, not additional benchmark measurements.

## Optional static tool-surface scanner

The S1 stage can also run a pinned scanner over literal JSON/Python tool
definitions and `SKILL.md` instructions. It parses source without importing or
executing the audited extension. Syntax-only context marks selected comments
and literal references as informational; uncertain syntax receives no
exemption. The scanner is advisory: phrase matches need contextual review. The
existing Fugu S1 rules still run if this optional
component is absent; its metrics report the tool-surface pass as disabled.
Scanner errors or omitted surfaces mark S1 coverage incomplete.

To build and install the pinned component locally, use an existing Rust
toolchain:

```sh
uv run --no-sync python tools/build_static_rules.py
```

The build fetches the pinned source and uses `cargo build --locked --release`;
it does not install Rust. By default the scanner looks for
`src/fugu/_bin/static-rules`. Set `FUGU_STATIC_RULES_BINARY` to use another
binary, and optionally set `FUGU_STATIC_RULES_SHA256` to require its expected
SHA-256. `FUGU_STATIC_RULES_IMAGE` selects an existing trusted container image
as the scanner's isolated runtime; that invocation uses Docker with networking disabled and
read-only mounts. If no image is selected, a configured binary runs locally.
If an image is selected but Docker is unavailable, the invocation fails and
S1 coverage is marked incomplete; it does not fall back to local execution.
The application Dockerfile is configured to compile the
pinned scanner and place it at `/opt/fugu/static-rules`. See
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md) for upstream attribution and
license details.

## Current-source checks

The retained 4 October source checks preserve baseline S1 decision signatures
and stage status on all 45 recorded inputs. Regressions cover sensitive reads after
JavaScript regexes and escaped line breaks, Python exception operands and
comparison operands, captured names, and UTF-8 source positions. Inert comments
and simple rejection guards retain informational evidence. See the [current
source verification](../bench/results/2026-10-04-integration/guard-operand-correction/README.md).

Normal configured S1 activation on an inert `SKILL.md` returned five advisory
findings with no scanner omissions or parse errors. That [installed activation
proof](../bench/results/2026-10-04-integration/lead-integration-verification/installed-activation.json)
and the frozen paired results remain unchanged. Source checks do not replace
the workflow measurement. A fresh final application-image build and deployment
smoke remain unverified after the recorded Docker Buildx denial.

## Current application limits

The checked application uses a shared, immutable profile for inference and
source coverage. Its main bounds are:

| Area | Current default |
|---|---:|
| Model output | 4,096 tokens per request |
| SDK timeout / automatic SDK retries | 90 seconds / 0 |
| Semantic review | Up to 24 units, each at most 6,000 characters |
| Harness source and RED input packet | 32,000 characters, including file headings and separators |
| Generated RED probes | First 3 valid probes, at most 200 characters each |
| Materialized source tree | 512 MiB / 20,000 entries |

The SDK retry count does not include the stages’ bounded response recovery;
those requests are recorded separately. The source-tree caps are checked after
materialization and do not cap bytes transferred during a shallow Git clone.
See [production limits](production-limits.md) for file caps, fixed probes,
coverage metrics, and cleanup bounds.

## Developer verification and source intake

From the repository root: `uv run --no-sync python -m pytest -q`. From `web/`:
`npm run build`, `npm run lint`, `npm run contract`, `npm run smoke`,
`node scripts/audit-result.mjs`, and `node scripts/edge-reducer.mjs`.
The 2 October benchmark's scoped checks and independent artifact review verified
chart arithmetic, original evidence preservation and application hashes.
The dated 7 October candidate verification and historical advisory assessment
are in the [assessment](hackathon-assessment.md); this cleanup does not reassess it.

Source intake materializes direct internal file links into an owned regular-file
snapshot and records their provenance. External, broken, cyclic, chained and
directory links fail extraction; direct stage calls still reject descendant
symlinks. See [source intake](source-intake.md). Preflight and copying are
not race-proof isolation of a changing source tree. The 2 October
full-capability benchmark exercised the Docker chamber. Public deployment
safety is not established by local tests or these guards. No deployment target
is assigned.

## Historical measurement methods

[4 October workflow integration](benchmark-workflow-integration.md) ·
[3 October production-profile measurement](benchmark-current-limits-partial-retry.md) ·
[2 October full-capability measurement](benchmark-full.md).

For extraction policy and provenance, see [source intake](source-intake.md).
For repository fan-out and member omissions, see
[composition coverage](composition-coverage.md).
