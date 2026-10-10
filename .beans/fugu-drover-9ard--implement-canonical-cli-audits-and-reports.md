---
# fugu-drover-9ard
title: Implement canonical CLI audits and reports
status: in-progress
type: task
priority: normal
created_at: 2026-10-10T08:36:24Z
updated_at: 2026-10-10T11:20:11Z
parent: fugu-drover-p0u7
---

Reuse run_auto_job and existing verdict policy; implement explicit offline/full profiles, hosted-data consent, text/JSON output, exit codes, child-environment filtering, cleanup and documentation.

Follow the durable fugu-cli-byok-20261010 spec, plan and role brief.

- [x] Write failing behavioral CLI/input/coverage tests.
- [x] Implement canonical audit adapter, output and mode handling.
- [x] Verify credential-free children, no key output, cleanup, fan-out and API compatibility.
- [ ] Commit phase B and docs; publish exact candidate SHAs.

Phase B verification: 420 passed, 23 subtests passed (one seeded Starlette deprecation warning). Behavioral red/green, fake hosted/keyring/subprocess boundaries, canonical full roots/leaves and offline fixtures are retained under /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/. Shared types/model limits, web and frozen benchmark artifacts unchanged. Independent named-commit review and disposable package/platform validation belong to separate assigned records.
