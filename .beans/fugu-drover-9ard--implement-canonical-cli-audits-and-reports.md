---
# fugu-drover-9ard
title: Implement canonical CLI audits and reports
status: in-progress
type: task
priority: normal
created_at: 2026-10-10T08:36:24Z
updated_at: 2026-10-10T11:36:19Z
parent: fugu-drover-p0u7
---

Reuse run_auto_job and existing verdict policy; implement explicit offline/full profiles, hosted-data consent, text/JSON output, exit codes, child-environment filtering, cleanup and documentation.

Follow the durable fugu-cli-byok-20261010 spec, plan and role brief.

- [x] Write failing behavioral CLI/input/coverage tests.
- [x] Implement canonical audit adapter, output and mode handling.
- [x] Verify credential-free children, no key output, cleanup, fan-out and API compatibility.
- [x] Commit phase B and docs; publish exact candidate SHAs.

Phase B verification: 420 passed, 23 subtests passed (one seeded Starlette deprecation warning). Behavioral red/green, fake hosted/keyring/subprocess boundaries, canonical full roots/leaves and offline fixtures are retained under /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/. Shared types/model limits, web and frozen benchmark artifacts unchanged. Independent named-commit review and disposable package/platform validation belong to separate assigned records.

Completed implementation only. Product/test/docs commit: caa5bac4f2230a4648b6ccc5e797954a64d253b7. Required phase A commits: 4e86ec39fdb8851c89234a7e2a15237a15a8d984, 6ec7770011ac15107c5a3728ca690b83e4fa1f26, 1afa5f102a65f0dc9eee8c200a3b573892400e0c. Final record commit and all actual A+B SHAs are named by candidate.json and coder-report.md in /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/. Candidate requires independent exact-commit review; no landing/push/publication authorized. Live provider, native OS storage/dialogs, Docker and Python 3.10 runtime/wheel installation are not verified by the fake tests.


## Required exact-candidate correction — BYOK-IMPL-01
Independent review of 6821130b4161c0eff53303c323ac3e058cc715f5 is CHANGES: rejected URL query/fragment credentials echo in JSON source.
- [ ] Mask rejected query/fragment/encoded token URLs, add behavioral regression cases, verify and commit the correction for fresh independent review.
Review: /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/reviewer-report.md
