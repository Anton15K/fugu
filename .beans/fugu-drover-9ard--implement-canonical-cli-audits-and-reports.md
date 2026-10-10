---
# fugu-drover-9ard
title: Implement canonical CLI audits and reports
status: completed
type: task
priority: normal
created_at: 2026-10-10T08:36:24Z
updated_at: 2026-10-10T11:42:18Z
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
- [x] Mask rejected query/fragment/encoded token URLs, add behavioral regression cases, verify and commit the correction for fresh independent review.
Review: /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/reviewer-report.md

BYOK-IMPL-01 correction committed as da3d34b14b2c0d3b859b97e75f52f86e531b244a. Verification: initial behavioral red 8 failed / 7 passed; restored green 15/15; guarded CLI/security/API/intake/casebook regression 435/435 plus 23 subtests (one inherited Starlette warning). Actual module-entry tests use URL tokens distinct from provider keys and assert exit 2, one JSON object, no raw/decoded token on stdout/stderr and zero backend/credential-resolution/intake/provider attempts. Userinfo and local/public HTTPS source display controls pass. Only cli_output.py, mapped security tests and this B record changed. Evidence: /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/correction-1-evidence/. New exact head and all ordered A+B+correction SHAs are named by candidate.json/coder-report.md after final committed verification; prior evidence is preserved. Fresh exact-candidate independent review under fugu-drover-opb5 is pending; this completed B record covers implementation only and claims no approval.
