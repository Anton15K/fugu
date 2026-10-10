---
# fugu-drover-5rzh
title: Implement the BYOK CLI credential layer
status: completed
type: task
priority: normal
created_at: 2026-10-10T08:36:23Z
updated_at: 2026-10-10T10:56:22Z
parent: fugu-drover-p0u7
---

Secure configure/status/logout, environment precedence, trusted OS-keyring adapter, dotenv isolation, scoped credential context and Python 3.10 CLI packaging.

Follow the durable fugu-cli-byok-20261010 spec, plan and role brief.

- [x] Add behavioral failing tests with fake credentials/backends.
- [x] Implement secure credentials and auth commands, with no plaintext fallback.
- [x] Verify redaction, endpoint/target dotenv isolation and scoped context; retain red/green evidence.
- [x] Commit assigned changes and record; provide exact SHAs for phase B.

## Phase A Implementation Evidence

Implemented revision-2 credential contracts: environment-presence precedence, provider-specific lazy native storage, saved Tavily lookup only with use_stored_tavily=True, exact native backend allowlist, hidden configure input, safe local status/logout and one bounded no-redirect Nebius catalog verification. Scoped ContextVar settings and Tavily resolution restore without credential environment mutation; CLI dotenv guard preserves the server's default path. Added Python 3.10 CLI entry and optional keyring==25.7.0 extra/lock; all existing dependency pins unchanged. Approved spec/plan copied to the assigned product docs.

67 authored auth tests plus 18 config/client/reputation regressions passed (85 total). Initial suite: 55 failed / 1 existing-behavior pass. Resolver increment and scoped-client redirect tests failed before their implementations; truthiness mutation reintroduced empty-env saved-key resurrection and failed, then the restored implementation passed. Real SDK catalog request construction/parsing used fake transports; native keyrings and terminal behavior are simulated. No original credentials/logs, real keyring/provider calls, shared environment sync, paid target execution, push or publication.

Report: /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/phase-a-report.md. Committed exact phase-A handoff follows; phase B remains unassigned and untouched.

## Phase A Completion

Implementation committed as 4e86ec39fdb8851c89234a7e2a15237a15a8d984. All 85 scoped auth/config/client/reputation tests passed before commit. Exact committed verification and the full required non-merge commit set are recorded in phase-a.json and phase-a-report.md under /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/. Phase A implementation is complete; independent candidate review/integration gates remain separate. Phase B awaits its explicit assignment.
