---
# fugu-drover-p0u7
title: Deliver the Fugu BYOK CLI
status: completed
type: feature
priority: normal
created_at: 2026-10-10T08:35:53Z
updated_at: 2026-10-10T11:56:47Z
---

Product feature requested through BYOK plan and fleet handoff. Parent planning task: fugu-drover-yow5. Ship a Python 3.10-compatible CLI using users own provider keys, optional secure OS-keyring setup, environment-variable CI support, explicit offline/full audit profiles, canonical evidence/coverage reports and documented exit codes. Preserve web behavior and keep provider keys outside target execution. Product tasks and exact-candidate review must finish before declaring this feature complete.

- [x] Credential-layer task approved and completed.
- [x] Canonical audit/report CLI task approved and completed.
- [x] Independent exact-candidate review approved.
- [x] Integration, disposable installation smoke and docs verified.

No live provider requests, real credentials, third-party target execution or public hosted-service changes are included.

Plan revision 2 resolves BYOK-PLAN-01 (provider-specific lazy keyring access, env presence, explicit saved Tavily lookup) and BYOK-PLAN-02 (explicit full AuditJob depth and six-probe parity). Fresh independent plan review requested; implementation remains gated until APPROVE.

## Local acceptance completed — 2026-10-10T11:56:12.720344+00:00
All application acceptance gates completed locally. Source candidate b0128add2a7c446aaa2e4c72ac2819c4797ffdcb; fresh independent APPROVE, exact approved tree integrated at 0f5e2cc24a8ac12c4f736aa383526fa442371e8c. Python 3.11.16 and 3.10.20 each: 435 guarded tests + 23 subtests, 7 edge probes, 10 Docker pure units; built-wheel install and 14 installed console checks passed. Native credential stores/providers/live Git/chambers were simulated or excluded. No publication/landing. Final report: /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/integration-report.md
