# Guard-operand correction verification

The source passed **200 scoped tests**, scoped Ruff and Python 3.10 grammar checks. One existing Starlette/AnyIO deprecation warning remains. **20 static-stage/verdict probes** retain high findings for evaluated comparison and exception operands, regex and line-coordinate cases, and captured names. The simple name-based rejection guard and inert comments retain informational evidence. Fixtures were parsed and scanned as text; they were never executed.

Six new regressions failed before the correction and pass afterward. Python rejection-list exemptions now require a simple name as the membership operand, an unshadowed built-in exception with constant arguments, and an absent or `None` cause. Calls, attributes, subscripts, assignments and awaited expressions do not establish an inert rejection. This is a conservative syntax check, without general data-flow analysis.

The static replay preserves baseline S1 decision signatures and stage status on **45/45 recorded inputs**. [Verification](verification.json) binds all 39 current source files, the changed test file, commands and preservation checks. [Probe results](context-probes.json), [source replay](source-only-verification.json), [test log](tests.log), [red regressions](red-repository.log) and [inventory](inventory.json) are retained. The optional replay scripts require the preserved local delivery package and write only scratch outputs.

The earlier [installed S1 activation](../lead-integration-verification/installed-activation.json) remains an observed five-advisory-finding result on inert `SKILL.md`, without scanner omissions or parse errors. Its consumer and scanner configuration are unchanged. Earlier [source checks](../context-correction/README.md) and all original measurements remain preserved. The paired **36 complete / four partial** result predates this source correction.

No inference, search, container or target execution occurred in these source checks. All 3,241 protected historical benchmark files and three owner files retain their hashes. The native final-image Buildx denial remains; no fresh application-image build or deployment smoke is claimed.
