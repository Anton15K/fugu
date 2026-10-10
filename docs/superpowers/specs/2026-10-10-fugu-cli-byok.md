# Fugu BYOK CLI specification

Revision 2 (10 October 2026): resolves independent plan findings BYOK-PLAN-01 and BYOK-PLAN-02.

Goal: developers can audit an agent extension from a terminal using their own provider credentials, with the same inspectable findings, policy and coverage boundaries as the web product. No Fugu account is required. The user requested the BYOK plan and fleet handoff after discussing this model.

## Scope and assumptions

First release: installed `fugu` command, secure provider configuration, environment-key CI use, local source/Git intake, canonical audit execution, text/JSON reports and automation exit codes. Retain the web UI. Hosted Fugu accounts, OAuth/device login, billing, a paid service, auto-generated upstream issues and release publication are outside this assignment. Assume a single-user CLI process; never add per-user keys to the shared HTTP service. Python 3.10 is the compatibility floor.

Application starting point: remote main 7072144d8e39f91815bc92dd5275d41b1cc3822b, which includes the reviewed jury README. Local application main is older; start task branches from the pinned current application base, not setup/drover. This explicit base governs review/ancestor checks for this assignment. Do not change main/setup refs or merge setup branches. Preserve all existing untracked research/logs and the application's shared contract types.

## User journey and commands

- `fugu --help` / `fugu --version`: work without credentials, provider clients, keyring access, dotenv loading or network calls.
- `fugu configure --provider nebius` (default) or `--provider tavily`: show intended provider/data flow, prompt through getpass, store in an approved OS credential backend. No plaintext fallback, key argument or default provider call. Empty input cancels; a locked/unavailable/unsupported backend fails with environment-variable instructions. Never answer native OS credential-access dialogs for the human.
- `fugu auth status`: show configured/missing, source (environment/keyring), supported endpoint and storage availability; never print a key or key fragment. No network by default.
- `fugu auth status --verify`: one bounded Nebius model-list request with fake transport in tests; report authentication/catalog reachability, not successful inference, available credits or model execution. No automatic retries. Tavily configuration status remains local in this release.
- `fugu auth logout [--provider nebius|tavily|all]`: remove only Fugu's keyring entries, idempotently. Do not edit environment variables, project files, other applications' credentials or revoke keys at the provider. Say if an environment credential remains effective.
- `fugu audit SOURCE [--mode full|offline] [--format text|json] [--allow-hosted] [--reputation] [--detonate]`: default full. Full requires a Nebius key; missing keys fail before source intake rather than silently falling back. Show that selected text/prompts go to Nebius and usage is billed to the user's provider project. Interactive full runs confirm that disclosure; noninteractive full requires --allow-hosted. No prompt contaminates JSON stdout. A nonempty TAVILY_API_KEY enables reputation automatically. If it is absent, default full runs exclude reputation without requesting storage; --reputation explicitly requests it and permits saved Tavily lookup. If requested reputation has no key (including an explicitly empty env override), fail preflight with exit 2. Explain intentional exclusions. Detonation is explicit opt-in and uses only fake canaries.
- Offline accepts a local directory only; reject network/Git inputs, --reputation and --detonate before intake. Never initialize/read a keyring, call providers/OSV/Tavily, discover/run Docker or execute a target. Run production concealment/static checks and deterministic composition when relevant; optional external tool-surface scanner is explicitly disabled in offline mode. Its absence is disclosed.

No listening server or browser is required. An existing Git URL in full mode uses the established safe intake/selection rules; reject embedded URL passwords/tokens and non-HTTPS remotes in the initial CLI. Do not introduce private-Git authentication in this release. On completion the user reviews reasons, exhibits and coverage, fixes/investigates the candidate, or stores JSON through shell redirection. Persistent history, opening the web UI and a new report-import API are deferred.

## Credential and configuration contract

Environment credentials take precedence over stored credentials. An explicitly present empty value disables that provider for this process; it must not resurrect a saved key. Invalid environment credentials do not silently fall back after a 401/403. NEBIUS_API_KEY and TAVILY_API_KEY retain their names. CI uses environment credentials and never prompts or requires desktop storage.

Storage access is command- and provider-specific. Audit and Nebius verification may lazily acquire/read the Nebius store only when NEBIUS_API_KEY is absent. Presence, including an empty value, prevents that provider's storage lookup. Audit may read stored Tavily only when --reputation is requested and TAVILY_API_KEY is absent. An environment-only headless full audit with absent optional Tavily never instantiates a desktop backend. Configure always acquires the approved store and writes the selected provider entry regardless of environment precedence. Logout always acquires the approved store to delete selected Fugu entries regardless of environment precedence, and reports any still-effective environment credential. Local status skips stored lookup for each present env provider; for absent providers it may inspect Fugu entries through approved storage and return presence only. Unavailable storage is a safe status, not a reason to prompt or print backend details. Help/version/offline never request storage.

The CLI disables dotenv discovery before importing application configuration. Add an explicit FUGU_NO_DOTENV guard in config.py rather than relying on python-dotenv versions to honor PYTHON_DOTENV_DISABLED. Preserve existing web/server dotenv behavior. An audited directory's .env cannot change keys, endpoints, profiles or consent. Keep any global nonsecret settings separate from the source tree; no persistent settings file is necessary for the first release.

CLI credential-bearing requests accept only the official EU/US HTTPS Token Factory endpoints already declared in config.py. Validate explicit NEBIUS_BASE_URL before credential use; reject userinfo, query/fragment and unsupported hosts rather than forwarding a key. Preserve existing server endpoint-override behavior outside the CLI. Do not send a key on a cross-host redirect.

Use a lazy OS-keyring adapter with an explicit allowlist of native macOS Keychain, Windows Credential Locker and Linux Secret Service backends. Reject null/fail/plaintext/alternate/third-party/chained backends; priority alone is insufficient. Use Fugu-specific service/account names and provider-separated entries. Optional packaging extra `cli` may pin keyring==25.7.0 (published metadata requires Python >=3.9) and its lockfile; no base-dependency/SDK changes. This assignment permits these dependency-file edits and dependency installation ONLY in an owned disposable verification environment, not synchronization of the shared seeded environment. No real OS credential store is touched in fleet tests.

Pass credentials in a scoped runtime context, never through an environment mutation. Existing get_settings()/make_client() and reputation key resolution must consult the scope for CLI execution and retain their old behavior otherwise. Credential dataclass fields have repr=False. No keys in findings, audit metadata, logs, SQLite, stdout/stderr, exception detail, generated prompts, Docker arguments, target mounts or child process environment. Redact known runtime credentials at CLI output/error boundaries; retain fake-canary evidence. Treat required provider authentication headers as a separate plane from model prompt/evidence content. Test that runtime credentials are not included when constructing those contents.

Filter provider credentials from Git, Docker and optional scanner subprocess environments while preserving necessary normal execution variables. Never run or import audited source on the host. No credential exposure proof may depend on real provider keys or real target execution.

## Audit and report contract

Reuse server.composition_jobs.run_auto_job, JobStore, server.jobs finding_public/stage_public and aggregate_verdict; the findings-only run_audit return value is insufficient for coverage-sensitive CI. Add an adapter, not a second policy/engine. Keep src/fugu/types.py and web/API wire contracts unchanged. Preserve shared production limits, fan-out caps, extraction safety, bounded subprocess cleanup and owned-snapshot lifetime. Explicitly construct the root AuditJob with depth="full" for both CLI modes. Full single-source and fan-out leaves therefore use the same canonical full harness profile: exactly six static probes under the pinned production limits. Offline depth is inert metadata; only local stages are built and no provider/harness/keyring/Docker/subprocess is invoked. Do not change shared types or limits to achieve this mapping.

The full CLI profile requires concealment, static, semantic and harness. Reputation is optional when no Tavily key; once enabled, failures/partial coverage are disclosed and count as incomplete. Detonation is required only with --detonate; unavailable chamber or no executed trigger then means incomplete. Repository omissions/failed members and partial required stages always count as incomplete. Local offline profile requires only its actual local checks, and labels all exclusions; local PASS is not full-workflow PASS or safety certification. No source or model intent becomes claimed execution.

Text output puts verdict, mode, coverage limits and recommended next action first. JSON stdout is exactly one newline-terminated object, including for handled failures; progress/consent/errors belong on stderr and are secret-safe. Stable envelope version 1:

```json
{"schema_version":1,"mode":"offline","audit_status":"done","source":"<source>","verdict":{},"stages":[],"findings":[],"children":[],"coverage":{"required_stages":[],"excluded_stages":[],"incomplete":false},"error":null,"exit_code":0}
```

Use the existing canonical verdict object inside the envelope; extraction/configuration failures have verdict=null, not fabricated PASS/FAIL. Include member summaries and coverage where fan-out ran. Report errors with a stable category and safe message. No raw SDK/provider body or backend exception is printed.

Exit codes: 0 = PASS and all checks required by the chosen profile complete; 1 = complete profile with canonical WARN/FAIL; 2 = usage/configuration/credential/intake error; 3 = failed/incomplete requested audit, omitted members, unavailable requested check or no verdict; 130 = cancellation. Priority is preflight 2 / interruption 130; after execution, incomplete 3 takes precedence over finding severity, which remains in JSON. Offline excluded hosted checks alone do not make exit 3. Human-interrupted runs cancel work and reclaim owned temporary snapshots/resources, not original sources.

## Acceptance and independent review

All fleet verification uses fake credentials, fake keyring backends and fake network/subprocess transports. Never consume the operator's .env or keys, call paid APIs, retry previously blocked research, execute third-party targets or alter shared servers/databases. Run Python with PYTHONPATH="$PWD/src:$PWD" uv run --no-sync and disable dotenv for tests. Preserve Python 3.10 syntax/imports. Integration may install the built project into an owned disposable environment; no shared sync/install.

Verify key precedence/empty override with no store lookup; configure/logout persistence despite nonempty env; environment-only headless full with absent optional Tavily and zero backend acquisition; explicit --reputation saved lookup and missing-key preflight; single-source full depth and literal six static probes; two-unit fan-out leaf full depth and member coverage; no-key preflight; locked/insecure backend; logout with remaining CI env; malformed/disallowed endpoint; source-directory malicious .env; credential context concurrency/restoration; JSON stderr separation; known-key error redaction; child environments; offline zero network/keyring/Docker; real deterministic hidden/ordinary/missing fixtures; fan-out omissions; no-trigger and failed required stages; cancellation cleanup; web/API regressions. Fake providers test request construction and parsing, not real sponsor runtime or billing.

## User Stories

- US-1: As a developer, I find the CLI setup and audit commands in the existing README without losing charts or the web setup.
- US-2: As a developer, I configure my provider key through a hidden prompt and see its source/status without exposing it.
- US-3: As a CI owner, I use NEBIUS_API_KEY with explicit hosted consent and receive parseable JSON and reliable exit codes without a desktop login.
- US-4: As an offline user, I audit a local directory without credentials/network/target execution and see the performed and excluded checks.
- US-5: As a developer, I inspect canonical findings and member coverage and distinguish incomplete analysis from a clean result.
- US-6: As a user on a headless or locked desktop, I get environment-key instructions instead of plaintext persistence or a stuck prompt.
- US-7: As a developer, I log out of Fugu's stored credentials and understand that provider revocation/environment cleanup are separate actions.
- US-8: As an existing web user, I retain the same API verdict/data contracts and configured server behavior.
- US-9: As an interrupted CLI user, I receive a cancellation result and my original source survives cleanup.

Sources checked 10 October 2026: https://keyring.readthedocs.io/en/latest/ (native backends and insecure alternatives), https://pypi.org/pypi/keyring/json (25.7.0 / Python >=3.9), https://dev.nebius.com/cookbook/opencode-nebius-token-factory (API-key/project billing and model-list verification). BYOK does not make enabled inference entirely local.
