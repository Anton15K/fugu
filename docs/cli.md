# Audit an extension from the terminal

The local Fugu CLI uses your own provider keys and the same intake, findings,
verdict policy and repository fan-out as the web application. It needs no Fugu
account, listening server or browser. Reports are printed to your terminal;
redirect JSON to retain a report. CLI jobs use an ephemeral in-memory store,
without reading the web server's history database.

## Install and configure

Use Python 3.10 or newer. From a checkout of Fugu, install into your own virtual
environment (the `cli` extra supplies native credential storage):

```bash
python3 -m venv .venv-cli
. .venv-cli/bin/activate
python -m pip install '.[cli]'
fugu --help
fugu --version
fugu configure --provider nebius
fugu auth status
```

`python -m fugu` is also supported. `configure` explains the selected provider's
data flow and reads the key through an interactive hidden prompt. Empty input
cancels without writing. Keys have no command-line argument and are stored only
in Fugu's provider-specific OS credential entries (`fugu.byok`, accounts
`nebius` and `tavily`). Approved backends are native macOS Keychain, Windows
Credential Locker and Linux Secret Service. Chained, plaintext, alternate and
unavailable backends are rejected. A locked/headless backend returns safe
instructions to use environment keys; Fugu does not fall back to a file.
Handle any native OS storage dialog yourself.

For an optional local credential/catalog check:

```bash
fugu auth status --verify
```

Without `--verify`, status makes no network request and never prints a key or
fragment. Verification sends one bounded Nebius model-catalog request without
redirects, retries or inference. Success establishes authentication/catalog
reachability; it does not prove model execution, available credits or billing.
Optional Tavily storage is never requested just to verify Nebius.

Environment variables override saved keys. Presence matters: an explicitly
empty `NEBIUS_API_KEY` or `TAVILY_API_KEY` disables that provider and never
resurrects its saved key. Invalid environment credentials do not trigger a
saved-key fallback. Auth/configure/logout behavior is independent of a project's
`.env`; the CLI disables dotenv discovery before application configuration loads.

Only these credential-bearing Nebius endpoints are accepted, with optional
trailing slash:

- `https://api.tokenfactory.nebius.com/v1/` (EU, default)
- `https://api.tokenfactory.us-central1.nebius.com/v1/` (US)

Set `NEBIUS_BASE_URL` explicitly to select one. Other hosts, non-HTTPS endpoints,
userinfo, ports, query strings and fragments fail before credential use.

## Inspect a local source offline

```bash
fugu audit ./candidate --mode offline
fugu audit ./candidate --mode offline --format json > offline-audit.json
```

Offline accepts a local directory only. It runs production concealment and
static rules, plus deterministic composition when a repository contains
multiple skill units. It does not request storage, call providers, OSV or Tavily,
discover/run Docker, launch a subprocess or import/execute the target. The
optional external tool-surface scanner is explicitly disabled, even when
configured in the environment. Network/Git inputs, `--reputation` and
`--detonate` fail preflight in offline mode.

Every report names performed and excluded checks. Offline exclusions include
semantic, harness, reputation, detonation and the external tool-surface scanner.
A complete offline PASS describes local checks only; it is not a full workflow
PASS or safety certification. Review decoded exhibits, rule matches and remaining
coverage before installing.

## Request a full audit with your Nebius key

```bash
fugu audit ./candidate
fugu audit https://example.com/owner/public-repository.git --allow-hosted
```

Full is the default mode and requires Nebius credentials before intake.
Interactive runs disclose and confirm hosted data flows on stderr.
Noninteractive runs require `--allow-hosted`; no consent means no intake or
provider request. Selected extension text and prompts go to Nebius Token Factory
for NVIDIA Nemotron semantic judgments and A/B harness responses. Usage is billed
to your provider project. These are model analysis and stated-intent comparisons,
not a complete target tool-execution loop. The canonical full profile uses six
static harness probes plus bounded generated probes, on roots and fan-out leaves.

Public Git sources must use HTTPS without embedded usernames/passwords/tokens,
query or fragment. Existing tree/blob selection rules and bounded source safety
checks apply. This release adds no private-Git authentication. Local sources are
copied into owned snapshots; originals are never deleted.

### Reputation and execution

A nonempty `TAVILY_API_KEY` automatically enables reputation for full mode.
Absent Tavily environment credentials without `--reputation` intentionally omit
reputation and never request saved Tavily storage. To opt into a saved Tavily key:

```bash
fugu configure --provider tavily
fugu audit ./candidate --reputation --allow-hosted
```

The flag requires a resulting key. An explicitly empty Tavily environment value
still disables it and produces a preflight error. Enabled reputation sends
identifiers/search queries to Tavily and pinned-package vulnerability lookups to
OSV. Failed or skipped requested reputation checks count as incomplete.

Detonation is off by default. `--detonate` explicitly requests the existing local
Docker chamber with fake canaries, never the remote driver selector. Review the
[execution boundary](readme-reference.md) before opting in. An unavailable chamber,
no runnable/executed trigger, missing result or partial requested execution is
incomplete, even when no severe finding is present. Trigger execution is bounded;
no canary hit is not proof of harmless behavior. Provider credentials are filtered
from Git, Docker, scanner and cleanup child environments and are never added to
target mounts or command arguments. A configured optional external static scanner
may run in full mode; disabled/unconfigured scanners are disclosed as exclusions.

## Use JSON and exit codes in CI

Provision `NEBIUS_API_KEY` through your CI secret environment; no desktop keyring
is needed. Do not put it in command arguments or echo it. With optional Tavily
absent, an environment-only full audit acquires no native storage backend.

```bash
# NEBIUS_API_KEY is supplied by the CI secret environment.
fugu audit ./candidate --allow-hosted --format json > audit.json
```

JSON stdout contains exactly one newline-terminated object, including handled
failures. Disclosures, consent and safe errors go to stderr. Envelope version 1
contains `schema_version`, `mode`, `audit_status`, `source`, canonical `verdict`,
`stages`, `findings`, `children`, `coverage`, `error` and `exit_code`. No verdict is
fabricated for an intake/configuration failure. Stage/finding payloads use the
canonical public serializers. Child reports include member summaries and required
stage coverage; the parent includes omitted-unit counts/labels. Known runtime
credentials are redacted before JSON escaping; fake-canary evidence remains.

| Exit | Meaning |
|---|---|
| 0 | Canonical PASS and all checks required by the selected profile complete |
| 1 | Complete selected profile with canonical WARN or FAIL |
| 2 | Usage, configuration, credential, consent or intake error |
| 3 | Incomplete/failed requested audit, omitted member or missing verdict |
| 130 | Cancellation |

Preflight errors and interruption take priority. After execution, incomplete
coverage takes precedence over severity: unscanned binary, oversized, unreadable
or otherwise omitted source files count as incomplete. A canonical FAIL remains FAIL in JSON
but returns 3 if requested analysis was partial. A parent PASS never hides a
failed/skipped/missing required member check. Intentional optional exclusions
alone do not make coverage incomplete. Text reports lead with verdict, mode,
coverage limits and next action, then reasons and finding exhibits.

Ctrl-C cancels async work and reclaims owned extraction snapshots. Git/Docker
subprocesses are killed/drained boundedly; cleanup addresses only the run's owned
resources. An unresponsive/unavailable Docker daemon can prevent container/network
removal despite cleanup attempts; inspect the daemon before reusing a chamber.
An in-flight synchronous SDK call may finish its bounded request while the executor
shuts down. Original inputs and unrelated resources are preserved.

## Remove saved keys

```bash
fugu auth logout --provider nebius
fugu auth logout --provider all
```

Logout idempotently removes only Fugu's stored entries, even if environment
credentials remain. It does not change environment variables/project files,
remove another application's entries or revoke a provider key. Status/logout
say when an environment credential is still effective; unset it separately or
revoke the key at the provider if needed.

## Verification boundaries

CLI tests use authored inert fixtures and fake provider, keyring and subprocess
transports. They exercise canonical intake/stages, request construction, output,
coverage and cancellation. They do not establish live provider inference/billing,
real desktop storage/dialog behavior or successful Docker chamber operation.
Independent review and disposable installation verification are separate gates;
no package publication or live target execution is part of those fake tests.
The web interface and its existing setup remain available from the
[README](../README.md#run-locally).
