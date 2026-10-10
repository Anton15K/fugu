# Fugu BYOK CLI Implementation Plan

Revision 2 (10 October 2026): addresses BYOK-PLAN-01 and BYOK-PLAN-02; fresh independent approval is required before phase A.

> **For agentic workers:** Use the native named Drover coder/reviewer/integrator sessions under fleet-peers. Implement this plan task-by-task with scoped behavioral red/green tests and independent exact-candidate review. The human selected fleet delivery; do not ask again which execution method to use.

**Goal:** Ship a terminal audit tool with secure BYOK setup, offline checks, canonical hosted audit reports and reliable CI exits.

**Architecture:** A thin argparse CLI delegates to canonical run_auto_job and JobStore. Lazy credential/keyring adapters and scoped settings provide provider keys without mutating process environment; the web interface and policy remain shared. Output/exit mapping is a separate adapter over canonical findings and coverage.

**Tech Stack:** Python 3.10+, argparse/getpass/contextvars/dataclasses, existing Fugu/asyncio/OpenAI-wire SDK, optional keyring==25.7.0.

**Spec:** /Users/antonkogun/.local/share/drover/briefs/fugu-cli-byok-20261010-spec.md

## Global constraints

- Base 7072144d8e39f91815bc92dd5275d41b1cc3822b; this pinned application base governs branch/review ancestry. Never merge setup/drover or setup/openrig into product.
- Python 3.10 compatibility; preserve src/fugu/types.py, existing web/API contracts, benchmark artifacts and model/production-limit choices.
- Only one coder edits product files. Reviewer and integrator use separate worktrees. Reports remain under /Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/.
- PYTHONPATH="$PWD/src:$PWD" uv run --no-sync; no shared environment sync/install or reading/copying .env, databases, logs or credentials.
- Optional CLI keyring extra + lockfile are the only dependency changes in scope; installation is allowed only in integrator-owned disposable verification state.
- All inference/keyring/subprocess validation uses fake secrets and transports. No paid calls, external-target execution, live chamber runs or retries of native-blocked research.
- Human Git owner retains push/main landing/release/deployment. Produce an approved local candidate and PR draft; do not publish merely to test it.
- Track work through beans, not additional mutable todo documents. The plan describes test cycles; bean checklists are the status source.

## Review focus

1. CWD is the audited repository and has a hostile .env: auth/help/audit must not consume it or route keys to its endpoint (Task A tests).
2. A keyring is locked, insecure, chained or absent on headless CI: fail safely for persistence; env-key audits still work without prompting (Task A tests).
3. An environment override is explicitly empty or invalid while a saved key exists: no resurrection or auth-error fallback (Task A tests).
4. A nominal PASS has skipped/failed requested checks, missing members or no execution for --detonate: coverage-sensitive exit 3, no silent clean success (Task B tests).
5. SDK/subprocess errors contain a fake credential or cancellation happens during extraction: redact output, filter children, preserve original input and reclaim owned snapshots (Task B/integration tests).

## Contracts and file map

Create src/fugu/cli.py (argparse entry/dispatch), src/fugu/__main__.py (module entry), src/fugu/credentials.py (key/context data and secure storage adapter), src/fugu/cli_audit.py (canonical runner/profile/report adapter), src/fugu/cli_output.py (text/JSON/error redaction + exit mapping), src/fugu/subprocess_env.py (provider-key-free child environment). Create tests/test_cli_auth.py, tests/test_cli_audit.py, tests/test_cli_security.py and docs/cli.md.

Modify pyproject.toml (console entry and optional cli extra), uv.lock only for the assigned extra, src/fugu/config.py (dotenv guard + credential scope), src/fugu/pipeline/stages/reputation.py (scoped Tavily resolution), src/fugu/pipeline/stages/static_scan.py (explicit optional-scanner disable), src/fugu/server/jobs.py + src/fugu/detonation/docker_driver.py + src/fugu/pipeline/stages/tool_surface.py (sanitized provider-key-free subprocess environments), README.md (short CLI entry/link, retain charts and local/web instructions). client.py may change only if needed to maintain correct scoped settings / safe verification timeout. Do not edit other shared contracts; request a scope amendment in the report if a real dependency requires it.

Shared signatures, defined by Task A and consumed by Task B:

```python
@dataclass(frozen=True)
class CredentialSet:
    nebius: str = field(default="", repr=False)
    tavily: str = field(default="", repr=False)
    base_url: str = "https://api.tokenfactory.nebius.com/v1/"

class SecretStore(Protocol):
    def get(self, provider: str) -> str | None: ...
    def set(self, provider: str, value: str) -> None: ...
    def delete(self, provider: str) -> None: ...

# credentials.py
resolve_credentials(environ: Mapping[str, str], store: SecretStore | None,
                    *, use_stored_tavily: bool = False) -> CredentialSet
credential_status(environ: Mapping[str, str], store: SecretStore | None) -> dict[str, Any]
# config.py; restores prior scope in finally, does not mutate os.environ
credential_scope(keys: CredentialSet) -> ContextManager[None]
get_reputation_api_key() -> str
# subprocess_env.py
credential_free_env(environ: Mapping[str, str] | None = None) -> dict[str, str]
# cli.py
main(argv: Sequence[str] | None = None) -> int
# cli_audit.py
run_cli_audit(source: str, mode: str, keys: CredentialSet,
              *, detonate: bool = False) -> dict[str, Any]
# cli_output.py
exit_for_report(report: Mapping[str, Any]) -> int
render_report(report: Mapping[str, Any], format: str,
              secrets: Sequence[str] = ()) -> str
```

The annotations above are interface contracts, not placeholder implementation tasks. SecretStore methods are protocol definitions. Keyring acquisition is lazy and provider-specific. A SecretStore adapter may exist before its backend is acquired; constructors must not acquire storage. Apply this command table, using environment PRESENCE rather than truthiness:

| Command | Storage acquisition/read/write rule |
| --- | --- |
| help/version/offline | No adapter/backend request, no stored reads. Offline rejects --reputation/--detonate before intake. |
| full audit | Nebius: get only if NEBIUS_API_KEY is absent. Tavily: get only if --reputation is requested AND TAVILY_API_KEY is absent. Present empty env disables that provider without get/backend acquisition; nonempty env wins even after auth failure. |
| auth status --verify | Resolve Nebius only, with the same env-presence rule; never acquire storage for absent optional Tavily just to verify Nebius. |
| configure | Acquire approved store and set selected provider even if its env variable is present/nonempty. |
| logout | Acquire approved store and delete selected provider(s) even if env overrides remain; report still-effective env credentials. |
| local status | For each present env provider, show environment source/disabled without stored lookup. For absent providers, approved storage may inspect entry presence; unavailable storage is reported safely, without prompts or secret output. |

A nonempty TAVILY_API_KEY automatically enables reputation for full mode. With absent Tavily env and no --reputation, omit it intentionally and never acquire its store. --reputation passes use_stored_tavily=True to the resolver and requires a resulting key; absent/empty credentials fail preflight with exit 2. The flag is the explicit saved-Tavily lookup path. Env-only headless full audits must work without importing/acquiring any desktop backend when optional Tavily is absent. All exceptions exposed to users become categorized safe errors, never raw backend/SDK exceptions.

## Task A — credential layer and command entry

**Bean:** fugu-drover-5rzh. **Owner:** fugu-codex-coder.
**Files:** cli.py, __main__.py, credentials.py, config.py, reputation.py, cli_output.py (safe errors), pyproject.toml, uv.lock, tests/test_cli_auth.py, the assigned bean. Credential-layer changes form one reviewable commit set.

1. Write subprocess-level tests that launch the actual CLI module with fake stores/keys. Pin these behaviors before implementation: --help/--version zero provider/keyring calls; hidden configure input; explicit empty env beats saved key with zero get/backend calls; configure sets and logout deletes selected storage despite a nonempty env override; environment-only headless full setup with absent Tavily never acquires a backend; explicit saved Tavily resolution is opt-in; secure/unavailable backend handling; local status without network; explicit --verify uses one bounded fake model-list request. A core resolver test is:

```python
def test_empty_environment_disables_saved_key():
    class Saved:
        def get(self, provider):
            raise AssertionError("present empty env must not read saved credentials")
    keys = resolve_credentials({"NEBIUS_API_KEY": ""}, Saved())
    assert keys.nebius == ""
```

2. Run each relevant new test before implementation and retain the meaningful failing assertions; missing entry points are an initial failure, then test actual precedence/redaction behavior. Use only fake sentinel values; never query a real keyring.
3. Add console entry `fugu = "fugu.cli:main"`; __main__.py exits via main(). Parse help/version/auth arguments before importing application configuration. CLI sets FUGU_NO_DOTENV before the first config import; config adds:

```python
if os.environ.get("FUGU_NO_DOTENV") != "1":
    load_dotenv()
```

4. Implement CredentialSet/SecretStore/approved keyring adapter and the exact resolution/status rules. Scoped settings use ContextVar with token reset in finally; get_settings()/reputation use the scope when present, retaining server behavior when absent. Stored keys remain in memory, never os.environ. Mask known keys at safe error boundaries; keyring state/status never returns secret strings. Use getpass; fail on noninteractive configure rather than echoing/reading argv secrets.
5. Add hostile-CWD `.env` and concurrent-context tests. Read them as authored temporary fixtures, not operator configuration. Verify unsupported CLI endpoints fail before clients/intake and invalid env auth never triggers stored-key retry. Keyring--verify/model-list success explicitly isn't an inference/billing test.
6. Run scoped auth/config/reputation/client regression tests, update the assigned record and commit only permitted paths. Copy spec/plan into application docs/superpowers/{specs,plans}/2026-10-10-fugu-cli-byok.md as part of the product branch so the design travels with review; this is an explicit additional docs scope. Report contracts, red/green output and SHAs. Check phase A complete locally; integrator then assigns B on the same branch.

## Task B — canonical audits, automation and docs

**Bean:** fugu-drover-9ard; depends on A. **Owner:** same coder / same branch.
**Files:** cli_audit.py, cli_output.py, cli.py, subprocess_env.py, static_scan.py, jobs.py, docker_driver.py, tool_surface.py, tests/test_cli_audit.py, tests/test_cli_security.py, docs/cli.md, README.md, assigned bean. Consume Task A's exact interfaces; no shared-type or web changes.

1. Write offline behavior tests over owned hidden/ordinary/missing fixtures through the real canonical runner. Guard provider construction, keyring reads, network and subprocess calls; assert zero attempts. Test flags and the literal exit-code contract separately:

```python
@pytest.mark.parametrize("status,incomplete,expected", [
    ("pass", False, 0), ("warn", False, 1),
    ("fail", False, 1), ("pass", True, 3), ("fail", True, 3),
])
def test_coverage_controls_exit(status, incomplete, expected):
    report = {"audit_status": "done", "verdict": {"status": status},
              "coverage": {"incomplete": incomplete}, "error": None}
    assert exit_for_report(report) == expected
```

2. Observe failures, then implement the adapter around JobStore/AuditJob/run_auto_job, serializing existing public findings/stages and verdict. Explicitly construct AuditJob(depth="full") for both modes; never inherit the standard default. Full single-source jobs and canonical fan-out leaves retain depth="full" and the current literal six static harness probes. Offline depth is inert metadata; its stage list still has zero providers, harness, keyring, Docker or subprocess calls. Add behavior tests with a fake provider that capture the full single-source root depth and count exactly 6 static probes; a two-unit fan-out test captures both full-depth leaves and their coverage. Keep shared production limits/types unchanged. Required stages/exclusions live in the new CLI envelope, not changed server payloads. Offline uses the actual local scanners, explicit excluded coverage and existing deterministic composition. Fix the optional surface-scanner constructor to distinguish default None (environment activation) from explicit False (offline disable); current `surface_scanner or ...` would otherwise reactivate it.
3. Full profile assembles semantic/harness plus optional reputation under credential_scope. Add --reputation to argparse: nonempty Tavily env enables automatically; absent env without the flag excludes reputation and never requests storage; the flag allows saved lookup only if env is absent and missing/empty resulting credentials fail preflight. Test the env-only headless full path with no keyring imports/backend acquisition, and the explicit saved-key path with fake stores. Default detonation remains off; --detonate appends the existing Docker-backed DetonationStage explicitly, not the unverified remote-driver selector. No target execution is performed during fleet tests. Full mode validates credentials/endpoint/consent before intake; CI requires --allow-hosted. No silent offline fallback.
4. Implement single-object JSON/text rendering, safe errors and literal exits. Collect any partial result on failed jobs; null verdict if none. Aggregate child member omissions and failed/partial required stage coverage instead of assuming parent PASS is enough. Keep actual verdict severity even when exit 3 takes precedence. Required no-trigger detonation counts as incomplete; intentionally excluded optional checks do not.
5. Add credential_free_env and pass it to the relevant existing Git/Docker/scanner subprocess launches and scanner cleanup. Filter NEBIUS_API_KEY/TAVILY_API_KEY; never add credentials to target env/mounts/argv or prompts. Test fake subprocess call args/env and serialized reports/errors for sentinel absence. Do not present sanitized Docker-client environment as proof of running a real chamber. Add cancellation tests around owned snapshots and cleanup. Do not delete source trees or another agent's resources.
6. Add docs/cli.md with install/configure/env CI/local/full flow, keyring failure instructions, provider billing/data disclosure, exclusions/exits, logout behavior and fake-versus-live evidence boundaries. Link it from the jury README with two short commands, preserving charts/captions and web setup. This is not a new API/login/server subsystem.
7. Run scoped CLI/security plus touched pipeline/source/server/casebook regressions. Retain red/green output, update task records and commit assigned changes. Write candidate.json only after all commits exist:

Generate the artifact from actual Git state, not illustrative IDs:

```python
import json, subprocess
from pathlib import Path
base = "7072144d8e39f91815bc92dd5275d41b1cc3822b"
def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()
commits = git("rev-list", "--reverse", "--no-merges", f"{base}..HEAD").splitlines()
assert commits
output = Path("/Users/antonkogun/.local/share/drover/reports/fugu-cli-byok-20261010/candidate.json")
output.write_text(json.dumps({"state": "READY_FOR_REVIEW", "base_sha": base,
    "branch": git("branch", "--show-current"), "commits": commits,
    "head_sha": git("rev-parse", "HEAD"),
    "report": str(output.parent / "coder-report.md")}, indent=2) + "\n")
```

Include both A and B commits and necessary design/task records; no merge commit in the named implementation set.

## Task C — independent review and integration

**Review bean:** fugu-drover-opb5. **Integration/coordinator bean:** fugu-drover-au1g.

1. Reviewer first inspects this spec/plan read-only and writes plan-review.json with state APPROVE or CHANGES and concrete findings. The coordinator starts implementation only after that report is complete; return plan findings to root/coder instead of silently changing contracts. This is fleet design validation within the requested handoff; no request to reselect execution method.
2. Coordinator assigns Task A, waits for an exact named-commit phase-A handoff, then assigns B only when coder is idle/done. Watch durable handoffs with interruptible waits <=60 seconds. Do not prompt working/blocked agents or answer permissions. On actual missing user decision, write the precise question and stop dependent work.
3. Reviewer cherry-picks ALL candidate commits onto detached pinned application base in its own worktree. Independently run CLI credential/security/intake/coverage tests plus appropriate affected API integration checks; inspect actual behavior and named commits. Demonstrate no frozen benchmark/contract/model changes. Recount scope and record LANDABLE and APPROVE/CHANGES. No approval based on an uncommitted preview or coder assertions.
4. Coordinator returns concrete CHANGES to the idle coder, waits for a new candidate artifact and obtains review of the new exact head. Do not auto-accept unresolved high/critical findings. No third-party native-blocked research is retried to validate this feature.
5. Integrator assembles the approved commits onto the same pinned base in its own worktree. Verify packaging/entry point through a built wheel installed into an owned disposable Python 3.10-compatible environment, without modifying the seeded shared environment. Run --help/--version, fake configure/status/logout and credential-free offline fixture smoke from a directory outside the source repo. Run affected integration tests and orchestration boundary. Browser/UI suites are needed only if any UI changes were authorized (none are in this scope).
6. Prepare PR body/title with exact implementation, validation and limitations. Report runtime version(s), optional-keyring platforms actually verified versus simulated, installation commands, test totals, exact release candidate and follow-up human-owned tasks. Complete records only when all acceptance items are done. Stop at reviewed local branch; pushing, merging, publishing a package and paid/demo runs are separate human-directed actions.

## Self-review and coverage map

US-1 -> B documentation; US-2/6/7 -> A auth/keyring; US-3 -> A env + B consent/JSON/exits; US-4 -> B offline guards; US-5 -> B canonical/member coverage; US-8 -> scoped touched API tests + C integration; US-9 -> B cancellation + C smoke. All five Review Focus inputs have tests assigned above. No unsupported model, inferred hosted OAuth, real keyring write, target import or public service is needed. Empty env semantics, endpoint restrictions, exact interfaces and exit precedence are fixed; plan reviewer must report conflicts before coding.
