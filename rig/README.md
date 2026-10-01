# Fugu project rig

Six resident Codex seats cover the entire project. Give the lead an outcome;
it plans, delegates at most two concurrent implementation tasks, obtains
independent review, and manages the task's PR through merge. Other seats remain
idle until needed. Quota is consumed when seats actually run tasks and startup.

| Session | Focus | Model | Effort |
|---|---|---|---|
| `control-lead@fugu` | Planning, architecture, integration | GPT-6-Astra | high |
| `build-backend@fugu` | Pipeline, API, storage, sandboxes | GPT-6.1-Sol | high |
| `build-frontend@fugu` | React, UX, browser behavior | GPT-6.1-Sol | high |
| `research-security@fugu` | Threats, corpus, benchmarks | GPT-6-Astra | high |
| `quality-reviewer@fugu` | Independent review, integration QA | GPT-6-Astra | high |
| `delivery-release@fugu` | Docs, packaging, demo and assigned deployments | GPT-6.1-Sol | medium |

## Start and inspect

Run from the project root. Requires OpenRig, authenticated Codex and GitHub,
Python 3.11+ for the administrative profile installer, and the project's normal
tools for assigned tasks. This setup was authored against OpenRig 0.6.3 and
Codex 0.159.3. AgentSpecs import the installed shared resource directory at
`/opt/homebrew/lib/node_modules/@openrig/cli/daemon/specs/agents/shared`; on a
different installation, resolve its shared AgentSpec with `rig specs ls --kind
agent --json` and update the six import paths before validation.

```sh
python3 rig/setup.py
rig spec validate rig.yaml --json
rig spec audit rig.yaml --json
rig spec preflight rig.yaml --json
rig up ./rig.yaml --cwd /Users/antonkogun/dev/nebius_hack --yes --json
rig ps --nodes --rig fugu --json
rig capture --rig fugu --lines 50 --json
```

The installer writes only `fugu-rig-high.config.toml` and
`fugu-rig-medium.config.toml` under the actual `CODEX_HOME` (default
`~/.codex`). It refuses conflicts and symlinks; identical files are no-ops.
Use `--codex-home /path` for a deliberately selected alternate Codex home.
It does not change the base model or reasoning defaults. OpenRig may add its
managed hooks/trust and project guidance during launch; those changes belong
to native coordination setup. Dedicated profiles use a workspace-write sandbox,
outbound network, and auto-review for eligible approval requests; no full-access
launch policy or new blanket command allowance is configured.

Probe loading with `codex -p fugu-rig-high mcp list` and
`codex -p fugu-rig-medium mcp list`. This Codex version does not support
`--strict-config` on `mcp list`. Profile parsing is separate from observing the
effective live seat model/effort and authenticated orientation.

## First-start hook review

Codex may pause on inherited hooks before OpenRig can deliver orientation.
Use the native hook review screen to inspect and trust only the four OpenRig
activity-relay callbacks (SessionStart, UserPromptSubmit, Stop and
PermissionRequest). The installed script is
`/opt/homebrew/lib/node_modules/@openrig/cli/daemon/assets/plugins/openrig-core/hooks/scripts/activity-relay.cjs`.
Leave unrelated hooks untrusted and use Escape to skip their review prompt.
Do not use Trust all or bypass hook trust.

After the terminal is interactive, OpenRig's startup view can continue pending
fresh-context delivery without replacing the process. Check for authenticated
`oriented: verified` on every seat, rather than treating `startupStatus: ready`
as orientation proof. Inspect the exact installed recovery help before retrying.

## Assign an outcome

```sh
rig send control-lead@fugu "Task: improve the scorecard's accessibility. Coordinate implementation, review, testing, and a PR through merge; report the evidence."
```

Replace that example with your outcome. The lead makes the durable work record;
use `rig queue --help` to inspect the native queue surface. For a quick status
request, message the lead at the same address. `rig send --verify` proves pane
delivery, not agent acknowledgement. Use `rig tui` or the existing OpenRig UI
for interactive inspection.

## Authority

Commits, pushes, PRs, reviews and merge are authorized for assigned outcomes.
Independent review and required repository checks must pass before merge.
All seats share Anton15K's GitHub identity: their independent verdict does not
provide formal self-approval on GitHub. Required approval by a different account
remains a blocker rather than something the rig bypasses.

Paid Nebius/Token Factory and Tavily use is authorized until existing quota
ends. Exhausted quota stops affected work; the team records what remains.
No automatic quota purchase or billing changes are authorized. A numeric
remaining-quota cap is not implemented. Deploying or publishing a release
requires an explicitly assigned deployment/publication task and known target.

See `CULTURE.md` for ownership, concurrency, evidence and recovery rules, and
`VERIFICATION.md` for the actual startup observations when setup is complete.

## Stop and resume

```sh
rig down fugu --snapshot
rig up fugu --existing --json
rig ps --nodes --rig fugu --json
```

Use the existing-rig path to resume rather than recreating a second team. A
failed resume is reported; do not treat it as a successful fresh boot. For a
single-seat problem, inspect `rig seat status <session>` and current help before
using targeted recovery. Do not restart or mutate other rigs on this host.
To undo the profile installation, remove only those two dedicated files if
they still match the checked-in profiles, after stopping seats that use them.
Keep your other Codex settings and OpenRig rigs.
