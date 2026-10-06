# Your Codex-only Drover setup

Installed on 2026-10-06 from andrebrov/drover commit
`8f84b19be96972018bf45addd1f824a221285c51`. Beans is v0.4.2; the downloaded
macOS arm64 archive SHA-256 was checked against GitHub release metadata.

- Tools/source: `/Users/antonkogun/dev/drover`
- Project/main checkout: `/Users/antonkogun/dev/fugu-drover`
- Configuration: `~/.config/drover/config`
- Reports, queue and logs: `~/.local/share/drover`
- Team: `fugu-codex-coder` and `fugu-codex-reviewer`, both Codex.
- You are the lead: add tasks, resolve questions, inspect reviews, land and push.

The project starts at the existing Fugu checkout's committed HEAD, not its dirty
files. Its local `main` includes the standalone Drover setup. This is a separate
clone, with its own Git metadata and task board. The OpenRig checkout is untouched.
No keys, live SQLite WAL/SHM state or uncommitted changes were copied. The committed
`fugu.db` snapshot is present because it is tracked in the repository; it is independent
of the original checkout's live database. The Python environment is
shared via a symlink; Python commands use `PYTHONPATH="$PWD/src:$PWD" uv run --no-sync`
to select the current worktree source instead of the original editable install. Frontend dependencies are
copied locally and seeded into new worktrees. Hosted Fugu analysis needs separate
credential setup if you later assign work that calls those APIs.

## First start

Open a terminal inside Herdr (`herdr` from your terminal), then run:

```sh
export PATH="$HOME/.local/bin:$PATH"
cd ~/dev/fugu-drover
fleet up
fleet status
fleet models
```

Each seat has its own workspace and Git worktree. Codex uses your existing login
and default model configuration. If Codex asks about trusting a directory, inspect
it and answer the dialog yourself. Approval prompts are preserved; the watcher
does not turn approval bypass back on.

There are no ready tasks initially and no background jobs are loaded. You can
try one tick with `fleet-watch once`, then run `fleet-watch run` in a dedicated
Herdr shell. Ctrl-C stops that foreground watcher. Keep exactly one watcher.

For a persistent watcher after the seats are ready:

```sh
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.drover.fleet-watch.plist"
```

Only load that watcher job. The installer rendered other optional jobs, but they
are not needed for this starter setup. Check the watcher with:

```sh
tail -f ~/.local/share/drover/watch/watch.log
fleet-watch queue
fleet-scoreboard
```

To stop the persistent watcher:

```sh
launchctl bootout "gui/$(id -u)/dev.drover.fleet-watch"
```

## Add work

Create one clearly scoped task with acceptance criteria, permitted files and
verification commands. For example, write `task.md` outside the project:

```md
Describe the exact requested change here.

Permitted files: list the relevant code and tests.
Acceptance criteria: describe observable behavior.
Verification: name the scoped tests and any browser checks.

- [ ] Implement the requested behavior.
- [ ] Run the scoped checks and paste evidence into the report.
```

Then, in the main checkout:

```sh
cd ~/dev/fugu-drover
beans create "Your task title" -t task -s todo --body-file /path/to/task.md
beans list --ready
git add -- .beans/<the-new-task-file>.md
git commit -m "task: describe your task"
fleet-watch enqueue <bean-id>
```

Beans prints the generated ID and file path. Commit the task file to LOCAL main
before dispatch; no push is needed. With a watcher running, it picks up the task.
Alternatively, with the watcher stopped, dispatch manually:

```sh
fleet assign <bean-id> fugu-codex-coder
fleet-watch once
```

Do not manage the same task through both independent dispatchers. Avoid editing
the main checkout while a watcher tick is running. `beans tui` opens the task board.

## The loop

Task committed on main -> coder implements on `fleet/<coder>-<bean>` -> coder
writes a report and calls `fleet-done` -> watcher routes the separate Codex
reviewer -> CHANGES returns to the coder, APPROVE waits for you to land.

```sh
fleet read fugu-codex-coder 40
fleet read fugu-codex-reviewer 40
fleet-scoreboard
cat ~/.local/share/drover/watch/state/blocked
ls ~/.local/share/drover/reports
```

`blocked` exists only after a blocker is recorded. Check reports/commits and test
output, not just the pane's idle/done label. Keep approval prompts for the human.

## Land approved work

Read the reviewer report, require `VERDICT: APPROVE` and `LANDABLE: YES`, and check
that it covers the current commits. Pause new work while integrating:

```sh
touch ~/.local/share/drover/watch/state/finish-first
fleet-land-bean <bean-id>
fleet-verify-main
```

`fleet-land-bean` lands to LOCAL main behind build/test gates and never pushes.
The cumulative gate verifies a clean worktree. Inspect deleted code separately
(`git diff --diff-filter=D --name-only <before-sha> main`): Drover's automated
landing does not implement its documented deletion gate. If a gate is red,
fix it before proceeding; do not clear pause markers just to force a push.

When you explicitly want to publish the verified commits to Fugu's origin:

```sh
fleet-push
```

That command runs the cumulative gate before pushing `main`; it never force
pushes. No publication was performed during setup. Coordinate integration with
the OpenRig lead because both clones ultimately target the same GitHub repository.
Migrations and deployments remain separate explicit tasks.

To resume new task dispatch after integration:

```sh
rm ~/.local/share/drover/watch/state/finish-first
```

## Local compatibility changes

Upstream requires cross-harness review. This installation adds the opt-in
`DROVER_ALLOW_SAME_HARNESS_REVIEW=1` for a separate Codex reviewer. It preserves
the cross-harness default when off and rejects reviewing one's own work.
It also respects `DROVER_YOLO=0` in the watcher, allows automatic spec/task feed
to be disabled, and disables TypeSafe inference with `DROVER_TYPESAFE=0`.
Agent rules and prompts describe the actual Codex-only team and human lead.

The local patch is saved in `~/dev/drover/local-codex-only.patch`; regression
tests live in `~/dev/drover/tests/test_codex_only.py`. Do not blindly replace
the installation with upstream updates: retain/reapply the patch and rerun
`python3 -m unittest discover -s ~/dev/drover/tests -v`.

Setup verification covers configuration, installation and local routing/gating
regressions. Live pane startup and a full coder -> reviewer task require the
first-start step inside Herdr; they were not run from the external setup session.
