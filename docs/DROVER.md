# Codex-only Drover with separate setup branches

## What lives where

| Worktree | Branch | Purpose |
| --- | --- | --- |
| `~/dev/fugu-main` | `main` after the boundary PR is merged | Application and task records; no framework setup |
| `~/dev/fugu-openrig` | `setup/openrig` | OpenRig topology, culture, runtime profiles and startup guidance |
| `~/dev/fugu-drover` | `setup/drover` | Codex-only Drover team guidance, Beans configuration and this guide |

These worktrees share Git metadata in `~/dev/fugu-drover/.git`. The original
OpenRig checkout `~/dev/nebius_hack` is separate and remains untouched; existing
running seats still use it. The OpenRig setup worktree is prepared, not started.
Do not relocate the active team until its work is handed off and it is idle.

Drover's tool source is `~/dev/drover`, based on upstream commit
`8f84b19be96972018bf45addd1f824a221285c51`. Beans v0.4.2 is installed. The runtime
config is `~/.config/drover/config`; logs, reports and queues are under
`~/.local/share/drover`. Beans configuration is also copied outside Git at
`~/.config/drover/beans.yml`. The local `beans` wrapper applies that configuration
to these worktrees while reading/writing each worktree's own `.beans/*.md` records.
It uses the ordinary Beans binary unchanged in other repositories.

The team has `fugu-codex-coder` and `fugu-codex-reviewer`; both run Codex using your
existing login and default model. You are the lead. A local tested compatibility
flag permits the separate Codex reviewer, since upstream requires another harness.
TypeSafe inference, approval bypass, autonomous task generation and autoland are
disabled. Only tasks you add are eligible. No agents or background jobs were
started during installation.

## Start inside Herdr

Open Herdr from your terminal with `herdr`, then use a shell inside it:

```sh
export PATH="$HOME/.local/bin:$PATH"
cd ~/dev/fugu-drover
fleet up
fleet status
fleet models
fleet-watch run
```

The watcher runs in that foreground shell; Ctrl-C stops it. Keep one watcher.
Coders/reviewers get their own worktrees forked from application main, not from
setup/drover. Ignored local skills are installed into those task worktrees;
never stage them. Answer Codex trust/approval dialogs yourself after inspection.

For a persistent watcher after the seats are ready, load only this job:

```sh
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.drover.fleet-watch.plist"
```

Stop it with `launchctl bootout "gui/$(id -u)/dev.drover.fleet-watch"`. The optional
other rendered jobs are not loaded. Live pane startup must be performed inside
Herdr; the external setup session did not run it.

## Add a task

Write a task body outside Git that names the requested behavior, acceptance
criteria, permitted files, and scoped tests. Include checklist items the coder
can complete. Then:

```sh
cd ~/dev/fugu-main
beans create "Your task title" -t task -s todo --body-file /path/to/task.md
beans list --ready
git add -- .beans/<the-generated-task-file>.md
git commit -m "task: describe your task"
cd ~/dev/fugu-drover
fleet-watch enqueue <bean-id>
```

Beans prints the actual generated file and ID. Task records must be committed
on LOCAL main before dispatch; no push is needed. With the watcher stopped you
can use `fleet assign <bean-id> fugu-codex-coder` and `fleet-watch once` instead.
Do not run competing dispatchers or merge the entire setup branches into main.
`beans tui` in the application worktree opens the task board.

## Follow work and land it

Coder -> report + `fleet-done` -> separate Codex reviewer -> CHANGES returns to
the coder, or APPROVE waits for you. Inspect actual reports and named commits.

```sh
fleet read fugu-codex-coder 40
fleet read fugu-codex-reviewer 40
fleet-scoreboard
tail -f ~/.local/share/drover/watch/watch.log
ls ~/.local/share/drover/reports
```

The human handles blockers in `~/.local/share/drover/watch/state/blocked` when
that file exists. Native permission prompts remain human decisions.
After reviewing an APPROVE / LANDABLE: YES verdict on the current commit:

```sh
touch ~/.local/share/drover/watch/state/finish-first
fleet-land-bean <bean-id>
fleet-verify-main
```

Landing targets LOCAL application main and never pushes. The gates include the
framework boundary, frontend build/lint and Python checks. The Python environment
is shared; every configured Python command supplies `PYTHONPATH="$PWD/src:$PWD"`
and `uv run --no-sync`, so imports select the current worktree. Do not sync or
modify shared dependencies without an assignment. No secrets or live database
WAL/SHM state were copied. A committed database snapshot is present in Git.

Inspect code deletions before landing: Drover does not implement its documented
deletion gate. If verification is red, fix it before pushing. When you explicitly
want to push the verified application commits, use `fleet-push`; it verifies
main first and never force pushes. Coordinate with the existing OpenRig lead
because both repositories target Fugu's GitHub origin. Migrations/deployments
are separate explicit tasks. Remove `state/finish-first` after integration to
allow new tasks again.

## Keep the boundary

Main permits application code, the shared AGENTS.md restriction, task Markdown
records, and historical evidence. It rejects OpenRig/Drover configuration,
`.beans.yml`, `.agents/`, `.codex/` and related setup files. CI runs on main pushes
and PRs to main. Configuration branches never merge wholesale into main; transfer
only application task commits. Update each setup branch deliberately when main
changes; resolve root policy/setup guidance differences without landing them.

Local Drover patches are saved in `~/dev/drover/local-codex-only.patch` and tested
by `python3 -m unittest discover -s ~/dev/drover/tests -v`. Retain/reapply them
when updating upstream. The compatibility patch does not claim model diversity.
