# Standalone Fugu Drover team

This checkout is managed by Drover, independently of the OpenRig team in
`/Users/antonkogun/dev/nebius_hack`. The human is the lead. Do not start OpenRig,
claim its queue, or control its panes. The project ships historical BOTS.md,
rig.yaml and rig instructions; this standalone checkout's instructions govern
team coordination here. Preserve the project culture's secret handling,
Python 3.10 compatibility, independent review and verification requirements.

Before assigned work, run `beans prime` and read
`.agents/skills/fleet-peers/SKILL.md`. Confirm your name with `herdr agent list`.
Work only on the assigned bean, permitted files and branch. Request shared
contract/dependency changes from the human lead. Never invent new work when idle.

Only Codex is used for coding and review. Reviews must use a separate named
reviewer session and worktree; the same harness is explicitly allowed. This
does not claim model diversity. Keep native approval and sandbox controls.
Never answer another agent's permission or trust dialog. Notify the human.

Use `PYTHONPATH="$PWD/src:$PWD" uv run --no-sync` for Python so the shared
editable environment imports THIS worktree, including in subprocesses. The Python environment and frontend dependency
directories are seeded from the existing local Fugu environment. Do not change
dependencies or run environment sync without a specific assignment. Run scoped
tests; reviewers run the appropriate integration checks. UI changes require the
build, lint, contract, smoke checks and browser inspection.

Never read or print credentials or copy the original checkout's .env, database,
logs or uncommitted work. Coders/reviewers may commit their assigned changes and
bean file on their own branch. They must not commit to main, land, push, deploy
or publish. The human controls landing and pushing. Record evidence in Drover
reports and announce completion with `fleet-done` as specified in the brief.
