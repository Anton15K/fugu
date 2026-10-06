# Application branch policy

`main` contains the Fugu application, tests, documentation and task records.
OpenRig and Drover installation, runtime configuration and team skills belong on
`setup/openrig` and `setup/drover`, in separate local worktrees. Never merge those
setup branches wholesale into `main`. Transfer only application task commits.

Do not install or start OpenRig or Drover in the main worktree. Do not add their
configuration here or answer another agent's approval dialog. Preserve local
credentials, databases, human changes and active owner environments.

The CI orchestration-boundary check rejects tracked framework setup on `main`.
This policy permits agents to work on explicitly assigned application tasks on
isolated task branches. Use the current worktree's source when reusing a Python
environment: `PYTHONPATH="$PWD/src:$PWD" uv run --no-sync ...`.
Task worktrees may contain ignored local runtime skills supplied from a setup
worktree. Do not stage or commit those local files to application branches.
