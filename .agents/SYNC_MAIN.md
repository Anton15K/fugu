# Preserve setup when syncing application main

This procedure applies only to `setup/openrig` and `setup/drover`. Application
`main` deliberately removed the framework setup. An ordinary first merge of
main can therefore delete setup files. Use the helper below for every sync;
do not use raw `git pull`, merge, or rebase to update a setup branch from main.
Only the lead/operator or an agent assigned Git ownership performs this work.
Keep other writers idle, and never alter the active original OpenRig checkout.

## Sync procedure

1. Confirm the intended setup worktree and branch with `git status -sb`.
   Commit your assigned changes first. Leave unrelated owner changes alone;
   the helper refuses dirty tracked or untracked files and never stashes them.
2. Run from that setup worktree:

   ```sh
   python3 .agents/sync_main.py
   ```

   It fetches `origin main`, records a backup ref and the pre-merge commit,
   and merges the fetched commit without committing. It restores setup files
   from the pre-merge commit and verifies their modes and contents in the index
   and worktree. It does not start or control agents, push, or modify main.
   `--no-fetch` uses local main for offline verification; normal updates fetch.
3. If application files conflict, resolve those files manually and stage only
   their explicit paths. Keep the restored setup unchanged. Do not use a blanket
   `-X ours` strategy: application updates must still be integrated. To cancel,
   use `git merge --abort` while this merge is in progress; the printed backup
   ref also retains the original commit. Do not reset or stash owner changes.
4. Review `git diff --cached` and `git status`. The helper keeps the branch's
   root `AGENTS.md`, so read any relevant new application policy from
   `git show MERGE_HEAD:AGENTS.md` and incorporate compatible requirements
   deliberately without replacing this branch's setup guidance.
5. Run the helper regression tests:

   ```sh
   python3 -m unittest discover -s .agents/tests -p test_sync_main.py -v
   ```

   On the prepared `setup/openrig` worktree, also run its setup checks using
   the existing shared environment and the correct worktree imports:

   ```sh
   PYTHONPATH="$PWD/src:$PWD" VIRTUAL_ENV=/Users/antonkogun/dev/nebius_hack/.venv uv run --no-sync --active python -m pytest tests/test_rig_setup.py -q
   ```

   Run additional application checks appropriate to the imported changes.
   Obtain independent review where the team's rules require it. After review,
   finish with `git commit -m "chore: sync main while preserving agent setup"`.
   Push the setup branch only when authorized; never push it as main.

## Protected setup

The helper preserves the pre-merge versions of:

- Root `AGENTS.md`, `BOTS.md`, `tests/test_rig_setup.py`, and `docs/DROVER.md`.
- Root `rig/`, `openrig/`, `drover/`, `.openrig/`, `.drover/`, `.agents/`, `.codex/`.
- Nested `.openrig/`, `.drover/`, `.agents/`, and `.codex/` directories.
- Files named `rig.yaml`, `rig.yml`, `drover.yaml`, `drover.yml`, `drover.config`,
  `.beans.yml`, or `.beans.yaml`, wherever they appear.

That includes this guide, the helper, and its tests. Add new setup paths to the
helper and its tests before syncing if they fall outside this inventory.
`.beans/*.md` task records are application records and merge normally; they
are not frozen by this procedure. External runtime configuration and credentials
stay outside Git. Never copy secrets or live database state during a sync.

Setup branches are configuration branches, not application integration branches.
Product tasks start from application main; transfer only their application
commits back to main. Never merge a setup branch wholesale into main. Main's
required `framework-free-main` CI check rejects tracked framework setup.

Git does not enforce these rules on arbitrary commands. Agents must follow
`AGENTS.md` and use this helper; a raw merge can still discard setup.
