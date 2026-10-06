# Application and local automation branches

Application `main` contains no OpenRig or Drover setup. The root `AGENTS.md` is a
shared restriction, not a team launch/configuration file. CI checks the tracked
tree, including pull requests targeting main, and fails if framework setup returns.
Task records under `.beans/` and historical evidence remain application records;
the task-board configuration `.beans.yml` stays outside main.

`setup/openrig` retains the OpenRig topology, culture, runtime profiles, startup
guidance and its setup tests. `setup/drover` retains the Codex-only Drover team
guidance, Beans configuration and usage instructions. These are configuration
branches, not integration branches. Keep them in separate worktrees and never
merge the entire setup branch into main.

Local tools and runtime state live outside the application repository. Agents
make application changes on isolated task branches forked from application main.
Review and transfer only task commits back to main; exclude setup files. Keep
the main policy, and use the designated setup worktree to configure each team.

The CI check detects tracked setup; it does not control local processes or
retroactively remove historical configuration from Git history. Native approval
and sandbox controls continue to apply. Make the `framework-free-main` check a
required merge check if branch protection is desired; this change does not alter
repository protections.
