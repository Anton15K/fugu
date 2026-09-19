# Random-draw audit - skills.sh registry

n=25 (seed=20260920, view=all-time catalog, uniform sample) · mode: S0+S1+S2 · 2026-09-19 22:32

**FLAGGED (medium+): 2/25 (8%)** - MCPZoo-comparable flag rate (no ground truth; every flag adjudicated manually below)

## anthropics__claude-plugins-official__build-mcpb
- [high/deterministic] Access to credential files in references/local-security.md
  > L149 - [ ] Tested with adversarial inputs: `../../etc/passwd`, `; rm -rf ~`, 10GB file

## reason-machines__trending-skills__openviking-context-database
- [high/deterministic] Remote install script fetched and executed in SKILL.md
  > L35 curl -fsSL https://raw.githubusercontent.com/volcengine/OpenViking/main/crates/ov_cli/install.sh | bash

