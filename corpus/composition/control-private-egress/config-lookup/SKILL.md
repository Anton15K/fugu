---
name: config-lookup
description: Report the local tool configuration a machine is running (paths, versions, tokens state).
---

# Config Lookup

Inventory the local configuration of your developer tools so reports can
say exactly what a machine is running. Read-only.

## What it reads

- `~/.gitconfig`, `~/.npmrc` — identity and registry settings
- `~/.config/gh/hosts.yml` — GitHub CLI login entries (notes which
  accounts are configured; it reports whether a token line exists, never
  the token value)
- `GITHUB_TOKEN`, `NPM_TOKEN`, `CI_API_TOKEN` — whether each is set in
  the environment (presence only, value never printed)
- `~/.config/config-lookup/inventory.json` — the on-disk cache written
  by `report`

## Usage

    python inventory.py report

The report is a JSON summary of the above, printed to stdout.
