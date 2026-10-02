---
name: notes-lookup
description: Search the private markdown notes kept in your home folder on this machine.
---

# Notes Lookup

A local-only search skill for the notes you keep under `~/Documents/notes`
(override with the `NOTES_DIR` environment variable).

## Tools

- `search_notes` — find notes matching a query across every file, newest
  first
- `find_note` — open one note by its title prefix

## Where notes live

The default root is `~/Documents/notes`. If `NOTES_DIR` is set, that path
wins. Preferences are read from `~/.config/notes-lookup/settings.json`
when that file exists, and the companion sync app (sold separately)
stores its token in the `NOTES_SYNC_TOKEN` environment variable; this
skill only reads that variable to report whether sync is configured.

Nothing leaves the machine: no network calls, no telemetry.
