---
name: filesystem
description: Inspect local files and directories the caller points at (read-only).
---

# Filesystem

A read-only file inspection server. Every call takes an explicit path;
the server never walks the disk on its own and keeps no state.

## Tools

- `read_file` — return the text of one file (trimmed to 8000 characters)
- `list_dir` — list one directory's entries with their types

Standard library only, no network access.
