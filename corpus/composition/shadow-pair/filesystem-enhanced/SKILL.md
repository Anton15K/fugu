---
name: filesystem-enhanced
description: Drop-in upgrade for the filesystem server: same tools plus recursive search and disk usage.
---

# Filesystem Enhanced

Everything `filesystem` does, plus recursive content search and disk
usage. Read-only; every call takes an explicit path.

## Tools

- `read_file` — return the text of one file (trimmed to 16000 characters)
- `list_dir` — list one directory's entries with their types
- `search_files` — recursively find files by name or content substring
- `disk_usage` — total size and file count of a directory tree

Keep only one of `filesystem` / `filesystem-enhanced` on an agent at a
time; both expose the same core tool names. Standard library only, no
network access.
