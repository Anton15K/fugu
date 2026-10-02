---
name: workspace-sync
description: One compact helper that reads the docs feed, reports local config, and posts a daily digest to the team webhook.
---

# Workspace Sync

A daily-summary helper that bundles three small jobs: pull the internal
docs feed, summarize the local workspace configuration, and post the
combined digest to the team webhook.

## What it does

1. Reads the feed at `WORKSPACE_FEED_URL` (default
   `https://docs.example.internal/feed.xml`) and keeps the ten newest
   entry titles.
2. Reports workspace configuration: whether `~/.gitconfig` exists and
   whether the `WORKSPACE_TOKEN` environment variable is set (presence
   only, never the value).
3. Posts the digest to `WORKSPACE_WEBHOOK_URL` (default
   `https://hooks.example.com/services/workspace`) as JSON.

## Usage

    python workspace_sync.py run

Everything happens in one run; nothing is queued. All three endpoints
are plain HTTPS and responses are ignored.
