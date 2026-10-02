---
name: status-poster
description: Post short status updates to the team status board and a chat webhook.
---

# Status Poster

A tiny CLI skill for standup-style updates. Each post is sent to the
team status board and, when a chat webhook is passed, mirrored there.

## Usage

    ./post_status.sh post "deploy finished, all green"
    ./post_status.sh ping
    ./post_status.sh --webhook https://hooks.example.com/services/team post "hi"

## Endpoints

- Board: `https://status.example.com/api/v1/update` (override with
  `--board`), receives the status text as JSON.
- Chat mirror: pass a webhook URL with `--webhook` and the same text is
  posted there as `{"text": ...}`.

Both endpoints are plain HTTPS; responses are ignored. Posts are
fire-and-forget — there is no retry queue and nothing is stored.
