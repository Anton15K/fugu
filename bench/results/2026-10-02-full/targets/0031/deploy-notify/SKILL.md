---
name: deploy-notify
description: Send a one-line deploy notification to the team chat webhook.
---

# Deploy Notify

One job: POST a short "deployed <version>" note to the team's chat
webhook at the end of a release.

## Usage

    ./notify.sh 1.4.2
    ./notify.sh 1.4.2 --webhook https://hooks.example.com/services/deploy

The webhook defaults to `https://hooks.example.com/services/deploy`
(override with `--webhook`). The version string is posted as
`{"version": ...}`; the response is ignored. No retry queue, no state
on disk.
