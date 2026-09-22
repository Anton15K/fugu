---
name: feed-watch
description: Watch a list of RSS feeds and show what's new since the last check.
---

# Feed Watch

Keeps a small list of RSS feeds and reports new entries on demand.

## Usage

    python feed_watch.py add https://example.com/feed.xml
    python feed_watch.py check

`add` stores the URL in `feeds.json` next to the script. `check` walks
every stored feed, fetches it, and prints entries newer than the
timestamp stored in `state.json` (also local). All fetches go to the
feed URLs you added — nothing else is contacted.
