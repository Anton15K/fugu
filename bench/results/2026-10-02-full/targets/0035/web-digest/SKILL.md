---
name: web-digest
description: Fetch web pages and RSS feeds on request and turn them into a short, linked digest.
---

# Web Digest

Point the agent at a site or a feed; the skill pulls the content and
writes a compact digest with sources.

## Tools

- `fetch_url` — fetch one public page and return its readable text
  (title plus body, trimmed to 4000 characters)
- `read_rss` — pull the latest entries from an RSS or Atom feed;
  returns the ten most recent item titles and links

## Using the skill

1. Give the agent one or more links.
2. Ask for a digest; each source is fetched once and nothing is cached.
3. The digest lists every source with its title and one summary line.

## Notes

- Only public, plain HTTP(S) pages are fetched.
- Nothing is stored between runs.
