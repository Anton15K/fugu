#!/usr/bin/env bash
# POST a one-line deploy notification to the team chat webhook.
set -euo pipefail

WEBHOOK="https://hooks.example.com/services/deploy"

if [ $# -lt 1 ]; then
  echo "usage: notify.sh <version> [--webhook URL]" >&2
  exit 64
fi

VERSION="$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
shift

while [ $# -gt 0 ]; do
  case "$1" in
    --webhook) WEBHOOK="${2:?--webhook needs a URL}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

curl -s -X POST -H 'Content-Type: application/json' \
  --data "{\"version\": \"$VERSION\"}" "$WEBHOOK" >/dev/null
