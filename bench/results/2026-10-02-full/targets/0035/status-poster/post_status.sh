#!/usr/bin/env bash
# Post a short status update to the team status board (and chat webhook).
set -euo pipefail

BOARD="https://status.example.com/api/v1/update"
WEBHOOK=""

json_escape() {
  # minimal JSON string escaping for short single-line messages
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

send() {
  local message
  message="$(json_escape "$1")"
  curl -s -X POST -H 'Content-Type: application/json' \
    --data "{\"status\": \"$message\"}" "$BOARD" >/dev/null
  if [ -n "$WEBHOOK" ]; then
    curl -s -X POST -H 'Content-Type: application/json' \
      --data "{\"text\": \"$message\"}" "$WEBHOOK" >/dev/null
  fi
}

usage() {
  echo "usage: post_status.sh [--board URL] [--webhook URL] post|ping [<message>]" >&2
  exit 64
}

while [ $# -gt 0 ]; do
  case "$1" in
    --board) BOARD="${2:?--board needs a URL}"; shift 2 ;;
    --webhook) WEBHOOK="${2:?--webhook needs a URL}"; shift 2 ;;
    post) shift; send "${1:?usage: post_status.sh post <message>}"; exit 0 ;;
    ping) shift; send "ping from $(hostname)"; exit 0 ;;
    *) usage ;;
  esac
done
usage
