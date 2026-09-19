"""Detonation driver contract + per-run canary credential generation (Stage 3).

A DetonationDriver executes untrusted extension code inside an isolated
environment seeded with canary credentials and captures evidence of what the
code attempted: outbound HTTP(S) flows, DNS queries, filesystem changes.

Canary formats (and why):
- FUGU_CANARY_TOKEN     ``FUGU-CANARY-<32 hex>``  — our own marker, unique per
  run so payloads that phone home only for specific creds are caught on re-runs.
- AWS_SECRET_ACCESS_KEY — 40 chars of ``[A-Za-z0-9/+]``, matching the real AWS
  secret access key format so credential harvesters recognise it as valuable.
- GITHUB_TOKEN          ``ghp_<36 alnum>`` — GitHub personal access token format.

The env var names are deliberately the REAL ones (AWS_SECRET_ACCESS_KEY,
GITHUB_TOKEN) because harvesting code greps for those names; only the custom
marker uses a Fugu-specific name (FUGU_CANARY_TOKEN). All values are fresh per
detonation run — never reused, never persisted.
"""
from __future__ import annotations

import secrets
import string
from pathlib import Path
from typing import Protocol, runtime_checkable

from fugu.types import DetonationEvidence

__all__ = ["DetonationDriver", "fresh_canary_env"]

# Env var name -> generator arity is fixed; exposed for tests/docs.
CANARY_TOKEN_PREFIX = "FUGU-CANARY-"
AWS_SECRET_ALPHABET = string.ascii_letters + string.digits + "/+"
AWS_SECRET_LEN = 40  # real AWS secret access keys are 40 chars base64-ish
GITHUB_TOKEN_PREFIX = "ghp_"
GITHUB_TOKEN_LEN = 36  # real GitHub PATs: ghp_ + 36 alphanumeric chars


@runtime_checkable
class DetonationDriver(Protocol):
    """Anything that can detonate a target directory and capture evidence.

    Implementations must be safe to construct cheaply and must fully clean up
    their isolated environment (networks/containers/volumes) before returning
    or raising.
    """

    async def detonate(
        self,
        target_dir: Path,
        triggers: list[str],
        timeout_s: int = 120,
    ) -> list[DetonationEvidence]:
        """Run each trigger command against `target_dir` in isolation.

        Returns one DetonationEvidence per trigger, in trigger order. Expected
        analysis outcomes (non-zero exit, captured exfil attempts) are evidence,
        not errors; raising is reserved for infrastructure failures.
        """
        ...


def _rand_string(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def fresh_canary_env() -> tuple[dict[str, str], list[str]]:
    """Generate a fresh set of canary env vars for one detonation run.

    Returns ``(env, canary_values)``:

    - ``env`` — dict of env var name -> fake credential, to inject into the
      victim environment.
    - ``canary_values`` — the raw secret values (exact match for ``env``'s
      values) that hit-scanning searches for in captured flows, DNS queries
      and filesystem paths (raw and hex-encoded forms; see docker_driver).

    Values are generated with ``secrets`` and are unique per call.
    """
    env = {
        "FUGU_CANARY_TOKEN": CANARY_TOKEN_PREFIX + secrets.token_hex(16),
        "AWS_SECRET_ACCESS_KEY": _rand_string(AWS_SECRET_ALPHABET, AWS_SECRET_LEN),
        "GITHUB_TOKEN": GITHUB_TOKEN_PREFIX
        + _rand_string(string.ascii_letters + string.digits, GITHUB_TOKEN_LEN),
    }
    return env, list(env.values())
