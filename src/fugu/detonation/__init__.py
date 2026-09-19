"""Stage 3 detonation: run untrusted extension code, capture the blast radius.

Promotes the VALIDATED spike (spikes/001-canary-egress/) into a reusable
driver. See base.py for the DetonationDriver protocol and canary formats,
triggers.py for trigger derivation.
"""
from fugu.detonation.base import DetonationDriver, fresh_canary_env
from fugu.detonation.docker_driver import DockerDriver, evidence_to_findings
from fugu.detonation.triggers import derive_triggers

__all__ = [
    "DetonationDriver",
    "DockerDriver",
    "derive_triggers",
    "evidence_to_findings",
    "fresh_canary_env",
]
