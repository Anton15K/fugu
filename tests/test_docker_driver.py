"""End-to-end + unit tests for the Docker detonation driver.

Docker-dependent tests are skipped when the daemon is unreachable (CI without
docker). The end-to-end test detonates the corpus-style malicious install.sh
fixture (curl POST of the canary env var to a dead domain + nslookup
hex-subdomain), asserts canary hits / flows / dns / fs_changes, and asserts
full cleanup (no containers or networks left with the fugu-det- prefix).

Run: uv run --no-sync pytest tests/test_docker_driver.py -q
(slow on first run — builds python:3.11-slim-derived images; ~1-2 min)
"""
from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fugu.detonation.base import (  # noqa: E402
    DetonationDriver,
    fresh_canary_env,
)
from fugu.detonation.docker_driver import (  # noqa: E402
    DockerDriver,
    evidence_to_findings,
    scan_for_canaries,
)
from fugu.detonation.triggers import derive_triggers  # noqa: E402
from fugu.types import DetonationEvidence, DnsRecord, FlowRecord  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "malicious_ext"
NET_PREFIX = "fugu-det-"

HEX32 = re.compile(r"^[0-9a-f]{32}$")
AWS_RE = re.compile(r"^[A-Za-z0-9/+]{40}$")
GHP_RE = re.compile(r"^ghp_[A-Za-z0-9]{36}$")


def docker_available() -> bool:
    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=15,
        )
        return r.returncode == 0 and bool(r.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


DOCKER_UP = docker_available()
requires_docker = pytest.mark.skipif(not DOCKER_UP, reason="docker daemon unreachable")


def _list_by_prefix(kind: str, prefix: str) -> list[str]:
    """`docker ps -a --format name` or `docker network ls` filtered by prefix."""
    cmd = (
        ["docker", "ps", "-a", "--format", "{{.Names}}"]
        if kind == "container"
        else ["docker", "network", "ls", "--format", "{{.Name}}"]
    )
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return [n for n in r.stdout.split() if n.startswith(prefix)]


# --------------------------------------------------------------------------- canaries
def test_fresh_canary_env_formats():
    env, values = fresh_canary_env()
    assert set(env) == {"FUGU_CANARY_TOKEN", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"}
    tok = env["FUGU_CANARY_TOKEN"]
    assert tok.startswith("FUGU-CANARY-") and HEX32.fullmatch(tok[len("FUGU-CANARY-"):])
    assert AWS_RE.fullmatch(env["AWS_SECRET_ACCESS_KEY"]), "AWS secret format (40 b64ish)"
    ghp = env["GITHUB_TOKEN"]
    assert GHP_RE.fullmatch(ghp), "ghp_ + 36 alnum"
    # values list matches env exactly, for hit-scanning
    assert sorted(values) == sorted(env.values())


def test_fresh_canary_env_unique_per_call():
    a_env, _ = fresh_canary_env()
    b_env, _ = fresh_canary_env()
    assert a_env != b_env, "canaries must be fresh per run"


def test_driver_satisfies_protocol():
    assert isinstance(DockerDriver(), DetonationDriver)


# --------------------------------------------------------------------------- scanning
def test_scan_for_canaries_hex_dns():
    _, values = fresh_canary_env()
    tok = values[0]
    hx = tok.encode().hex()
    flows = [FlowRecord(host="webhook.example-attacker.test", method="POST",
                        path="/collect", body=f'{{"token": "{tok}"}}')]
    dns = [DnsRecord(query=hx[:30] + ".exfil.example-attacker.test")]
    fs = [f"A /tmp/.fugu_ext_cache_{values[1][:8]}"]
    hits = scan_for_canaries(values, flows=flows, dns=dns, fs_changes=fs)
    vectors = {h.meta["vector"] for h in hits}
    assert vectors == {"http", "dns"}  # fs line has no full canary value
    assert all(len(h.excerpt) <= 500 for h in hits)
    assert any(h.source.startswith("dns.query[") for h in hits)
    assert any(h.source.startswith("mitm.flow[") for h in hits)


def test_scan_for_canaries_none_when_clean():
    _, values = fresh_canary_env()
    flows = [FlowRecord(host="api.vendor.test", method="GET", path="/v1/ping")]
    dns = [DnsRecord(query="api.vendor.test")]
    assert scan_for_canaries(values, flows=flows, dns=dns, fs_changes=[]) == []


def test_evidence_to_findings_mapping():
    _, values = fresh_canary_env()
    tok = values[0]
    ev = DetonationEvidence(
        trigger="bash install.sh", exit_code=0, duration_s=0.5,
        flows=[FlowRecord(host="webhook.example-attacker.test", method="POST",
                          path="/collect", body=tok)],
        dns=[DnsRecord(query=tok.encode().hex()[:30] + ".exfil.example-attacker.test")],
        canary_hits=scan_for_canaries(
            values,
            flows=[FlowRecord(host="h", method="POST", path="/c", body=tok)],
            dns=[DnsRecord(query=tok.encode().hex()[:30] + ".x.test")],
            fs_changes=[],
        ),
    )
    (fnd,) = evidence_to_findings(ev)
    assert set(fnd.owasp_ids) == {"LLM02", "MCP01"}
    assert fnd.severity == "critical" and fnd.confidence == "deterministic"
    assert fnd.stage == "detonation" and fnd.evidence


def test_evidence_to_findings_unexpected_egress():
    ev = DetonationEvidence(
        trigger="import pkg", exit_code=0, duration_s=0.1,
        flows=[FlowRecord(host="api.vendor.test", method="GET", path="/v1/ping")],
        dns=[DnsRecord(query="api.vendor.test")],
    )
    (fnd,) = evidence_to_findings(ev)
    assert set(fnd.owasp_ids) == {"MCP10", "LLM02"}
    assert fnd.confidence == "empirical"


def test_evidence_to_findings_silent_binary():
    ev = DetonationEvidence(trigger="import pkg", exit_code=0, duration_s=0.1)
    assert evidence_to_findings(ev) == []


# --------------------------------------------------------------------------- triggers
def test_derive_triggers_install_sh():
    assert derive_triggers(FIXTURE) == [f"bash {FIXTURE}/install.sh".replace(
        str(FIXTURE), "/opt/target")]


def test_derive_triggers_python_and_npm(tmp_path):
    (tmp_path / "mypkg").mkdir()
    (tmp_path / "mypkg" / "__init__.py").write_text("")
    (tmp_path / "package.json").write_text(
        '{"scripts": {"postinstall": "node setup.js"}}'
    )
    got = derive_triggers(tmp_path)
    assert "npm install --prefix /opt/target" in got
    assert 'python -c "import mypkg"' in got


# --------------------------------------------------------------------------- e2e
@requires_docker
def test_detonate_malicious_fixture_end_to_end():
    left = _list_by_prefix("container", NET_PREFIX)
    assert not left, f"pre-existing fugu-det containers would pollute: {left}"

    driver = DockerDriver()
    evidence = asyncio.run(driver.detonate(FIXTURE, ["bash /opt/target/install.sh"],
                                           timeout_s=90))

    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.trigger == "bash /opt/target/install.sh"
    assert ev.exit_code == 0  # malicious install "succeeds" — that's the point

    # flows captured: https POST + plain http GET through the mitm proxy
    hosts = {f.host for f in ev.flows}
    assert any("webhook.example-attacker.test" in h for h in hosts), hosts
    assert any("plain.example-attacker.test" in h for h in hosts), hosts

    # dns captured: hex-subdomain exfil queries
    assert any(".exfil.example-attacker.test" in d.query for d in ev.dns), \
        [d.query for d in ev.dns][:10]

    # fs telemetry: the fixture writes /tmp/.fugu_ext_cache and state.json
    assert any(".fugu_ext_cache" in c for c in ev.fs_changes), ev.fs_changes[:10]
    assert any("fugu-test/state.json" in c for c in ev.fs_changes)

    # canary hits: at least one http (body/url) and one dns (hex) vector
    vectors = {h.meta.get("vector") for h in ev.canary_hits}
    assert "http" in vectors and "dns" in vectors, vectors
    assert all(len(h.excerpt) <= 500 for h in ev.canary_hits)

    # findings: exfil -> LLM02+MCP01 critical deterministic; fs hit -> MCP01
    findings = evidence_to_findings(ev)
    exfil = [f for f in findings if "LLM02" in f.owasp_ids and "MCP01" in f.owasp_ids]
    assert exfil and exfil[0].severity == "critical"
    fsf = [f for f in findings if f.title.startswith("Canary credential persisted")]
    assert fsf, "fixture writes canary to /tmp/.fugu_ext_cache -> fs hit expected"

    # ---- cleanup: no containers/networks with our prefix remain -------------
    assert _list_by_prefix("container", NET_PREFIX) == []
    assert _list_by_prefix("network", NET_PREFIX) == []


@requires_docker
def test_detonate_clean_target_no_canary_hits(tmp_path):
    (tmp_path / "hello.py").write_text("print('hello')\n")
    driver = DockerDriver()
    evidence = asyncio.run(driver.detonate(tmp_path, ['python /opt/target/hello.py'],
                                           timeout_s=90))
    (ev,) = evidence
    assert ev.exit_code == 0
    assert ev.canary_hits == []
    assert ev.flows == [] and ev.dns == []
    assert evidence_to_findings(ev) == []
    assert _list_by_prefix("container", NET_PREFIX) == []
    assert _list_by_prefix("network", NET_PREFIX) == []
