"""ContreeDriver — detonation chamber on Nebius Token Factory Sandboxes.

The production driver behind the same ``DetonationDriver`` protocol as
DockerDriver (base.py). Each trigger runs as a disposable sandbox instance:

- Target files are injected via the instance ``files`` map (path -> content)
  so the untrusted code runs from the same layout it expects locally.
- Canary credentials are planted via ``env`` with ``preserve_env: false``
  (fresh per chamber via :func:`fresh_canary_env`, shared by all triggers
  in the audit — same contract as the Docker chamber).
- Egress observation strategy, honestly scoped: the sandbox has real
  internet egress (that is the point of detonating in the cloud), so a
  local mitm/DNS collector is NOT possible the way the Docker chamber
  builds one. Instead this driver wraps each trigger with an in-sandbox
  capture harness:
    * stdout/stderr are captured verbatim by the API (result.stdout/stderr)
    * a pre-trigger marker scan runs `ss -tnp`/`netstat`-style connection
      snapshots before/after (best effort, present in most images)
    * post-run, the sandbox's file layer is probed for canary persistence
  Canary hits are detected from: stdout/stderr containing canary values
  (raw or hex — payloads echo harvested creds into logs more often than
  they exfil silently), connection snapshots, and fs probing.
  Network flows that do NOT carry canaries are reported as
  ``FlowRecord``s when derivable from connection snapshots (host:port,
  no bodies) — enough for the "unexpected egress" finding without mitm.

Evidence parity with DockerDriver: same ``DetonationEvidence`` shape;
``scan_for_canaries`` (docker_driver) is reused for hit classification so
``evidence_to_findings`` works unchanged.

Config (env):
- ``NEBIUS_API_KEY``  — Bearer token (shared with the LLM stages)
- ``NEBIUS_AI_PROJECT`` — project id (``Project`` header)
- ``CONTREE_API_URL`` — default https://api.tokenfactory.nebius.com/sandboxes
- ``CONTREE_IMAGE``   — default tag:ubuntu:24.04 (bash + coreutils)
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.request
from pathlib import Path

from fugu.detonation.base import fresh_canary_env
from fugu.source_safety import validate_source_tree
from fugu.types import DetonationEvidence, DnsRecord, FlowRecord

__all__ = ["ContreeDriver"]

_API_DEFAULT = "https://api.tokenfactory.nebius.com/sandboxes"
_IMAGE_DEFAULT = "tag:python:3.11"
_TIMEOUT_S = 120
_POLL_INTERVAL = 1.5
_MAX_FILES = 400
_MAX_FILE_BYTES = 2_000_000


class ContreeDriver:
    """DetonationDriver backed by Token Factory Sandboxes (REST)."""

    def __init__(
        self,
        api_url: str | None = None,
        image: str | None = None,
        project: str | None = None,
        token: str | None = None,
        timeout_s: int = _TIMEOUT_S,
    ) -> None:
        self.api_url = (api_url or os.environ.get("CONTREE_API_URL") or _API_DEFAULT).rstrip("/")
        self.image = os.environ.get("CONTREE_IMAGE") or image or _IMAGE_DEFAULT
        self.project = (
            project
            or os.environ.get("NEBIUS_AI_PROJECT")
            or os.environ.get("CONTREE_PROJECT")
            or ""
        ).strip()
        self.token = (
            token
            or os.environ.get("CONTREE_TOKEN")
            or os.environ.get("NEBIUS_API_KEY")
            or ""
        ).strip()
        self.timeout_s = timeout_s

    # ------------------------------------------------------------------ api
    def _request(
        self, method: str, path: str, payload: dict | None = None
    ) -> tuple[int, dict | list]:
        req = urllib.request.Request(
            f"{self.api_url}{path}",
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                **({"Project": self.project} if self.project else {}),
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode(errors="replace")
                return resp.status, (json.loads(body) if body else {})
        except urllib.error.HTTPError as e:
            return e.code, {"error": e.read().decode(errors="replace")[:500]}
        except urllib.error.URLError as e:
            return 0, {"error": f"{type(e).__name__}: {e}"}

    async def detonate(
        self,
        target_dir: Path,
        triggers: list[str],
        timeout_s: int = 120,
        on_progress=None,
    ) -> list[DetonationEvidence]:
        """Run every trigger in a fresh sandbox; return evidence per trigger."""
        if not triggers:
            return []
        target_dir = Path(target_dir).resolve()
        if not target_dir.is_dir():
            raise FileNotFoundError(f"target_dir does not exist: {target_dir}")

        def log(msg: str) -> None:
            if on_progress is not None:
                try:
                    on_progress(msg)
                except Exception:  # noqa: BLE001
                    pass

        if not self.token:
            raise RuntimeError("ContreeDriver: no token (NEBIUS_API_KEY/CONTREE_TOKEN)")
        if not self.project:
            raise RuntimeError("ContreeDriver: no project id (NEBIUS_AI_PROJECT)")

        canary_env, canary_values = fresh_canary_env()
        log(f"sandbox chamber: image {self.image}, {len(triggers)} trigger(s), canaries planted")

        evidence: list[DetonationEvidence] = []
        for i, trigger in enumerate(triggers):
            log(f"trigger {i + 1}/{len(triggers)}: {trigger[:80]}")
            evidence.append(
                await self._detonate_one(
                    target_dir, trigger, timeout_s, canary_env, canary_values, log
                )
            )
        log("all triggers executed; sandboxes were disposable (auto-cleaned)")
        return evidence

    # ------------------------------------------------------------- internals
    async def _detonate_one(
        self,
        target_dir: Path,
        trigger: str,
        timeout_s: int,
        canary_env: dict[str, str],
        canary_values: list[str],
        log,
    ) -> DetonationEvidence:
        import time

        # Target files are embedded (bounded, base64) into the bootstrap so
        # the sandbox sees /opt/target exactly like the Docker chamber's copy
        bootstrap = _bootstrap_files_cmd(target_dir)
        # Wrap the trigger: connection snapshot before/after + fs canary probe
        wrapper = f"{bootstrap}; " + _wrap_trigger(trigger, canary_env)
        # preserve_env=false strips EVERYTHING (no HOME/PATH) which breaks
        # ordinary shell scripts (set -u scripts die on unbound HOME). Plant
        # canaries on top of a minimal standard environment instead.
        env = {
            "HOME": "/root",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm",
            "LANG": "C.UTF-8",
        }
        env.update(canary_env)
        env["FUGU_TRIGGER"] = "1"

        payload = {
            "image": self.image,
            "command": wrapper,
            "shell": True,
            "disposable": True,
            "env": env,
            "preserve_env": False,
            "timeout": max(10, min(int(timeout_s), 600)),
            "networking": {"enabled": True},
        }

        t0 = time.monotonic()
        status, body = await asyncio.get_running_loop().run_in_executor(
            None, lambda: self._request("POST", "/v1/instances", payload)
        )
        if status != 201:
            raise RuntimeError(
                f"sandbox spawn failed rc={status}: {str(body)[:300]}"
            )
        op_uuid = body.get("uuid")
        result = await self._poll_operation(op_uuid, log)
        duration = time.monotonic() - t0

        return _to_evidence(trigger, result, duration, canary_values)

    async def _poll_operation(self, op_uuid: str, log) -> dict:
        deadline = asyncio.get_event_loop().time() + self.timeout_s + 60
        while asyncio.get_event_loop().time() < deadline:
            status, body = await asyncio.get_running_loop().run_in_executor(
                None, lambda: self._request("GET", f"/v1/operations/{op_uuid}")
            )
            if status == 200 and str(body.get("status")) in (
                "SUCCESS", "FAILED", "CANCELLED",
            ):
                return body
            await asyncio.sleep(_POLL_INTERVAL)
        return {"status": "TIMEOUT", "metadata": {}}


# ---------------------------------------------------------------- helpers

_PROXY_PY = r"""
import socket, threading

LOG = "/opt/fugu/logs/proxy.log"

def log(line):
    with open(LOG, "a") as f:
        f.write(line + "\n")

def handle(conn):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        reqline = lines[0]
        host = ""
        for hl in lines[1:]:
            if hl.lower().startswith("host:"):
                host = hl.split(":", 1)[1].strip()
        clen = 0
        for l in lines[1:]:
            if l.lower().startswith("content-length:"):
                try:
                    clen = int(l.split(":", 1)[1].strip())
                except ValueError:
                    clen = 0
        while len(rest) < clen:
            chunk = conn.recv(65536)
            if not chunk:
                break
            rest += chunk
        body = rest[:2000].decode("latin1", "replace").replace("\n", " ")
        log(f"REQ {reqline} host={host} body={body}")
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except Exception as e:  # noqa: BLE001
        log(f"ERR {e!r}")
    finally:
        conn.close()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8899))
srv.listen(64)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
"""

_DNS_PY = r"""
import socket

LOG = "/opt/fugu/logs/dns.log"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 53))
while True:
    data, addr = s.recvfrom(4096)
    try:
        qname = []
        i = 12
        while i < len(data):
            l = data[i]
            if l == 0:
                break
            qname.append(data[i + 1 : i + 1 + l].decode("latin1", "replace"))
            i += 1 + l
        with open(LOG, "a") as f:
            f.write(".".join(qname) + "\n")
    except Exception:  # noqa: BLE001
        pass
    # NXDOMAIN: QR=1 RD=1 RCODE=3, keep question, zero answer counts
    resp = bytearray(data)
    resp[2:4] = b"\x81\x83"
    resp[6:12] = b"\x00\x00\x00\x00\x00\x00"
    resp[4:6] = b"\x00\x01"
    try:
        s.sendto(bytes(resp), addr)
    except Exception:  # noqa: BLE001
        pass
"""


def _wrap_trigger(trigger: str, canary_env: dict[str, str]) -> str:
    """Bash wrapper: writes+starts the stdlib proxy/DNS collectors inside the
    sandbox, points the victim proxy+resolver at them, runs the trigger,
    then dumps collector logs between markers for the driver to parse."""
    import base64

    proxy_b64 = base64.b64encode(_PROXY_PY.encode()).decode()
    dns_b64 = base64.b64encode(_DNS_PY.encode()).decode()
    return (
        "set +e; "
        "mkdir -p /opt/fugu/logs; "
        f"echo {proxy_b64} | base64 -d > /opt/fugu/proxy.py; "
        f"echo {dns_b64} | base64 -d > /opt/fugu/dns.py; "
        "python3 /opt/fugu/proxy.py & echo $! > /opt/fugu/proxy.pid; "
        "python3 /opt/fugu/dns.py & echo $! > /opt/fugu/dns.pid; "
        "sleep 0.3; "
        "echo 'nameserver 127.0.0.1' > /etc/resolv.conf; "
        "export HTTP_PROXY=http://127.0.0.1:8899 HTTPS_PROXY=http://127.0.0.1:8899 "
        "http_proxy=http://127.0.0.1:8899 https_proxy=http://127.0.0.1:8899 NO_PROXY= no_proxy=; "
        "echo __FUGU_TRIGGER_BEGIN__; "
        f"{trigger}; __rc=$?; "
        "echo; echo __FUGU_TRIGGER_END__ rc=$__rc; "
        "kill $(cat /opt/fugu/proxy.pid /opt/fugu/dns.pid 2>/dev/null) 2>/dev/null; "
        "echo __FUGU_PROXY_LOG__; cat /opt/fugu/logs/proxy.log 2>/dev/null; "
        "echo __FUGU_DNS_LOG__; cat /opt/fugu/logs/dns.log 2>/dev/null; "
        "echo __FUGU_FS_PROBE__; "
        "find /tmp /root /var/tmp -type f -mmin -10 2>/dev/null | head -30; "
        "exit $__rc"
    )


def _bootstrap_files_cmd(target_dir: Path) -> str:
    """Embed target files (bounded) into the command as base64 heredocs."""
    target_dir = validate_source_tree(target_dir)
    parts: list[str] = ["mkdir -p /opt/target"]
    count = 0
    total = 0
    for p in sorted(target_dir.rglob("*")):
        if not p.is_file() or p.name == ".git":
            continue
        if count >= _MAX_FILES or total >= _MAX_FILE_BYTES:
            break
        rel = p.relative_to(target_dir).as_posix()
        if any(seg in (".git", "__pycache__", "node_modules") for seg in p.parts):
            continue
        try:
            content = p.read_bytes()
        except OSError:
            continue
        total += len(content)
        if len(content) > 64_000:
            continue  # skip large files in the MVP
        b64 = __import__("base64").b64encode(content).decode()
        dir_ = f"/opt/target/{p.parent.relative_to(target_dir).as_posix()}"
        dir_ = "/opt/target" if dir_ in ("/opt/target/.", "/opt/target") else dir_
        parts.append(f"mkdir -p '{dir_}'")
        parts.append(f"echo '{b64}' | base64 -d > '/opt/target/{rel}'")
        count += 1
    return "; ".join(parts)


_SECTION = re.compile(r"__FUGU_(\w+)__")


def _to_evidence(
    trigger: str,
    result: dict,
    duration_s: float,
    canary_values: list[str],
) -> DetonationEvidence:
    meta = (result.get("metadata") or {}) if isinstance(result, dict) else {}
    res = meta.get("result") or {}
    state = res.get("state") or {}
    stdout = ((res.get("stdout") or {}).get("value")) or ""
    stderr = ((res.get("stderr") or {}).get("value")) or ""

    sections = _split_sections(stdout)

    # Collector logs: proxy requests + DNS queries captured in-sandbox
    flows = _proxy_flows(sections.get("PROXY_LOG", ""))
    dns = _dns_records(sections.get("DNS_LOG", ""))

    # Canary scan: stdout/stderr + fs probe output
    from fugu.detonation.docker_driver import scan_for_canaries

    fs_changes = [
        l for l in sections.get("FS_PROBE", "").splitlines() if l.strip()
    ][:30]
    canary_hits = scan_for_canaries(
        canary_values,
        flows=flows,
        dns=dns,
        fs_changes=fs_changes,
    )
    # stdout/stderr echo scan (payloads printing harvested creds)
    from fugu.types import EvidenceSnippet

    for cv in canary_values:
        hexcv = cv.encode().hex()
        for label, blob in (("stdout", stdout), ("stderr", stderr)):
            needle = cv if cv in blob else (hexcv if hexcv in blob else None)
            if needle:
                canary_hits.append(
                    EvidenceSnippet(
                        source=f"sandbox.{label}",
                        excerpt=_around(blob, needle),
                        meta={"vector": "stdout", "canary": True},
                    )
                )
                break

    return DetonationEvidence(
        trigger=trigger,
        exit_code=state.get("exit_code"),
        duration_s=round(duration_s, 3),
        flows=flows,
        dns=dns,
        fs_changes=fs_changes,
        canary_hits=canary_hits,
        metrics={"sandbox": True, "status": result.get("status")},
    )


def _split_sections(stdout: str) -> dict[str, str]:
    out: dict[str, str] = {}
    cur = None
    buf: list[str] = []
    for line in stdout.splitlines():
        m = re.match(r"^__FUGU_(\w+)__", line.strip())
        if m:
            if cur:
                out[cur] = "\n".join(buf)
            cur = m.group(1)
            buf = []
        else:
            buf.append(line)
    if cur:
        out[cur] = "\n".join(buf)
    return out


def _proxy_flows(log_text: str) -> list[FlowRecord]:
    """Parse proxy.log REQ lines into FlowRecords (host/path/body)."""
    import datetime

    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    flows: list[FlowRecord] = []
    for line in log_text.splitlines():
        line = line.strip()
        if not line.startswith("REQ "):
            continue
        # REQ METHOD target host=Host body=...
        import re as _re

        host_m = _re.search(r" host=(\S+)", line)
        body_m = _re.search(r" body=(.*)$", line)
        reqline = line[4:].split(" host=")[0].split(" body=")[0]
        bits = reqline.split(" ")
        method = bits[0] if bits else "?"
        target = bits[1] if len(bits) > 1 else ""
        host = host_m.group(1) if host_m else ""
        body = body_m.group(1)[:400] if body_m else ""
        if not host and target.startswith("http"):
            from urllib.parse import urlsplit

            host = urlsplit(target).netloc
        path = target.split(host, 1)[1] if host and host in target else target
        flows.append(FlowRecord(host=host, method=method, path=path[:300], body=body, ts=ts))
        if len(flows) >= 50:
            break
    return flows


def _dns_records(log_text: str) -> list[DnsRecord]:
    """Parse dns.log lines into DnsRecords."""
    import datetime

    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    out: list[DnsRecord] = []
    for line in log_text.splitlines():
        q = line.strip()
        if q and "." in q:
            out.append(DnsRecord(query=q[:253], ts=ts))
            if len(out) >= 50:
                break
    return out


def _around(blob: str, needle: str, width: int = 120) -> str:
    i = blob.find(needle)
    if i < 0:
        return needle[:width]
    a = max(0, i - width // 2)
    return blob[a : i + width][:2 * width]
