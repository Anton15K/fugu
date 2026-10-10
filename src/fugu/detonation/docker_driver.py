"""Docker detonation driver — promotes spike 001 into a reusable Stage-3 engine.

Per ``detonate()`` call (one isolated chamber):

1. Fresh canaries via :func:`fugu.detonation.base.fresh_canary_env` — every
   chamber gets unique credentials (catches payloads that phone home only for
   specific creds), shared by all triggers in that chamber.
2. Unique docker network ``fugu-det-<runid>`` on a random /24 inside
   172.31.0.0/16 (with create-retry on stale collisions); fixed IPs:
   DNS = x.x.x.10, mitm = x.x.x.11.
3. mitmproxy container starts FIRST (detached) — its CA is generated on first
   boot; we ``docker exec cat`` it out and bake it into the victim image so
   the victim trusts the MITM CA for HTTPS interception. Runs
   ``mitmdump -s /addon.py --set connection_strategy=lazy`` (CRITICAL: with
   the default ``eager``, mitm connects upstream *before* decrypting, and
   dead C2 domains kill the flow before the ``request`` hook fires — spike
   001 verdict). The addon logs each request (host/path/body/ts) to JSONL.
4. DNS collector container at .10 (our stdlib resolver, replies NXDOMAIN so
   clients fail fast); victim gets ``--dns`` pointing at it, so all its
   queries land in our log.
5. Victim image built from a generated Dockerfile: python:3.11-slim +
   curl/dnsutils + MITM CA imported via update-ca-certificates + the target
   dir copied to /opt/target.
6. For EACH trigger: a KEPT container (no --rm, named <runid>-victim-<i>,
   labelled fugu.run=<runid>) runs the command with canary env +
   HTTP(S)_PROXY/http(s)_proxy pointing at the mitm container; then
   ``docker diff`` harvests filesystem changes; then the container is
   removed.
7. dns/mitm JSONL logs are parsed into DnsRecord/FlowRecord; flows (host,
   path, body), DNS queries (raw AND hex-encoded canary forms) and
   fs_changes are scanned for canary substrings -> EvidenceSnippet list in
   DetonationEvidence.canary_hits.
8. ``finally``: full teardown — victim/collector containers, label sweep,
   network, victim image; logs dir removed unless keep_logs.

Known limitation (documented, deliberate): the collector logs are shared
across triggers within one chamber, so flows/dns are cumulative per chamber;
per-trigger attribution comes from canary_hits only. Fresh canaries per
chamber keep this sound.

Canary hit-scanning detail (DNS): exfil tooling hex-encodes secrets into
subdomain labels. We compute ``hex(value.encode())`` per canary and search for
it in queries; because long hex blobs get chunked into DNS labels by the
attacker (spike and corpus fixture both use 30-char chunks; labels max at 63),
we also search every 30-char window of the hex form.

OWASP mapping used by :func:`evidence_to_findings` (judgment documented):

==========================  ======================  ==========================
Evidence condition          OWASP ids               rationale
==========================  ======================  ==========================
canary hit in any outbound  LLM02, MCP01            LLM02 sensitive info
flow (host/path/body) or                            disclosure — data provably
a DNS query                                         left the sandbox; MCP01
                                                    token mismanagement — a
                                                    credential was read from
                                                    env and transmitted
unexpected egress:         MCP07, LLM02            undeclared outbound data
outbound flows or DNS                              movement (authz/audit gap)
outbound flows or DNS                              — the extension shipped
queries with NO canary hit                          data somewhere undeclared
                                                    (lower severity; LLM02
                                                    because disclosure is
                                                    possible but unproven)
canary in fs_changes        MCP01                   secret (or its hex form)
(canary value or hex                                persisted to disk = token
form on disk)                                       mishandling
==========================  ======================  ==========================

Severity/confidence: canary exfil = critical / deterministic (exact-value
match, observed behavior). Unexpected egress = medium / empirical (observed,
but intent unproven). Canary on disk = high / deterministic. Plain fs_changes
without canaries produce no finding — writing files during install is normal.
"""
from __future__ import annotations

from fugu.subprocess_env import credential_free_env

import asyncio
import json
import logging
import re
import secrets
import shlex
import shutil
import tempfile
import time
import uuid
from pathlib import Path

from fugu.types import (
    DetonationEvidence,
    DnsRecord,
    EvidenceSnippet,
    Finding,
    FlowRecord,
)
from fugu.detonation.base import fresh_canary_env

__all__ = ["DockerDriver", "evidence_to_findings", "scan_for_canaries"]

log = logging.getLogger("fugu.detonation")

# collector image is tagged once per driver instance; victim image per run
_DNS_IMG = "fugu-det/dns:latest"
_MITM_IMG = "mitmproxy/mitmproxy:latest"
_COLLECTORS_DIR = Path(__file__).parent / "collectors"

# Fixed IPs inside the per-run /24 network (random k-th subnet of 172.31.0.0/16)
_SUBNET_BASE = "172.31"
_NET_PREFIX = "fugu-det-"

# docker diff line kinds we report (C=changed A=added D=deleted)
_DIFF_LINE = re.compile(r"^(C|A|D)\s+(\S+)$")

_EXCERPT_MAX = 500  # EvidenceSnippet.excerpt contract: <= 500 chars


class DockerDriver:
    """DetonationDriver backed by a local Docker daemon (dev/fallback driver).

    The production Sandboxes (contree) driver implements the same protocol
    (see base.py). All docker invocations go through asyncio subprocesses so
    the driver is usable from the async pipeline; cleanup happens in
    ``finally`` regardless of outcome.
    """

    def __init__(self, keep_logs: bool = False, evidence_grace_s: float = 15.0) -> None:
        self.keep_logs = keep_logs
        self.evidence_grace_s = evidence_grace_s
        self._dns_img_built = False
        self._mitm_img_built = False

    # ------------------------------------------------------------------ api
    async def detonate(
        self,
        target_dir: Path,
        triggers: list[str],
        timeout_s: int = 120,
        on_progress=None,
    ) -> list[DetonationEvidence]:
        """Run every trigger in a fresh chamber; return evidence per trigger.

        Expected analysis outcomes (non-zero exit codes, captured exfil
        attempts) are evidence, not errors; raising is reserved for
        infrastructure failures (daemon down, build error, CA timeout).
        """
        if not triggers:
            return []
        target_dir = Path(target_dir).resolve()
        if not target_dir.is_dir():
            raise FileNotFoundError(f"target_dir does not exist: {target_dir}")

        run_id = f"{_NET_PREFIX}{uuid.uuid4().hex[:12]}"
        k = secrets.randbelow(200) + 20  # stay off .0/.1/.2 subnet corners
        subnet = f"{_SUBNET_BASE}.{k}.0/24"
        dns_ip = f"{_SUBNET_BASE}.{k}.10"
        mitm_ip = f"{_SUBNET_BASE}.{k}.11"

        return await self._detonate_chamber(
            run_id, target_dir, triggers, timeout_s, subnet, dns_ip, mitm_ip, on_progress
        )

    # ------------------------------------------------------------- internals
    async def _run(
        self, args: list[str], timeout: float | None = None, check: bool = False
    ) -> str:
        """Run a docker CLI command; return stdout (trailing ws stripped)."""
        proc = await asyncio.create_subprocess_exec(
            "docker",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=credential_free_env(),
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            await _reap_process(proc)
            raise
        text = out.decode(errors="replace").strip()
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"docker {' '.join(args[:3])}... failed rc={proc.returncode}: "
                f"{err.decode(errors='replace')[:400]}"
            )
        return text

    async def _detonate_chamber(
        self,
        run_id: str,
        target_dir: Path,
        triggers: list[str],
        timeout_s: int,
        subnet: str,
        dns_ip: str,
        mitm_ip: str,
        on_progress=None,
    ) -> list[DetonationEvidence]:
        def log(msg: str) -> None:
            if on_progress is not None:
                try:
                    on_progress(msg)  # stage tag comes from the SSE envelope
                except Exception:  # noqa: BLE001 - progress must never kill a run
                    pass

        # Collector logs dir semantics: the driver READS these files
        # directly (canary watchdog, CA pickup) AND the daemon bind-mounts
        # the same path into collector containers. So the path must be
        # visible AT THE SAME PATH to both this process and the daemon:
        #   - bare metal: any tempdir (daemon shares /var/folders, /tmp).
        #   - Fugu in a container: mount a host dir SAME-PATH into the
        #     container and point FUGU_DET_LOGS_DIR at it, e.g.
        #       -v /var/fugu/det-logs:/var/fugu/det-logs         #       -e FUGU_DET_LOGS_DIR=/var/fugu/det-logs
        import os as _os
        forced = _os.environ.get("FUGU_DET_LOGS_DIR")
        if forced:
            forced_path = Path(forced)
            forced_path.mkdir(parents=True, exist_ok=True)
            logs_dir = Path(tempfile.mkdtemp(prefix=f"{run_id}-logs-", dir=forced_path))
        else:
            logs_dir = Path(tempfile.mkdtemp(prefix=f"{run_id}-logs-"))
        victim_img = f"{run_id}/victim:latest"
        ca_pem = logs_dir / "mitmca.pem"
        evidence: list[DetonationEvidence] = []
        net_name = run_id  # network shares the run-id name (prefix fugu-det-)

        mitm_container = f"{run_id}-mitm"
        dns_container = f"{run_id}-dns"
        victim_names = [f"{run_id}-victim-{i}" for i in range(len(triggers))]

        try:
            await self._create_network(subnet, net_name)

            # ---- mitm first (CA must exist before victim image build) --------
            # The addon is BAKED into an image (not bind-mounted): when Fugu
            # itself runs in a container, bind sources under /app are unknown
            # to the host daemon behind the socket.
            mitm_img = await self._build_mitm_image()
            await self._run(
                [
                    "run", "-d", "--rm", "--name", mitm_container,
                    "--network", net_name, "--ip", mitm_ip, "--dns", dns_ip,
                    "--label", f"fugu.run={run_id}",
                    "-v", f"{logs_dir}:/logs",
                    mitm_img,
                    "mitmdump", "-s", "/srv/mitm_addon.py",
                    "--listen-host", "0.0.0.0", "--listen-port", "8080",
                    "--set", "connection_strategy=lazy",
                ],
                check=True,
            )
            await self._wait_mitm_ca(mitm_container, ca_pem)

            await self._build_dns_image()
            await self._run(
                [
                    "run", "-d", "--rm", "--name", dns_container,
                    "--network", net_name, "--ip", dns_ip,
                    "--cap-add", "NET_ADMIN", "--label", f"fugu.run={run_id}",
                    "-v", f"{logs_dir}:/logs",
                    _DNS_IMG,
                    "python", "/srv/dns_collector.py", "/logs/dns.log",
                ],
                check=True,
            )
            await asyncio.sleep(1.0)  # let collectors settle
            log("chamber up: network %s, dns+mitm collectors running" % net_name)

            await self._build_victim_image(target_dir, ca_pem, victim_img)
            log("victim image built (target copied in, CA installed)")

            canary_env, canary_values = fresh_canary_env()

            log("detonating %d trigger(s)" % len(triggers))
            for i, trigger in enumerate(triggers):
                log("trigger %d/%d: %s" % (i + 1, len(triggers), trigger))
                evidence.append(
                    await self._exec_trigger(
                        run_id=run_id,
                        victim=victim_names[i],
                        net=net_name,
                        dns_ip=dns_ip,
                        mitm_ip=mitm_ip,
                        image=victim_img,
                        trigger=trigger,
                        timeout_s=timeout_s,
                        canary_env=canary_env,
                        canary_values=canary_values,
                        logs_dir=logs_dir,
                    )
                )
            log("all triggers executed; tearing chamber down")
            return evidence
        finally:
            await self._teardown(
                run_id, net_name, mitm_container, dns_container,
                victim_names, logs_dir, victim_img,
            )

    async def _create_network(self, subnet: str, net_name: str) -> None:
        """Create the chamber network; retry with a fresh subnet on collision."""
        for attempt in range(4):
            s = subnet if attempt == 0 else (
                f"{_SUBNET_BASE}.{secrets.randbelow(200) + 20}.0/24"
            )
            await self._run(["network", "create", "--subnet", s, net_name], check=False)
            if await self._net_exists(net_name):
                return
        raise RuntimeError(f"could not create docker network {net_name}")

    async def _net_exists(self, name: str) -> bool:
        return bool(
            await self._run(["network", "inspect", "-f", "{{.Id}}", name], check=False)
        )

    async def _wait_mitm_ca(self, mitm_container: str, ca_pem: Path) -> None:
        """Poll `docker exec cat` until mitmproxy has written its CA."""
        for _ in range(30):
            cert = await self._run(
                ["exec", mitm_container, "cat",
                 "/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"],
            )
            if "BEGIN CERTIFICATE" in cert:
                ca_pem.write_text(cert + "\n")
                return
            await asyncio.sleep(1.0)
        raise RuntimeError("mitmproxy CA not generated within 30s")

    async def _build_mitm_image(self) -> str:
        """mitmproxy image with our addon baked in (no host bind-mounts)."""
        tag = "fugu-mitm:latest"
        if self._mitm_img_built:
            return tag
        # Based on the official image so the mitmproxy USER and its home
        # (/home/mitmproxy — where the CA confdir lives) match what
        # _wait_mitm_ca polls.
        dockerfile = (
            "FROM mitmproxy/mitmproxy:latest\n"
            "COPY mitm_addon.py /srv/mitm_addon.py\n"
        )
        await self._build_image(tag, dockerfile, ["mitm_addon.py"])
        self._mitm_img_built = True
        return tag

    async def _build_dns_image(self) -> None:
        if self._dns_img_built:
            return
        dockerfile = (
            "FROM python:3.11-slim\n"
            "COPY dns_collector.py /srv/dns_collector.py\n"
            'CMD ["python", "/srv/dns_collector.py", "/logs/dns.log"]\n'
        )
        await self._build_image(_DNS_IMG, dockerfile, ["dns_collector.py"])
        self._dns_img_built = True

    async def _build_victim_image(
        self, target_dir: Path, ca_pem: Path, tag: str
    ) -> None:
        dockerfile = (
            "FROM python:3.11-slim\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            "curl dnsutils && rm -rf /var/lib/apt/lists/*\n"
            "COPY mitmca.pem /usr/local/share/ca-certificates/fugu-mitmca.crt\n"
            "RUN update-ca-certificates\n"
            "COPY target/ /opt/target/\n"
            "WORKDIR /opt/target\n"
            "RUN chmod -R a+rX /opt/target "
            "&& (chmod +x /opt/target/install.sh || true)\n"
        )
        await self._build_image(tag, dockerfile, [], context=target_dir, ca=ca_pem)

    async def _build_image(
        self,
        tag: str,
        dockerfile_text: str,
        files: list[str],
        context: Path | None = None,
        ca: Path | None = None,
    ) -> None:
        """Build an image from a temp context that pulls in collector/target files."""
        with tempfile.TemporaryDirectory(prefix="fugu-build-") as td:
            ctx = Path(td)
            if context is not None:
                shutil.copytree(context, ctx / "target")
            for fname in files:
                (ctx / fname).write_bytes((_COLLECTORS_DIR / fname).read_bytes())
            if ca is not None:
                (ctx / "mitmca.pem").write_bytes(ca.read_bytes())
            (ctx / "Dockerfile").write_text(dockerfile_text)
            await self._run(["build", "-q", "-t", tag, str(ctx)], timeout=900, check=True)

    async def _exec_trigger(
        self,
        *,
        run_id: str,
        victim: str,
        net: str,
        dns_ip: str,
        mitm_ip: str,
        image: str,
        trigger: str,
        timeout_s: int,
        canary_env: dict[str, str],
        canary_values: list[str],
        logs_dir: Path,
    ) -> DetonationEvidence:
        proxy = f"http://{mitm_ip}:8080"
        env_flags: list[str] = []
        for k, v in canary_env.items():
            env_flags += ["-e", f"{k}={v}"]
        for k, v in (
            ("HTTP_PROXY", proxy), ("HTTPS_PROXY", proxy),
            ("http_proxy", proxy), ("https_proxy", proxy),
            ("NO_PROXY", ""), ("no_proxy", ""),
        ):
            env_flags += ["-e", f"{k}={v}"]

        # KEPT container (no --rm): docker diff needs the fs; we rm explicitly
        # after harvesting. bash -lc so PATH behaves; host-side asyncio timeout
        # guards the whole docker run.
        t0 = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "run", "--name", victim, "--network", net, "--dns", dns_ip,
            *env_flags,
            "--label", f"fugu.run={run_id}",
            image,
            "bash", "-lc", trigger,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=credential_free_env(),
        )
        # Canary-evidence watchdog: after a grace period, poll collector
        # logs; the moment a canary value (raw or hex-encoded) appears in
        # NEW log bytes since this trigger started, kill the victim — the
        # evidence is already captured, so waiting out a hanging exfil call
        # (or the host timeout) is pure latency. Cumulative shared logs are
        # handled by scanning only the suffix appended after t0.
        log_sizes_t0 = self._collector_log_sizes(logs_dir)
        killed_by: str | None = None  # None | "timeout" | "evidence"
        try:
            while proc.returncode is None:
                await asyncio.sleep(0.5)
                elapsed = time.monotonic() - t0
                if elapsed >= timeout_s:
                    killed_by = "timeout"
                    break
                if (
                    elapsed >= self.evidence_grace_s
                    and self._new_log_bytes_contain_canary(logs_dir, log_sizes_t0, canary_values)
                ):
                    killed_by = "evidence"
                    break
            if killed_by:
                proc.kill()
            out, err = await proc.communicate()
        except asyncio.CancelledError:
            await _reap_process(proc)
            raise
        if killed_by == "timeout":
            exit_code: int | None = None
        else:
            exit_code = proc.returncode

        duration_s = time.monotonic() - t0
        fs_changes = await self._harvest_diff(victim)
        await self._run(["rm", "-f", victim], check=False)

        flows, dns = self._read_collector_logs(logs_dir)
        hits = scan_for_canaries(canary_values, flows=flows, dns=dns, fs_changes=fs_changes)
        return DetonationEvidence(
            trigger=trigger,
            exit_code=exit_code,
            duration_s=round(duration_s, 3),
            flows=flows,
            dns=dns,
            fs_changes=fs_changes,
            canary_hits=hits,
            metrics={
                "stdout_tail": out.decode(errors="replace")[-2000:],
                "stderr_tail": err.decode(errors="replace")[-2000:],
            },
        )

    async def _harvest_diff(self, container: str) -> list[str]:
        """docker diff on the KEPT container -> normalized change lines."""
        out = await self._run(["diff", container], timeout=120)
        lines: list[str] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            lines.append(line if _DIFF_LINE.match(line) else f"? {line}")
        return lines

    @staticmethod
    def _collector_log_sizes(logs_dir: Path) -> dict[str, int]:
        """Byte sizes of collector logs (for suffix-only canary scanning)."""
        sizes: dict[str, int] = {}
        for name in ("mitm.log", "dns.log"):
            p = logs_dir / name
            sizes[name] = p.stat().st_size if p.is_file() else 0
        return sizes

    def _new_log_bytes_contain_canary(
        self, logs_dir: Path, sizes_t0: dict[str, int], canary_values: list[str]
    ) -> bool:
        """True if canary bytes (raw or hex-encoded) appear in log data
        appended since sizes_t0 was taken (i.e., during THIS trigger)."""
        needles: list[str] = []
        for v in canary_values:
            needles.append(v)
            needles.extend(_hex_forms(v))
        for name, off in sizes_t0.items():
            p = logs_dir / name
            if not p.is_file():
                continue
            with p.open("rb") as f:
                f.seek(off)
                chunk = f.read()
            for needle in needles:
                if needle.encode() in chunk:
                    return True
        return False

    @staticmethod
    def _read_collector_logs(logs_dir: Path) -> tuple[list[FlowRecord], list[DnsRecord]]:
        """Parse shared collector JSONL logs into typed records.

        Logs are cumulative across triggers in a chamber (documented
        limitation — see module docstring).
        """
        flows: list[FlowRecord] = []
        dns: list[DnsRecord] = []
        mitm_log = logs_dir / "mitm.log"
        dns_log = logs_dir / "dns.log"
        if mitm_log.is_file():
            for line in mitm_log.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                flows.append(
                    FlowRecord(
                        host=str(r.get("host", "")),
                        method=str(r.get("method", "")),
                        path=str(r.get("path", "")),
                        body=str(r.get("body") or ""),
                        ts=str(r.get("ts", "")),
                    )
                )
        if dns_log.is_file():
            for line in dns_log.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                dns.append(DnsRecord(query=str(r.get("query", "")), ts=str(r.get("ts", ""))))
        return flows, dns

    async def _teardown(
        self,
        run_id: str,
        net_name: str,
        mitm_container: str,
        dns_container: str,
        victim_names: list[str],
        logs_dir: Path,
        victim_img: str,
    ) -> None:
        async def remove(args: list[str]) -> str:
            try:
                return await self._run(args, timeout=10, check=False)
            except Exception:
                # Infrastructure errors must not abandon the remaining owned
                # resources or write private subprocess details into logs.
                log.debug("owned chamber cleanup command unavailable")
                return ""

        try:
            for name in [*victim_names, dns_container, mitm_container]:
                await remove(["rm", "-f", name])
            leftover = await remove(["ps", "-aq", "--filter", f"label=fugu.run={run_id}"])
            for cid in leftover.split():
                await remove(["rm", "-f", cid])
            await remove(["network", "rm", net_name])
            await remove(["rmi", "-f", victim_img])
        finally:
            if not self.keep_logs:
                shutil.rmtree(logs_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Canary hit-scanning
# ---------------------------------------------------------------------------
def _hex_forms(value: str) -> list[str]:
    """Hex encodings of a canary to search for in DNS queries.

    Full hex blob plus 30-char windows (attackers chunk long hex into DNS
    labels — the corpus fixture and spike both use 30-char chunks; DNS labels
    max out at 63 chars anyway).
    """
    hx = value.encode().hex()
    if len(hx) <= 30:
        return [hx]
    return [hx] + [hx[i : i + 30] for i in range(0, len(hx), 30)]


def scan_for_canaries(
    canary_values: list[str],
    *,
    flows: list[FlowRecord],
    dns: list[DnsRecord],
    fs_changes: list[str],
) -> list[EvidenceSnippet]:
    """Scan captured evidence for canary substrings (raw + hex for DNS).

    Flow hits: canary in host, path or body. DNS hits: raw canary or any hex
    form (full or 30-char window) inside the query name. FS hits: canary or
    its full hex form in a docker-diff path.
    """
    hits: list[EvidenceSnippet] = []
    for value in canary_values:
        hex_full = value.encode().hex()
        for i, fl in enumerate(flows):
            where = None
            if value in fl.host:
                where = "host"
            elif value in fl.path:
                where = "path"
            elif value in fl.body:
                where = "body"
            if where:
                field = getattr(fl, where)
                hits.append(
                    EvidenceSnippet(
                        source=f"mitm.flow[{i}].{where}",
                        excerpt=(
                            f"{fl.method} {fl.host}{fl.path[:120]} :: "
                            f"{field[:_EXCERPT_MAX - 140]}"
                        )[:_EXCERPT_MAX],
                        meta={"vector": "http", "field": where, "canary": _kind(value)},
                    )
                )
        for i, rec in enumerate(dns):
            if value in rec.query or any(h in rec.query for h in _hex_forms(value)):
                hits.append(
                    EvidenceSnippet(
                        source=f"dns.query[{i}]",
                        excerpt=rec.query[:_EXCERPT_MAX],
                        meta={"vector": "dns", "canary": _kind(value)},
                    )
                )
        for i, line in enumerate(fs_changes):
            if value in line or hex_full in line:
                hits.append(
                    EvidenceSnippet(
                        source=f"fs.change[{i}]",
                        excerpt=line[:_EXCERPT_MAX],
                        meta={"vector": "fs", "canary": _kind(value)},
                    )
                )
    return hits


def _kind(value: str) -> str:
    """Which canary slot a value came from (for snippet metadata)."""
    if value.startswith("FUGU-CANARY-"):
        return "fugu_token"
    if value.startswith("ghp_"):
        return "github_token"
    if len(value) == 40 and any(c in value for c in "/+"):
        return "aws_secret"
    return "unknown"


# ---------------------------------------------------------------------------
# Evidence -> Findings
# ---------------------------------------------------------------------------
def evidence_to_findings(ev: DetonationEvidence) -> list[Finding]:
    """Map a DetonationEvidence to Findings (see module docstring table).

    Deterministic: same evidence in, same findings out. No LLM involved.
    """
    findings: list[Finding] = []
    exfil_hits = [h for h in ev.canary_hits if h.meta.get("vector") in ("http", "dns")]
    fs_hits = [h for h in ev.canary_hits if h.meta.get("vector") == "fs"]

    if exfil_hits:
        vectors = sorted({str(h.meta.get("vector")) for h in exfil_hits})
        findings.append(
            Finding(
                owasp_ids=["LLM02", "MCP01"],
                title="Canary credential exfiltrated over the network",
                detail=(
                    f"Trigger {shlex.quote(ev.trigger)} sent a canary value out "
                    f"of the sandbox via {'/'.join(vectors)}: {len(exfil_hits)} "
                    "captured hit(s). Canaries are unique per run, so any hit "
                    "proves the extension read injected credentials and "
                    "transmitted them to a third party."
                ),
                severity="critical",
                confidence="deterministic",
                stage="detonation",
                evidence=exfil_hits,
            )
        )

    if fs_hits:
        findings.append(
            Finding(
                owasp_ids=["MCP01"],
                title="Canary credential persisted to disk",
                detail=(
                    f"Trigger {shlex.quote(ev.trigger)} wrote a canary value (or "
                    f"its hex form) to the container filesystem: {len(fs_hits)} "
                    "path(s). Secrets should not be persisted by "
                    "install/import/invoke logic."
                ),
                severity="high",
                confidence="deterministic",
                stage="detonation",
                evidence=fs_hits,
            )
        )

    if (ev.flows or ev.dns) and not exfil_hits:
        hosts = sorted({f.host for f in ev.flows})[:5]
        doms = sorted({d.query for d in ev.dns})[:5]
        findings.append(
            Finding(
                owasp_ids=["MCP07", "LLM02"],
                title="Unexpected network egress during trigger execution",
                detail=(
                    f"Trigger {shlex.quote(ev.trigger)} caused {len(ev.flows)} "
                    f"outbound HTTP(S) flow(s) and {len(ev.dns)} DNS queries; "
                    "no canary was involved, but the extension contacted "
                    "infrastructure the audit did not expect. Hosts: "
                    f"{hosts or doms}."
                ),
                severity="medium",
                confidence="empirical",
                stage="detonation",
                evidence=[
                    EvidenceSnippet(
                        source=f"mitm.flow[{i}]",
                        excerpt=f"{f.method} {f.host}{f.path[:200]}",
                        meta={"vector": "http"},
                    )
                    for i, f in enumerate(ev.flows[:5])
                ]
                + [
                    EvidenceSnippet(
                        source=f"dns.query[{i}]",
                        excerpt=d.query[:200],
                        meta={"vector": "dns"},
                    )
                    for i, d in enumerate(ev.dns[:5])
                ],
            )
        )

    return findings


async def _reap_process(proc) -> None:
    """Kill/drain only the subprocess owned by this operation, boundedly."""
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(proc.communicate(), timeout=0.1)
    except Exception:
        transport = getattr(proc, "_transport", None)
        if transport is not None:
            transport.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=0.1)
        except Exception:
            pass
