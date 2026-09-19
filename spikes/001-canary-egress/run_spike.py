"""Spike 001 orchestrator: local Docker detonation chamber.

Usage: uv run python spikes/001-canary-egress/run_spike.py
Needs: Docker daemon running (image pulls: python:3.11-slim, mitmproxy/mitmproxy).

Order matters: mitmproxy starts FIRST (detached) so its CA exists; we docker cp
the CA out, bake it into the victim image, then detonate.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

SPIKE = Path(__file__).parent
LOGS = SPIKE / "logs"
NET = "fugu-spike-net"
DNS_IP = "172.28.0.10"
MITM_IP = "172.28.0.11"
CANARY = "REDACTED-CANARY"
CANARY_AWS = "REDACTED-AWS-FAKE"

DNS_IMG = "fugu-spike/dns:latest"
VICTIM_IMG = "fugu-spike/victim:latest"


def sh(*args, check=True, **kw):
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    if check and r.returncode != 0:
        print(f"CMD FAILED: {' '.join(args)}\nSTDOUT: {r.stdout}\nSTDERR: {r.stderr}")
        sys.exit(1)
    return r


def start_mitm():
    """Start mitmproxy detached; wait for its CA to be generated; copy it out."""
    sh("docker", "network", "create", "--subnet=172.28.0.0/24", NET, check=False)
    old = sh("docker", "ps", "-aq", "-f", "name=fugu-mitm", check=False)
    if old.stdout.strip():
        sh("docker", "rm", "-f", "fugu-mitm", check=False)
    sh("docker", "run", "-d", "--rm", "--name", "fugu-mitm", "--network", NET,
       "--ip", MITM_IP, "--dns", DNS_IP,
       "-v", f"{SPIKE}/mitm_addon.py:/addon.py:ro",
       "-v", f"{LOGS}:/logs", "mitmproxy/mitmproxy:latest",
       "mitmdump", "-s", "/addon.py", "--listen-host", "0.0.0.0", "--listen-port", "8080",
       "--set", "connection_strategy=lazy")
    # CA is written on first boot
    for _ in range(20):
        r = sh("docker", "exec", "fugu-mitm", "cat",
               "/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem", check=False)
        if r.returncode == 0 and "BEGIN CERTIFICATE" in r.stdout:
            (SPIKE / "mitmca.pem").write_text(r.stdout)
            print("mitmproxy CA extracted")
            return
        time.sleep(1)
    print("FATAL: could not extract mitmproxy CA"); sys.exit(1)


def build_images():
    (SPIKE / "Dockerfile.dns").write_text(
        "FROM python:3.11-slim\n"
        "COPY dns_collector.py /srv/dns_collector.py\n"
        'CMD ["python", "/srv/dns_collector.py", "/logs/dns.log"]\n'
    )
    (SPIKE / "Dockerfile.victim").write_text(
        "FROM python:3.11-slim\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils && rm -rf /var/lib/apt/lists/*\n"
        "COPY mitmca.pem /usr/local/share/ca-certificates/fugu-mitmca.crt\n"
        "RUN update-ca-certificates\n"
        "COPY malicious_extension.sh /opt/ext/install.sh\n"
        "RUN chmod +x /opt/ext/install.sh\n"
    )
    sh("docker", "build", "-q", "-t", DNS_IMG, "-f", str(SPIKE / "Dockerfile.dns"), str(SPIKE))
    sh("docker", "build", "-q", "-t", VICTIM_IMG, "-f", str(SPIKE / "Dockerfile.victim"), str(SPIKE))
    print("images built")


def start_dns():
    sh("docker", "run", "-d", "--rm", "--name", "fugu-dns", "--network", NET,
       "--ip", DNS_IP, "--cap-add=NET_ADMIN", "-v", f"{LOGS}:/logs", DNS_IMG)


def detonate():
    env = [
        "-e", f"CANARY_TOKEN={CANARY}",
        "-e", f"FAKE_AWS_SECRET_ACCESS_KEY={CANARY_AWS}",
        "-e", f"HTTPS_PROXY=http://{MITM_IP}:8080",
        "-e", f"HTTP_PROXY=http://{MITM_IP}:8080",
        "-e", f"https_proxy=http://{MITM_IP}:8080",
        "-e", f"http_proxy=http://{MITM_IP}:8080",
        "-e", "NO_PROXY=", "-e", "no_proxy=",
    ]
    print(">>> detonating malicious extension install hook...")
    t0 = time.time()
    r = sh("docker", "run", "--rm", "--network", NET, "--dns", DNS_IP,
           *env, VICTIM_IMG, "/opt/ext/install.sh", check=False)
    print(f">>> exit={r.returncode} in {time.time()-t0:.1f}s")
    print(r.stdout or "(no stdout)")
    if r.stderr:
        print("STDERR:", r.stderr[:400])


def read(name):
    p = LOGS / name
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def evidence():
    print("\n" + "=" * 70 + "\nEVIDENCE RECORD\n" + "=" * 70)
    dns_recs, mitm_recs = read("dns.log"), read("mitm.log")
    canary_hex = CANARY.encode().hex()
    canary_aws_hex = CANARY_AWS.encode().hex()

    print(f"\n[DNS collector] {len(dns_recs)} queries")
    for r in dns_recs[:12]:
        print(f"  {r['query'][:80]}")
    print(f"\n[MITM collector] {len(mitm_recs)} requests")
    for r in mitm_recs[:12]:
        print(f"  {r['method']} {r['host']}{r['path'][:50]}")
        if r.get("body"):
            print(f"    body: {r['body'][:110]}")

    https_hits = [r for r in mitm_recs
                  if CANARY in (r.get("body") or "") or CANARY_AWS in (r.get("body") or "")]
    http_hits = [r for r in mitm_recs if CANARY in (r.get("path") or "")]
    dns_hex_hits = [r for r in dns_recs
                    if canary_hex[:30] in r["query"] or canary_hex[30:60] in r["query"]
                    or canary_aws_hex[:30] in r["query"]]
    dns_exfil_domain = [r for r in dns_recs if "exfil.example-attacker" in r["query"]]

    print("\n" + "=" * 70 + "\nVERDICT (spike questions)\n" + "=" * 70)
    v1, v2, v3 = bool(https_hits), bool(dns_hex_hits), bool(http_hits)
    print(f"001a HTTPS body w/ canary captured : {'PASS' if v1 else 'FAIL'} ({len(https_hits)} flows)")
    print(f"001b DNS hex-canary captured       : {'PASS' if v2 else 'FAIL'} "
          f"({len(dns_hex_hits)} hex hits, {len(dns_exfil_domain)} exfil-domain queries)")
    print(f"002  plain-HTTP canary in URL      : {'PASS' if v3 else 'FAIL'} ({len(http_hits)} flows)")
    ok = v1 and v2 and v3
    print(f"\nSPIKE 001: {'*** ALL VECTORS CAPTURED - VALIDATED ***' if ok else '*** PARTIAL/FAILED ***'}")
    return ok


def cleanup():
    sh("docker", "rm", "-f", "fugu-dns", "fugu-mitm", check=False)
    sh("docker", "network", "rm", NET, check=False)


if __name__ == "__main__":
    LOGS.mkdir(exist_ok=True)
    (LOGS / "dns.log").write_text("")
    (LOGS / "mitm.log").write_text("")
    try:
        start_mitm()
        build_images()
        start_dns()
        time.sleep(1.5)
        detonate()
        time.sleep(2)
        evidence()
    finally:
        cleanup()
