"""DNS collector: logs every A query QNAME to JSONL, replies NXDOMAIN.

Runs as a container on the spike network at a fixed IP (172.28.0.10); the victim
container is started with --dns 172.28.0.10 so ALL its DNS passes through us.
Port 53/udp is fine inside the container (root there).
"""
import json
import socket
import sys
import threading
from datetime import datetime, timezone

OUT = sys.argv[1] if len(sys.argv) > 1 else "/logs/dns.log"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 53))


def parse_qname(data: bytes) -> str:
    labels, i = [], 12
    while i < len(data) and data[i] != 0:
        n = data[i]
        labels.append(data[i + 1 : i + 1 + n].decode("latin1"))
        i += 1 + n
    return ".".join(labels)


def question_section(data: bytes) -> bytes:
    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    return data[12 : i + 5]  # QNAME + null + QTYPE(2) + QCLASS(2)


def handle(data: bytes, addr):
    try:
        qname = parse_qname(data)
    except Exception:
        qname = "<unparseable>"
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "client": addr[0], "query": qname}
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    # 12-byte header: ID + QR/RD/RCODE=NXDOMAIN + QDCOUNT echo + zero counts
    header = data[:2] + b"\x81\x83" + data[4:6] + b"\x00\x00" * 3
    try:
        sock.sendto(header + question_section(data), addr)
    except OSError:
        pass


print(f"dns collector listening on udp/53 -> {OUT}", flush=True)
while True:
    data, addr = sock.recvfrom(4096)
    threading.Thread(target=handle, args=(data, addr), daemon=True).start()
