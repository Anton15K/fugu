# Spike 001: Canary egress capture in a disposable detonation chamber

## Question
Can we run untrusted "extension" code in an isolated container seeded with **canary
credentials**, capture **all egress** (HTTPS body via MITM proxy, DNS labels via our own
resolver, plain HTTP), and produce an **evidence record** proving exfiltration — the
mechanism Stage 3 (dynamic detonation) of the auditor depends on?

Sub-questions:
- **001a** HTTPS: explicit proxy + our CA trusted in the image → mitmproxy captures POST body containing canary
- **001b** DNS: container's only resolver is ours → canary encoded in subdomain gets logged
- **002** FS telemetry: `docker diff` before/after trigger = filesystem change report

This is the local Docker driver. The production driver swaps in Nebius Sandboxes
(`contree-sdk`) behind the same interface:

```
detonate(image, trigger_cmd, canary_env, dns) -> Evidence(
    network=[{proto, host, body_snippet, canary_hits}],
    dns=[{query, canary_hits}],
    fs_changes=[...],
)
```

## Approaches considered
| Approach | Pros | Cons | Choice |
|---|---|---|---|
| mitmproxy container, explicit proxy env + CA in image | sees HTTPS bodies; real-world scripts (requests/curl/pip) honor proxy env | defeatable by malware that ignores proxies (accepted MVP risk; network-level redirect later) | ✅ |
| Network gateway w/ iptables REDIRECT (transparent) | captures even proxy-ignoring clients | needs NET_ADMIN/host quirks; overkill for spike | later |
| Plain HTTP-only capture | trivial | misses HTTPS bodies — the main exfil channel | ❌ |

## Components
- `dns_collector.py` — stdlib DNS server (A queries), logs every queried name to JSONL
- `mitm_addon.py` — mitmdump addon writing {host, path, body} per flow to JSONL
- `malicious_extension.sh` — the "extension install hook": reads canary env, exfiltrates
  via HTTPS POST, DNS subdomain, and plain HTTP (three vectors)
- `run_spike.py` — orchestrates: build victim image (CA trusted, canaries baked as env),
  start collectors, detonate, harvest evidence, print verdict table

## Verdict: VALIDATED (2026-09-19, all 3 vectors)

### What worked
- **001a HTTPS body capture: PASS.** Full canary token + fake AWS key captured in the POST body to the (nonexistent) C2 domain. Critical: mitmproxy needs `--set connection_strategy=lazy` — with the default `eager`, mitm connects upstream *before* decrypting the client request, and dead C2 domains kill the flow before the `request` hook fires. With `lazy`, evidence is captured even when upstream is unreachable (the normal case in analysis).
- **001b DNS exfil capture: PASS.** All hex-encoded canary subdomain queries logged by the stdlib DNS collector (fixed-IP container + `--dns` override on the victim). NXDOMAIN replies make clients fail fast.
- **002 plain HTTP: PASS.** Canary in URL captured via proxy env.
- Use the `request` hook, not `response` — attacker infrastructure is usually dead; we must capture intent, not completed transactions.

### What didn't
- First run: HTTPS capture failed (eager connection strategy) — fixed as above.
- Victim must trust the MITM CA (baked at image build) AND honor proxy env vars. Malware that ignores proxies/uses raw sockets would evade this MVP design — accepted; network-level redirect (iptables/NATIVE) is the production hardening.

### Surprises
- The malicious install exits 0 in 0.3s — "successful install" and "exfiltration" are indistinguishable without instrumentation. This IS the demo.
- Detonation round-trip (build excluded) is sub-second; a full audit's Stage 3 will be dominated by image import, not execution.

### Recommendation for the real build
- Keep the driver interface (`detonate(image, trigger, canary_env, dns) -> Evidence`) — Docker driver validated here; Sandboxes driver swaps in behind it (their env-var injection + fs snapshots replace our proxy/DNS tricks where possible, but we should still run OUR dns/mitm collectors as sandbox-internal processes if Sandboxes networking allows, else fall back to per-run proxies).
- Always rerun detonation with fresh canary values (catches payloads that phone home only for specific creds).
- Evidence record should store: flow log + dns log + canary hits + exit code + duration + fs diff (`docker diff`, not yet wired in this spike — trivial next).

