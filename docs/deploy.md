# Deploying Fugu (demo URL for the hackathon)

The whole product is **one container**: FastAPI (API + SPA) + the detonation
chamber, which shells out to `docker`. The chamber creates *sibling* containers
(victim + mitm/DNS collectors) on an isolated bridge network — same layout as
local dev. Therefore the host must be a VM with Docker; serverless platforms
cannot host the chamber.

## Requirements on the host

- Docker 24+ (with the `docker` CLI usable by the app user)
- 2 vCPU / 4 GB RAM is plenty (LLM calls are remote via Token Factory)
- A persistent volume/dir for `/data` (SQLite job store, WAL mode)

## Run it

```bash
# 1. build (web/dist is committed prebuilt; no node needed on the host)
docker build -t fugu .

# 2. run — docker socket mounted so the chamber can spawn sibling containers
# 2. run. The two same-path mounts matter:
#    - docker.sock  : the chamber spawns victim/collector SIBLING containers
#    - /var/fugu/det-logs (same path host<->container): collector logs the
#      driver reads directly (canary watchdog, CA pickup). On Linux any
#      shared dir works; on Docker Desktop also add it to File Sharing.
mkdir -p /var/fugu/det-logs
docker run -d --name fugu \
  -p 80:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v fugu-data:/data \
  -v /var/fugu/det-logs:/var/fugu/det-logs \
  -e FUGU_DET_LOGS_DIR=/var/fugu/det-logs \
  -e NEBIUS_API_KEY=... \
  -e NEBIUS_BASE_URL=... \
  --restart unless-stopped \
  fugu
```

The socket mount is deliberate and scoped: the container needs to create
short-lived victim containers on host networks. If that is unacceptable for
your environment, run the chamber with the Sandboxes driver instead
(`FUGU_DRIVER=contree`) and drop the socket.

## Verified locally (Docker Desktop, macOS)

Full audit of `https://github.com/lharries/whatsapp-mcp` inside the
container: all 6 stages ok, detonation `triggers:2 detonations:2` in the
sibling-container chamber, LLM stages live against Token Factory, restart
persistence via `/data`. The image carries the `docker` CLI (copied from
`docker:cli`) and bakes mitm/DNS collectors into images — no host bind
mounts of app internals.

## Verify

```bash
curl -s http://<host>/api/health          # {"status":"ok", "stages":[...]}
# then submit an audit with executable content:
curl -s -X POST http://<host>/api/audits \
  -H 'Content-Type: application/json' \
  -d '{"source":"https://github.com/lharries/whatsapp-mcp","depth":"full"}'
```

## TLS

Terminate TLS at a reverse proxy (Caddy/nginx) or a cloud LB:

```
fugu.example.com {
  reverse_proxy 127.0.0.1:8000
}
```

Demo URLs judges open must be https. Also set SSE buffering off at the proxy
(`proxy_buffering off;` for nginx; Caddy defaults are fine) — the live pipeline
view is an SSE stream.

## Keep-alive through judging (Dec 1–15)

- `--restart unless-stopped` + persistent `/data` volume: the app survives
  reboots and deploys; job history survives restarts (verified: SQLite reload
  + SSE history replay).
- The demo host should be up from submission (Oct 30) through judging.
- Cheap is fine: audits are bounded (single-audit p95 well under a minute of
  CPU), so a small VM tier holds.

## Secrets

- `NEBIUS_API_KEY` / `NEBIUS_BASE_URL` — Token Factory inference (LLM stages)
- `TAVILY_API_KEY` (optional) — enables the S5 reputation stage
- Never bake them into the image; pass at `docker run` (or your platform's
  secret store).
