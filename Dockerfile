# Fugu — single-image deploy (API + SPA + detonation chamber)
#
# The chamber shells out to `docker`, so this image runs as a container that
# mounts the host docker socket (docker-in-docker is NOT used — victims are
# sibling containers on a host network, exactly like local dev). See
# docs/deploy.md.
FROM python:3.11-slim

# tini: proper signal handling + zombie reaping (victim containers' shells)
# docker CLI: the detonation chamber shells out to it (victim + collectors run
# as SIBLING containers via the mounted host socket — see docs/deploy.md)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app

# uv for fast, locked installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# app code (web/dist ships prebuilt in the repo)
COPY README.md pyproject.toml uv.lock ./
COPY src ./src
COPY web/dist ./web/dist
RUN uv sync --frozen --no-dev

ENV FUGU_DB=/data/fugu.db \
    PYTHONUNBUFFERED=1

VOLUME /data

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uv", "run", "--no-sync", "python", "-m", "fugu.server", "--host", "0.0.0.0", "--port", "8000", "--db", "/data/fugu.db"]
