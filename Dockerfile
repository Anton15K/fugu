# Fugu — single-image deploy (API + SPA + detonation chamber)
#
# The chamber shells out to `docker`, so this image runs as a container that
# mounts the host docker socket (docker-in-docker is NOT used — victims are
# sibling containers on a host network, exactly like local dev). See
# docs/deploy.md.
FROM rust:1-bookworm AS static-rules-builder
WORKDIR /build
RUN curl --fail --silent --show-error --location \
      https://codeload.github.com/ksek87/fuzzd/tar.gz/f739e120cd7dc253fead2a1f13668f9535e4d8a5 \
      -o /tmp/static-rules.tar.gz \
    && tar -xzf /tmp/static-rules.tar.gz --strip-components=1 \
    && cargo build --locked --release --bin fuzzd

FROM python:3.11-slim

# tini: proper signal handling + zombie reaping (victim containers' shells)
# docker CLI: the detonation chamber shells out to it (victim + collectors run
# as SIBLING containers via the mounted host socket — see docs/deploy.md)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app
COPY --from=static-rules-builder /build/target/release/fuzzd /opt/fugu/static-rules
COPY THIRD_PARTY_NOTICES.md /opt/fugu/THIRD_PARTY_NOTICES.md

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
    FUGU_STATIC_RULES_BINARY=/opt/fugu/static-rules \
    PYTHONUNBUFFERED=1

VOLUME /data

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uv", "run", "--no-sync", "python", "-m", "fugu.server", "--host", "0.0.0.0", "--port", "8000", "--db", "/data/fugu.db"]
