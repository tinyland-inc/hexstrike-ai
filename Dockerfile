# HexStrike-AI (tinyland-inc/hexstrike-ai) — standalone Dockerfile
#
# No upstream Dockerfile exists. This builds from the Python source:
# - Flask REST API server on port 8888
# - Core Python dependencies (flask, requests, psutil, fastmcp, beautifulsoup4)
# - Skips heavy binary analysis deps (pwntools, angr, mitmproxy, selenium)
#   to keep the image small. These can be added via HEXSTRIKE_EXTRA_DEPS build arg.
# - Common security CLI tools installed from Alpine packages
#
# Build context: repo root
# GHCR workflow builds from main branch pushes.

FROM python:3.12-alpine

# Install common security tools + build deps for Python C extensions (psutil).
RUN apk add --no-cache \
    ca-certificates \
    curl \
    git \
    openssh-client \
    nmap \
    nmap-scripts \
    openssl \
    bind-tools \
    wget \
    netcat-openbsd \
    gcc \
    musl-dev \
    linux-headers \
    python3-dev \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Install core Python dependencies only.
# The full requirements.txt includes pwntools/angr/mitmproxy which need
# glibc and add ~2GB. We install a curated subset for the Flask API server.
COPY requirements.txt ./requirements-full.txt
RUN pip install --no-cache-dir \
    'flask>=2.3.0,<4.0.0' \
    'requests>=2.31.0,<3.0.0' \
    'psutil>=5.9.0,<6.0.0' \
    'fastmcp>=0.2.0,<1.0.0' \
    'beautifulsoup4>=4.12.0,<5.0.0' \
    'aiohttp>=3.8.0,<4.0.0' \
    && apk del gcc musl-dev linux-headers python3-dev

# Optional: install extra deps at build time.
# Build with: docker build --build-arg HEXSTRIKE_EXTRA_DEPS="selenium webdriver-manager" ...
ARG HEXSTRIKE_EXTRA_DEPS=""
RUN if [ -n "$HEXSTRIKE_EXTRA_DEPS" ]; then \
      pip install --no-cache-dir $HEXSTRIKE_EXTRA_DEPS; \
    fi

# Copy application source
COPY . .

# Create non-root user
RUN addgroup -g 1000 hexstrike && \
    adduser -D -u 1000 -G hexstrike hexstrike && \
    mkdir -p /workspace /results && \
    chown -R hexstrike:hexstrike /app /workspace /results

USER hexstrike

# --- tinyland customizations ---

# Flask REST API server — bridges adapter sidecar to security tools.
# This file lives in deploy/fork-dockerfiles/hexstrike-ai/ in RemoteJuggler
# and is pushed to the repo via push-to-forks.sh.
COPY --chown=hexstrike:hexstrike hexstrike_server.py /app/hexstrike_server.py

# Workspace bootstrap files -- copied to /workspace-defaults/ so the K8s init
# container can seed the PVC on first boot without overwriting evolved state.
COPY --chown=hexstrike:hexstrike tinyland/workspace/ /workspace-defaults/

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://localhost:8888/health || exit 1

# Start Flask REST API server.
# The adapter sidecar communicates via POST /api/command.
CMD ["python3", "hexstrike_server.py", "--host", "0.0.0.0", "--port", "8888"]
