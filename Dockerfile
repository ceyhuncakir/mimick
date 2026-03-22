FROM python:3.12-slim

# System deps needed by security tools and Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git unzip nmap libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Install uv ──────────────────────────────────────────────────────
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# ── Install security tools via install-tools.sh ─────────────────────
# Uses pre-built GitHub release binaries (no Go SDK needed)
COPY install-tools.sh /tmp/install-tools.sh
RUN chmod +x /tmp/install-tools.sh \
    && /tmp/install-tools.sh \
    && rm /tmp/install-tools.sh
ENV PATH="/root/go/bin:/root/.local/bin:${PATH}"

# ── Install mimick ──────────────────────────────────────────────────
WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock .python-version README.md ./

# Install dependencies (cached unless lock changes)
RUN uv sync --frozen --no-install-project

# Copy source code, docs, and prompt templates
COPY src/ src/
COPY docs/ docs/
COPY prompts/ prompts/

# Install the project itself
RUN uv sync --frozen

# ── Install Playwright + Chromium browser ─────────────────────────
RUN uv run playwright install --with-deps chromium

# ── Copy .env for API keys ──────────────────────────────────────────
COPY .env .env

# ── Runtime config ──────────────────────────────────────────────────
ENV MIMICK_OUTPUT_DIR=/app/results
VOLUME ["/app/results"]
EXPOSE 8117

ENTRYPOINT ["/bin/sh", "-c", "set -a; . /app/.env 2>/dev/null; set +a; exec uv run mimick \"$@\"", "--"]
CMD ["--help"]
