FROM python:3.12-slim AS base

# System deps needed by security tools and builds
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git unzip nmap libpcap-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# ── Install uv ──────────────────────────────────────────────────────
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# ── Install Go (needed to build security tools) ─────────────────────
ARG GO_VERSION=1.23.4
RUN arch=$(dpkg --print-architecture) \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" \
       | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# ── Install Go-based security tools ─────────────────────────────────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && CGO_ENABLED=1 go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && go install -v github.com/hahwul/dalfox/v2@latest

# ── Install Python-based security tools via uv ──────────────────────
RUN uv tool install wafw00f \
    && uv tool install arjun
ENV PATH="/root/.local/bin:${PATH}"

# ── Install sqlmap ──────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# ── Install cannon ──────────────────────────────────────────────────
WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock .python-version README.md ./

# Install dependencies (cached unless lock changes)
RUN uv sync --frozen --no-install-project

# Copy source code and docs
COPY src/ src/
COPY docs/ docs/

# Install the project itself
RUN uv sync --frozen

# ── Install Playwright + Chromium browser ─────────────────────────
# Install system deps required by Chromium, then install the browser
RUN uv run playwright install --with-deps chromium

# ── Runtime config ──────────────────────────────────────────────────
ENV CANNON_OUTPUT_DIR=/app/results
VOLUME ["/app/results"]
EXPOSE 8117

ENTRYPOINT ["uv", "run", "cannon"]
CMD ["--help"]
