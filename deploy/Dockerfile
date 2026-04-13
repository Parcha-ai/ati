# ATI Proxy — Agent Tools Interface
# Downloads pre-built binary from GitHub releases. No compilation needed.

ARG ATI_VERSION=v0.7.7

FROM debian:bookworm-slim

ARG ATI_VERSION

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --create-home ati

# Node.js for MCP stdio providers (e.g., GitHub MCP server via npx)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Download pre-built static binary with Sentry support from GitHub releases (multi-arch)
ARG TARGETARCH
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x86_64") && \
    curl -fSL "https://github.com/Parcha-ai/ati/releases/download/${ATI_VERSION}/ati-${ARCH}-unknown-linux-musl-sentry" \
    -o /usr/local/bin/ati && \
    curl -fSL "https://github.com/Parcha-ai/ati/releases/download/${ATI_VERSION}/ati-${ARCH}-unknown-linux-musl-sentry.sha256" \
    -o /tmp/ati.sha256 && \
    EXPECTED=$(awk '{print $1}' /tmp/ati.sha256) && \
    echo "${EXPECTED}  /usr/local/bin/ati" | sha256sum -c - && \
    rm /tmp/ati.sha256 && \
    chmod +x /usr/local/bin/ati

ENV ATI_DIR=/app
COPY manifests/ /app/manifests/
COPY specs/ /app/specs/

WORKDIR /app
USER ati
EXPOSE 18093

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:18093/health || exit 1

CMD ["ati", "proxy", "--port", "18093", "--bind", "0.0.0.0"]
