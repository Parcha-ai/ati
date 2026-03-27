# ATI Proxy — Agent Tools Interface
# Downloads pre-built binary from GitHub releases. No compilation needed.

ARG ATI_VERSION=v0.6.0

FROM debian:bookworm-slim

ARG ATI_VERSION

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home ati

# Download pre-built static binary from GitHub releases
RUN curl -fSL "https://github.com/Parcha-ai/ati/releases/download/${ATI_VERSION}/ati-x86_64-unknown-linux-musl" \
    -o /usr/local/bin/ati && \
    chmod +x /usr/local/bin/ati

COPY manifests/ /app/manifests/

WORKDIR /app
USER ati
EXPOSE 18093

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:18093/health || exit 1

CMD ["ati", "proxy", "--port", "18093", "--bind", "0.0.0.0"]
