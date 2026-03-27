# ATI Proxy — Agent Tools Interface
# Multi-stage build: compile Rust binary, then copy to slim runtime image.

FROM rust:1.82-slim-bookworm AS builder
WORKDIR /app

# Cache dependency compilation: copy manifests first, build a dummy,
# then copy real source. This avoids re-downloading crates on every code change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    mkdir -p src/cli src/core src/output src/providers src/proxy src/security && \
    touch src/lib.rs src/cli/mod.rs src/core/mod.rs src/output/mod.rs \
          src/providers/mod.rs src/proxy/mod.rs src/security/mod.rs && \
    cargo build --release --locked 2>/dev/null || true && \
    rm -rf src

# Now copy real source and build
COPY src/ src/
RUN cargo build --release --locked

# Runtime image — minimal, no Rust toolchain
FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home ati

COPY --from=builder /app/target/release/ati /usr/local/bin/ati
COPY manifests/ /app/manifests/

WORKDIR /app
USER ati
EXPOSE 18093

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:18093/health || exit 1

CMD ["ati", "proxy", "--port", "18093", "--bind", "0.0.0.0"]
