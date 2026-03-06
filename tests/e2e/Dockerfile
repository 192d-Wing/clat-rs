# Multi-stage build for both clat-rs and plat-rs binaries
FROM rust:1.93-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release --package clat-rs --package plat-rs

# Runtime image with networking tools for testing
FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    tcpdump \
    iputils-ping \
    curl \
    ncat \
    socat \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/clat-rs /usr/local/bin/clat-rs
COPY --from=builder /build/target/release/plat-rs /usr/local/bin/plat-rs
