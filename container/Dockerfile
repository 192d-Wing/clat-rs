FROM rust:1.93-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY proto/ proto/
COPY src/ src/

RUN cargo build --release

FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create runtime directories for UDS sockets and a non-root user
RUN groupadd --system clat \
    && useradd --system --gid clat --no-create-home --shell /usr/sbin/nologin clat \
    && install -d -m 0750 -o clat -g clat /run/clat-rs

COPY --from=builder /build/target/release/clat-rs /usr/local/bin/clat-rs
COPY config.example.yml /etc/clat-rs/config.yml

# Run as non-root. TUN creation requires CAP_NET_ADMIN which must be
# granted at container runtime:
#   docker run --cap-drop=ALL --cap-add=NET_ADMIN ...
USER clat

ENTRYPOINT ["clat-rs"]
CMD ["--config", "/etc/clat-rs/config.yml"]
