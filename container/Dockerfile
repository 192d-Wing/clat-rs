FROM rust:1.93-trixie AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/clat-rs /usr/local/bin/clat-rs
COPY config.example.toml /etc/clat-rs/config.toml

ENTRYPOINT ["clat-rs"]
CMD ["--config", "/etc/clat-rs/config.toml"]
