FROM dhi.io/rust:1.93 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY proto/ proto/
COPY src/ src/

RUN cargo build --release

FROM dhi.io/debian-base:trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/clat-rs /usr/local/bin/clat-rs
COPY config.example.yml /etc/clat-rs/config.yml

EXPOSE 50051

ENTRYPOINT ["clat-rs"]
CMD ["--config", "/etc/clat-rs/config.yml"]
