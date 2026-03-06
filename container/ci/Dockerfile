FROM rust:1.93-trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy llvm-tools-preview

RUN cargo install --locked cargo-audit cargo-nextest cargo-llvm-cov

# Install Task (go-task) runner
RUN sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin
