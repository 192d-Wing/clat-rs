# Development

## Requirements

- Rust 1.93+ (edition 2024)
- `protobuf-compiler` (protoc) for gRPC code generation
- [Task](https://taskfile.dev/) (optional, for task automation)
- [cargo-nextest](https://nexte.st/) for running tests
- [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) for coverage reports
- [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit) for dependency security audits

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Using Taskfile
task build
task release
```

## Testing

```bash
# Run tests with nextest
task test

# Or directly
cargo nextest run
```

## Code Coverage

```bash
# HTML report (opens in target/llvm-cov/html/)
task coverage

# Terminal summary
task coverage-text

# LCOV format (for CI integration)
task coverage-lcov
```

## Pre-commit Checklist

Before committing, always run:

```bash
task pre-commit
```

This runs (in order):
1. `cargo fmt` — format code
2. `cargo clippy -- -D warnings` — lint with warnings as errors
3. `cargo audit` — check for known vulnerabilities
4. `cargo nextest run` — run tests

Or run each step individually:

```bash
task fmt
task clippy
task audit
task test
```

## CI Checks

To verify without modifying files (useful in CI):

```bash
task check
```

This runs `fmt-check` (no modifications), clippy, audit, and tests.

## Available Tasks

| Task | Description |
|------|-------------|
| `task build` | Debug build |
| `task release` | Release build |
| `task test` | Run tests with nextest |
| `task coverage` | HTML coverage report |
| `task coverage-text` | Terminal coverage summary |
| `task coverage-lcov` | LCOV coverage report |
| `task fmt` | Format code |
| `task fmt-check` | Check formatting (no changes) |
| `task clippy` | Run clippy lints |
| `task audit` | Security audit |
| `task check` | fmt-check + clippy + audit + test |
| `task pre-commit` | fmt + clippy + audit + test |
| `task clean` | Remove build artifacts |

## Project Structure

```
clat-rs/
├── src/                    Source code (see architecture.md)
├── proto/clat.proto        gRPC service definition
├── build.rs                Protobuf compilation build script
├── config.example.yml      Example configuration
├── config.schema.json      JSON Schema for config validation
├── container/Dockerfile    Docker multi-stage build
├── deploy/                 systemd units and DHCPv6-PD hook
├── docs/                   Documentation
├── Cargo.toml              Dependencies and package metadata
└── Taskfile.yml            Task automation
```
