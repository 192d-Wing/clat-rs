# clat-rs

A CLAT (Customer-side translator) daemon implementing [RFC 6877](https://datatracker.ietf.org/doc/html/rfc6877) for 464XLAT IPv4/IPv6 address translation, written in Rust.

## What is 464XLAT?

464XLAT enables IPv4 connectivity over IPv6-only networks. It works with two components:

- **CLAT** (client-side) — translates IPv4 packets from LAN clients into IPv6 packets using stateless NAT46 (RFC 6052)
- **PLAT** (provider-side) — translates IPv6 packets back to IPv4 for the public internet (typically a NAT64 gateway)

clat-rs implements both sides of this architecture:

```
                    IPv6-only network
                    ┌──────────────────────────────┐
  LAN clients       │                              │       Internet
  ┌────────┐  IPv4  │  ┌─────────┐  IPv6  ┌─────┐  │ IPv4  ┌────────┐
  │ Host A ├────────┼──┤ clat-rs ├────────┤PLAT ├──┼───────┤ Server │
  │ Host B ├────────┼──┤  (CLAT) │        │NAT64│  │       └────────┘
  └────────┘        │  └─────────┘        └─────┘  │
                    └──────────────────────────────┘
```

## Key Features

### CLAT (Customer-side Translator)

- **Stateless IPv4/IPv6 translation** per RFC 6052 and RFC 6145
- **DHCPv6 Prefix Delegation** support with automatic /96 derivation
- **gRPC control plane** for runtime prefix updates (hot-swap without restart)
- **Multiple IPv4 subnets** served simultaneously

### PLAT (Provider-side NAT64 Gateway)

- **Stateful NAT64** per RFC 6146 with session table and IPv4 address pool
- **ICMP error translation** with embedded inner packet handling
- **IPv6/IPv4 fragment header translation**
- **Per-source rate limiting** for session creation
- **Packet validation** — bogon IPv4 destination and reserved IPv6 source filtering
- **Privilege dropping** after TUN device creation (Linux)
- **gRPC control plane** for status, session management, and prefix hot-swap

### Shared

- **Async I/O** built on tokio for concurrent packet processing and gRPC
- **Docker and systemd** deployment support

## Quick Start

```bash
# Build
cargo build --release

# Run with a config file
sudo ./target/release/clat-rs --config config.example.yml

# Query daemon status
clat-rs ctl status

# Update DHCPv6-PD prefix at runtime
clat-rs ctl set-prefix "2001:db8:aa00::/48"
```

Requires `CAP_NET_ADMIN` (or root) for TUN device creation.

## Documentation

- [Configuration](configuration.md) — config file reference and examples
- [Architecture](architecture.md) — module design and packet flow
- [gRPC API](grpc-api.md) — control plane reference
- [Deployment](deployment.md) — Docker, systemd, and DHCPv6-PD integration
- [Development](development.md) — building, testing, and contributing

## Standards Compliance

| RFC | Description |
|-----|-------------|
| [RFC 6877](https://datatracker.ietf.org/doc/html/rfc6877) | 464XLAT combination of stateful and stateless translation |
| [RFC 6146](https://datatracker.ietf.org/doc/html/rfc6146) | Stateful NAT64: Network Address and Protocol Translation |
| [RFC 6052](https://datatracker.ietf.org/doc/html/rfc6052) | IPv6 addressing of IPv4/IPv6 translators |
| [RFC 6145](https://datatracker.ietf.org/doc/html/rfc6145) | IP/ICMP translation algorithm |
| [RFC 1071](https://datatracker.ietf.org/doc/html/rfc1071) | Computing the Internet checksum |
