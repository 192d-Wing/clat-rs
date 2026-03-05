# Architecture

## Module Overview

```
src/
├── main.rs          CLI entry point, daemon initialization, gRPC server spawn
├── config.rs        YAML config loading, validation, DHCPv6-PD /96 derivation
├── state.rs         Shared daemon state (tokio::sync::watch for prefix hot-swap)
├── packet_loop.rs   Main async loop: TUN read/write + raw IPv6 socket I/O
├── translate.rs     Core IPv4↔IPv6 packet translation (RFC 6877)
├── addr.rs          RFC 6052 /96 address embedding and extraction
├── checksum.rs      Internet checksum (RFC 1071): header, pseudo-header, incremental
├── icmp.rs          ICMP↔ICMPv6 type/code mapping (RFC 6145)
├── grpc.rs          Tonic gRPC service implementation (SetPrefix, GetStatus)
├── ctl.rs           gRPC client for CLI control commands
└── tun_device.rs    TUN device creation with address/netmask/MTU configuration
```

## Packet Flow

```
                         ┌─────────────────────────────────────────────┐
                         │               clat-rs daemon                │
                         │                                             │
  LAN (IPv4)             │  ┌───────────┐     ┌─────────────────┐      │  WAN (IPv6)
  ──────────────────────►│  │ TUN clat0 │────►│  ipv4_to_ipv6() │──────┼──────────────►
  IPv4 packets           │  │           │     │  translate.rs   │      │  IPv6 packets
                         │  │           │     └─────────────────┘      │  (raw socket)
  ◄──────────────────────│  │           │◄────┌─────────────────┐      │
  IPv4 packets           │  └───────────┘     │  ipv6_to_ipv4() │◄─────┼──────────────
                         │                    │  translate.rs   │      │  IPv6 packets
                         │                    └─────────────────┘      │
                         │                                             │
                         │  ┌───────────────┐   ┌──────────────┐       │
                         │  │ gRPC server   │◄──│ SharedState  │       │
                         │  │ [::1]:50051   │──►│ (watch)      │       │
                         │  └───────────────┘   └──────────────┘       │
                         └─────────────────────────────────────────────┘
```

### Startup Sequence

1. Parse CLI arguments and load YAML config
2. Resolve initial CLAT prefix (explicit, DHCPv6-PD derived, or deferred to gRPC)
3. Create `SharedState` with tokio watch channels for prefix updates
4. Spawn gRPC control server on `[::1]:50051`
5. Create TUN device `clat0` with configured IPv4 address/networks/MTU
6. Enter packet loop

### Packet Loop (`packet_loop::run`)

The main loop uses `tokio::select!` to concurrently handle:

- **Prefix watch** — reacts to gRPC-triggered prefix updates, hot-swaps CLAT /96 without restart
- **TUN read** — receives IPv4 packets from LAN, translates to IPv6 via `ipv4_to_ipv6()`, sends on raw IPv6 socket
- **Raw IPv6 recv** — receives IPv6 packets from uplink, translates to IPv4 via `ipv6_to_ipv4()`, writes to TUN
- **Signal handling** — graceful shutdown on SIGINT/SIGTERM

### Translation Logic

**IPv4 → IPv6** (`translate::ipv4_to_ipv6`):

1. Parse IPv4 header (etherparse)
2. Embed source IPv4 in CLAT /96 prefix (RFC 6052)
3. Embed destination IPv4 in PLAT /96 prefix
4. Build IPv6 header (traffic class from TOS, hop limit from TTL)
5. Translate ICMP → ICMPv6 or pass TCP/UDP with checksum adjustment

**IPv6 → IPv4** (`translate::ipv6_to_ipv4`):

1. Verify source matches PLAT prefix and destination matches CLAT prefix
2. Extract IPv4 addresses from last 32 bits of each /96
3. Build IPv4 header with computed header checksum
4. Translate ICMPv6 → ICMP or pass TCP/UDP with checksum adjustment

### Address Embedding (RFC 6052)

For /96 prefixes, the IPv4 address occupies the last 32 bits of the 128-bit IPv6 address:

```
/96 prefix (96 bits)                    IPv4 (32 bits)
┌──────────────────────────────────────┬───────────────┐
│  2001:0db8:aaaa:0000:0000:0000       │  c0a8:0102    │
└──────────────────────────────────────┴───────────────┘
Result: 2001:db8:aaaa::c0a8:0102  (embeds 192.168.1.2)
```

### Checksum Handling

- **IPv4 header checksum**: Computed from scratch (RFC 1071)
- **TCP/UDP pseudo-header**: Incremental adjustment — subtracts old (IPv4 or IPv6) pseudo-header contribution and adds new, avoiding full payload re-checksum
- **ICMPv6**: Includes IPv6 pseudo-header in checksum (unlike ICMPv4), requiring conversion during translation

### State Management

`SharedState` uses `tokio::sync::watch` channels to broadcast prefix updates from the gRPC server to the packet loop without locks or restarts. The packet loop pauses translation when no CLAT prefix is available and resumes immediately when one is set.
