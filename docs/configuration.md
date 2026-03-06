# Configuration

clat-rs is configured via a YAML file, validated against `config.schema.json`. The default path is `/etc/clat-rs/config.yml`.

## Example

```yaml
# yaml-language-server: $schema=config.schema.json

clat_ipv4_addr: "192.168.1.1"
clat_ipv4_networks:
  - "192.168.1.0/24"

# Option A: explicit /96 prefix
# clat_v6_prefix: "2001:db8:aaaa::/96"

# Option B: DHCPv6-PD prefix (first /96 derived automatically)
dhcpv6_pd_prefix: "2001:db8:aaaa::/48"

plat_v6_prefix: "64:ff9b::/96"
uplink_interface: "eth0"
mtu: 1400
```

## Reference

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `clat_ipv4_addr` | string | IPv4 address assigned to the CLAT TUN interface. Acts as the gateway for LAN clients. |
| `clat_ipv4_networks` | string[] | IPv4 subnets served by the CLAT in CIDR notation. At least one required. |
| `plat_v6_prefix` | string | /96 IPv6 prefix for PLAT-side (destination) address embedding. Use `64:ff9b::/96` for the well-known NAT64 prefix. |
| `uplink_interface` | string | Host network interface used for IPv6 uplink (e.g., `eth0`). |

### CLAT Prefix (one of three options)

The CLAT /96 prefix determines the IPv6 source address used for translated packets. Configure it in one of three ways:

| Field | Type | Description |
|-------|------|-------------|
| `clat_v6_prefix` | string | Explicit /96 IPv6 prefix for CLAT-side address embedding. |
| `dhcpv6_pd_prefix` | string | DHCPv6 Prefix Delegation prefix (e.g., `/48`, `/56`). The first /96 is derived automatically. |
| *(neither)* | — | Prefix provided at runtime via gRPC `SetPrefix` RPC (see [gRPC API](grpc-api.md)). Translation is paused until a prefix is received. |

**Priority order**: `clat_v6_prefix` > `dhcpv6_pd_prefix` > gRPC runtime.

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mtu` | integer | `1400` | TUN interface MTU. Range: 1280–9000. Should be ≤1440 to avoid fragmentation from the 20-byte larger IPv6 header. |

## DHCPv6-PD Prefix Derivation

When `dhcpv6_pd_prefix` is set, the first /96 subnet is derived by zero-padding:

| Input | Derived /96 |
|-------|-------------|
| `2001:db8:aaaa::/48` | `2001:db8:aaaa::/96` |
| `2001:db8:aa00::/56` | `2001:db8:aa00::/96` |
| `2001:db8:aaaa:bbbb::/64` | `2001:db8:aaaa:bbbb::/96` |

Prefixes longer than /96 are rejected.

## CLI Arguments

```
clat-rs [OPTIONS] [COMMAND]

Options:
  -c, --config <PATH>       Config file path [default: /etc/clat-rs/config.yml]
      --grpc-addr <ADDR>    gRPC listen address [default: [::1]:50051]

Commands:
  ctl    Control a running clat-rs daemon via gRPC

Control subcommands:
  clat-rs ctl set-prefix <PREFIX>    Set DHCPv6-PD prefix on the running daemon
  clat-rs ctl status                 Query daemon status
```

## Schema Validation

The `config.schema.json` file provides JSON Schema (draft-07) validation. Editors supporting YAML Language Server can use the `$schema` directive for autocompletion and validation:

```yaml
# yaml-language-server: $schema=config.schema.json
```

---

## PLAT Configuration (plat-rs)

The PLAT daemon (`plat-rs`) uses a separate config file, defaulting to `/etc/plat-rs/config.yml`.

### Example

```yaml
nat64_prefix: "64:ff9b::/96"
ipv4_pool:
  - "198.51.100.0/24"
uplink_interface: eth0
egress_interface: eth1
mtu: 1500

session:
  max_sessions: 65536
  tcp_timeout_secs: 7200
  udp_timeout_secs: 300
  icmp_timeout_secs: 60

port_range: [1024, 65535]

security:
  max_new_sessions_per_source: 100
  rate_window_secs: 1
  reject_bogon_v4_dst: true
  reject_reserved_v6_src: true
  drop_uid: 65534   # nobody (Linux only, 0 = disabled)
  drop_gid: 65534
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `nat64_prefix` | string | NAT64 /96 prefix in CIDR notation (e.g., `64:ff9b::/96`) |
| `ipv4_pool` | string[] | IPv4 address pool for NAT bindings, in CIDR notation |
| `uplink_interface` | string | IPv6-facing uplink interface name |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `egress_interface` | string | *uplink_interface* | IPv4-facing egress interface (defaults to uplink) |
| `mtu` | integer | `1500` | TUN interface MTU |
| `port_range` | [u16, u16] | `[1024, 65535]` | Ephemeral port range for NAT pool |
| `grpc_addr` | string | `[::1]:50052` | gRPC control server listen address |

### Session Configuration (`session`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_sessions` | integer | `65536` | Maximum concurrent NAT64 sessions |
| `tcp_timeout_secs` | integer | `7200` | TCP session idle timeout (seconds) |
| `udp_timeout_secs` | integer | `300` | UDP session idle timeout (seconds) |
| `icmp_timeout_secs` | integer | `60` | ICMP session idle timeout (seconds) |

### Security Configuration (`security`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_new_sessions_per_source` | integer | `100` | Max new sessions a single IPv6 source can create per rate window |
| `rate_window_secs` | integer | `1` | Rate limiting window duration (seconds) |
| `reject_bogon_v4_dst` | bool | `true` | Drop packets targeting bogon IPv4 addresses (RFC 1918, loopback, multicast, link-local) |
| `reject_reserved_v6_src` | bool | `true` | Drop packets from reserved IPv6 sources (loopback, unspecified, multicast, v4-mapped) |
| `drop_uid` | integer | `0` | Drop to this UID after TUN creation (Linux only, 0 = disabled) |
| `drop_gid` | integer | `0` | Drop to this GID after TUN creation (Linux only, 0 = disabled) |

### PLAT CLI Arguments

```text
plat-rs [OPTIONS] [COMMAND]

Options:
  -c, --config <PATH>       Config file path [default: /etc/plat-rs/config.yml]
      --grpc-addr <ADDR>    gRPC listen address [default: [::1]:50052]

Commands:
  ctl    Control a running plat-rs daemon via gRPC

Control subcommands:
  plat-rs ctl set-prefix <PREFIX>       Set NAT64 prefix on the running daemon
  plat-rs ctl status                     Query daemon status
  plat-rs ctl list-sessions [-l LIMIT]   List active NAT64 sessions
  plat-rs ctl flush-sessions             Flush all active sessions
```
