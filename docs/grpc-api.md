# gRPC API

clat-rs exposes a gRPC control plane for runtime management. The server listens on `[::1]:50051` by default (configurable via `--grpc-addr`).

## Service Definition

```protobuf
service ClatControl {
  rpc SetPrefix(SetPrefixRequest) returns (SetPrefixResponse);
  rpc GetStatus(GetStatusRequest) returns (StatusResponse);
}
```

The full protobuf definition is in `proto/clat.proto`.

## RPCs

### SetPrefix

Update the DHCPv6-PD prefix at runtime. The daemon derives the first /96 subnet and begins (or continues) translation immediately.

**Request:**

| Field | Type | Description |
|-------|------|-------------|
| `dhcpv6_pd_prefix` | string | DHCPv6-PD prefix in CIDR notation (e.g., `2001:db8:aa00::/48`) |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `derived_clat_prefix` | string | The /96 prefix now active for CLAT translation |

**Example (CLI):**

```bash
clat-rs ctl set-prefix "2001:db8:aa00::/48"
# Output: derived CLAT prefix: 2001:db8:aa00::/96
```

**Errors:**
- Invalid prefix format
- Prefix length > 96

### GetStatus

Query the current daemon state.

**Request:** empty

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `clat_prefix` | string | Active CLAT /96 prefix (empty if not yet set) |
| `plat_prefix` | string | PLAT /96 prefix from config |
| `uplink_interface` | string | Uplink interface name |
| `translating` | bool | Whether the packet loop is actively translating |

**Example (CLI):**

```bash
clat-rs ctl status
```

## Using with grpcurl

```bash
# Status
grpcurl -plaintext '[::1]:50051' clat.ClatControl/GetStatus

# Set prefix
grpcurl -plaintext -d '{"dhcpv6_pd_prefix": "2001:db8:aa00::/48"}' \
  '[::1]:50051' clat.ClatControl/SetPrefix
```

## Integration with DHCPv6-PD

The primary use case for the gRPC API is automated prefix updates from a DHCPv6-PD client. See [Deployment](deployment.md#dhcpv6-pd-integration) for the odhcp6c hook script that calls `SetPrefix` on prefix delegation events.
