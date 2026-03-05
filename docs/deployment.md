# Deployment

## Prerequisites

- Linux with TUN device support
- `CAP_NET_ADMIN` capability (or root) for TUN device creation
- An IPv6-only uplink with a NAT64/PLAT gateway

## Docker

### Build the Image

```bash
docker build -t clat-rs -f container/Dockerfile .
```

### Run

```bash
docker run --rm \
  --net=host \
  --cap-add=NET_ADMIN \
  -v /etc/clat-rs:/etc/clat-rs:ro \
  clat-rs --config /etc/clat-rs/config.yml --grpc-addr [::1]:50051
```

- `--net=host` is required for TUN device and raw socket access
- `--cap-add=NET_ADMIN` grants TUN creation permissions
- Mount your config file at `/etc/clat-rs/config.yml`

## systemd

### CLAT Daemon Service

Install the service unit from `deploy/clat-rs.service`:

```bash
sudo cp deploy/clat-rs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now clat-rs
```

The provided unit runs clat-rs via Docker. To run the binary directly, replace the `ExecStart` line:

```ini
ExecStart=/usr/local/bin/clat-rs --config /etc/clat-rs/config.yml --grpc-addr [::1]:50051
```

### DHCPv6-PD Integration

For dynamic prefix delegation, deploy both the DHCPv6-PD client and the hook script.

#### 1. Install the hook script

```bash
sudo mkdir -p /etc/odhcp6c/hook.d
sudo cp deploy/odhcp6c-hook.sh /etc/odhcp6c/hook.d/clat-rs.sh
sudo chmod +x /etc/odhcp6c/hook.d/clat-rs.sh
```

The hook script reacts to odhcp6c events (`bound`, `update`, `rebound`, `ra-updated`) and calls `clat-rs ctl set-prefix` via gRPC to update the daemon.

The gRPC address defaults to `[::1]:50051` and can be overridden with the `CLAT_RS_GRPC_ADDR` environment variable.

#### 2. Install the DHCPv6-PD service

```bash
sudo cp deploy/clat-dhcpv6.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Enable for your WAN interface (e.g., `eth0`):

```bash
sudo systemctl enable --now clat-dhcpv6@eth0
```

This runs `odhcp6c -P 48` requesting a /48 prefix delegation. Adjust the `-P` value in the unit file if your ISP delegates a different prefix length.

#### Service Ordering

The `clat-dhcpv6.service` unit is ordered `Before=clat-rs.service` so that:

1. odhcp6c starts and requests a prefix delegation
2. On receiving a prefix, the hook script calls `clat-rs ctl set-prefix`
3. clat-rs begins translation with the delegated prefix

If clat-rs starts before a prefix is available, it will wait (translation paused) until a prefix is provided via gRPC.

## Configuration

Place your config file at `/etc/clat-rs/config.yml`. See [Configuration](configuration.md) for the full reference.

When using DHCPv6-PD with the hook script, you can omit both `clat_v6_prefix` and `dhcpv6_pd_prefix` from the config — the prefix will be provided at runtime via gRPC.

## Logging

clat-rs uses `env_logger`. Control log level via the `RUST_LOG` environment variable:

```bash
RUST_LOG=info clat-rs --config config.yml
RUST_LOG=debug clat-rs --config config.yml
```

For the Docker deployment, add `-e RUST_LOG=info` to the `docker run` command or set it in the systemd unit's `Environment=` directive.
