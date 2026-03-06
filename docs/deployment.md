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

## Fedora CoreOS

Fedora CoreOS is the recommended OS for production XDP deployments. Its immutable
filesystem, automatic kernel updates with rollback, and rolling release model keep
the XDP/AF_XDP stack current without manual intervention.

### Butane Configuration

Create a Butane config (`clat-rs.bu`) to provision the node with clat-rs on first boot:

```yaml
variant: fcos
version: "1.5.0"
storage:
  files:
    - path: /etc/clat-rs/config.yml
      mode: 0644
      contents:
        inline: |
          clat_ipv4_addr: 192.168.1.1
          clat_ipv4_networks:
            - "192.168.1.0/24"
          clat_v6_prefix: "2001:db8:aaaa::/96"
          plat_v6_prefix: "64:ff9b::/96"
          uplink_interface: eth0
          xdp:
            xdp_program: /usr/lib/clat-rs/clat-xdp
            zero_copy: true
            busy_poll: true
            gateway_mac: "aa:bb:cc:dd:ee:ff"

    - path: /usr/lib/clat-rs/clat-xdp
      mode: 0644
      contents:
        source: https://your-artifact-server/clat-xdp

systemd:
  units:
    - name: clat-rs.service
      enabled: true
      contents: |
        [Unit]
        Description=clat-rs CLAT daemon (XDP)
        After=network-online.target
        Wants=network-online.target

        [Service]
        ExecStart=/usr/bin/podman run --rm --name clat-rs \
          --net=host \
          --privileged \
          -v /etc/clat-rs:/etc/clat-rs:ro \
          -v /usr/lib/clat-rs:/usr/lib/clat-rs:ro \
          -v /sys/fs/bpf:/sys/fs/bpf \
          ghcr.io/your-org/clat-rs:latest \
          --config /etc/clat-rs/config.yml
        ExecStop=/usr/bin/podman stop clat-rs
        Restart=on-failure
        RestartSec=5s

        [Install]
        WantedBy=multi-user.target
```

Transpile to Ignition and provision:

```bash
butane --strict < clat-rs.bu > clat-rs.ign
```

### Container Capabilities for XDP

XDP requires access to BPF syscalls, the host network namespace, and NIC hardware.
The simplest approach is `--privileged`. For a tighter security posture, use granular
capabilities:

```bash
podman run --rm \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=BPF \
  --cap-add=SYS_RESOURCE \
  --security-opt=no-new-privileges \
  -v /etc/clat-rs:/etc/clat-rs:ro \
  -v /usr/lib/clat-rs:/usr/lib/clat-rs:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ghcr.io/your-org/clat-rs:latest \
  --config /etc/clat-rs/config.yml
```

- `NET_ADMIN` — TUN device creation and XDP program attachment
- `BPF` — loading eBPF programs and creating BPF maps
- `SYS_RESOURCE` — locking UMEM memory (`RLIMIT_MEMLOCK`)
- `--net=host` — required for NIC access and TUN device visibility

### Automatic Updates

Fedora CoreOS updates itself via [Zincati](https://coreos.github.io/zincati/).
Updates apply a new OS image and reboot. The clat-rs container restarts automatically
via the systemd unit.

To control the update schedule (e.g., maintenance windows):

```bash
# Check update status
rpm-ostree status

# Pin the current deployment to prevent rollback cleanup
sudo ostree admin pin 0
```

Configure Zincati's update strategy in `/etc/zincati/config.d/`:

```toml
# /etc/zincati/config.d/55-updates-strategy.toml
[updates]
strategy = "periodic"

[[updates.periodic.window]]
days = ["Sat"]
start_time = "02:00"
length_minutes = 120
```

### NIC Tuning on CoreOS

Since the filesystem is immutable, apply NIC tuning via a oneshot systemd unit:

```ini
# /etc/systemd/system/nic-tuning.service
[Unit]
Description=NIC tuning for XDP
After=network-online.target
Before=clat-rs.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ethtool -G eth0 rx 4096 tx 4096
ExecStart=/usr/sbin/ethtool -K eth0 rx on tx on

[Install]
WantedBy=multi-user.target
```

Add this unit to your Butane config under `systemd.units`.

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
