# XDP/AF_XDP Acceleration

clat-rs supports hardware-accelerated packet processing via Linux XDP (eXpress Data Path)
and AF_XDP sockets. This bypasses the kernel network stack on the IPv6 side, providing
zero-copy packet I/O directly between the NIC and userspace.

## Supported Hardware

Any NIC with an XDP-capable driver works. NICs with AF_XDP zero-copy support get the
best performance:

| NIC | Driver | XDP | AF_XDP Zero-Copy |
|-----|--------|-----|------------------|
| Intel X710 | `i40e` | Yes | Yes |
| Intel X550 | `ixgbe` | Yes | Yes |
| Intel E810 | `ice` | Yes | Yes |
| Mellanox ConnectX-5+ | `mlx5` | Yes | Yes |
| Generic (any NIC) | any | Via `SKB_MODE` | No (copy mode) |

## Architecture

```
Without XDP (default):
  NIC → kernel stack → raw socket → userspace → translate → TUN → apps
  apps → TUN → userspace → translate → raw socket → kernel stack → NIC

With XDP:
  NIC → XDP program → AF_XDP socket → userspace → translate → TUN → apps
  apps → TUN → userspace → translate → AF_XDP TX ring → NIC
```

The XDP eBPF program runs in the NIC driver's receive path. It inspects each incoming
Ethernet frame and redirects IPv6 packets matching the CLAT /96 prefix to an AF_XDP
socket. All other traffic passes through the kernel stack normally.

The IPv4 side still uses a TUN device (`clat0`) so translated packets are delivered
to local applications through the normal kernel routing table.

## Prerequisites

- Linux kernel >= 5.4 (for AF_XDP zero-copy); >= 6.0 recommended for mature
  AF_XDP batch APIs and best zero-copy driver support (`ice`, `mlx5`)
- Rust nightly toolchain (for building the eBPF program)
- `bpf-linker` (install via `cargo install bpf-linker`)
- `CAP_NET_ADMIN` + `CAP_BPF` (or root)

**Recommended OS:** Fedora CoreOS — rolling kernel updates keep the XDP/AF_XDP
stack current, and the immutable image model suits single-purpose CLAT appliances.
See [Deployment — Fedora CoreOS](deployment.md#fedora-coreos) for provisioning
instructions.

## Building

### 1. Build the eBPF XDP program

The eBPF program is a separate crate that cross-compiles to BPF bytecode:

```bash
cd crates/clat-xdp-ebpf
cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release
```

The compiled object file will be at:
```
target/bpfel-unknown-none/release/clat-xdp
```

### 2. Build clat-rs with XDP support

```bash
cargo build -p clat-rs --features xdp --release
```

## Configuration

Add an `xdp` section to your config YAML:

```yaml
clat_ipv4_addr: 192.168.1.1
clat_ipv4_networks:
  - "192.168.1.0/24"
clat_v6_prefix: "2001:db8:aaaa::/96"
plat_v6_prefix: "64:ff9b::/96"
uplink_interface: eth0

xdp:
  # Path to the compiled eBPF object file (required)
  xdp_program: /usr/lib/clat-rs/clat-xdp

  # NIC RX queue to bind (default: 0)
  queue_id: 0

  # Enable zero-copy mode (requires driver support)
  # Falls back to copy mode (XDP_COPY) when false
  zero_copy: true

  # Dedicate a CPU core to busy-polling (lowest latency, highest throughput)
  # When false, uses poll()+sleep when idle (~10us wake latency)
  busy_poll: true

  # Gateway MAC address for outbound Ethernet headers (required)
  # This is the MAC of your upstream router/gateway on the uplink interface
  gateway_mac: "aa:bb:cc:dd:ee:ff"

  # UMEM buffer pool size (default: 4096 frames)
  umem_frames: 4096

  # UMEM frame size in bytes (default: 4096, valid: 2048 or 4096)
  frame_size: 4096
```

### Finding your gateway MAC

```bash
# Get the default gateway IP
ip -6 route show default dev eth0

# Look up its MAC in the neighbor table
ip -6 neigh show dev eth0
```

## How It Works

### eBPF XDP Program (`clat-xdp-ebpf`)

The XDP program runs at the earliest point in the kernel receive path, before any
socket or protocol processing. For each incoming frame it:

1. Checks the EtherType is IPv6 (`0x86DD`)
2. Compares the destination IPv6 address's first 12 bytes against the CLAT /96 prefix
   stored in a BPF `Array` map (three u32 comparisons)
3. On match: redirects the frame to the AF_XDP socket via `XskMap` for the RX queue
4. On mismatch: returns `XDP_PASS` to let the kernel handle it normally

The prefix is stored in a BPF map so it can be updated at runtime (hot-swap via gRPC)
without reloading the XDP program.

### AF_XDP Sockets

AF_XDP provides a fast path between the NIC and userspace using shared memory (UMEM):

- **UMEM**: A pre-allocated, page-aligned memory region divided into fixed-size frames.
  In zero-copy mode the NIC DMA's directly into/from these frames.
- **Fill Ring**: Userspace provides empty frame addresses for the kernel to fill with
  received packets.
- **RX Ring**: Kernel delivers received packet descriptors (UMEM address + length).
- **TX Ring**: Userspace submits packet descriptors for transmission.
- **Completion Ring**: Kernel returns frame addresses after TX DMA completes.

### Packet Loop

The XDP packet loop runs on a dedicated OS thread (not tokio) for deterministic latency:

**RX path (inbound):**
1. Batch-receive up to 64 descriptors from the AF_XDP RX ring
2. For each frame: strip the 14-byte Ethernet header, pass IPv6 payload through
   `nat64_core::translate::ipv6_to_ipv4`
3. Write the translated IPv4 packet to the TUN device
4. Return the UMEM frame to the allocator

**TX path (outbound):**
1. Non-blocking read from the TUN device
2. Translate IPv4 to IPv6 via `nat64_core::translate::ipv4_to_ipv6`
3. Allocate a UMEM frame, write Ethernet header (dst MAC, src MAC, EtherType) +
   IPv6 payload
4. Submit the descriptor to the AF_XDP TX ring
5. Call `sendto()` to kick the kernel TX path

**Housekeeping (each iteration):**
- Drain the completion ring and recycle TX frames
- Replenish the fill ring with free frames
- If idle: either `spin_loop()` (busy-poll mode) or `poll()`+sleep 10us

## Tuning

### NIC Configuration

```bash
# Set RSS to spread traffic across queues (X710 example)
ethtool -L eth0 combined 4

# Pin IRQs to specific cores for queue affinity
# (check /proc/interrupts for IRQ numbers)
echo 2 > /proc/irq/<irq>/smp_affinity

# Enable rx/tx checksum offload
ethtool -K eth0 rx on tx on

# Increase ring buffer sizes
ethtool -G eth0 rx 4096 tx 4096
```

### Process Pinning

For best results with `busy_poll: true`, pin the clat-rs process to the same core
that handles the NIC queue's interrupts:

```bash
# Pin to core 2
taskset -c 2 ./clat-rs --config /etc/clat-rs/config.yml
```

### Multi-Queue (Future)

The current implementation binds to a single NIC queue. Multi-queue support (one
AF_XDP socket per queue, one thread per socket) is planned. In the meantime, use
Flow Director or `ethtool -N` to steer CLAT-prefix traffic to a single queue:

```bash
# Steer traffic matching the CLAT prefix to queue 0 (X710)
ethtool -N eth0 flow-type ipv6-other dst-ip 2001:db8:aaaa::/96 action 0
```

## Troubleshooting

### "interface not found"
The `uplink_interface` in your config must match an existing network interface.
Check with `ip link show`.

### "gateway_mac must be set"
The XDP TX path needs the destination MAC address for outbound Ethernet frames.
See "Finding your gateway MAC" above.

### Zero-copy bind fails
Your NIC driver may not support AF_XDP zero-copy. Set `zero_copy: false` to fall
back to copy mode (still faster than raw sockets). Check driver support:
```bash
ethtool -i eth0 | grep driver
```

### XDP program won't attach
- Ensure no other XDP program is already attached: `ip link show dev eth0`
- Check kernel logs: `dmesg | tail`
- Verify you have `CAP_BPF` and `CAP_NET_ADMIN`
