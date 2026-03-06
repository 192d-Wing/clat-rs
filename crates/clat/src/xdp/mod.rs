mod af_xdp;
mod consts;
mod program;

use std::io::{Read, Write};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::state::SharedState;

use af_xdp::{FrameAllocator, Umem, XskSocket};
use consts::{DEFAULT_FRAME_SIZE, DEFAULT_NUM_FRAMES, XdpDesc};
use program::XdpProgram;

const ETH_HDR_LEN: usize = 14;
const ETH_P_IPV6: [u8; 2] = [0x86, 0xDD];
const ETH_P_IPV4: [u8; 2] = [0x08, 0x00];
const BATCH_SIZE: usize = 64;

/// Run the CLAT packet loop using AF_XDP for the IPv6 side.
///
/// This replaces the TUN+raw-socket loop with a zero-copy XDP path on the
/// network side while keeping the TUN device for the IPv4/application side.
pub fn run(config: &Config, state: Arc<SharedState>) -> anyhow::Result<()> {
    let xdp_cfg = config
        .xdp
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("xdp section required in config when --features xdp"))?;

    let clat_prefix = state
        .current_prefix()
        .ok_or_else(|| anyhow::anyhow!("CLAT prefix must be set before starting XDP loop"))?;
    let plat_prefix = config.plat_prefix();
    let iface = &config.uplink_interface;

    // Resolve interface index
    let ifindex = iface_index(iface)?;

    // Load and attach XDP eBPF program
    let mut xdp_prog =
        XdpProgram::load_and_attach(&xdp_cfg.xdp_program, iface, clat_prefix, xdp_cfg.zero_copy)?;

    // Allocate UMEM
    let num_frames = xdp_cfg.umem_frames.unwrap_or(DEFAULT_NUM_FRAMES);
    let frame_size = xdp_cfg.frame_size.unwrap_or(DEFAULT_FRAME_SIZE);
    let umem = Umem::new(num_frames, frame_size)?;

    // Create AF_XDP socket on queue 0
    let queue_id = xdp_cfg.queue_id.unwrap_or(0);
    let mut xsk = XskSocket::new(&umem, ifindex, queue_id, xdp_cfg.zero_copy)?;

    // Register the XSK fd in the BPF map
    let mut xsk_map = xdp_prog.xsk_map()?;
    xsk_map.set(queue_id, xsk.fd.as_raw_fd(), 0)?;

    // Frame allocator
    let mut allocator = FrameAllocator::new(num_frames, frame_size);

    // Pre-fill the fill ring so the kernel has buffers for RX
    let prefill: Vec<u64> = (0..1024).filter_map(|_| allocator.alloc()).collect();
    umem.fill.submit(&prefill);

    // Create synchronous TUN device for the IPv4 side
    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name("clat0")
        .address(config.clat_ipv4_addr)
        .netmask(prefix_to_netmask(config.parse_ipv4_networks()?[0].1))
        .mtu(config.mtu)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let mut tun_dev = tun::create(&tun_config)?;

    // Set TUN to non-blocking for polling
    unsafe {
        let fd = std::os::fd::AsRawFd::as_raw_fd(&tun_dev);
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    tracing::info!(
        "XDP packet loop started: queue={queue_id} iface={iface} zero_copy={}",
        xdp_cfg.zero_copy
    );
    state.set_translating(true);

    // Resolve gateway MAC for TX ethernet headers
    let gw_mac = xdp_cfg.gateway_mac()?;
    let src_mac = iface_mac(iface)?;

    let mut rx_descs = [XdpDesc::default(); BATCH_SIZE];
    let mut tun_buf = [0u8; 65536];
    let mut completed = Vec::with_capacity(BATCH_SIZE);
    let mut current_prefix = clat_prefix;
    let mut prefix_rx = state.subscribe_prefix();

    loop {
        // Check for prefix updates (non-blocking)
        if let Ok(true) = prefix_rx.has_changed() {
            if let Some(new_prefix) = *prefix_rx.borrow_and_update() {
                if new_prefix != current_prefix {
                    tracing::info!("hot-swapping CLAT prefix: {current_prefix} -> {new_prefix}");
                    xdp_prog.update_prefix(new_prefix)?;
                    current_prefix = new_prefix;
                }
            }
        }

        // --- RX path: AF_XDP → translate IPv6→IPv4 → TUN ---
        let rx_count = xsk.recv_batch(&mut rx_descs);
        for desc in &rx_descs[..rx_count as usize] {
            // SAFETY: descriptors come from kernel with valid addr/len within UMEM
            let frame = unsafe { umem.frame_slice(desc.addr, desc.len) };

            // Strip Ethernet header, translate IPv6 → IPv4
            if frame.len() > ETH_HDR_LEN {
                let ipv6_pkt = &frame[ETH_HDR_LEN..];
                if let Some(ipv4_pkt) =
                    nat64_core::translate::ipv6_to_ipv4(ipv6_pkt, current_prefix, plat_prefix)
                {
                    tracing::debug!(
                        event_type = "translation",
                        direction = "v6_to_v4",
                        path = "xdp",
                        bytes = ipv4_pkt.len(),
                        "XDP: translated IPv6 to IPv4"
                    );
                    let _ = tun_dev.write(&ipv4_pkt);
                }
            }

            // Return frame to allocator
            allocator.free(desc.addr);
        }

        // --- TX path: TUN → translate IPv4→IPv6 → AF_XDP ---
        loop {
            match tun_dev.read(&mut tun_buf) {
                Ok(0) => break,
                Ok(n) => {
                    let ipv4_pkt = &tun_buf[..n];
                    if let Some(ipv6_pkt) =
                        nat64_core::translate::ipv4_to_ipv6(ipv4_pkt, current_prefix, plat_prefix)
                    {
                        tracing::debug!(
                            event_type = "translation",
                            direction = "v4_to_v6",
                            path = "xdp",
                            bytes = ipv6_pkt.len(),
                            "XDP: translated IPv4 to IPv6"
                        );
                        if let Some(addr) = allocator.alloc() {
                            // Write Ethernet header + IPv6 packet into UMEM frame
                            // SAFETY: addr is a valid frame from our allocator
                            let frame = unsafe { umem.frame_slice_mut(addr) };
                            let total_len = ETH_HDR_LEN + ipv6_pkt.len();
                            if total_len <= frame.len() {
                                // Ethernet header: dst MAC, src MAC, ethertype
                                frame[0..6].copy_from_slice(&gw_mac);
                                frame[6..12].copy_from_slice(&src_mac);
                                frame[12..14].copy_from_slice(&ETH_P_IPV6);
                                frame[ETH_HDR_LEN..total_len].copy_from_slice(&ipv6_pkt);

                                let tx_desc = XdpDesc {
                                    addr,
                                    len: total_len as u32,
                                    options: 0,
                                };
                                xsk.send_batch(&[tx_desc]);
                            } else {
                                allocator.free(addr);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::warn!("TUN read error: {e}");
                    break;
                }
            }
        }

        // Kick TX if we submitted anything
        xsk.kick_tx();

        // Reclaim completed TX frames
        completed.clear();
        umem.comp.drain(&mut completed);
        for addr in &completed {
            allocator.free(*addr);
        }

        // Replenish fill ring
        let mut fill_addrs = Vec::with_capacity(BATCH_SIZE);
        while fill_addrs.len() < BATCH_SIZE {
            if let Some(addr) = allocator.alloc() {
                fill_addrs.push(addr);
            } else {
                break;
            }
        }
        if !fill_addrs.is_empty() {
            umem.fill.submit(&fill_addrs);
        }

        // If no work was done, briefly yield to avoid 100% CPU spin
        if rx_count == 0 && completed.is_empty() {
            if xdp_cfg.busy_poll {
                std::hint::spin_loop();
            } else {
                xsk.wake_rx();
                std::thread::sleep(Duration::from_micros(10));
            }
        }

        // Check for shutdown
        if !state.is_translating() {
            break;
        }
    }

    state.set_translating(false);
    tracing::info!("XDP packet loop stopped");
    Ok(())
}

fn iface_index(name: &str) -> anyhow::Result<u32> {
    let c_name = std::ffi::CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        anyhow::bail!("interface not found: {name}");
    }
    Ok(idx)
}

fn iface_mac(name: &str) -> anyhow::Result<[u8; 6]> {
    let path = format!("/sys/class/net/{name}/address");
    let mac_str = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read MAC from {path}: {e}"))?;
    parse_mac(mac_str.trim())
}

fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("invalid MAC address: {s}");
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)?;
    }
    Ok(mac)
}

fn prefix_to_netmask(prefix_len: u8) -> std::net::Ipv4Addr {
    if prefix_len == 0 {
        return std::net::Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask: u32 = !0u32 << (32 - prefix_len);
    std::net::Ipv4Addr::from(mask)
}

use std::os::fd::AsRawFd;
