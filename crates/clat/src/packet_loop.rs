use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::state::SharedState;
use crate::tun_device;

const TUN_NAME: &str = "clat0";
const BUF_SIZE: usize = 65536;

/// Run the main CLAT packet translation loop.
///
/// If no CLAT prefix is available at startup, waits for one to be set via gRPC.
pub async fn run(config: &Config, state: Arc<SharedState>) -> anyhow::Result<()> {
    let networks: Vec<(Ipv4Addr, u8)> = config.parse_ipv4_networks()?;
    let plat_prefix: Ipv6Addr = config.plat_prefix();

    // Create TUN device using the first network for the interface address
    let (first_network, first_prefix_len) = networks[0];
    let mut tun_dev = tun_device::create_tun(
        TUN_NAME,
        config.clat_ipv4_addr,
        first_network,
        first_prefix_len,
        config.mtu,
    )?;

    // Log additional networks (routes would be added via ip route in production)
    for (net, prefix) in &networks[1..] {
        tracing::info!("additional CLAT network: {net}/{prefix}");
    }

    let send_sock = create_raw_ipv6_send_socket()?;
    let recv_sock = create_raw_ipv6_recv_socket().await?;

    let mut prefix_rx = state.subscribe_prefix();

    // Wait for initial prefix if not set
    if state.current_prefix().is_none() {
        tracing::info!("no CLAT prefix configured — waiting for gRPC SetPrefix...");
        loop {
            if prefix_rx.changed().await.is_err() {
                anyhow::bail!("prefix channel closed before a prefix was set");
            }
            if prefix_rx.borrow().is_some() {
                break;
            }
        }
    }

    let mut clat_prefix = state.current_prefix().unwrap();
    tracing::info!(
        event_type = "lifecycle",
        action = "packet_loop_start",
        tun_device = TUN_NAME,
        clat_prefix = %clat_prefix,
        "CLAT packet loop started"
    );
    state.set_translating(true);

    let mut tun_buf = [0u8; BUF_SIZE];
    let mut raw_buf = [0u8; BUF_SIZE];

    loop {
        tokio::select! {
            // Watch for prefix updates (hot-swap)
            result = prefix_rx.changed() => {
                if result.is_err() {
                    tracing::warn!("prefix watch channel closed");
                    break;
                }
                if let Some(new_prefix) = *prefix_rx.borrow_and_update()
                    && new_prefix != clat_prefix
                {
                    tracing::info!("hot-swapping CLAT prefix: {clat_prefix} -> {new_prefix}");
                    clat_prefix = new_prefix;
                }
            }

            // Read IPv4 packet from TUN -> translate to IPv6 -> send out
            result = tun_dev.read(&mut tun_buf) => {
                let n = result?;
                if n == 0 {
                    continue;
                }
                let ipv4_packet = &tun_buf[..n];

                if let Some(ipv6_packet) = nat64_core::translate::ipv4_to_ipv6(ipv4_packet, clat_prefix, plat_prefix)
                {
                    tracing::debug!(
                        event_type = "translation",
                        direction = "v4_to_v6",
                        bytes = ipv6_packet.len(),
                        "translated IPv4 to IPv6"
                    );
                    if let Err(e) = send_ipv6_packet(&send_sock, &ipv6_packet).await {
                        tracing::warn!("failed to send IPv6 packet: {e}");
                    }
                }
            }

            // Read IPv6 packet from raw socket -> translate to IPv4 -> write to TUN
            result = recv_sock.recv(&mut raw_buf) => {
                let n = result?;
                if n == 0 {
                    continue;
                }
                let ipv6_packet = &raw_buf[..n];

                if let Some(ipv4_packet) = nat64_core::translate::ipv6_to_ipv4(ipv6_packet, clat_prefix, plat_prefix)
                {
                    tracing::debug!(
                        event_type = "translation",
                        direction = "v6_to_v4",
                        bytes = ipv4_packet.len(),
                        "translated IPv6 to IPv4"
                    );
                    if let Err(e) = tun_dev.write_all(&ipv4_packet).await {
                        tracing::warn!("failed to write IPv4 packet to TUN: {e}");
                    }
                }
            }

            // Handle shutdown signal
            _ = tokio::signal::ctrl_c() => {
                tracing::info!(
                    event_type = "lifecycle",
                    action = "packet_loop_stop",
                    reason = "signal",
                    "CLAT received shutdown signal"
                );
                break;
            }
        }
    }

    state.set_translating(false);
    Ok(())
}

/// Create a raw IPv6 socket for sending packets.
/// On Linux, this requires CAP_NET_RAW.
fn create_raw_ipv6_send_socket() -> anyhow::Result<std::net::UdpSocket> {
    // In a full implementation, this would be:
    //   socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)
    // For now we use a UDP socket as a development placeholder.
    let sock = std::net::UdpSocket::bind("[::]:0")?;
    Ok(sock)
}

/// Create a raw IPv6 socket for receiving packets destined to our CLAT prefix.
/// In production, this would use a BPF/packet filter to capture only packets
/// matching the CLAT prefix on the uplink interface.
async fn create_raw_ipv6_recv_socket() -> anyhow::Result<UdpSocket> {
    // Development placeholder — bind to a high port.
    // In production, this would be a raw socket with a BPF filter
    // or we'd read from a second TUN/TAP device on the IPv6 side.
    let sock = UdpSocket::bind("[::]:9864").await?;
    tracing::warn!(
        "using development UDP socket for IPv6 recv (port 9864) — replace with raw socket for production"
    );
    Ok(sock)
}

/// Send a raw IPv6 packet out the uplink.
async fn send_ipv6_packet(sock: &std::net::UdpSocket, packet: &[u8]) -> anyhow::Result<()> {
    if packet.len() < 40 {
        return Ok(());
    }

    // Extract destination IPv6 from the packet header
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&packet[24..40]);
    let dst = Ipv6Addr::from(dst_bytes);

    // For raw sockets this would be sendto() with the raw packet.
    // With UDP placeholder, we send to the destination.
    let dst_addr = std::net::SocketAddr::from((dst, 0));
    sock.send_to(packet, dst_addr)?;
    Ok(())
}
