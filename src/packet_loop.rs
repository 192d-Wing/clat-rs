use std::net::Ipv6Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::translate;
use crate::tun_device;

const TUN_NAME: &str = "clat0";
const BUF_SIZE: usize = 65536;

/// Run the main CLAT packet translation loop.
pub async fn run(config: &Config) -> anyhow::Result<()> {
    let (network_addr, prefix_len) = config.parse_ipv4_network()?;
    let clat_prefix = config.clat_prefix();
    let plat_prefix = config.plat_prefix();

    // Create TUN device
    let mut tun_dev = tun_device::create_tun(
        TUN_NAME,
        config.clat_ipv4_addr,
        network_addr,
        prefix_len,
        config.mtu,
    )?;

    // Bind a raw IPv6 socket for sending/receiving translated packets.
    // We use a UDP socket bound to [::]:0 as a placeholder — in production
    // this would be a raw socket (IPPROTO_RAW) for IPv6.
    // For now, we use a raw socket via std and wrap it.
    let send_sock = create_raw_ipv6_send_socket()?;
    let recv_sock = create_raw_ipv6_recv_socket(clat_prefix).await?;

    log::info!("CLAT packet loop started on {TUN_NAME}");

    let mut tun_buf = [0u8; BUF_SIZE];
    let mut raw_buf = [0u8; BUF_SIZE];

    loop {
        tokio::select! {
            // Read IPv4 packet from TUN -> translate to IPv6 -> send out
            result = tun_dev.read(&mut tun_buf) => {
                let n = result?;
                if n == 0 {
                    continue;
                }
                let ipv4_packet = &tun_buf[..n];

                if let Some(ipv6_packet) = translate::ipv4_to_ipv6(ipv4_packet, clat_prefix, plat_prefix)
                    && let Err(e) = send_ipv6_packet(&send_sock, &ipv6_packet).await
                {
                    log::warn!("failed to send IPv6 packet: {e}");
                }
            }

            // Read IPv6 packet from raw socket -> translate to IPv4 -> write to TUN
            result = recv_sock.recv(&mut raw_buf) => {
                let n = result?;
                if n == 0 {
                    continue;
                }
                let ipv6_packet = &raw_buf[..n];

                if let Some(ipv4_packet) = translate::ipv6_to_ipv4(ipv6_packet, clat_prefix, plat_prefix)
                    && let Err(e) = tun_dev.write_all(&ipv4_packet).await
                {
                    log::warn!("failed to write IPv4 packet to TUN: {e}");
                }
            }

            // Handle shutdown signal
            _ = tokio::signal::ctrl_c() => {
                log::info!("received shutdown signal, stopping CLAT");
                break;
            }
        }
    }

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
async fn create_raw_ipv6_recv_socket(_clat_prefix: Ipv6Addr) -> anyhow::Result<UdpSocket> {
    // Development placeholder — bind to a high port.
    // In production, this would be a raw socket with a BPF filter
    // or we'd read from a second TUN/TAP device on the IPv6 side.
    let sock = UdpSocket::bind("[::]:9864").await?;
    log::warn!(
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
