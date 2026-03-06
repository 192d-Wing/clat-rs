use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::config::Config;
use crate::session::{LookupResult, SessionKey};
use crate::state::SharedState;

const BUF_SIZE: usize = 65536;

/// Minimum IPv6 header length.
const IPV6_HDR_LEN: usize = 40;
/// Minimum IPv4 header length.
const IPV4_HDR_LEN: usize = 20;

/// Reap interval for expired sessions.
const REAP_INTERVAL_SECS: u64 = 30;

/// Run the main PLAT NAT64 packet translation loop.
pub async fn run(config: &Config, state: Arc<SharedState>) -> anyhow::Result<()> {
    let v6_sock = create_v6_socket(config).await?;
    let v4_sock = create_v4_socket(config).await?;

    let mut prefix_rx = state.subscribe_prefix();

    // Wait for initial prefix if not set
    if state.current_prefix().is_none() {
        log::info!("no NAT64 prefix configured — waiting for gRPC SetPrefix...");
        loop {
            if prefix_rx.changed().await.is_err() {
                anyhow::bail!("prefix channel closed before a prefix was set");
            }
            if prefix_rx.borrow().is_some() {
                break;
            }
        }
    }

    let mut nat64_prefix = state.current_prefix().unwrap();
    log::info!("PLAT packet loop started with NAT64 prefix {nat64_prefix}");
    state.set_translating(true);

    let mut v6_buf = [0u8; BUF_SIZE];
    let mut v4_buf = [0u8; BUF_SIZE];

    let mut reap_interval =
        tokio::time::interval(std::time::Duration::from_secs(REAP_INTERVAL_SECS));
    reap_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Prefix hot-swap
            result = prefix_rx.changed() => {
                if result.is_err() {
                    log::warn!("prefix watch channel closed");
                    break;
                }
                if let Some(new_prefix) = *prefix_rx.borrow_and_update()
                    && new_prefix != nat64_prefix
                {
                    log::info!("hot-swapping NAT64 prefix: {nat64_prefix} -> {new_prefix}");
                    nat64_prefix = new_prefix;
                }
            }

            // Inbound: IPv6 from uplink -> translate to IPv4 -> send on egress
            result = v6_sock.recv_from(&mut v6_buf) => {
                let (n, _src_addr) = result?;
                if n < IPV6_HDR_LEN {
                    continue;
                }
                let ipv6_packet = &v6_buf[..n];

                if let Some(ipv4_packet) = translate_v6_to_v4(
                    ipv6_packet, nat64_prefix, &state,
                )
                    && let Err(e) = send_v4_packet(&v4_sock, &ipv4_packet).await
                {
                    log::warn!("failed to send IPv4 packet: {e}");
                }
            }

            // Return: IPv4 from egress -> reverse NAT -> translate to IPv6 -> send on uplink
            result = v4_sock.recv_from(&mut v4_buf) => {
                let (n, _src_addr) = result?;
                if n < IPV4_HDR_LEN {
                    continue;
                }
                let ipv4_packet = &v4_buf[..n];

                if let Some(ipv6_packet) = translate_v4_to_v6(
                    ipv4_packet, nat64_prefix, &state,
                )
                    && let Err(e) = send_v6_packet(&v6_sock, &ipv6_packet).await
                {
                    log::warn!("failed to send IPv6 packet: {e}");
                }
            }

            // Periodic session reaping
            _ = reap_interval.tick() => {
                let mut nat = state.nat.lock().unwrap();
                let crate::state::NatState { sessions, pool } = &mut *nat;
                let reaped = sessions.reap_expired(pool);
                if reaped > 0 {
                    log::debug!("reaped {reaped} expired sessions");
                }
            }

            // Shutdown
            _ = tokio::signal::ctrl_c() => {
                log::info!("received shutdown signal, stopping PLAT");
                break;
            }
        }
    }

    state.set_translating(false);
    Ok(())
}

/// Translate an inbound IPv6 packet to IPv4 via the session table.
///
/// 1. Extract the 5-tuple from the IPv6 packet
/// 2. Look up or create a NAT session
/// 3. Translate the packet using nat64-core
/// 4. Rewrite the source address/port to the pool binding
fn translate_v6_to_v4(
    ipv6_packet: &[u8],
    nat64_prefix: Ipv6Addr,
    state: &SharedState,
) -> Option<Vec<u8>> {
    if ipv6_packet.len() < IPV6_HDR_LEN {
        return None;
    }

    // Verify destination matches NAT64 prefix
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&ipv6_packet[24..40]);
    let dst_v6 = Ipv6Addr::from(dst_bytes);
    if !nat64_core::addr::matches_prefix_96(dst_v6, nat64_prefix) {
        return None;
    }

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&ipv6_packet[8..24]);
    let src_v6 = Ipv6Addr::from(src_bytes);

    let next_header = ipv6_packet[6];
    let (src_port, dst_port) = extract_ports(next_header, &ipv6_packet[IPV6_HDR_LEN..])?;

    let key = SessionKey {
        src_v6,
        dst_v6,
        protocol: next_header,
        src_port,
        dst_port,
    };

    // Look up or create session
    let binding = {
        let mut nat = state.nat.lock().unwrap();
        let crate::state::NatState { sessions, pool } = &mut *nat;
        match sessions.lookup_or_create(key, pool) {
            LookupResult::Existing(b) | LookupResult::Created(b) => b,
            LookupResult::Exhausted => {
                log::warn!("NAT session exhausted for {src_v6}");
                return None;
            }
        }
    };

    // The PLAT flow differs from CLAT: the IPv6 source is an arbitrary client address
    // (not prefix-embedded), so nat64_core::translate::ipv6_to_ipv4 won't work directly.
    // We build the IPv4 packet manually using nat64-core building blocks.
    let dst_v4 = nat64_core::addr::extract_ipv4_from_ipv6(dst_v6);
    let src_v4 = binding.pool_addr;

    let payload_len = u16::from_be_bytes([ipv6_packet[4], ipv6_packet[5]]) as usize;
    if ipv6_packet.len() < IPV6_HDR_LEN + payload_len {
        return None;
    }
    let payload = &ipv6_packet[IPV6_HDR_LEN..IPV6_HDR_LEN + payload_len];

    // Map ICMPv6 -> ICMP protocol number
    let ipv4_proto = match next_header {
        58 => 1, // ICMPv6 -> ICMP
        p => p,
    };

    let total_len = (IPV4_HDR_LEN + payload_len) as u16;
    let hop_limit = ipv6_packet[7];
    let tos = ((ipv6_packet[0] & 0x0F) << 4) | (ipv6_packet[1] >> 4);

    let mut pkt = Vec::with_capacity(total_len as usize);
    // IPv4 header
    pkt.push(0x45); // version + IHL
    pkt.push(tos);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // identification
    pkt.extend_from_slice(&[0x40, 0x00]); // DF, no fragment
    pkt.push(hop_limit.saturating_sub(1));
    pkt.push(ipv4_proto);
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(&src_v4.octets());
    pkt.extend_from_slice(&dst_v4.octets());

    // Compute IPv4 header checksum
    let hdr_cksum = nat64_core::checksum::ipv4_header_checksum(&pkt[..IPV4_HDR_LEN]);
    pkt[10] = (hdr_cksum >> 8) as u8;
    pkt[11] = (hdr_cksum & 0xFF) as u8;

    // Translate and append payload
    match next_header {
        58 => {
            // ICMPv6 -> ICMPv4
            if payload.len() < 4 {
                return None;
            }
            let mapping = nat64_core::icmp::icmpv6_to_icmpv4(payload[0], payload[1])?;
            let mut icmp_payload = payload.to_vec();
            icmp_payload[0] = mapping.icmp_type;
            icmp_payload[1] = mapping.icmp_code;
            icmp_payload[2] = 0;
            icmp_payload[3] = 0;
            let cksum = nat64_core::checksum::internet_checksum(&icmp_payload);
            icmp_payload[2] = (cksum >> 8) as u8;
            icmp_payload[3] = (cksum & 0xFF) as u8;
            pkt.extend_from_slice(&icmp_payload);
        }
        6 | 17 => {
            // TCP/UDP: rewrite source port to mapped_port, recompute checksum
            let mut tp_payload = payload.to_vec();
            if tp_payload.len() < 8 {
                return None;
            }
            // Overwrite source port
            tp_payload[0] = (binding.mapped_port >> 8) as u8;
            tp_payload[1] = (binding.mapped_port & 0xFF) as u8;

            // Recompute transport checksum from scratch over IPv4 pseudo-header
            let cksum_offset = if next_header == 6 { 16 } else { 6 };
            if tp_payload.len() <= cksum_offset + 1 {
                return None;
            }
            tp_payload[cksum_offset] = 0;
            tp_payload[cksum_offset + 1] = 0;

            let pseudo = nat64_core::checksum::ipv4_pseudo_header_sum(
                src_v4,
                dst_v4,
                ipv4_proto,
                tp_payload.len() as u16,
            );
            let mut sum = pseudo;
            let mut i = 0;
            while i + 1 < tp_payload.len() {
                sum += u32::from(u16::from_be_bytes([tp_payload[i], tp_payload[i + 1]]));
                i += 2;
            }
            if i < tp_payload.len() {
                sum += u32::from(tp_payload[i]) << 8;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let cksum = !(sum as u16);
            // For UDP, if checksum computes to 0, it means "no checksum" in IPv4
            // which is acceptable (unlike IPv6)
            tp_payload[cksum_offset] = (cksum >> 8) as u8;
            tp_payload[cksum_offset + 1] = (cksum & 0xFF) as u8;

            pkt.extend_from_slice(&tp_payload);
        }
        _ => {
            pkt.extend_from_slice(payload);
        }
    }

    state.increment_translations();
    Some(pkt)
}

/// Translate a return IPv4 packet back to IPv6 via reverse session lookup.
fn translate_v4_to_v6(
    ipv4_packet: &[u8],
    nat64_prefix: Ipv6Addr,
    state: &SharedState,
) -> Option<Vec<u8>> {
    if ipv4_packet.len() < IPV4_HDR_LEN {
        return None;
    }
    if ipv4_packet[0] >> 4 != 4 {
        return None;
    }

    let ihl = ((ipv4_packet[0] & 0x0F) as usize) * 4;
    let total_len = u16::from_be_bytes([ipv4_packet[2], ipv4_packet[3]]) as usize;
    if ipv4_packet.len() < total_len || total_len < ihl {
        return None;
    }

    let protocol = ipv4_packet[9];
    let dst_v4 = Ipv4Addr::new(
        ipv4_packet[16],
        ipv4_packet[17],
        ipv4_packet[18],
        ipv4_packet[19],
    );
    let src_v4 = Ipv4Addr::new(
        ipv4_packet[12],
        ipv4_packet[13],
        ipv4_packet[14],
        ipv4_packet[15],
    );

    let payload = &ipv4_packet[ihl..total_len];

    // Extract destination port for reverse lookup
    let (_src_port, dst_port) = extract_ports(protocol, payload)?;

    // Reverse lookup: the IPv4 dst is our pool address, dst_port is mapped_port
    let (fwd_key, _binding) = {
        let mut nat = state.nat.lock().unwrap();
        nat.sessions.reverse_lookup(dst_v4, dst_port, protocol)?
    };

    // Build IPv6 packet:
    //   src = nat64_prefix :: src_v4 (the remote server)
    //   dst = fwd_key.src_v6 (the original IPv6 client)
    let src_v6 = nat64_core::addr::embed_ipv4_in_ipv6(nat64_prefix, src_v4);
    let dst_v6 = fwd_key.src_v6;

    let ipv6_next_header = match protocol {
        1 => 58, // ICMP -> ICMPv6
        p => p,
    };

    let payload_len = payload.len();
    let ttl = ipv4_packet[8];
    let tos = ipv4_packet[1];

    let mut pkt = Vec::with_capacity(IPV6_HDR_LEN + payload_len);
    // IPv6 header
    pkt.push(0x60 | (tos >> 4));
    pkt.push(tos << 4);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.extend_from_slice(&(payload_len as u16).to_be_bytes());
    pkt.push(ipv6_next_header);
    pkt.push(ttl.saturating_sub(1));
    pkt.extend_from_slice(&src_v6.octets());
    pkt.extend_from_slice(&dst_v6.octets());

    // Translate and append payload
    match protocol {
        1 => {
            // ICMP -> ICMPv6
            if payload.len() < 4 {
                return None;
            }
            let mapping = nat64_core::icmp::icmpv4_to_icmpv6(payload[0], payload[1])?;
            let mut icmpv6 = payload.to_vec();
            icmpv6[0] = mapping.icmp_type;
            icmpv6[1] = mapping.icmp_code;
            icmpv6[2] = 0;
            icmpv6[3] = 0;
            // ICMPv6 checksum includes pseudo-header
            let pseudo = nat64_core::checksum::ipv6_pseudo_header_sum(
                src_v6,
                dst_v6,
                58,
                icmpv6.len() as u32,
            );
            let mut sum = pseudo;
            let mut i = 0;
            while i + 1 < icmpv6.len() {
                sum += u32::from(u16::from_be_bytes([icmpv6[i], icmpv6[i + 1]]));
                i += 2;
            }
            if i < icmpv6.len() {
                sum += u32::from(icmpv6[i]) << 8;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let cksum = !(sum as u16);
            icmpv6[2] = (cksum >> 8) as u8;
            icmpv6[3] = (cksum & 0xFF) as u8;
            pkt.extend_from_slice(&icmpv6);
        }
        6 | 17 => {
            // TCP/UDP: rewrite destination port back to original, recompute checksum
            let mut tp = payload.to_vec();
            if tp.len() < 8 {
                return None;
            }
            // Restore original destination port (the client's source port)
            tp[2] = (fwd_key.src_port >> 8) as u8;
            tp[3] = (fwd_key.src_port & 0xFF) as u8;

            // Recompute checksum over IPv6 pseudo-header
            let cksum_offset = if protocol == 6 { 16 } else { 6 };
            if tp.len() <= cksum_offset + 1 {
                return None;
            }
            tp[cksum_offset] = 0;
            tp[cksum_offset + 1] = 0;

            let pseudo = nat64_core::checksum::ipv6_pseudo_header_sum(
                src_v6,
                dst_v6,
                ipv6_next_header,
                tp.len() as u32,
            );
            let mut sum = pseudo;
            let mut i = 0;
            while i + 1 < tp.len() {
                sum += u32::from(u16::from_be_bytes([tp[i], tp[i + 1]]));
                i += 2;
            }
            if i < tp.len() {
                sum += u32::from(tp[i]) << 8;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let cksum = !(sum as u16);
            // In IPv6, UDP checksum 0 must be sent as 0xFFFF
            let cksum = if protocol == 17 && cksum == 0 {
                0xFFFF
            } else {
                cksum
            };
            tp[cksum_offset] = (cksum >> 8) as u8;
            tp[cksum_offset + 1] = (cksum & 0xFF) as u8;

            pkt.extend_from_slice(&tp);
        }
        _ => {
            pkt.extend_from_slice(payload);
        }
    }

    state.increment_translations();
    Some(pkt)
}

/// Extract (src_port, dst_port) from a transport-layer payload.
/// For ICMP/ICMPv6, uses the identifier field as "port".
fn extract_ports(protocol: u8, payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() < 4 {
        return None;
    }
    match protocol {
        6 | 17 => {
            // TCP/UDP: first 4 bytes are src_port, dst_port
            let src = u16::from_be_bytes([payload[0], payload[1]]);
            let dst = u16::from_be_bytes([payload[2], payload[3]]);
            Some((src, dst))
        }
        1 | 58 => {
            // ICMP/ICMPv6: use identifier (bytes 4-5) as both ports
            if payload.len() < 6 {
                return None;
            }
            let id = u16::from_be_bytes([payload[4], payload[5]]);
            Some((id, id))
        }
        _ => Some((0, 0)),
    }
}

/// Create the IPv6-facing socket (uplink side).
async fn create_v6_socket(config: &Config) -> anyhow::Result<UdpSocket> {
    // Development placeholder — in production this would be a raw socket
    // with a BPF filter matching the NAT64 prefix on the uplink interface.
    let sock = UdpSocket::bind("[::]:9865").await?;
    log::warn!(
        "using development UDP socket for IPv6 (port 9865, interface {}) — replace with raw socket for production",
        config.uplink_interface
    );
    Ok(sock)
}

/// Create the IPv4-facing socket (egress side).
async fn create_v4_socket(config: &Config) -> anyhow::Result<UdpSocket> {
    // Development placeholder — in production this would be a raw socket
    // for sending/receiving IPv4 packets.
    let sock = UdpSocket::bind("0.0.0.0:9866").await?;
    log::warn!(
        "using development UDP socket for IPv4 (port 9866, interface {}) — replace with raw socket for production",
        config.egress_interface()
    );
    Ok(sock)
}

async fn send_v4_packet(sock: &UdpSocket, packet: &[u8]) -> anyhow::Result<()> {
    if packet.len() < IPV4_HDR_LEN {
        return Ok(());
    }
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let dst_addr = std::net::SocketAddr::from((dst, 0));
    sock.send_to(packet, dst_addr).await?;
    Ok(())
}

async fn send_v6_packet(sock: &UdpSocket, packet: &[u8]) -> anyhow::Result<()> {
    if packet.len() < IPV6_HDR_LEN {
        return Ok(());
    }
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&packet[24..40]);
    let dst = Ipv6Addr::from(dst_bytes);
    let dst_addr = std::net::SocketAddr::from((dst, 0));
    sock.send_to(packet, dst_addr).await?;
    Ok(())
}
