use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Config;
use crate::session::{LookupResult, SessionKey};
use crate::state::SharedState;
use crate::tun_device;

const BUF_SIZE: usize = 65536;

/// Minimum IPv6 header length.
const IPV6_HDR_LEN: usize = 40;
/// Minimum IPv4 header length.
const IPV4_HDR_LEN: usize = 20;

/// Reap interval for expired sessions.
const REAP_INTERVAL_SECS: u64 = 30;

/// Run the main PLAT NAT64 packet translation loop.
pub async fn run(config: &Config, state: Arc<SharedState>) -> anyhow::Result<()> {
    // Get first pool address for the IPv4 TUN interface
    let first_pool_addr = {
        let nat = state.nat.lock().unwrap();
        let addrs = nat.pool.addresses();
        if addrs.is_empty() {
            anyhow::bail!("IPv4 pool has no addresses");
        }
        addrs[0]
    };

    let mut v6_tun = tun_device::create_v6_tun("plat6", config.mtu)?;
    let mut v4_tun = tun_device::create_v4_tun("plat4", first_pool_addr, config.mtu)?;

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

            // Inbound: IPv6 from uplink TUN -> translate to IPv4 -> write to egress TUN
            result = v6_tun.read(&mut v6_buf) => {
                let n = result?;
                if n < IPV6_HDR_LEN {
                    continue;
                }
                let ipv6_packet = &v6_buf[..n];

                if let Some(ipv4_packet) = translate_v6_to_v4(
                    ipv6_packet, nat64_prefix, &state,
                )
                    && let Err(e) = v4_tun.write_all(&ipv4_packet).await
                {
                    log::warn!("failed to write IPv4 packet to TUN: {e}");
                }
            }

            // Return: IPv4 from egress TUN -> reverse NAT -> translate to IPv6 -> write to uplink TUN
            result = v4_tun.read(&mut v4_buf) => {
                let n = result?;
                if n < IPV4_HDR_LEN {
                    continue;
                }
                let ipv4_packet = &v4_buf[..n];

                if let Some(ipv6_packet) = translate_v4_to_v6(
                    ipv4_packet, nat64_prefix, &state,
                )
                    && let Err(e) = v6_tun.write_all(&ipv6_packet).await
                {
                    log::warn!("failed to write IPv6 packet to TUN: {e}");
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

    // Check for ICMPv6 error messages — these need special handling
    // because the session lookup uses the embedded inner packet, not the outer.
    if next_header == 58 {
        let payload = &ipv6_packet[IPV6_HDR_LEN..];
        if !payload.is_empty() && is_icmpv6_error(payload[0]) {
            return translate_icmpv6_error_to_v4(ipv6_packet, payload, nat64_prefix, state);
        }
    }

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
            if payload.len() < 8 {
                return None;
            }
            let mapping = nat64_core::icmp::icmpv6_to_icmpv4(payload[0], payload[1])?;
            let mut icmp_payload = payload.to_vec();
            icmp_payload[0] = mapping.icmp_type;
            icmp_payload[1] = mapping.icmp_code;
            // Rewrite ICMP identifier to mapped_port (like TCP/UDP source port rewrite)
            icmp_payload[4] = (binding.mapped_port >> 8) as u8;
            icmp_payload[5] = (binding.mapped_port & 0xFF) as u8;
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

    // Check for ICMPv4 error messages — these need special handling
    // because the session lookup uses the embedded inner packet, not the outer.
    if protocol == 1 && !payload.is_empty() && is_icmpv4_error(payload[0]) {
        return translate_icmpv4_error_to_v6(ipv4_packet, payload, nat64_prefix, state);
    }

    // Extract destination port for reverse lookup
    let (_src_port, dst_port) = extract_ports(protocol, payload)?;

    // Map IPv4 protocol to IPv6 next_header for session lookup
    // (sessions are keyed by IPv6 next_header: ICMPv6=58, not ICMP=1)
    let session_proto = match protocol {
        1 => 58, // ICMP -> ICMPv6
        p => p,
    };

    // Reverse lookup: the IPv4 dst is our pool address, dst_port is mapped_port
    let (fwd_key, _binding) = {
        let mut nat = state.nat.lock().unwrap();
        nat.sessions
            .reverse_lookup(dst_v4, dst_port, session_proto)?
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
            if payload.len() < 8 {
                return None;
            }
            let mapping = nat64_core::icmp::icmpv4_to_icmpv6(payload[0], payload[1])?;
            let mut icmpv6 = payload.to_vec();
            icmpv6[0] = mapping.icmp_type;
            icmpv6[1] = mapping.icmp_code;
            // Restore original ICMP identifier from the forward session key
            icmpv6[4] = (fwd_key.src_port >> 8) as u8;
            icmpv6[5] = (fwd_key.src_port & 0xFF) as u8;
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

/// Check if an ICMPv6 type is an error message (carries an embedded packet).
fn is_icmpv6_error(icmp_type: u8) -> bool {
    matches!(icmp_type, 1..=4) // Dest Unreachable, Packet Too Big, Time Exceeded, Parameter Problem
}

/// Check if an ICMPv4 type is an error message (carries an embedded packet).
fn is_icmpv4_error(icmp_type: u8) -> bool {
    matches!(icmp_type, 3 | 11 | 12) // Dest Unreachable, Time Exceeded, Parameter Problem
}

/// Translate an ICMPv6 error message to ICMPv4.
///
/// ICMPv6 errors embed the offending IPv6 packet starting at byte 8.
/// We look up the session for the inner flow and translate both the
/// outer ICMP header and the embedded inner packet.
fn translate_icmpv6_error_to_v4(
    ipv6_packet: &[u8],
    payload: &[u8],
    nat64_prefix: Ipv6Addr,
    state: &SharedState,
) -> Option<Vec<u8>> {
    // ICMPv6 error: [type(1) code(1) checksum(2) unused/mtu(4) embedded_ipv6_packet...]
    if payload.len() < 8 + IPV6_HDR_LEN {
        return None;
    }

    let mapping = nat64_core::icmp::icmpv6_to_icmpv4(payload[0], payload[1])?;
    let inner_v6 = &payload[8..];

    // Parse the embedded IPv6 header
    let mut inner_src_bytes = [0u8; 16];
    inner_src_bytes.copy_from_slice(&inner_v6[8..24]);
    let inner_src_v6 = Ipv6Addr::from(inner_src_bytes);

    let mut inner_dst_bytes = [0u8; 16];
    inner_dst_bytes.copy_from_slice(&inner_v6[24..40]);
    let inner_dst_v6 = Ipv6Addr::from(inner_dst_bytes);

    let inner_next_header = inner_v6[6];
    let inner_payload = if inner_v6.len() > IPV6_HDR_LEN {
        &inner_v6[IPV6_HDR_LEN..]
    } else {
        &[]
    };

    // Extract ports from the inner packet's transport header
    let (inner_src_port, inner_dst_port) = extract_ports(inner_next_header, inner_payload)?;

    // Look up the session for the inner flow
    // The inner packet was sent BY our client, so the session key matches
    let inner_key = SessionKey {
        src_v6: inner_src_v6,
        dst_v6: inner_dst_v6,
        protocol: inner_next_header,
        src_port: inner_src_port,
        dst_port: inner_dst_port,
    };

    let inner_binding = {
        let mut nat = state.nat.lock().unwrap();
        let crate::state::NatState { sessions, pool } = &mut *nat;
        match sessions.lookup_or_create(inner_key, pool) {
            LookupResult::Existing(b) | LookupResult::Created(b) => b,
            LookupResult::Exhausted => return None,
        }
    };

    // Build the translated inner IPv4 header
    let inner_dst_v4 = nat64_core::addr::extract_ipv4_from_ipv6(inner_dst_v6);
    let inner_src_v4 = inner_binding.pool_addr;
    let inner_ipv4_proto = match inner_next_header {
        58 => 1,
        p => p,
    };

    let inner_payload_len = u16::from_be_bytes([inner_v6[4], inner_v6[5]]) as usize;
    let inner_payload_actual = inner_payload.len().min(inner_payload_len);
    // RFC 6145: include as much of the inner packet as possible, at least 8 bytes of transport
    let inner_total_len = (IPV4_HDR_LEN + inner_payload_actual) as u16;

    let mut inner_v4 = Vec::with_capacity(inner_total_len as usize);
    inner_v4.push(0x45);
    inner_v4.push(0x00);
    inner_v4.extend_from_slice(&inner_total_len.to_be_bytes());
    inner_v4.extend_from_slice(&[0x00, 0x00]); // id
    inner_v4.extend_from_slice(&[0x40, 0x00]); // DF
    inner_v4.push(inner_v6[7]); // hop limit -> TTL
    inner_v4.push(inner_ipv4_proto);
    inner_v4.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    inner_v4.extend_from_slice(&inner_src_v4.octets());
    inner_v4.extend_from_slice(&inner_dst_v4.octets());

    let hdr_cksum = nat64_core::checksum::ipv4_header_checksum(&inner_v4[..IPV4_HDR_LEN]);
    inner_v4[10] = (hdr_cksum >> 8) as u8;
    inner_v4[11] = (hdr_cksum & 0xFF) as u8;

    // Rewrite inner transport source port to mapped_port
    if inner_payload_actual >= 2 {
        let mut tp = inner_payload[..inner_payload_actual].to_vec();
        match inner_next_header {
            6 | 17 if tp.len() >= 2 => {
                tp[0] = (inner_binding.mapped_port >> 8) as u8;
                tp[1] = (inner_binding.mapped_port & 0xFF) as u8;
            }
            58 if tp.len() >= 6 => {
                // ICMPv6 echo identifier
                tp[4] = (inner_binding.mapped_port >> 8) as u8;
                tp[5] = (inner_binding.mapped_port & 0xFF) as u8;
            }
            _ => {}
        }
        inner_v4.extend_from_slice(&tp);
    }

    // Build the outer ICMPv4 error packet
    // Outer addresses: src = whoever sent the error (embedded in prefix), dst = our pool addr
    let outer_src_v6 = Ipv6Addr::from({
        let mut b = [0u8; 16];
        b.copy_from_slice(&ipv6_packet[8..24]);
        b
    });
    let outer_dst_v4 = inner_src_v4; // error goes back to the original sender (our pool addr)
    let outer_src_v4 = if nat64_core::addr::matches_prefix_96(outer_src_v6, nat64_prefix) {
        nat64_core::addr::extract_ipv4_from_ipv6(outer_src_v6)
    } else {
        // Source of error is not in the NAT64 prefix — use 0.0.0.0 as fallback
        // (this shouldn't normally happen in a well-configured network)
        Ipv4Addr::new(0, 0, 0, 0)
    };

    let icmp_payload_len = 8 + inner_v4.len(); // type+code+cksum+unused + inner
    let outer_total_len = (IPV4_HDR_LEN + icmp_payload_len) as u16;
    let hop_limit = ipv6_packet[7];
    let tos = ((ipv6_packet[0] & 0x0F) << 4) | (ipv6_packet[1] >> 4);

    let mut pkt = Vec::with_capacity(outer_total_len as usize);
    pkt.push(0x45);
    pkt.push(tos);
    pkt.extend_from_slice(&outer_total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]); // no DF for ICMP errors
    pkt.push(hop_limit.saturating_sub(1));
    pkt.push(1); // ICMP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&outer_src_v4.octets());
    pkt.extend_from_slice(&outer_dst_v4.octets());

    let outer_hdr_cksum = nat64_core::checksum::ipv4_header_checksum(&pkt[..IPV4_HDR_LEN]);
    pkt[10] = (outer_hdr_cksum >> 8) as u8;
    pkt[11] = (outer_hdr_cksum & 0xFF) as u8;

    // ICMP error header: type, code, checksum(0), unused/mtu(4 bytes from original)
    let mut icmp_hdr = Vec::with_capacity(icmp_payload_len);
    icmp_hdr.push(mapping.icmp_type);
    icmp_hdr.push(mapping.icmp_code);
    icmp_hdr.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    // Copy the 4-byte field (unused for most errors, MTU for Packet Too Big)
    icmp_hdr.extend_from_slice(&payload[4..8]);
    icmp_hdr.extend_from_slice(&inner_v4);

    // For Packet Too Big -> Frag Needed, adjust the MTU field
    if payload[0] == nat64_core::icmp::ICMPV6_PACKET_TOO_BIG {
        let mtu_v6 = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        // Subtract 20 bytes for the IPv6/IPv4 header size difference
        let mtu_v4 = mtu_v6.saturating_sub(20).min(65535) as u16;
        // ICMPv4 Frag Needed: bytes 4-5 are unused (0), bytes 6-7 are next-hop MTU
        icmp_hdr[4] = 0;
        icmp_hdr[5] = 0;
        icmp_hdr[6] = (mtu_v4 >> 8) as u8;
        icmp_hdr[7] = (mtu_v4 & 0xFF) as u8;
    }

    let cksum = nat64_core::checksum::internet_checksum(&icmp_hdr);
    icmp_hdr[2] = (cksum >> 8) as u8;
    icmp_hdr[3] = (cksum & 0xFF) as u8;

    pkt.extend_from_slice(&icmp_hdr);

    state.increment_translations();
    Some(pkt)
}

/// Translate an ICMPv4 error message to ICMPv6.
///
/// ICMPv4 errors embed the offending IPv4 header + first 8 bytes of payload.
/// We look up the session for the inner flow and translate both the
/// outer ICMP header and the embedded inner packet.
fn translate_icmpv4_error_to_v6(
    ipv4_packet: &[u8],
    payload: &[u8],
    nat64_prefix: Ipv6Addr,
    state: &SharedState,
) -> Option<Vec<u8>> {
    // ICMPv4 error: [type(1) code(1) checksum(2) unused/mtu(4) embedded_ipv4_packet...]
    if payload.len() < 8 + IPV4_HDR_LEN {
        return None;
    }

    let mapping = nat64_core::icmp::icmpv4_to_icmpv6(payload[0], payload[1])?;
    let inner_v4 = &payload[8..];

    // Parse the embedded IPv4 header
    let inner_ihl = ((inner_v4[0] & 0x0F) as usize) * 4;
    if inner_v4.len() < inner_ihl {
        return None;
    }
    let inner_src_v4 = Ipv4Addr::new(inner_v4[12], inner_v4[13], inner_v4[14], inner_v4[15]);
    // inner_dst_v4 not needed: we get the original destination from fwd_key.dst_v6
    let inner_protocol = inner_v4[9];

    let inner_tp = if inner_v4.len() > inner_ihl {
        &inner_v4[inner_ihl..]
    } else {
        &[]
    };

    // Extract ports from inner transport header
    let (inner_src_port, _inner_dst_port) = extract_ports(inner_protocol, inner_tp)?;

    // Map protocol for session lookup
    let inner_session_proto = match inner_protocol {
        1 => 58,
        p => p,
    };

    // Reverse lookup: the inner packet was sent BY our PLAT (src=pool, sport=mapped)
    // so we use the inner source address/port for reverse lookup.
    let (fwd_key, _binding) = {
        let mut nat = state.nat.lock().unwrap();
        nat.sessions
            .reverse_lookup(inner_src_v4, inner_src_port, inner_session_proto)?
    };

    // Build the translated inner IPv6 header.
    // The inner IPv4 packet was the translated forward flow (src=pool, dst=server).
    // Reconstruct the original pre-NAT IPv6 packet: src=client, dst=64:ff9b::server.
    let inner_src_v6 = fwd_key.src_v6; // original client
    let inner_dst_v6 = fwd_key.dst_v6; // 64:ff9b::server
    let inner_next_header = match inner_protocol {
        1 => 58,
        p => p,
    };

    let inner_tp_len = inner_tp.len();
    let inner_payload_len = inner_tp_len as u16;

    let mut inner_v6 = Vec::with_capacity(IPV6_HDR_LEN + inner_tp_len);
    inner_v6.push(0x60);
    inner_v6.extend_from_slice(&[0x00, 0x00, 0x00]);
    inner_v6.extend_from_slice(&inner_payload_len.to_be_bytes());
    inner_v6.push(inner_next_header);
    inner_v6.push(inner_v4[8]); // TTL -> hop limit
    inner_v6.extend_from_slice(&inner_src_v6.octets());
    inner_v6.extend_from_slice(&inner_dst_v6.octets());

    // Rewrite inner transport dest port back to original
    if inner_tp_len >= 4 {
        let mut tp = inner_tp.to_vec();
        match inner_protocol {
            6 | 17 if tp.len() >= 4 => {
                // Restore original destination port (client's source port)
                tp[2] = (fwd_key.src_port >> 8) as u8;
                tp[3] = (fwd_key.src_port & 0xFF) as u8;
            }
            1 if tp.len() >= 6 => {
                // Restore ICMP identifier
                tp[4] = (fwd_key.src_port >> 8) as u8;
                tp[5] = (fwd_key.src_port & 0xFF) as u8;
            }
            _ => {}
        }
        inner_v6.extend_from_slice(&tp);
    }

    // Build the outer ICMPv6 error packet
    let outer_src_v4 = Ipv4Addr::new(
        ipv4_packet[12],
        ipv4_packet[13],
        ipv4_packet[14],
        ipv4_packet[15],
    );
    let outer_src_v6 = nat64_core::addr::embed_ipv4_in_ipv6(nat64_prefix, outer_src_v4);
    let outer_dst_v6 = fwd_key.src_v6; // error goes back to the original client

    let icmpv6_body_len = 8 + inner_v6.len(); // type+code+cksum+unused + inner
    let ttl = ipv4_packet[8];
    let tos = ipv4_packet[1];

    let mut pkt = Vec::with_capacity(IPV6_HDR_LEN + icmpv6_body_len);
    pkt.push(0x60 | (tos >> 4));
    pkt.push(tos << 4);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.extend_from_slice(&(icmpv6_body_len as u16).to_be_bytes());
    pkt.push(58); // ICMPv6
    pkt.push(ttl.saturating_sub(1));
    pkt.extend_from_slice(&outer_src_v6.octets());
    pkt.extend_from_slice(&outer_dst_v6.octets());

    // ICMPv6 error body
    let mut icmpv6 = Vec::with_capacity(icmpv6_body_len);
    icmpv6.push(mapping.icmp_type);
    icmpv6.push(mapping.icmp_code);
    icmpv6.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    // Copy the 4-byte field
    icmpv6.extend_from_slice(&payload[4..8]);
    icmpv6.extend_from_slice(&inner_v6);

    // For Frag Needed -> Packet Too Big, adjust MTU
    if payload[0] == nat64_core::icmp::ICMPV4_DEST_UNREACHABLE
        && payload[1] == nat64_core::icmp::ICMPV4_DU_FRAG_NEEDED
    {
        let mtu_v4 = u16::from_be_bytes([payload[6], payload[7]]);
        // Add 20 bytes for IPv4→IPv6 header size difference
        let mtu_v6 = (u32::from(mtu_v4) + 20).min(65535);
        icmpv6[4] = (mtu_v6 >> 24) as u8;
        icmpv6[5] = ((mtu_v6 >> 16) & 0xFF) as u8;
        icmpv6[6] = ((mtu_v6 >> 8) & 0xFF) as u8;
        icmpv6[7] = (mtu_v6 & 0xFF) as u8;
    }

    // ICMPv6 checksum with pseudo-header
    let pseudo = nat64_core::checksum::ipv6_pseudo_header_sum(
        outer_src_v6,
        outer_dst_v6,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Ipv4Pool;
    use crate::session::SessionTimeouts;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    const NAT64_PREFIX: &str = "64:ff9b::";

    fn test_state() -> Arc<SharedState> {
        let cidrs = vec![(Ipv4Addr::new(198, 51, 100, 1), 32)];
        let pool = Ipv4Pool::new(&cidrs, (10000, 10100)).unwrap();
        Arc::new(SharedState::new(
            Some(NAT64_PREFIX.parse().unwrap()),
            "eth0".into(),
            "eth0".into(),
            pool,
            1000,
            SessionTimeouts::default(),
        ))
    }

    /// Build a minimal IPv6/TCP SYN packet.
    /// src_v6 is an arbitrary client, dst_v6 embeds the IPv4 destination under the NAT64 prefix.
    fn build_ipv6_tcp_syn(
        src_v6: Ipv6Addr,
        dst_v6: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let tcp_len: u16 = 20; // minimal TCP header
        let mut pkt = Vec::with_capacity(IPV6_HDR_LEN + tcp_len as usize);

        // IPv6 header
        pkt.push(0x60); // version=6, traffic class high nibble=0
        pkt.push(0x00); // traffic class low nibble + flow label
        pkt.push(0x00);
        pkt.push(0x00); // flow label
        pkt.extend_from_slice(&tcp_len.to_be_bytes()); // payload length
        pkt.push(6); // next header = TCP
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&src_v6.octets());
        pkt.extend_from_slice(&dst_v6.octets());

        // TCP header (20 bytes, SYN)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 1]); // seq = 1
        pkt.extend_from_slice(&[0, 0, 0, 0]); // ack = 0
        pkt.push(0x50); // data offset = 5 (20 bytes), no flags high nibble
        pkt.push(0x02); // SYN flag
        pkt.extend_from_slice(&[0x20, 0x00]); // window = 8192
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

        // Compute TCP checksum over IPv6 pseudo-header
        let pseudo =
            nat64_core::checksum::ipv6_pseudo_header_sum(src_v6, dst_v6, 6, tcp_len as u32);
        let tcp_data = &pkt[IPV6_HDR_LEN..];
        let mut sum = pseudo;
        let mut i = 0;
        while i + 1 < tcp_data.len() {
            sum += u32::from(u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]));
            i += 2;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        let cksum_off = IPV6_HDR_LEN + 16;
        pkt[cksum_off] = (cksum >> 8) as u8;
        pkt[cksum_off + 1] = (cksum & 0xFF) as u8;

        pkt
    }

    /// Build a minimal IPv6/UDP packet.
    fn build_ipv6_udp(
        src_v6: Ipv6Addr,
        dst_v6: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut pkt = Vec::with_capacity(IPV6_HDR_LEN + udp_len);

        // IPv6 header
        pkt.push(0x60);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pkt.push(17); // UDP
        pkt.push(64);
        pkt.extend_from_slice(&src_v6.octets());
        pkt.extend_from_slice(&dst_v6.octets());

        // UDP header
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(payload);

        // Compute UDP checksum
        let pseudo =
            nat64_core::checksum::ipv6_pseudo_header_sum(src_v6, dst_v6, 17, udp_len as u32);
        let udp_data = &pkt[IPV6_HDR_LEN..];
        let mut sum = pseudo;
        let mut i = 0;
        while i + 1 < udp_data.len() {
            sum += u32::from(u16::from_be_bytes([udp_data[i], udp_data[i + 1]]));
            i += 2;
        }
        if i < udp_data.len() {
            sum += u32::from(udp_data[i]) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        let cksum = if cksum == 0 { 0xFFFF } else { cksum };
        let cksum_off = IPV6_HDR_LEN + 6;
        pkt[cksum_off] = (cksum >> 8) as u8;
        pkt[cksum_off + 1] = (cksum & 0xFF) as u8;

        pkt
    }

    /// Build a minimal IPv6/ICMPv6 echo request.
    fn build_ipv6_icmp_echo(
        src_v6: Ipv6Addr,
        dst_v6: Ipv6Addr,
        identifier: u16,
        seq: u16,
    ) -> Vec<u8> {
        let icmp_len: usize = 8;
        let mut pkt = Vec::with_capacity(IPV6_HDR_LEN + icmp_len);

        // IPv6 header
        pkt.push(0x60);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&(icmp_len as u16).to_be_bytes());
        pkt.push(58); // ICMPv6
        pkt.push(64);
        pkt.extend_from_slice(&src_v6.octets());
        pkt.extend_from_slice(&dst_v6.octets());

        // ICMPv6 echo request
        pkt.push(128); // type = echo request
        pkt.push(0); // code
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&identifier.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());

        // Compute ICMPv6 checksum
        let pseudo =
            nat64_core::checksum::ipv6_pseudo_header_sum(src_v6, dst_v6, 58, icmp_len as u32);
        let icmp_data = &pkt[IPV6_HDR_LEN..];
        let mut sum = pseudo;
        let mut i = 0;
        while i + 1 < icmp_data.len() {
            sum += u32::from(u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]));
            i += 2;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        pkt[IPV6_HDR_LEN + 2] = (cksum >> 8) as u8;
        pkt[IPV6_HDR_LEN + 3] = (cksum & 0xFF) as u8;

        pkt
    }

    /// Verify IPv4 header checksum is valid.
    fn verify_ipv4_checksum(pkt: &[u8]) -> bool {
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        nat64_core::checksum::internet_checksum(&pkt[..ihl]) == 0
    }

    /// Verify TCP checksum over IPv4 pseudo-header.
    fn verify_tcp_checksum_v4(pkt: &[u8]) -> bool {
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let tcp_data = &pkt[ihl..total_len];
        let pseudo =
            nat64_core::checksum::ipv4_pseudo_header_sum(src, dst, 6, tcp_data.len() as u16);
        let mut sum = pseudo;
        let mut i = 0;
        while i + 1 < tcp_data.len() {
            sum += u32::from(u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]));
            i += 2;
        }
        if i < tcp_data.len() {
            sum += u32::from(tcp_data[i]) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum as u16 == 0xFFFF
    }

    // --- Tests ---

    #[test]
    fn test_extract_ports_tcp() {
        let payload = [0x00, 0x50, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01];
        let (src, dst) = extract_ports(6, &payload).unwrap();
        assert_eq!(src, 80);
        assert_eq!(dst, 443);
    }

    #[test]
    fn test_extract_ports_udp() {
        let payload = [0x04, 0x00, 0x00, 0x35, 0x00, 0x10, 0x00, 0x00];
        let (src, dst) = extract_ports(17, &payload).unwrap();
        assert_eq!(src, 1024);
        assert_eq!(dst, 53);
    }

    #[test]
    fn test_extract_ports_icmp() {
        // Type=8, Code=0, Checksum=0, Identifier=0x1234, Seq=1
        let payload = [8, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
        let (src, dst) = extract_ports(1, &payload).unwrap();
        assert_eq!(src, 0x1234);
        assert_eq!(dst, 0x1234);
    }

    #[test]
    fn test_extract_ports_too_short() {
        assert!(extract_ports(6, &[0, 1, 2]).is_none());
        assert!(extract_ports(1, &[8, 0, 0, 0, 0x12]).is_none()); // needs 6 bytes for ICMP
    }

    #[test]
    fn test_v6_to_v4_tcp_syn() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst_v4 = Ipv4Addr::new(198, 51, 100, 200);
        let dst_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, dst_v4);

        let ipv6_pkt = build_ipv6_tcp_syn(src_v6, dst_v6, 12345, 80);
        let ipv4_pkt =
            translate_v6_to_v4(&ipv6_pkt, prefix, &state).expect("translation should succeed");

        // Verify IPv4 basics
        assert_eq!(ipv4_pkt[0] >> 4, 4); // version
        assert_eq!(ipv4_pkt[9], 6); // protocol = TCP

        // Dst should be the extracted IPv4
        let out_dst = Ipv4Addr::new(ipv4_pkt[16], ipv4_pkt[17], ipv4_pkt[18], ipv4_pkt[19]);
        assert_eq!(out_dst, dst_v4);

        // Src should be the pool address
        let out_src = Ipv4Addr::new(ipv4_pkt[12], ipv4_pkt[13], ipv4_pkt[14], ipv4_pkt[15]);
        assert_eq!(out_src, Ipv4Addr::new(198, 51, 100, 1));

        // TTL should be decremented
        assert_eq!(ipv4_pkt[8], 63);

        // Verify checksums
        assert!(verify_ipv4_checksum(&ipv4_pkt));
        assert!(verify_tcp_checksum_v4(&ipv4_pkt));

        // Source port should be rewritten to mapped_port (from pool)
        let tcp_src_port = u16::from_be_bytes([ipv4_pkt[20], ipv4_pkt[21]]);
        assert!((10000..=10100).contains(&tcp_src_port));

        // Dest port preserved
        let tcp_dst_port = u16::from_be_bytes([ipv4_pkt[22], ipv4_pkt[23]]);
        assert_eq!(tcp_dst_port, 80);

        // Session should be created
        assert_eq!(state.translation_count(), 1);
        let nat = state.nat.lock().unwrap();
        assert_eq!(nat.sessions.len(), 1);
    }

    #[test]
    fn test_v6_to_v4_creates_session_and_reuses() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, Ipv4Addr::new(93, 184, 216, 34));

        let pkt1 = build_ipv6_tcp_syn(src_v6, dst_v6, 54321, 443);
        let out1 = translate_v6_to_v4(&pkt1, prefix, &state).unwrap();
        let mapped_port1 = u16::from_be_bytes([out1[20], out1[21]]);

        // Second packet with same 5-tuple should reuse the same session
        let pkt2 = build_ipv6_tcp_syn(src_v6, dst_v6, 54321, 443);
        let out2 = translate_v6_to_v4(&pkt2, prefix, &state).unwrap();
        let mapped_port2 = u16::from_be_bytes([out2[20], out2[21]]);

        assert_eq!(mapped_port1, mapped_port2);
        assert_eq!(state.translation_count(), 2);
        let nat = state.nat.lock().unwrap();
        assert_eq!(nat.sessions.len(), 1); // still one session
    }

    #[test]
    fn test_v6_to_v4_wrong_prefix_dropped() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        // Destination does NOT match the NAT64 prefix
        let dst_v6: Ipv6Addr = "2001:db8:1234::1".parse().unwrap();

        let pkt = build_ipv6_tcp_syn(src_v6, dst_v6, 12345, 80);
        assert!(translate_v6_to_v4(&pkt, prefix, &state).is_none());
    }

    #[test]
    fn test_v6_to_v4_runt_packet_dropped() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let short = [0x60, 0x00, 0x00]; // way too short
        assert!(translate_v6_to_v4(&short, prefix, &state).is_none());
    }

    #[test]
    fn test_v6_to_v4_udp() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let src_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
        let dst_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, dst_v4);

        let dns_query = [0xAA, 0xBB, 0x01, 0x00]; // fake DNS
        let pkt = build_ipv6_udp(src_v6, dst_v6, 5000, 53, &dns_query);
        let out = translate_v6_to_v4(&pkt, prefix, &state).unwrap();

        assert_eq!(out[0] >> 4, 4); // IPv4
        assert_eq!(out[9], 17); // UDP

        let out_dst = Ipv4Addr::new(out[16], out[17], out[18], out[19]);
        assert_eq!(out_dst, dst_v4);

        assert!(verify_ipv4_checksum(&out));

        // Dest port preserved
        let udp_dst_port = u16::from_be_bytes([out[22], out[23]]);
        assert_eq!(udp_dst_port, 53);

        // Payload preserved
        let ihl = ((out[0] & 0x0F) as usize) * 4;
        let udp_payload = &out[ihl + 8..];
        assert_eq!(udp_payload, &dns_query);
    }

    #[test]
    fn test_v6_to_v4_icmp_echo() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let src_v6: Ipv6Addr = "2001:db8::3".parse().unwrap();
        let dst_v4 = Ipv4Addr::new(1, 1, 1, 1);
        let dst_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, dst_v4);

        let pkt = build_ipv6_icmp_echo(src_v6, dst_v6, 0x1234, 1);
        let out = translate_v6_to_v4(&pkt, prefix, &state).unwrap();

        assert_eq!(out[0] >> 4, 4);
        assert_eq!(out[9], 1); // ICMP

        // ICMPv6 echo request (128) -> ICMPv4 echo request (8)
        let ihl = ((out[0] & 0x0F) as usize) * 4;
        assert_eq!(out[ihl], 8); // ICMP echo request type

        // Verify ICMP checksum
        let total_len = u16::from_be_bytes([out[2], out[3]]) as usize;
        let icmp_data = &out[ihl..total_len];
        assert_eq!(nat64_core::checksum::internet_checksum(icmp_data), 0);

        assert!(verify_ipv4_checksum(&out));
    }

    #[test]
    fn test_v4_to_v6_roundtrip_tcp() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let server_v4 = Ipv4Addr::new(93, 184, 216, 34);
        let dst_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, server_v4);

        // Step 1: v6->v4 (client sends TCP SYN)
        let v6_pkt = build_ipv6_tcp_syn(client_v6, dst_v6, 54321, 80);
        let v4_pkt = translate_v6_to_v4(&v6_pkt, prefix, &state).unwrap();
        let mapped_port = u16::from_be_bytes([v4_pkt[20], v4_pkt[21]]);
        let pool_addr = Ipv4Addr::new(v4_pkt[12], v4_pkt[13], v4_pkt[14], v4_pkt[15]);

        // Step 2: Build an IPv4 response (server replies with SYN-ACK)
        let tcp_reply_len: u16 = 20;
        let total_v4_len = (IPV4_HDR_LEN as u16) + tcp_reply_len;
        let mut reply = Vec::with_capacity(total_v4_len as usize);

        // IPv4 header: server -> pool_addr
        reply.push(0x45);
        reply.push(0x00);
        reply.extend_from_slice(&total_v4_len.to_be_bytes());
        reply.extend_from_slice(&[0x00, 0x01]); // id
        reply.extend_from_slice(&[0x40, 0x00]); // DF
        reply.push(64); // TTL
        reply.push(6); // TCP
        reply.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        reply.extend_from_slice(&server_v4.octets()); // src
        reply.extend_from_slice(&pool_addr.octets()); // dst

        let hdr_cksum = nat64_core::checksum::ipv4_header_checksum(&reply[..IPV4_HDR_LEN]);
        reply[10] = (hdr_cksum >> 8) as u8;
        reply[11] = (hdr_cksum & 0xFF) as u8;

        // TCP: src=80, dst=mapped_port, SYN-ACK
        reply.extend_from_slice(&80u16.to_be_bytes()); // src port
        reply.extend_from_slice(&mapped_port.to_be_bytes()); // dst port
        reply.extend_from_slice(&[0, 0, 0, 0]); // seq
        reply.extend_from_slice(&[0, 0, 0, 2]); // ack
        reply.push(0x50); // data offset
        reply.push(0x12); // SYN+ACK
        reply.extend_from_slice(&[0x20, 0x00]); // window
        reply.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        reply.extend_from_slice(&[0x00, 0x00]); // urgent

        // Compute TCP checksum
        let tcp_data = &mut reply[IPV4_HDR_LEN..].to_vec();
        let pseudo = nat64_core::checksum::ipv4_pseudo_header_sum(
            server_v4,
            pool_addr,
            6,
            tcp_data.len() as u16,
        );
        let mut sum = pseudo;
        let mut i = 0;
        while i + 1 < tcp_data.len() {
            sum += u32::from(u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]));
            i += 2;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        let cksum_off = IPV4_HDR_LEN + 16;
        reply[cksum_off] = (cksum >> 8) as u8;
        reply[cksum_off + 1] = (cksum & 0xFF) as u8;

        // Step 3: v4->v6 (reverse translate the reply)
        let v6_reply =
            translate_v4_to_v6(&reply, prefix, &state).expect("reverse translation should succeed");

        // Verify IPv6 header
        assert_eq!(v6_reply[0] >> 4, 6); // version
        assert_eq!(v6_reply[6], 6); // next header = TCP

        // Dst should be the original client
        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&v6_reply[24..40]);
        let out_dst = Ipv6Addr::from(dst_bytes);
        assert_eq!(out_dst, client_v6);

        // Src should be server embedded in prefix
        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&v6_reply[8..24]);
        let out_src = Ipv6Addr::from(src_bytes);
        let expected_src = nat64_core::addr::embed_ipv4_in_ipv6(prefix, server_v4);
        assert_eq!(out_src, expected_src);

        // Dest port should be restored to the client's original source port
        let tcp_dst_port =
            u16::from_be_bytes([v6_reply[IPV6_HDR_LEN + 2], v6_reply[IPV6_HDR_LEN + 3]]);
        assert_eq!(tcp_dst_port, 54321);

        // Src port should be 80 (server's port)
        let tcp_src_port = u16::from_be_bytes([v6_reply[IPV6_HDR_LEN], v6_reply[IPV6_HDR_LEN + 1]]);
        assert_eq!(tcp_src_port, 80);

        assert_eq!(state.translation_count(), 2); // one forward, one reverse
    }

    #[test]
    fn test_v4_to_v6_no_session_drops() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();

        // Build IPv4 packet to a pool address without any session
        let total_len: u16 = 40;
        let mut pkt = Vec::with_capacity(total_len as usize);
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0x40, 0x00]);
        pkt.push(64);
        pkt.push(6);
        pkt.extend_from_slice(&[0, 0]); // checksum
        pkt.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        pkt.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 1).octets());

        let hdr_cksum = nat64_core::checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (hdr_cksum >> 8) as u8;
        pkt[11] = (hdr_cksum & 0xFF) as u8;

        // TCP: src=80, dst=10000 (no session for this)
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&10000u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 16]); // rest of TCP header

        assert!(translate_v4_to_v6(&pkt, prefix, &state).is_none());
    }

    #[test]
    fn test_v4_to_v6_runt_dropped() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        assert!(translate_v4_to_v6(&[0x45, 0x00], prefix, &state).is_none());
    }

    #[test]
    fn test_v4_to_v6_wrong_version_dropped() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let mut pkt = vec![0x60; 40]; // version 6 in an IPv4 slot
        pkt[2] = 0;
        pkt[3] = 40;
        assert!(translate_v4_to_v6(&pkt, prefix, &state).is_none());
    }

    #[test]
    fn test_session_exhaustion() {
        // Pool with only 2 ports
        let cidrs = vec![(Ipv4Addr::new(198, 51, 100, 1), 32)];
        let pool = Ipv4Pool::new(&cidrs, (10000, 10001)).unwrap();
        let state = Arc::new(SharedState::new(
            Some(NAT64_PREFIX.parse().unwrap()),
            "eth0".into(),
            "eth0".into(),
            pool,
            1000, // max_sessions high, pool is the bottleneck
            SessionTimeouts::default(),
        ));

        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, Ipv4Addr::new(10, 0, 0, 1));

        // First two should succeed (2 ports available for TCP)
        let pkt1 = build_ipv6_tcp_syn(src_v6, dst_v6, 1000, 80);
        assert!(translate_v6_to_v4(&pkt1, prefix, &state).is_some());

        let pkt2 = build_ipv6_tcp_syn(src_v6, dst_v6, 1001, 80);
        assert!(translate_v6_to_v4(&pkt2, prefix, &state).is_some());

        // Third should fail — pool exhausted
        let pkt3 = build_ipv6_tcp_syn(src_v6, dst_v6, 1002, 80);
        assert!(translate_v6_to_v4(&pkt3, prefix, &state).is_none());
    }

    #[test]
    fn test_icmp_echo_roundtrip() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let client_v6: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let server_v4 = Ipv4Addr::new(1, 1, 1, 1);
        let dst_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, server_v4);

        // v6->v4: ICMPv6 echo request
        let v6_pkt = build_ipv6_icmp_echo(client_v6, dst_v6, 0xABCD, 1);
        let v4_pkt = translate_v6_to_v4(&v6_pkt, prefix, &state).unwrap();
        let ihl = ((v4_pkt[0] & 0x0F) as usize) * 4;

        // Should be ICMP echo request (type 8)
        assert_eq!(v4_pkt[ihl], 8);

        // Build ICMPv4 echo reply from the server
        let pool_addr = Ipv4Addr::new(v4_pkt[12], v4_pkt[13], v4_pkt[14], v4_pkt[15]);
        let icmp_id = u16::from_be_bytes([v4_pkt[ihl + 4], v4_pkt[ihl + 5]]);

        let icmp_reply_len: usize = 8;
        let total_len = (IPV4_HDR_LEN + icmp_reply_len) as u16;
        let mut reply = Vec::with_capacity(total_len as usize);
        reply.push(0x45);
        reply.push(0x00);
        reply.extend_from_slice(&total_len.to_be_bytes());
        reply.extend_from_slice(&[0, 0, 0x40, 0x00]);
        reply.push(64);
        reply.push(1); // ICMP
        reply.extend_from_slice(&[0, 0]);
        reply.extend_from_slice(&server_v4.octets());
        reply.extend_from_slice(&pool_addr.octets());

        let hdr_cksum = nat64_core::checksum::ipv4_header_checksum(&reply[..IPV4_HDR_LEN]);
        reply[10] = (hdr_cksum >> 8) as u8;
        reply[11] = (hdr_cksum & 0xFF) as u8;

        // ICMP echo reply: type=0, code=0
        reply.push(0); // type = echo reply
        reply.push(0);
        reply.extend_from_slice(&[0, 0]); // checksum placeholder
        reply.extend_from_slice(&icmp_id.to_be_bytes());
        reply.extend_from_slice(&1u16.to_be_bytes()); // seq

        let icmp_data = &reply[IPV4_HDR_LEN..];
        let cksum = nat64_core::checksum::internet_checksum(icmp_data);
        reply[IPV4_HDR_LEN + 2] = (cksum >> 8) as u8;
        reply[IPV4_HDR_LEN + 3] = (cksum & 0xFF) as u8;

        // v4->v6: translate reply back
        let v6_reply = translate_v4_to_v6(&reply, prefix, &state).unwrap();

        // Should be ICMPv6 echo reply (type 129)
        assert_eq!(v6_reply[IPV6_HDR_LEN], 129);

        // Destination should be original client
        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&v6_reply[24..40]);
        assert_eq!(Ipv6Addr::from(dst_bytes), client_v6);
    }

    /// Build an ICMPv6 Destination Unreachable error wrapping an inner IPv6/TCP packet.
    fn build_icmpv6_error(
        src_v6: Ipv6Addr,
        dst_v6: Ipv6Addr,
        icmp_type: u8,
        icmp_code: u8,
        extra_field: [u8; 4],
        inner_pkt: &[u8],
    ) -> Vec<u8> {
        let icmpv6_len = 8 + inner_pkt.len(); // type+code+cksum+field(4) + inner
        let payload_len = icmpv6_len as u16;
        let mut pkt = Vec::with_capacity(IPV6_HDR_LEN + icmpv6_len);

        // IPv6 header
        pkt.push(0x60);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.push(58); // ICMPv6
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&src_v6.octets());
        pkt.extend_from_slice(&dst_v6.octets());

        // ICMPv6 body
        pkt.push(icmp_type);
        pkt.push(icmp_code);
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&extra_field);
        pkt.extend_from_slice(inner_pkt);

        // Compute ICMPv6 checksum
        let icmpv6_data = &pkt[IPV6_HDR_LEN..];
        let pseudo = nat64_core::checksum::ipv6_pseudo_header_sum(
            src_v6,
            dst_v6,
            58,
            icmpv6_data.len() as u32,
        );
        let mut sum = pseudo;
        let mut i = 0;
        while i + 1 < icmpv6_data.len() {
            sum += u32::from(u16::from_be_bytes([icmpv6_data[i], icmpv6_data[i + 1]]));
            i += 2;
        }
        if i < icmpv6_data.len() {
            sum += u32::from(icmpv6_data[i]) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        let cksum_offset = IPV6_HDR_LEN + 2;
        pkt[cksum_offset] = (cksum >> 8) as u8;
        pkt[cksum_offset + 1] = (cksum & 0xFF) as u8;

        pkt
    }

    /// Build an ICMPv4 error wrapping an inner IPv4 packet.
    fn build_icmpv4_error(
        src_v4: Ipv4Addr,
        dst_v4: Ipv4Addr,
        icmp_type: u8,
        icmp_code: u8,
        extra_field: [u8; 4],
        inner_pkt: &[u8],
    ) -> Vec<u8> {
        let icmp_len = 8 + inner_pkt.len();
        let total_len = (IPV4_HDR_LEN + icmp_len) as u16;
        let mut pkt = Vec::with_capacity(total_len as usize);

        // IPv4 header
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.push(64); // TTL
        pkt.push(1); // ICMP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&src_v4.octets());
        pkt.extend_from_slice(&dst_v4.octets());

        let hdr_cksum = nat64_core::checksum::ipv4_header_checksum(&pkt[..IPV4_HDR_LEN]);
        pkt[10] = (hdr_cksum >> 8) as u8;
        pkt[11] = (hdr_cksum & 0xFF) as u8;

        // ICMP body
        pkt.push(icmp_type);
        pkt.push(icmp_code);
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&extra_field);
        pkt.extend_from_slice(inner_pkt);

        // Compute ICMP checksum
        let icmp_data = &pkt[IPV4_HDR_LEN..];
        let cksum = nat64_core::checksum::internet_checksum(icmp_data);
        pkt[IPV4_HDR_LEN + 2] = (cksum >> 8) as u8;
        pkt[IPV4_HDR_LEN + 3] = (cksum & 0xFF) as u8;

        pkt
    }

    #[test]
    fn test_icmpv6_dest_unreachable_translates_to_v4() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let server_v4 = Ipv4Addr::new(93, 184, 216, 34);
        let server_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, server_v4);
        let client_v6: Ipv6Addr = "2001:db8::10".parse().unwrap();

        // Scenario: A return IPv6 packet (src=64:ff9b::server, dst=client) was being
        // forwarded and hit a router that sent an ICMPv6 error TO 64:ff9b::server
        // (the source of the offending return packet). Since 64:ff9b::/96 is routed
        // to the PLAT, this error arrives at us.
        //
        // The inner embedded packet is the offending return packet:
        //   src=server_v6 (64:ff9b::server), dst=client_v6
        let router_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
        let inner_v6_pkt = build_ipv6_tcp_syn(server_v6, client_v6, 80, 44444);
        let icmpv6_error = build_icmpv6_error(
            router_v6,
            server_v6, // dst is in NAT64 prefix, so PLAT receives it
            1,         // Dest Unreachable
            0,         // No route to destination
            [0, 0, 0, 0],
            &inner_v6_pkt,
        );

        // Translate the ICMPv6 error to ICMPv4
        let v4_error = translate_v6_to_v4(&icmpv6_error, prefix, &state).unwrap();

        // Verify outer IPv4 header
        assert_eq!(v4_error[0] >> 4, 4); // IPv4
        assert_eq!(v4_error[9], 1); // ICMP
        assert!(verify_ipv4_checksum(&v4_error));

        // ICMP type should be 3 (Dest Unreachable)
        let ihl = ((v4_error[0] & 0x0F) as usize) * 4;
        assert_eq!(v4_error[ihl], 3);

        // Verify ICMP checksum
        let total_len = u16::from_be_bytes([v4_error[2], v4_error[3]]) as usize;
        let icmp_data = &v4_error[ihl..total_len];
        assert_eq!(nat64_core::checksum::internet_checksum(icmp_data), 0);

        // Verify there's an inner IPv4 packet embedded
        let inner_v4_start = ihl + 8;
        assert!(v4_error.len() > inner_v4_start + IPV4_HDR_LEN);
        assert_eq!(v4_error[inner_v4_start] >> 4, 4); // inner is IPv4
    }

    #[test]
    fn test_icmpv6_packet_too_big_mtu_adjustment() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let server_v4 = Ipv4Addr::new(8, 8, 8, 8);
        let server_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, server_v4);
        let client_v6: Ipv6Addr = "2001:db8::20".parse().unwrap();

        // Same scenario: a return packet (src=server_v6, dst=client) triggered
        // a Packet Too Big. Error is sent to server_v6 (in NAT64 prefix).
        let router_v6: Ipv6Addr = "2001:db8:aaaa::1".parse().unwrap();
        let inner_pkt = build_ipv6_tcp_syn(server_v6, client_v6, 443, 55555);
        let mtu_v6: u32 = 1280;
        let mtu_field = mtu_v6.to_be_bytes();
        let icmpv6_ptb = build_icmpv6_error(
            router_v6, server_v6, // dst in NAT64 prefix
            2,         // Packet Too Big
            0, mtu_field, &inner_pkt,
        );

        let v4_error = translate_v6_to_v4(&icmpv6_ptb, prefix, &state).unwrap();

        // Should be ICMPv4 Dest Unreachable, code 4 (Frag Needed)
        let ihl = ((v4_error[0] & 0x0F) as usize) * 4;
        assert_eq!(v4_error[ihl], 3); // Dest Unreachable
        assert_eq!(v4_error[ihl + 1], 4); // Frag Needed

        // MTU should be adjusted: 1280 - 20 = 1260
        let mtu_v4 = u16::from_be_bytes([v4_error[ihl + 6], v4_error[ihl + 7]]);
        assert_eq!(mtu_v4, 1260);
    }

    #[test]
    fn test_icmpv4_dest_unreachable_translates_to_v6() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let client_v6: Ipv6Addr = "2001:db8::30".parse().unwrap();
        let server_v4 = Ipv4Addr::new(203, 0, 113, 1);
        let server_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, server_v4);

        // Establish session via v6->v4 translation
        let tcp_pkt = build_ipv6_tcp_syn(client_v6, server_v6, 33333, 80);
        let v4_out = translate_v6_to_v4(&tcp_pkt, prefix, &state).unwrap();
        let pool_addr = Ipv4Addr::new(v4_out[12], v4_out[13], v4_out[14], v4_out[15]);
        let mapped_port = u16::from_be_bytes([v4_out[20], v4_out[21]]);

        // Build an ICMPv4 Dest Unreachable (Port Unreachable) from the server,
        // embedding the translated IPv4 packet (src=pool, dst=server, sport=mapped)
        let inner_v4_total = IPV4_HDR_LEN + 8; // header + 8 bytes of TCP
        let mut inner_v4 = Vec::with_capacity(inner_v4_total);
        inner_v4.push(0x45);
        inner_v4.push(0x00);
        inner_v4.extend_from_slice(&(inner_v4_total as u16).to_be_bytes());
        inner_v4.extend_from_slice(&[0, 0, 0x40, 0x00]);
        inner_v4.push(63); // TTL
        inner_v4.push(6); // TCP
        inner_v4.extend_from_slice(&[0, 0]); // checksum placeholder
        inner_v4.extend_from_slice(&pool_addr.octets()); // src = pool
        inner_v4.extend_from_slice(&server_v4.octets()); // dst = server

        let hdr_cksum = nat64_core::checksum::ipv4_header_checksum(&inner_v4[..IPV4_HDR_LEN]);
        inner_v4[10] = (hdr_cksum >> 8) as u8;
        inner_v4[11] = (hdr_cksum & 0xFF) as u8;

        // TCP: 8 bytes (src_port=mapped, dst_port=80, seq, ...)
        inner_v4.extend_from_slice(&mapped_port.to_be_bytes());
        inner_v4.extend_from_slice(&80u16.to_be_bytes());
        inner_v4.extend_from_slice(&[0, 0, 0, 0]); // seq number

        let icmpv4_error = build_icmpv4_error(
            server_v4,
            pool_addr,
            3, // Dest Unreachable
            3, // Port Unreachable
            [0, 0, 0, 0],
            &inner_v4,
        );

        let v6_error = translate_v4_to_v6(&icmpv4_error, prefix, &state).unwrap();

        // Verify outer IPv6 header
        assert_eq!(v6_error[0] >> 4, 6); // IPv6
        assert_eq!(v6_error[6], 58); // ICMPv6

        // Destination should be the original client
        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&v6_error[24..40]);
        assert_eq!(Ipv6Addr::from(dst_bytes), client_v6);

        // ICMPv6 type should be 1 (Dest Unreachable)
        assert_eq!(v6_error[IPV6_HDR_LEN], 1);

        // Verify inner IPv6 packet has restored destination port
        let inner_v6_start = IPV6_HDR_LEN + 8; // after ICMPv6 header
        let inner_v6_tcp_start = inner_v6_start + IPV6_HDR_LEN;
        if v6_error.len() > inner_v6_tcp_start + 4 {
            let inner_dst_port = u16::from_be_bytes([
                v6_error[inner_v6_tcp_start + 2],
                v6_error[inner_v6_tcp_start + 3],
            ]);
            assert_eq!(inner_dst_port, 33333); // restored original src_port
        }
    }

    #[test]
    fn test_icmpv4_frag_needed_mtu_adjustment() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let client_v6: Ipv6Addr = "2001:db8::40".parse().unwrap();
        let server_v4 = Ipv4Addr::new(198, 51, 100, 50);
        let server_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, server_v4);

        // Establish session
        let tcp_pkt = build_ipv6_tcp_syn(client_v6, server_v6, 22222, 443);
        let v4_out = translate_v6_to_v4(&tcp_pkt, prefix, &state).unwrap();
        let pool_addr = Ipv4Addr::new(v4_out[12], v4_out[13], v4_out[14], v4_out[15]);
        let mapped_port = u16::from_be_bytes([v4_out[20], v4_out[21]]);

        // Build inner IPv4 packet (the offending packet)
        let inner_v4_total = IPV4_HDR_LEN + 8;
        let mut inner_v4 = Vec::with_capacity(inner_v4_total);
        inner_v4.push(0x45);
        inner_v4.push(0x00);
        inner_v4.extend_from_slice(&(inner_v4_total as u16).to_be_bytes());
        inner_v4.extend_from_slice(&[0, 0, 0x40, 0x00]);
        inner_v4.push(63);
        inner_v4.push(6); // TCP
        inner_v4.extend_from_slice(&[0, 0]);
        inner_v4.extend_from_slice(&pool_addr.octets());
        inner_v4.extend_from_slice(&server_v4.octets());

        let hdr_cksum = nat64_core::checksum::ipv4_header_checksum(&inner_v4[..IPV4_HDR_LEN]);
        inner_v4[10] = (hdr_cksum >> 8) as u8;
        inner_v4[11] = (hdr_cksum & 0xFF) as u8;

        inner_v4.extend_from_slice(&mapped_port.to_be_bytes());
        inner_v4.extend_from_slice(&443u16.to_be_bytes());
        inner_v4.extend_from_slice(&[0, 0, 0, 0]);

        // ICMPv4 Frag Needed: type=3, code=4, bytes 6-7 = next-hop MTU
        let mtu_v4: u16 = 1400;
        let extra = [0, 0, (mtu_v4 >> 8) as u8, (mtu_v4 & 0xFF) as u8];
        let icmpv4_error = build_icmpv4_error(
            server_v4, pool_addr, 3, // Dest Unreachable
            4, // Frag Needed
            extra, &inner_v4,
        );

        let v6_error = translate_v4_to_v6(&icmpv4_error, prefix, &state).unwrap();

        // Should be ICMPv6 Packet Too Big (type=2)
        assert_eq!(v6_error[IPV6_HDR_LEN], 2);

        // MTU should be adjusted: 1400 + 20 = 1420
        let mtu_v6 = u32::from_be_bytes([
            v6_error[IPV6_HDR_LEN + 4],
            v6_error[IPV6_HDR_LEN + 5],
            v6_error[IPV6_HDR_LEN + 6],
            v6_error[IPV6_HDR_LEN + 7],
        ]);
        assert_eq!(mtu_v6, 1420);
    }

    #[test]
    fn test_icmpv6_error_creates_session_for_inner_flow() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let server_v4 = Ipv4Addr::new(10, 0, 0, 1);
        let server_v6 = nat64_core::addr::embed_ipv4_in_ipv6(prefix, server_v4);
        let client_v6: Ipv6Addr = "2001:db8::99".parse().unwrap();

        // No session pre-established. The ICMP error handler uses lookup_or_create
        // so it will create a session for the inner flow on-the-fly.
        let router_v6: Ipv6Addr = "2001:db8:bbbb::1".parse().unwrap();
        let inner_pkt = build_ipv6_tcp_syn(server_v6, client_v6, 80, 11111);
        let icmpv6_error = build_icmpv6_error(
            router_v6,
            server_v6, // dst in NAT64 prefix
            1,
            0,
            [0, 0, 0, 0],
            &inner_pkt,
        );

        let result = translate_v6_to_v4(&icmpv6_error, prefix, &state);
        assert!(result.is_some());
    }

    #[test]
    fn test_icmpv6_error_runt_inner_dropped() {
        let state = test_state();
        let prefix: Ipv6Addr = NAT64_PREFIX.parse().unwrap();
        let router_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let client_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();

        // Build an ICMPv6 error with a too-short inner packet (< 40 bytes IPv6 header)
        let short_inner = [0x60, 0x00, 0x00, 0x00]; // only 4 bytes
        let icmpv6_error =
            build_icmpv6_error(router_v6, client_v6, 1, 0, [0, 0, 0, 0], &short_inner);

        assert!(translate_v6_to_v4(&icmpv6_error, prefix, &state).is_none());
    }
}
