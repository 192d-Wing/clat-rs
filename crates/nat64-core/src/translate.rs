use std::net::{Ipv4Addr, Ipv6Addr};

use crate::addr;
use crate::checksum;
use crate::icmp;

const IPV4_HEADER_MIN_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// Translate an IPv4 packet to IPv6.
///
/// Returns the translated IPv6 packet, or `None` if the packet should be dropped.
pub fn ipv4_to_ipv6(
    packet: &[u8],
    clat_prefix: Ipv6Addr,
    plat_prefix: Ipv6Addr,
) -> Option<Vec<u8>> {
    if packet.len() < IPV4_HEADER_MIN_LEN {
        return None;
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_HEADER_MIN_LEN || packet.len() < ihl {
        return None;
    }

    // Validate IPv4 header checksum to prevent checksum laundering (M-1).
    // TUN devices deliver packets before kernel checksum verification,
    // so corrupted packets could otherwise receive fresh valid checksums.
    if checksum::internet_checksum(&packet[..ihl]) != 0 {
        return None;
    }

    let tos = packet[1];
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < total_len {
        return None;
    }

    let protocol = packet[9];
    let ttl = packet[8];

    // Drop packets that would expire after translation (TTL decrement)
    if ttl <= 1 {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let payload = &packet[ihl..total_len];
    let payload_len = payload.len();

    // Map protocol: ICMP -> ICMPv6
    let next_header = match protocol {
        PROTO_ICMP => PROTO_ICMPV6,
        p => p,
    };

    // Build IPv6 addresses per RFC 6052
    let src_v6 = addr::embed_ipv4_in_ipv6(clat_prefix, src_ip);
    let dst_v6 = addr::embed_ipv4_in_ipv6(plat_prefix, dst_ip);

    // Build IPv6 header (40 bytes)
    let mut v6_packet = Vec::with_capacity(IPV6_HEADER_LEN + payload_len);

    // Version (4) + Traffic Class high 4 bits
    v6_packet.push(0x60 | (tos >> 4));
    // Traffic Class low 4 bits + Flow Label (20 bits, set to 0)
    v6_packet.push(tos << 4);
    v6_packet.push(0x00);
    v6_packet.push(0x00);

    // Payload Length
    if payload_len > u16::MAX as usize {
        return None;
    }
    v6_packet.extend_from_slice(&(payload_len as u16).to_be_bytes());

    // Next Header
    v6_packet.push(next_header);

    // Hop Limit (TTL - 1)
    v6_packet.push(ttl.saturating_sub(1));

    // Source IPv6
    v6_packet.extend_from_slice(&src_v6.octets());
    // Destination IPv6
    v6_packet.extend_from_slice(&dst_v6.octets());

    // Translate payload
    match protocol {
        PROTO_ICMP => {
            let translated_payload =
                translate_icmpv4_to_icmpv6(payload, src_v6, dst_v6, payload_len)?;
            v6_packet.extend_from_slice(&translated_payload);
        }
        PROTO_TCP => {
            let mut tcp_payload = payload.to_vec();
            adjust_tcp_checksum_v4_to_v6(
                &mut tcp_payload,
                src_ip,
                dst_ip,
                PROTO_TCP,
                src_v6,
                dst_v6,
                next_header,
            );
            v6_packet.extend_from_slice(&tcp_payload);
        }
        PROTO_UDP => {
            let mut udp_payload = payload.to_vec();
            adjust_udp_checksum_v4_to_v6(
                &mut udp_payload,
                src_ip,
                dst_ip,
                PROTO_UDP,
                src_v6,
                dst_v6,
                next_header,
            );
            v6_packet.extend_from_slice(&udp_payload);
        }
        _ => {
            // Pass through other protocols unchanged
            v6_packet.extend_from_slice(payload);
        }
    }

    Some(v6_packet)
}

/// Translate an IPv6 packet to IPv4.
///
/// Returns the translated IPv4 packet, or `None` if the packet should be dropped.
pub fn ipv6_to_ipv4(
    packet: &[u8],
    clat_prefix: Ipv6Addr,
    plat_prefix: Ipv6Addr,
) -> Option<Vec<u8>> {
    if packet.len() < IPV6_HEADER_LEN {
        return None;
    }

    let version = packet[0] >> 4;
    if version != 6 {
        return None;
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let next_header = packet[6];
    let hop_limit = packet[7];

    // Drop packets with expired hop limit (RFC 6145 §4).
    if hop_limit <= 1 {
        return None;
    }

    let mut src_octets = [0u8; 16];
    src_octets.copy_from_slice(&packet[8..24]);
    let src_v6 = Ipv6Addr::from(src_octets);

    let mut dst_octets = [0u8; 16];
    dst_octets.copy_from_slice(&packet[24..40]);
    let dst_v6 = Ipv6Addr::from(dst_octets);

    // Verify prefixes: src should match PLAT, dst should match CLAT
    if !addr::matches_prefix_96(src_v6, plat_prefix) {
        return None;
    }
    if !addr::matches_prefix_96(dst_v6, clat_prefix) {
        return None;
    }

    // Extract embedded IPv4 addresses
    let src_ip = addr::extract_ipv4_from_ipv6(src_v6);
    let dst_ip = addr::extract_ipv4_from_ipv6(dst_v6);

    let payload_start = IPV6_HEADER_LEN;
    if packet.len() < payload_start + payload_len {
        return None;
    }
    let payload = &packet[payload_start..payload_start + payload_len];

    // Map protocol: ICMPv6 -> ICMP
    let protocol = match next_header {
        PROTO_ICMPV6 => PROTO_ICMP,
        p => p,
    };

    if IPV4_HEADER_MIN_LEN + payload_len > u16::MAX as usize {
        return None;
    }
    let total_len = (IPV4_HEADER_MIN_LEN + payload_len) as u16;

    // Build IPv4 header
    let tos = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let mut v4_packet = Vec::with_capacity(total_len as usize);

    // Version + IHL (5 = no options)
    v4_packet.push(0x45);
    // TOS
    v4_packet.push(tos);
    // Total Length
    v4_packet.extend_from_slice(&total_len.to_be_bytes());
    // Identification (0)
    v4_packet.extend_from_slice(&[0x00, 0x00]);
    // Flags + Fragment Offset (DF=1, no fragmentation)
    v4_packet.extend_from_slice(&[0x40, 0x00]);
    // TTL
    v4_packet.push(hop_limit.saturating_sub(1));
    // Protocol
    v4_packet.push(protocol);
    // Header Checksum (placeholder)
    v4_packet.extend_from_slice(&[0x00, 0x00]);
    // Source IP
    v4_packet.extend_from_slice(&src_ip.octets());
    // Destination IP
    v4_packet.extend_from_slice(&dst_ip.octets());

    // Compute IPv4 header checksum
    let hdr_cksum = checksum::ipv4_header_checksum(&v4_packet[..IPV4_HEADER_MIN_LEN]);
    v4_packet[10] = (hdr_cksum >> 8) as u8;
    v4_packet[11] = (hdr_cksum & 0xFF) as u8;

    // Translate payload
    match next_header {
        PROTO_ICMPV6 => {
            let translated_payload =
                translate_icmpv6_to_icmpv4(payload, src_v6, dst_v6, payload_len)?;
            v4_packet.extend_from_slice(&translated_payload);
        }
        PROTO_TCP => {
            let mut tcp_payload = payload.to_vec();
            adjust_tcp_checksum_v6_to_v4(
                &mut tcp_payload,
                src_v6,
                dst_v6,
                next_header,
                src_ip,
                dst_ip,
                protocol,
            );
            v4_packet.extend_from_slice(&tcp_payload);
        }
        PROTO_UDP => {
            let mut udp_payload = payload.to_vec();
            adjust_udp_checksum_v6_to_v4(
                &mut udp_payload,
                src_v6,
                dst_v6,
                next_header,
                src_ip,
                dst_ip,
                protocol,
            );
            v4_packet.extend_from_slice(&udp_payload);
        }
        _ => {
            v4_packet.extend_from_slice(payload);
        }
    }

    Some(v4_packet)
}

/// Translate ICMPv4 payload to ICMPv6.
fn translate_icmpv4_to_icmpv6(
    payload: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    payload_len: usize,
) -> Option<Vec<u8>> {
    if payload.len() < 4 {
        return None;
    }

    // Validate incoming ICMPv4 checksum to prevent laundering (M-1).
    // ICMP checksums are fully recomputed during translation, so a
    // corrupted packet would receive a fresh valid checksum without this check.
    if checksum::internet_checksum(payload) != 0 {
        return None;
    }

    let mapping = icmp::icmpv4_to_icmpv6(payload[0], payload[1])?;

    let mut result = payload.to_vec();
    result[0] = mapping.icmp_type;
    result[1] = mapping.icmp_code;
    // Zero checksum before recalculating
    result[2] = 0;
    result[3] = 0;

    // ICMPv6 checksum includes pseudo-header
    let pseudo_sum =
        checksum::ipv6_pseudo_header_sum(src_v6, dst_v6, PROTO_ICMPV6, payload_len as u32);
    let mut sum = pseudo_sum;
    let mut i = 0;
    while i + 1 < result.len() {
        sum += u32::from(u16::from_be_bytes([result[i], result[i + 1]]));
        i += 2;
    }
    if i < result.len() {
        sum += u32::from(result[i]) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    result[2] = (cksum >> 8) as u8;
    result[3] = (cksum & 0xFF) as u8;

    Some(result)
}

/// Translate ICMPv6 payload to ICMPv4.
fn translate_icmpv6_to_icmpv4(
    payload: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    payload_len: usize,
) -> Option<Vec<u8>> {
    if payload.len() < 4 {
        return None;
    }

    // Validate incoming ICMPv6 checksum (includes pseudo-header) to prevent laundering.
    let pseudo_sum =
        checksum::ipv6_pseudo_header_sum(src_v6, dst_v6, PROTO_ICMPV6, payload_len as u32);
    let mut sum = pseudo_sum;
    let mut i = 0;
    while i + 1 < payload.len() {
        sum += u32::from(u16::from_be_bytes([payload[i], payload[i + 1]]));
        i += 2;
    }
    if i < payload.len() {
        sum += u32::from(payload[i]) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if sum as u16 != 0xFFFF {
        return None;
    }

    let mapping = icmp::icmpv6_to_icmpv4(payload[0], payload[1])?;

    let mut result = payload.to_vec();
    result[0] = mapping.icmp_type;
    result[1] = mapping.icmp_code;
    // Zero checksum before recalculating
    result[2] = 0;
    result[3] = 0;

    // ICMPv4 checksum does NOT include pseudo-header
    let cksum = checksum::internet_checksum(&result);
    result[2] = (cksum >> 8) as u8;
    result[3] = (cksum & 0xFF) as u8;

    Some(result)
}

/// Adjust TCP checksum when translating IPv4 -> IPv6.
fn adjust_tcp_checksum_v4_to_v6(
    tcp: &mut [u8],
    old_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    old_proto: u8,
    new_src: Ipv6Addr,
    new_dst: Ipv6Addr,
    new_nh: u8,
) {
    if tcp.len() < 18 {
        return;
    }
    let old_cksum = u16::from_be_bytes([tcp[16], tcp[17]]);
    let new_cksum = checksum::adjust_checksum_v4_to_v6(
        old_cksum,
        old_src,
        old_dst,
        old_proto,
        new_src,
        new_dst,
        new_nh,
        tcp.len() as u16,
    );
    tcp[16] = (new_cksum >> 8) as u8;
    tcp[17] = (new_cksum & 0xFF) as u8;
}

/// Adjust UDP checksum when translating IPv4 -> IPv6.
fn adjust_udp_checksum_v4_to_v6(
    udp: &mut [u8],
    old_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    old_proto: u8,
    new_src: Ipv6Addr,
    new_dst: Ipv6Addr,
    new_nh: u8,
) {
    if udp.len() < 8 {
        return;
    }
    let old_cksum = u16::from_be_bytes([udp[6], udp[7]]);
    // In IPv4, UDP checksum 0 means "not computed". In IPv6, it's mandatory.
    if old_cksum == 0 {
        // Must compute full checksum for IPv6
        udp[6] = 0;
        udp[7] = 0;
        let pseudo = checksum::ipv6_pseudo_header_sum(new_src, new_dst, new_nh, udp.len() as u32);
        let mut sum = pseudo;
        let mut i = 0;
        while i + 1 < udp.len() {
            sum += u32::from(u16::from_be_bytes([udp[i], udp[i + 1]]));
            i += 2;
        }
        if i < udp.len() {
            sum += u32::from(udp[i]) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        // RFC 768: if computed checksum is 0, use 0xFFFF
        let cksum = if cksum == 0 { 0xFFFF } else { cksum };
        udp[6] = (cksum >> 8) as u8;
        udp[7] = (cksum & 0xFF) as u8;
    } else {
        let new_cksum = checksum::adjust_checksum_v4_to_v6(
            old_cksum,
            old_src,
            old_dst,
            old_proto,
            new_src,
            new_dst,
            new_nh,
            udp.len() as u16,
        );
        udp[6] = (new_cksum >> 8) as u8;
        udp[7] = (new_cksum & 0xFF) as u8;
    }
}

/// Adjust TCP checksum when translating IPv6 -> IPv4.
fn adjust_tcp_checksum_v6_to_v4(
    tcp: &mut [u8],
    old_src: Ipv6Addr,
    old_dst: Ipv6Addr,
    old_nh: u8,
    new_src: Ipv4Addr,
    new_dst: Ipv4Addr,
    new_proto: u8,
) {
    if tcp.len() < 18 {
        return;
    }
    let old_cksum = u16::from_be_bytes([tcp[16], tcp[17]]);
    let new_cksum = checksum::adjust_checksum_v6_to_v4(
        old_cksum,
        old_src,
        old_dst,
        old_nh,
        new_src,
        new_dst,
        new_proto,
        tcp.len() as u16,
    );
    tcp[16] = (new_cksum >> 8) as u8;
    tcp[17] = (new_cksum & 0xFF) as u8;
}

/// Adjust UDP checksum when translating IPv6 -> IPv4.
fn adjust_udp_checksum_v6_to_v4(
    udp: &mut [u8],
    old_src: Ipv6Addr,
    old_dst: Ipv6Addr,
    old_nh: u8,
    new_src: Ipv4Addr,
    new_dst: Ipv4Addr,
    new_proto: u8,
) {
    if udp.len() < 8 {
        return;
    }
    let old_cksum = u16::from_be_bytes([udp[6], udp[7]]);
    let new_cksum = checksum::adjust_checksum_v6_to_v4(
        old_cksum,
        old_src,
        old_dst,
        old_nh,
        new_src,
        new_dst,
        new_proto,
        udp.len() as u16,
    );
    udp[6] = (new_cksum >> 8) as u8;
    udp[7] = (new_cksum & 0xFF) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_icmp_echo_request(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut pkt = vec![0u8; 28]; // 20 IPv4 header + 8 ICMP

        // IPv4 header
        pkt[0] = 0x45; // version + IHL
        pkt[1] = 0x00; // TOS
        let total_len: u16 = 28;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[4..6].copy_from_slice(&[0x00, 0x01]); // ID
        pkt[6..8].copy_from_slice(&[0x40, 0x00]); // DF
        pkt[8] = 64; // TTL
        pkt[9] = PROTO_ICMP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());

        // IPv4 header checksum
        let cksum = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xFF) as u8;

        // ICMP Echo Request
        pkt[20] = icmp::ICMPV4_ECHO_REQUEST;
        pkt[21] = 0; // code
        pkt[22] = 0; // checksum (placeholder)
        pkt[23] = 0;
        pkt[24] = 0x00; // identifier
        pkt[25] = 0x01;
        pkt[26] = 0x00; // sequence
        pkt[27] = 0x01;

        let icmp_cksum = checksum::internet_checksum(&pkt[20..]);
        pkt[22] = (icmp_cksum >> 8) as u8;
        pkt[23] = (icmp_cksum & 0xFF) as u8;

        pkt
    }

    #[test]
    fn test_ipv4_to_ipv6_icmp_echo() {
        let clat_prefix: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat_prefix: Ipv6Addr = "2001:db8:1234::".parse().unwrap();

        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let ipv4_pkt = make_ipv4_icmp_echo_request(src, dst);
        let ipv6_pkt = ipv4_to_ipv6(&ipv4_pkt, clat_prefix, plat_prefix).unwrap();

        // Check IPv6 header
        assert_eq!(ipv6_pkt[0] >> 4, 6); // version
        assert_eq!(ipv6_pkt[6], PROTO_ICMPV6); // next header
        assert_eq!(ipv6_pkt[7], 63); // hop limit = 64 - 1

        // Check source IPv6 = clat_prefix :: src
        let expected_src = addr::embed_ipv4_in_ipv6(clat_prefix, src);
        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&ipv6_pkt[8..24]);
        assert_eq!(Ipv6Addr::from(src_bytes), expected_src);

        // Check destination IPv6 = plat_prefix :: dst
        let expected_dst = addr::embed_ipv4_in_ipv6(plat_prefix, dst);
        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&ipv6_pkt[24..40]);
        assert_eq!(Ipv6Addr::from(dst_bytes), expected_dst);

        // Check ICMPv6 type
        assert_eq!(ipv6_pkt[40], icmp::ICMPV6_ECHO_REQUEST);
    }

    #[test]
    fn test_roundtrip_icmp_echo() {
        let clat_prefix: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat_prefix: Ipv6Addr = "2001:db8:1234::".parse().unwrap();

        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let original = make_ipv4_icmp_echo_request(src, dst);
        let ipv6_pkt = ipv4_to_ipv6(&original, clat_prefix, plat_prefix).unwrap();

        // Now translate back: for the return path, swap prefixes
        // The IPv6 src has PLAT prefix (from server), dst has CLAT prefix (to client)
        // But our packet has src=CLAT, dst=PLAT (outbound)
        // For roundtrip testing, we simulate a "reply" by swapping src/dst in the IPv6 packet
        let mut reply_v6 = ipv6_pkt.clone();
        // Swap src and dst IPv6
        let src_copy: [u8; 16] = reply_v6[8..24].try_into().unwrap();
        let dst_copy: [u8; 16] = reply_v6[24..40].try_into().unwrap();
        reply_v6[8..24].copy_from_slice(&dst_copy);
        reply_v6[24..40].copy_from_slice(&src_copy);
        // Change ICMPv6 Echo Request to Echo Reply
        reply_v6[40] = icmp::ICMPV6_ECHO_REPLY;
        // Recompute ICMPv6 checksum
        reply_v6[42] = 0;
        reply_v6[43] = 0;
        let payload_len = reply_v6.len() - 40;
        let mut new_src = [0u8; 16];
        new_src.copy_from_slice(&reply_v6[8..24]);
        let mut new_dst = [0u8; 16];
        new_dst.copy_from_slice(&reply_v6[24..40]);
        let pseudo = checksum::ipv6_pseudo_header_sum(
            Ipv6Addr::from(new_src),
            Ipv6Addr::from(new_dst),
            PROTO_ICMPV6,
            payload_len as u32,
        );
        let mut sum = pseudo;
        let icmp_data = &reply_v6[40..];
        let mut i = 0;
        while i + 1 < icmp_data.len() {
            sum += u32::from(u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]));
            i += 2;
        }
        if i < icmp_data.len() {
            sum += u32::from(icmp_data[i]) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        reply_v6[42] = (cksum >> 8) as u8;
        reply_v6[43] = (cksum & 0xFF) as u8;

        let result = ipv6_to_ipv4(&reply_v6, clat_prefix, plat_prefix).unwrap();

        // Verify it's a valid ICMPv4 Echo Reply from dst to src
        assert_eq!(result[0] >> 4, 4); // IPv4
        assert_eq!(result[9], PROTO_ICMP);
        let result_src = Ipv4Addr::new(result[12], result[13], result[14], result[15]);
        let result_dst = Ipv4Addr::new(result[16], result[17], result[18], result[19]);
        assert_eq!(result_src, dst);
        assert_eq!(result_dst, src);
        assert_eq!(result[20], icmp::ICMPV4_ECHO_REPLY);
    }

    // --- Edge-case tests for ipv4_to_ipv6 ---

    #[test]
    fn test_ipv4_to_ipv6_too_short() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        // Packet shorter than minimum IPv4 header
        assert!(ipv4_to_ipv6(&[0x45; 10], clat, plat).is_none());
    }

    #[test]
    fn test_ipv4_to_ipv6_wrong_version() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x65; // version 6, not 4
        assert!(ipv4_to_ipv6(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv4_to_ipv6_truncated_total_len() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        // Total length claims 40 but we only have 20 bytes
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        assert!(ipv4_to_ipv6(&pkt, clat, plat).is_none());
    }

    // --- TCP translation tests ---

    fn make_ipv4_tcp_syn(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let tcp_len: usize = 20;
        let total_len: u16 = (IPV4_HEADER_MIN_LEN + tcp_len) as u16;
        let mut pkt = vec![0u8; total_len as usize];

        // IPv4 header
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[6..8].copy_from_slice(&[0x40, 0x00]); // DF
        pkt[8] = 64; // TTL
        pkt[9] = PROTO_TCP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());

        let hdr_cksum = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (hdr_cksum >> 8) as u8;
        pkt[11] = (hdr_cksum & 0xFF) as u8;

        // TCP header (minimal SYN)
        pkt[20] = 0x00;
        pkt[21] = 0x50; // src port 80
        pkt[22] = 0xC0;
        pkt[23] = 0x01; // dst port 49153
        // seq
        pkt[24..28].copy_from_slice(&1u32.to_be_bytes());
        // data offset (5 words = 20 bytes), SYN flag
        pkt[32] = 0x50;
        pkt[33] = 0x02; // SYN
        pkt[34..36].copy_from_slice(&8192u16.to_be_bytes()); // window

        // Compute TCP checksum
        let pseudo = checksum::ipv4_pseudo_header_sum(src, dst, PROTO_TCP, tcp_len as u16);
        let tcp_data = &pkt[20..];
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
        pkt[36] = (cksum >> 8) as u8;
        pkt[37] = (cksum & 0xFF) as u8;

        pkt
    }

    #[test]
    fn test_ipv4_to_ipv6_tcp() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let pkt = make_ipv4_tcp_syn(src, dst);
        let v6 = ipv4_to_ipv6(&pkt, clat, plat).unwrap();

        assert_eq!(v6[0] >> 4, 6); // IPv6
        assert_eq!(v6[6], PROTO_TCP); // next header = TCP
        assert_eq!(v6[7], 63); // hop limit

        // Verify TCP payload is present (src port preserved)
        assert_eq!(v6[40], 0x00);
        assert_eq!(v6[41], 0x50); // port 80
    }

    #[test]
    fn test_roundtrip_tcp() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let original = make_ipv4_tcp_syn(src, dst);
        let v6 = ipv4_to_ipv6(&original, clat, plat).unwrap();

        // Simulate a reply by swapping src/dst in IPv6
        let mut reply = v6.clone();
        let src_copy: [u8; 16] = reply[8..24].try_into().unwrap();
        let dst_copy: [u8; 16] = reply[24..40].try_into().unwrap();
        reply[8..24].copy_from_slice(&dst_copy);
        reply[24..40].copy_from_slice(&src_copy);

        // Recompute the TCP checksum from scratch
        let new_src = Ipv6Addr::from(<[u8; 16]>::try_from(&reply[8..24]).unwrap());
        let new_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&reply[24..40]).unwrap());
        let tcp_payload_len = reply.len() - 40;
        reply[56] = 0;
        reply[57] = 0;
        let pseudo =
            checksum::ipv6_pseudo_header_sum(new_src, new_dst, PROTO_TCP, tcp_payload_len as u32);
        let tcp_data = &reply[40..];
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
        reply[56] = (cksum >> 8) as u8;
        reply[57] = (cksum & 0xFF) as u8;

        let result = ipv6_to_ipv4(&reply, clat, plat).unwrap();
        assert_eq!(result[0] >> 4, 4);
        assert_eq!(result[9], PROTO_TCP);
    }

    // --- UDP translation tests ---

    fn make_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, with_checksum: bool) -> Vec<u8> {
        let udp_len: u16 = 12; // 8 header + 4 data
        let total_len: u16 = IPV4_HEADER_MIN_LEN as u16 + udp_len;
        let mut pkt = vec![0u8; total_len as usize];

        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[6..8].copy_from_slice(&[0x40, 0x00]);
        pkt[8] = 64;
        pkt[9] = PROTO_UDP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());

        let hdr_cksum = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (hdr_cksum >> 8) as u8;
        pkt[11] = (hdr_cksum & 0xFF) as u8;

        // UDP header
        pkt[20] = 0x13;
        pkt[21] = 0x88; // src port 5000
        pkt[22] = 0x00;
        pkt[23] = 0x35; // dst port 53
        pkt[24..26].copy_from_slice(&udp_len.to_be_bytes()); // length
        // Data
        pkt[28] = 0xDE;
        pkt[29] = 0xAD;
        pkt[30] = 0xBE;
        pkt[31] = 0xEF;

        if with_checksum {
            pkt[26] = 0;
            pkt[27] = 0;
            let pseudo = checksum::ipv4_pseudo_header_sum(src, dst, PROTO_UDP, udp_len);
            let udp_data = &pkt[20..];
            let mut sum = pseudo;
            let mut i = 0;
            while i + 1 < udp_data.len() {
                sum += u32::from(u16::from_be_bytes([udp_data[i], udp_data[i + 1]]));
                i += 2;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let cksum = !(sum as u16);
            pkt[26] = (cksum >> 8) as u8;
            pkt[27] = (cksum & 0xFF) as u8;
        } else {
            // Zero checksum (valid in IPv4 UDP)
            pkt[26] = 0;
            pkt[27] = 0;
        }

        pkt
    }

    #[test]
    fn test_ipv4_to_ipv6_udp_with_checksum() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let pkt = make_ipv4_udp(src, dst, true);
        let v6 = ipv4_to_ipv6(&pkt, clat, plat).unwrap();

        assert_eq!(v6[0] >> 4, 6);
        assert_eq!(v6[6], PROTO_UDP);
        // UDP checksum should be non-zero in IPv6
        let udp_cksum = u16::from_be_bytes([v6[46], v6[47]]);
        assert_ne!(udp_cksum, 0);
    }

    #[test]
    fn test_ipv4_to_ipv6_udp_zero_checksum() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        // IPv4 UDP with zero checksum (must be computed for IPv6)
        let pkt = make_ipv4_udp(src, dst, false);
        let v6 = ipv4_to_ipv6(&pkt, clat, plat).unwrap();

        assert_eq!(v6[6], PROTO_UDP);
        let udp_cksum = u16::from_be_bytes([v6[46], v6[47]]);
        // Must be non-zero in IPv6
        assert_ne!(udp_cksum, 0);
    }

    #[test]
    fn test_roundtrip_udp() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let original = make_ipv4_udp(src, dst, true);
        let v6 = ipv4_to_ipv6(&original, clat, plat).unwrap();

        // Simulate reply by swapping src/dst
        let mut reply = v6.clone();
        let src_copy: [u8; 16] = reply[8..24].try_into().unwrap();
        let dst_copy: [u8; 16] = reply[24..40].try_into().unwrap();
        reply[8..24].copy_from_slice(&dst_copy);
        reply[24..40].copy_from_slice(&src_copy);

        // Recompute UDP checksum
        let new_src = Ipv6Addr::from(<[u8; 16]>::try_from(&reply[8..24]).unwrap());
        let new_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&reply[24..40]).unwrap());
        let udp_len = reply.len() - 40;
        reply[46] = 0;
        reply[47] = 0;
        let pseudo = checksum::ipv6_pseudo_header_sum(new_src, new_dst, PROTO_UDP, udp_len as u32);
        let udp_data = &reply[40..];
        let mut sum = pseudo;
        let mut i = 0;
        while i + 1 < udp_data.len() {
            sum += u32::from(u16::from_be_bytes([udp_data[i], udp_data[i + 1]]));
            i += 2;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        let cksum = if cksum == 0 { 0xFFFF } else { cksum };
        reply[46] = (cksum >> 8) as u8;
        reply[47] = (cksum & 0xFF) as u8;

        let result = ipv6_to_ipv4(&reply, clat, plat).unwrap();
        assert_eq!(result[0] >> 4, 4);
        assert_eq!(result[9], PROTO_UDP);
        // Data should survive
        assert_eq!(result[28], 0xDE);
        assert_eq!(result[29], 0xAD);
    }

    // --- IPv6 to IPv4 edge cases ---

    #[test]
    fn test_ipv6_to_ipv4_too_short() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        assert!(ipv6_to_ipv4(&[0x60; 20], clat, plat).is_none());
    }

    #[test]
    fn test_ipv6_to_ipv4_wrong_version() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // version 4
        assert!(ipv6_to_ipv4(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv6_to_ipv4_prefix_mismatch() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let wrong: Ipv6Addr = "2001:db8:ffff::".parse().unwrap();

        // Build minimal valid IPv6 packet with wrong src prefix
        let mut pkt = vec![0u8; 48]; // 40 header + 8 payload
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&8u16.to_be_bytes()); // payload len
        pkt[6] = PROTO_TCP;
        pkt[7] = 64;
        // src = wrong prefix (should be plat)
        pkt[8..24]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(wrong, "1.2.3.4".parse().unwrap()).octets());
        pkt[24..40]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(clat, "5.6.7.8".parse().unwrap()).octets());

        assert!(ipv6_to_ipv4(&pkt, clat, plat).is_none());
    }

    // --- Unknown protocol passthrough ---

    #[test]
    fn test_ipv4_to_ipv6_unknown_protocol_passthrough() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let total_len: u16 = 24; // 20 header + 4 payload
        let mut pkt = vec![0u8; total_len as usize];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 47; // GRE (not TCP/UDP/ICMP)
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        let hdr_cksum = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (hdr_cksum >> 8) as u8;
        pkt[11] = (hdr_cksum & 0xFF) as u8;
        pkt[20..24].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);

        let v6 = ipv4_to_ipv6(&pkt, clat, plat).unwrap();
        assert_eq!(v6[6], 47); // GRE next header preserved
        // Payload passed through unchanged
        assert_eq!(&v6[40..44], &[0xCA, 0xFE, 0xBA, 0xBE]);
    }

    // --- ICMP too-short payload ---

    // --- Additional edge-case tests for coverage ---

    #[test]
    fn test_ipv4_to_ipv6_ihl_exceeds_packet() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        // IHL=15 (60 bytes header) but packet is only 20 bytes
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x4F; // version=4, IHL=15
        pkt[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(ipv4_to_ipv6(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv4_to_ipv6_ttl_zero() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let mut pkt = make_ipv4_icmp_echo_request(src, dst);
        pkt[8] = 0; // TTL=0
        // Recompute header checksum
        pkt[10] = 0;
        pkt[11] = 0;
        let cksum = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xFF) as u8;

        // TTL <= 1 packets must be dropped (RFC 6145 §4)
        assert!(ipv4_to_ipv6(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv4_to_ipv6_ttl_one() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let mut pkt = make_ipv4_icmp_echo_request(src, dst);
        pkt[8] = 1; // TTL=1
        pkt[10] = 0;
        pkt[11] = 0;
        let cksum = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xFF) as u8;

        assert!(ipv4_to_ipv6(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv6_to_ipv4_dst_prefix_mismatch() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let wrong: Ipv6Addr = "2001:db8:ffff::".parse().unwrap();

        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt[6] = PROTO_TCP;
        pkt[7] = 64;
        // src matches plat (correct)
        pkt[8..24]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(plat, "1.2.3.4".parse().unwrap()).octets());
        // dst uses wrong prefix (should be clat)
        pkt[24..40]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(wrong, "5.6.7.8".parse().unwrap()).octets());

        assert!(ipv6_to_ipv4(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv6_to_ipv4_truncated_payload() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();

        let mut pkt = vec![0u8; 44]; // 40 header + 4 actual payload
        pkt[0] = 0x60;
        // Payload length claims 20 but only 4 bytes available
        pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
        pkt[6] = PROTO_TCP;
        pkt[7] = 64;
        pkt[8..24]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(plat, "1.2.3.4".parse().unwrap()).octets());
        pkt[24..40]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(clat, "5.6.7.8".parse().unwrap()).octets());

        assert!(ipv6_to_ipv4(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv6_to_ipv4_unknown_protocol_passthrough() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src_v4: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_v4: Ipv4Addr = "5.6.7.8".parse().unwrap();

        let payload = [0xCA, 0xFE, 0xBA, 0xBE];
        let mut pkt = vec![0u8; 44]; // 40 header + 4 payload
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&4u16.to_be_bytes());
        pkt[6] = 47; // GRE (not TCP/UDP/ICMP)
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&addr::embed_ipv4_in_ipv6(plat, src_v4).octets());
        pkt[24..40].copy_from_slice(&addr::embed_ipv4_in_ipv6(clat, dst_v4).octets());
        pkt[40..44].copy_from_slice(&payload);

        let v4 = ipv6_to_ipv4(&pkt, clat, plat).unwrap();
        assert_eq!(v4[0] >> 4, 4);
        assert_eq!(v4[9], 47); // GRE preserved
        assert_eq!(&v4[20..24], &payload);
    }

    #[test]
    fn test_ipv6_to_ipv4_hop_limit_zero() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();

        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&4u16.to_be_bytes());
        pkt[6] = 47; // GRE
        pkt[7] = 0; // hop limit = 0
        pkt[8..24]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(plat, "1.2.3.4".parse().unwrap()).octets());
        pkt[24..40]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(clat, "5.6.7.8".parse().unwrap()).octets());

        // Hop limit <= 1 must be dropped (RFC 6145 §4)
        assert!(ipv6_to_ipv4(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv6_to_ipv4_hop_limit_one() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();

        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&4u16.to_be_bytes());
        pkt[6] = 47; // GRE
        pkt[7] = 1; // hop limit = 1
        pkt[8..24]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(plat, "1.2.3.4".parse().unwrap()).octets());
        pkt[24..40]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(clat, "5.6.7.8".parse().unwrap()).octets());

        assert!(ipv6_to_ipv4(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv6_to_ipv4_icmpv6_too_short() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();

        // ICMPv6 payload with only 2 bytes (< 4 minimum)
        let mut pkt = vec![0u8; 42];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&2u16.to_be_bytes());
        pkt[6] = PROTO_ICMPV6;
        pkt[7] = 64;
        pkt[8..24]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(plat, "1.2.3.4".parse().unwrap()).octets());
        pkt[24..40]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(clat, "5.6.7.8".parse().unwrap()).octets());

        assert!(ipv6_to_ipv4(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv4_to_ipv6_icmp_odd_payload() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        // ICMP echo request with 1 byte of data (odd total payload = 9 bytes)
        let total_len: u16 = 29; // 20 header + 9 ICMP
        let mut pkt = vec![0u8; total_len as usize];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = PROTO_ICMP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        pkt[10] = 0;
        pkt[11] = 0;
        let cksum = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xFF) as u8;

        // ICMP echo request (type=8, code=0)
        pkt[20] = icmp::ICMPV4_ECHO_REQUEST;
        pkt[21] = 0;
        pkt[24] = 0x00; // id
        pkt[25] = 0x01;
        pkt[26] = 0x00; // seq
        pkt[27] = 0x01;
        pkt[28] = 0xAB; // odd data byte
        pkt[22] = 0;
        pkt[23] = 0;
        let icmp_cksum = checksum::internet_checksum(&pkt[20..]);
        pkt[22] = (icmp_cksum >> 8) as u8;
        pkt[23] = (icmp_cksum & 0xFF) as u8;

        let v6 = ipv4_to_ipv6(&pkt, clat, plat).unwrap();
        assert_eq!(v6[6], PROTO_ICMPV6);
        // Verify payload length includes the odd byte
        let payload_len = u16::from_be_bytes([v6[4], v6[5]]);
        assert_eq!(payload_len, 9);
    }

    #[test]
    fn test_adjust_tcp_checksum_short_payload() {
        // TCP payload shorter than 18 bytes should be a no-op
        let mut tcp = vec![0u8; 16]; // too short
        let src4: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let dst4: Ipv4Addr = "2.2.2.2".parse().unwrap();
        let src6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let original = tcp.clone();
        adjust_tcp_checksum_v4_to_v6(&mut tcp, src4, dst4, 6, src6, dst6, 6);
        assert_eq!(tcp, original); // unchanged
    }

    #[test]
    fn test_adjust_tcp_checksum_v6_to_v4_short_payload() {
        let mut tcp = vec![0u8; 16];
        let src6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let src4: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let dst4: Ipv4Addr = "2.2.2.2".parse().unwrap();
        let original = tcp.clone();
        adjust_tcp_checksum_v6_to_v4(&mut tcp, src6, dst6, 6, src4, dst4, 6);
        assert_eq!(tcp, original);
    }

    #[test]
    fn test_adjust_udp_checksum_short_payload() {
        let mut udp = vec![0u8; 6]; // too short (< 8)
        let src4: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let dst4: Ipv4Addr = "2.2.2.2".parse().unwrap();
        let src6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let original = udp.clone();
        adjust_udp_checksum_v4_to_v6(&mut udp, src4, dst4, 17, src6, dst6, 17);
        assert_eq!(udp, original);
    }

    #[test]
    fn test_adjust_udp_checksum_v6_to_v4_short_payload() {
        let mut udp = vec![0u8; 6];
        let src6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let src4: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let dst4: Ipv4Addr = "2.2.2.2".parse().unwrap();
        let original = udp.clone();
        adjust_udp_checksum_v6_to_v4(&mut udp, src6, dst6, 17, src4, dst4, 17);
        assert_eq!(udp, original);
    }

    #[test]
    fn test_ipv6_to_ipv4_tos_preserved() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();

        let mut pkt = vec![0u8; 44];
        // Set traffic class to 0xAB: version(4bits)=6, TC high(4bits)=0xA, TC low(4bits)=0xB, flow label
        pkt[0] = 0x6A; // version=6, TC high nibble=0xA
        pkt[1] = 0xB0; // TC low nibble=0xB, flow label=0
        pkt[4..6].copy_from_slice(&4u16.to_be_bytes());
        pkt[6] = 47; // GRE
        pkt[7] = 64;
        pkt[8..24]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(plat, "1.2.3.4".parse().unwrap()).octets());
        pkt[24..40]
            .copy_from_slice(&addr::embed_ipv4_in_ipv6(clat, "5.6.7.8".parse().unwrap()).octets());

        let v4 = ipv6_to_ipv4(&pkt, clat, plat).unwrap();
        assert_eq!(v4[1], 0xAB); // TOS preserved
    }

    #[test]
    fn test_ipv4_to_ipv6_icmp_too_short() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        // ICMP payload too short (< 4 bytes)
        let total_len: u16 = 22; // 20 header + 2 payload
        let mut pkt = vec![0u8; total_len as usize];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = PROTO_ICMP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        let hdr_cksum = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (hdr_cksum >> 8) as u8;
        pkt[11] = (hdr_cksum & 0xFF) as u8;

        assert!(ipv4_to_ipv6(&pkt, clat, plat).is_none());
    }

    // --- M4: Checksum laundering prevention tests ---

    #[test]
    fn test_ipv4_bad_header_checksum_dropped() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let mut pkt = make_ipv4_icmp_echo_request(src, dst);
        // Corrupt the header checksum
        pkt[10] ^= 0xFF;

        assert!(ipv4_to_ipv6(&pkt, clat, plat).is_none());
    }

    #[test]
    fn test_ipv4_bad_icmp_checksum_dropped() {
        let clat: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let plat: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let src: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "198.51.100.1".parse().unwrap();

        let mut pkt = make_ipv4_icmp_echo_request(src, dst);
        // Corrupt the ICMP checksum (bytes 22-23)
        pkt[22] ^= 0xFF;

        assert!(ipv4_to_ipv6(&pkt, clat, plat).is_none());
    }
}
