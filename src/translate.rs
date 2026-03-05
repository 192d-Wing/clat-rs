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
    if packet.len() < ihl {
        return None;
    }

    let tos = packet[1];
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < total_len {
        return None;
    }

    let protocol = packet[9];
    let ttl = packet[8];
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
            let translated_payload = translate_icmpv6_to_icmpv4(payload)?;
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
fn translate_icmpv6_to_icmpv4(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 4 {
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
}
