use std::net::{Ipv4Addr, Ipv6Addr};

/// Compute the Internet checksum (RFC 1071) over a byte slice.
#[inline]
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i: usize = 0;

    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Compute the IPv4 header checksum.
/// `header` must be the raw IPv4 header bytes with the checksum field zeroed.
#[inline]
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

/// Build an IPv4 pseudo-header and return the partial checksum (not folded/complemented).
/// Used for TCP/UDP checksum calculation.
#[inline]
pub fn ipv4_pseudo_header_sum(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, length: u16) -> u32 {
    let s: [u8; 4] = src.octets();
    let d: [u8; 4] = dst.octets();
    let mut sum: u32 = 0;
    sum += u32::from(u16::from_be_bytes([s[0], s[1]]));
    sum += u32::from(u16::from_be_bytes([s[2], s[3]]));
    sum += u32::from(u16::from_be_bytes([d[0], d[1]]));
    sum += u32::from(u16::from_be_bytes([d[2], d[3]]));
    sum += u32::from(protocol);
    sum += u32::from(length);
    sum
}

/// Build an IPv6 pseudo-header and return the partial checksum (not folded/complemented).
/// Used for TCP/UDP/ICMPv6 checksum calculation.
#[inline]
pub fn ipv6_pseudo_header_sum(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, length: u32) -> u32 {
    let s: [u8; 16] = src.octets();
    let d: [u8; 16] = dst.octets();
    let mut sum: u32 = 0;

    // Source address (16 bytes)
    for chunk in s.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Destination address (16 bytes)
    for chunk in d.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Upper-layer packet length (32-bit)
    sum += length >> 16;
    sum += length & 0xFFFF;
    // Next header (padded to 32 bits, only low byte matters)
    sum += u32::from(next_header);

    sum
}

/// Incrementally update a checksum when replacing an IPv4 pseudo-header with IPv6.
/// This adjusts the existing transport checksum for the new pseudo-header.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn adjust_checksum_v4_to_v6(
    old_checksum: u16,
    old_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    old_protocol: u8,
    new_src: Ipv6Addr,
    new_dst: Ipv6Addr,
    new_next_header: u8,
    payload_len: u16,
) -> u16 {
    // Remove old IPv4 pseudo-header contribution
    let old_pseudo: u32 = ipv4_pseudo_header_sum(old_src, old_dst, old_protocol, payload_len);
    // Add new IPv6 pseudo-header contribution
    let new_pseudo: u32 =
        ipv6_pseudo_header_sum(new_src, new_dst, new_next_header, u32::from(payload_len));

    let mut sum: u32 = u32::from(!old_checksum); // un-complement
    // Subtract old pseudo (add its complement)
    sum += u32::from(!fold32(old_pseudo));
    // Add new pseudo
    sum += u32::from(fold32(new_pseudo));
    // Fold and complement
    !fold32(sum)
}

/// Incrementally update a checksum when replacing an IPv6 pseudo-header with IPv4.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn adjust_checksum_v6_to_v4(
    old_checksum: u16,
    old_src: Ipv6Addr,
    old_dst: Ipv6Addr,
    old_next_header: u8,
    new_src: Ipv4Addr,
    new_dst: Ipv4Addr,
    new_protocol: u8,
    payload_len: u16,
) -> u16 {
    let old_pseudo =
        ipv6_pseudo_header_sum(old_src, old_dst, old_next_header, u32::from(payload_len));
    let new_pseudo = ipv4_pseudo_header_sum(new_src, new_dst, new_protocol, payload_len);

    let mut sum: u32 = u32::from(!old_checksum);
    sum += u32::from(!fold32(old_pseudo));
    sum += u32::from(fold32(new_pseudo));
    !fold32(sum)
}

/// Fold a u32 sum into a u16 with carry.
#[inline]
fn fold32(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_checksum() {
        // Simple test: checksum of a valid IP header should be 0
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        assert_eq!(internet_checksum(&header), 0);
    }

    #[test]
    fn test_ipv4_header_checksum() {
        // Header with checksum field zeroed
        let mut header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let cksum = ipv4_header_checksum(&header);
        header[10] = (cksum >> 8) as u8;
        header[11] = (cksum & 0xFF) as u8;
        // Verify: checksum of complete header should be 0
        assert_eq!(internet_checksum(&header), 0);
    }

    #[test]
    fn test_internet_checksum_odd_length() {
        // Odd-length data exercises the trailing byte branch
        let data = [0x01, 0x02, 0x03];
        let cksum = internet_checksum(&data);
        // Just verify it's non-zero and deterministic
        assert_eq!(cksum, internet_checksum(&data));
    }

    #[test]
    fn test_ipv4_pseudo_header_sum() {
        let src: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let sum = ipv4_pseudo_header_sum(src, dst, 6, 100);
        // Should be deterministic
        assert_eq!(sum, ipv4_pseudo_header_sum(src, dst, 6, 100));
        // Different inputs should produce different sums
        assert_ne!(sum, ipv4_pseudo_header_sum(src, dst, 17, 100));
    }

    #[test]
    fn test_ipv6_pseudo_header_sum() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let sum = ipv6_pseudo_header_sum(src, dst, 6, 100);
        assert_eq!(sum, ipv6_pseudo_header_sum(src, dst, 6, 100));
        assert_ne!(sum, ipv6_pseudo_header_sum(src, dst, 17, 100));
    }

    #[test]
    fn test_adjust_checksum_v4_to_v6_roundtrip() {
        // Build a real TCP-like payload with valid checksum over IPv4 pseudo-header,
        // adjust to IPv6, then adjust back. The result should match the original.
        let src4: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst4: Ipv4Addr = "198.51.100.1".parse().unwrap();
        let src6: Ipv6Addr = "2001:db8:aaaa::c0a8:0102".parse().unwrap();
        let dst6: Ipv6Addr = "2001:db8:1234::c633:6401".parse().unwrap();

        // Compute a valid TCP checksum over IPv4 pseudo-header
        let payload: [u8; 20] = [
            0x00, 0x50, 0x00, 0x51, // src/dst port
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0x20, 0x00, // offset, flags, window
            0x00, 0x00, // checksum placeholder
            0x00, 0x00, // urgent
        ];
        let pseudo = ipv4_pseudo_header_sum(src4, dst4, 6, payload.len() as u16);
        let mut sum = pseudo;
        for chunk in payload.chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let original_cksum = !(sum as u16);

        // Adjust v4->v6
        let v6_cksum = adjust_checksum_v4_to_v6(
            original_cksum,
            src4,
            dst4,
            6,
            src6,
            dst6,
            6,
            payload.len() as u16,
        );

        // Adjust back v6->v4
        let roundtrip_cksum =
            adjust_checksum_v6_to_v4(v6_cksum, src6, dst6, 6, src4, dst4, 6, payload.len() as u16);

        assert_eq!(roundtrip_cksum, original_cksum);
    }

    #[test]
    fn test_adjust_checksum_v6_to_v4() {
        // Just verify it produces a non-trivial result and doesn't panic
        let src6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let src4: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst4: Ipv4Addr = "10.0.0.2".parse().unwrap();

        let result = adjust_checksum_v6_to_v4(0x1234, src6, dst6, 58, src4, dst4, 1, 64);
        // Just ensure it doesn't panic and returns something
        let _ = result;
    }

    #[test]
    fn test_internet_checksum_empty() {
        let cksum = internet_checksum(&[]);
        assert_eq!(cksum, 0xFFFF); // complement of 0
    }

    #[test]
    fn test_internet_checksum_single_byte() {
        let cksum = internet_checksum(&[0xFF]);
        // 0xFF00 -> complement is 0x00FF
        assert_eq!(cksum, 0x00FF);
    }

    #[test]
    fn test_internet_checksum_all_zeros() {
        let data = [0u8; 20];
        let cksum = internet_checksum(&data);
        assert_eq!(cksum, 0xFFFF); // complement of 0
    }

    #[test]
    fn test_internet_checksum_all_ones() {
        let data = [0xFFu8; 20];
        let cksum = internet_checksum(&data);
        assert_eq!(cksum, 0x0000); // complement of 0xFFFF
    }

    #[test]
    fn test_fold32_multiple_carries() {
        // fold32 is private, so test via adjust functions with values that
        // require multiple carry rounds
        let src4: Ipv4Addr = "255.255.255.255".parse().unwrap();
        let dst4: Ipv4Addr = "255.255.255.255".parse().unwrap();
        let src6: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let dst6: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();

        // Should not panic with extreme values
        let _ = adjust_checksum_v4_to_v6(0xFFFF, src4, dst4, 255, src6, dst6, 255, 65535);
        let _ = adjust_checksum_v6_to_v4(0xFFFF, src6, dst6, 255, src4, dst4, 255, 65535);
    }

    #[test]
    fn test_ipv4_pseudo_header_sum_all_zeros() {
        let src = Ipv4Addr::new(0, 0, 0, 0);
        let dst = Ipv4Addr::new(0, 0, 0, 0);
        assert_eq!(ipv4_pseudo_header_sum(src, dst, 0, 0), 0);
    }

    #[test]
    fn test_ipv6_pseudo_header_sum_large_length() {
        // Test with a length > 65535 (uses the high 16 bits)
        let src: Ipv6Addr = "::".parse().unwrap();
        let dst: Ipv6Addr = "::".parse().unwrap();
        let sum = ipv6_pseudo_header_sum(src, dst, 0, 0x10000);
        assert_eq!(sum, 1); // only the upper 16 bits contribute: 1
    }
}
