use std::net::{Ipv4Addr, Ipv6Addr};

/// Embed an IPv4 address into an IPv6 /96 prefix per RFC 6052.
///
/// For a /96 prefix, the IPv4 address occupies the last 32 bits:
///   prefix[0..96] ++ ipv4[0..32]
pub fn embed_ipv4_in_ipv6(prefix: Ipv6Addr, ipv4: Ipv4Addr) -> Ipv6Addr {
    let mut octets: [u8; 16] = prefix.octets();
    let v4: [u8; 4] = ipv4.octets();
    octets[12] = v4[0];
    octets[13] = v4[1];
    octets[14] = v4[2];
    octets[15] = v4[3];
    Ipv6Addr::from(octets)
}

/// Extract the IPv4 address from the last 32 bits of an IPv6 address (RFC 6052 /96).
pub fn extract_ipv4_from_ipv6(addr: Ipv6Addr) -> Ipv4Addr {
    let octets: [u8; 16] = addr.octets();
    Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15])
}

/// Check if an IPv6 address matches a given /96 prefix.
pub fn matches_prefix_96(addr: Ipv6Addr, prefix: Ipv6Addr) -> bool {
    let a: [u8; 16] = addr.octets();
    let p: [u8; 16] = prefix.octets();
    a[..12] == p[..12]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embed_and_extract() {
        let prefix: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let ipv4: Ipv4Addr = "192.168.1.2".parse().unwrap();

        let embedded = embed_ipv4_in_ipv6(prefix, ipv4);
        assert_eq!(
            embedded,
            "2001:db8:aaaa::c0a8:102".parse::<Ipv6Addr>().unwrap()
        );

        let extracted = extract_ipv4_from_ipv6(embedded);
        assert_eq!(extracted, ipv4);
    }

    #[test]
    fn test_rfc6877_appendix_a() {
        // From RFC 6877 Appendix A example:
        // CLAT prefix: 2001:db8:aaaa::/96, client: 192.168.1.2
        // -> 2001:db8:aaaa::192.168.1.2 = 2001:db8:aaaa::c0a8:0102
        let clat_prefix: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let client: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let result = embed_ipv4_in_ipv6(clat_prefix, client);
        assert_eq!(
            result,
            "2001:db8:aaaa::c0a8:102".parse::<Ipv6Addr>().unwrap()
        );

        // PLAT prefix: 2001:db8:1234::/96, server: 198.51.100.1
        // -> 2001:db8:1234::198.51.100.1 = 2001:db8:1234::c633:6401
        let plat_prefix: Ipv6Addr = "2001:db8:1234::".parse().unwrap();
        let server: Ipv4Addr = "198.51.100.1".parse().unwrap();
        let result = embed_ipv4_in_ipv6(plat_prefix, server);
        assert_eq!(
            result,
            "2001:db8:1234::c633:6401".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn test_matches_prefix() {
        let prefix: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        let addr: Ipv6Addr = "2001:db8:aaaa::c0a8:102".parse().unwrap();
        let other: Ipv6Addr = "2001:db8:1234::c0a8:102".parse().unwrap();

        assert!(matches_prefix_96(addr, prefix));
        assert!(!matches_prefix_96(other, prefix));
    }
}
