use std::fmt;
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};

/// Errors arising from prefix/CIDR parsing.
#[derive(Debug)]
pub enum PrefixError {
    /// The string does not have the expected `addr/len` format.
    InvalidFormat(String),
    /// The prefix length is not the expected value.
    UnsupportedPrefixLen { got: u8, max: u8 },
    /// The address portion could not be parsed.
    InvalidAddress(AddrParseError),
    /// The prefix length could not be parsed as a number.
    InvalidPrefixLen(std::num::ParseIntError),
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(s) => write!(f, "invalid prefix format: {s}"),
            Self::UnsupportedPrefixLen { got, max } => {
                write!(f, "unsupported prefix length /{got}, maximum is /{max}")
            }
            Self::InvalidAddress(e) => write!(f, "invalid address: {e}"),
            Self::InvalidPrefixLen(e) => write!(f, "invalid prefix length: {e}"),
        }
    }
}

impl std::error::Error for PrefixError {}

/// Parse a "/96" IPv6 prefix string, returning the prefix address.
pub fn parse_v6_prefix_96(prefix_str: &str) -> Result<Ipv6Addr, PrefixError> {
    let (addr_str, len_str) = split_cidr(prefix_str)?;
    let prefix_len: u8 = len_str.parse().map_err(PrefixError::InvalidPrefixLen)?;
    if prefix_len != 96 {
        return Err(PrefixError::UnsupportedPrefixLen {
            got: prefix_len,
            max: 96,
        });
    }
    let addr: Ipv6Addr = addr_str.parse().map_err(PrefixError::InvalidAddress)?;
    Ok(addr)
}

/// Derive the first /96 subnet from a DHCPv6-PD prefix.
///
/// For example, "2001:db8:aaaa::/48" -> "2001:db8:aaaa::" (first /96).
/// The PD prefix must be <= /96.
pub fn derive_first_96_from_pd(pd_str: &str) -> Result<Ipv6Addr, PrefixError> {
    let (addr_str, len_str) = split_cidr(pd_str)?;
    let prefix_len: u8 = len_str.parse().map_err(PrefixError::InvalidPrefixLen)?;
    if prefix_len > 96 {
        return Err(PrefixError::UnsupportedPrefixLen {
            got: prefix_len,
            max: 96,
        });
    }
    let addr: Ipv6Addr = addr_str.parse().map_err(PrefixError::InvalidAddress)?;

    // Zero out any bits beyond the prefix length to get a clean /96
    let mut octets = addr.octets();
    let start_byte = prefix_len as usize / 8;
    // Preserve bits within the first partial byte if prefix doesn't fall on a byte boundary
    if start_byte < 12 && !prefix_len.is_multiple_of(8) {
        let mask = !0u8 << (8 - prefix_len % 8);
        octets[start_byte] &= mask;
    }
    // Zero remaining bytes up to the /96 boundary
    for octet in &mut octets[(start_byte + usize::from(!prefix_len.is_multiple_of(8)))..12] {
        *octet = 0;
    }
    // Bytes 12-15 are for the embedded IPv4 address, zero them
    octets[12] = 0;
    octets[13] = 0;
    octets[14] = 0;
    octets[15] = 0;

    Ok(Ipv6Addr::from(octets))
}

/// Parse an IPv4 CIDR string, returning (network addr, prefix length).
pub fn parse_ipv4_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), PrefixError> {
    let (addr_str, len_str) = split_cidr(cidr)?;
    let addr: Ipv4Addr = addr_str.parse().map_err(PrefixError::InvalidAddress)?;
    let prefix_len: u8 = len_str.parse().map_err(PrefixError::InvalidPrefixLen)?;
    if prefix_len > 32 {
        return Err(PrefixError::UnsupportedPrefixLen {
            got: prefix_len,
            max: 32,
        });
    }
    Ok((addr, prefix_len))
}

/// Split a CIDR string into (address, prefix_len) parts.
fn split_cidr(s: &str) -> Result<(&str, &str), PrefixError> {
    s.split_once('/')
        .ok_or_else(|| PrefixError::InvalidFormat(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_first_96_from_48() {
        let result = derive_first_96_from_pd("2001:db8:aaaa::/48").unwrap();
        assert_eq!(result, "2001:db8:aaaa::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_derive_first_96_from_56() {
        let result = derive_first_96_from_pd("2001:db8:aa00::/56").unwrap();
        assert_eq!(result, "2001:db8:aa00::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_derive_first_96_from_64() {
        let result = derive_first_96_from_pd("2001:db8:aaaa:bbbb::/64").unwrap();
        assert_eq!(result, "2001:db8:aaaa:bbbb::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_derive_from_96_identity() {
        let result = derive_first_96_from_pd("2001:db8:aaaa:bbbb:cccc:dddd::/96").unwrap();
        assert_eq!(
            result,
            "2001:db8:aaaa:bbbb:cccc:dddd::"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
    }

    #[test]
    fn test_derive_rejects_longer_than_96() {
        assert!(derive_first_96_from_pd("2001:db8:aaaa::/128").is_err());
        assert!(derive_first_96_from_pd("2001:db8:aaaa::/97").is_err());
    }

    #[test]
    fn test_derive_rejects_invalid_format() {
        assert!(derive_first_96_from_pd("2001:db8:aaaa::").is_err()); // no prefix len
        assert!(derive_first_96_from_pd("not-an-address/48").is_err()); // bad addr
    }

    #[test]
    fn test_parse_v6_prefix_96_valid() {
        let addr = parse_v6_prefix_96("2001:db8:1234::/96").unwrap();
        assert_eq!(addr, "2001:db8:1234::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_parse_v6_prefix_96_wrong_length() {
        assert!(parse_v6_prefix_96("2001:db8::/64").is_err());
        assert!(parse_v6_prefix_96("2001:db8::/128").is_err());
    }

    #[test]
    fn test_parse_v6_prefix_96_invalid_format() {
        assert!(parse_v6_prefix_96("2001:db8::").is_err()); // no /
        assert!(parse_v6_prefix_96("bad/96").is_err()); // bad addr
    }

    #[test]
    fn test_parse_ipv4_cidr_valid() {
        let (addr, len) = parse_ipv4_cidr("192.168.1.0/24").unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(len, 24);
    }

    #[test]
    fn test_parse_ipv4_cidr_host() {
        let (addr, len) = parse_ipv4_cidr("10.0.0.1/32").unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(len, 32);
    }

    #[test]
    fn test_parse_ipv4_cidr_invalid() {
        assert!(parse_ipv4_cidr("192.168.1.0").is_err()); // no prefix
        assert!(parse_ipv4_cidr("192.168.1.0/33").is_err()); // too long
        assert!(parse_ipv4_cidr("bad/24").is_err()); // bad addr
    }
}
