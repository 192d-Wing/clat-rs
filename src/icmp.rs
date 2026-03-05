//! ICMP type/code translation between ICMPv4 and ICMPv6 per RFC 6145 Section 4.

/// ICMPv4 types
pub const ICMPV4_ECHO_REPLY: u8 = 0;
pub const ICMPV4_DEST_UNREACHABLE: u8 = 3;
pub const ICMPV4_ECHO_REQUEST: u8 = 8;
pub const ICMPV4_TIME_EXCEEDED: u8 = 11;

/// ICMPv6 types
pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// ICMPv4 "Destination Unreachable" codes
pub const ICMPV4_DU_NET_UNREACHABLE: u8 = 0;
pub const ICMPV4_DU_HOST_UNREACHABLE: u8 = 1;
pub const ICMPV4_DU_PROTOCOL_UNREACHABLE: u8 = 2;
pub const ICMPV4_DU_PORT_UNREACHABLE: u8 = 3;
pub const ICMPV4_DU_FRAG_NEEDED: u8 = 4;
pub const ICMPV4_DU_SRC_ROUTE_FAILED: u8 = 5;
pub const ICMPV4_DU_ADMIN_PROHIBITED: u8 = 13;

/// Result of translating an ICMP type/code pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpMapping {
    pub icmp_type: u8,
    pub icmp_code: u8,
}

/// Translate ICMPv4 type/code to ICMPv6 type/code.
/// Returns `None` if the message should be silently dropped.
pub fn icmpv4_to_icmpv6(icmp_type: u8, icmp_code: u8) -> Option<IcmpMapping> {
    match icmp_type {
        ICMPV4_ECHO_REQUEST => Some(IcmpMapping {
            icmp_type: ICMPV6_ECHO_REQUEST,
            icmp_code: 0,
        }),
        ICMPV4_ECHO_REPLY => Some(IcmpMapping {
            icmp_type: ICMPV6_ECHO_REPLY,
            icmp_code: 0,
        }),
        ICMPV4_DEST_UNREACHABLE => icmpv4_dest_unreach_to_v6(icmp_code),
        ICMPV4_TIME_EXCEEDED => Some(IcmpMapping {
            icmp_type: ICMPV6_TIME_EXCEEDED,
            icmp_code,
        }),
        _ => None, // Drop unsupported types
    }
}

fn icmpv4_dest_unreach_to_v6(code: u8) -> Option<IcmpMapping> {
    match code {
        ICMPV4_DU_NET_UNREACHABLE | ICMPV4_DU_HOST_UNREACHABLE | ICMPV4_DU_SRC_ROUTE_FAILED => {
            Some(IcmpMapping {
                icmp_type: ICMPV6_DEST_UNREACHABLE,
                icmp_code: 0, // No route to destination
            })
        }
        ICMPV4_DU_PROTOCOL_UNREACHABLE => Some(IcmpMapping {
            icmp_type: ICMPV6_DEST_UNREACHABLE,
            icmp_code: 4, // Port unreachable (closest equivalent)
        }),
        ICMPV4_DU_PORT_UNREACHABLE => Some(IcmpMapping {
            icmp_type: ICMPV6_DEST_UNREACHABLE,
            icmp_code: 4,
        }),
        ICMPV4_DU_FRAG_NEEDED => Some(IcmpMapping {
            icmp_type: ICMPV6_PACKET_TOO_BIG,
            icmp_code: 0,
        }),
        ICMPV4_DU_ADMIN_PROHIBITED => Some(IcmpMapping {
            icmp_type: ICMPV6_DEST_UNREACHABLE,
            icmp_code: 1, // Administratively prohibited
        }),
        _ => Some(IcmpMapping {
            icmp_type: ICMPV6_DEST_UNREACHABLE,
            icmp_code: 0,
        }),
    }
}

/// Translate ICMPv6 type/code to ICMPv4 type/code.
/// Returns `None` if the message should be silently dropped.
pub fn icmpv6_to_icmpv4(icmp_type: u8, icmp_code: u8) -> Option<IcmpMapping> {
    match icmp_type {
        ICMPV6_ECHO_REQUEST => Some(IcmpMapping {
            icmp_type: ICMPV4_ECHO_REQUEST,
            icmp_code: 0,
        }),
        ICMPV6_ECHO_REPLY => Some(IcmpMapping {
            icmp_type: ICMPV4_ECHO_REPLY,
            icmp_code: 0,
        }),
        ICMPV6_DEST_UNREACHABLE => icmpv6_dest_unreach_to_v4(icmp_code),
        ICMPV6_PACKET_TOO_BIG => Some(IcmpMapping {
            icmp_type: ICMPV4_DEST_UNREACHABLE,
            icmp_code: ICMPV4_DU_FRAG_NEEDED,
        }),
        ICMPV6_TIME_EXCEEDED => Some(IcmpMapping {
            icmp_type: ICMPV4_TIME_EXCEEDED,
            icmp_code,
        }),
        _ => None,
    }
}

fn icmpv6_dest_unreach_to_v4(code: u8) -> Option<IcmpMapping> {
    match code {
        0 => Some(IcmpMapping {
            // No route to destination -> net unreachable
            icmp_type: ICMPV4_DEST_UNREACHABLE,
            icmp_code: ICMPV4_DU_NET_UNREACHABLE,
        }),
        1 => Some(IcmpMapping {
            // Administratively prohibited
            icmp_type: ICMPV4_DEST_UNREACHABLE,
            icmp_code: ICMPV4_DU_ADMIN_PROHIBITED,
        }),
        3 => Some(IcmpMapping {
            // Address unreachable -> host unreachable
            icmp_type: ICMPV4_DEST_UNREACHABLE,
            icmp_code: ICMPV4_DU_HOST_UNREACHABLE,
        }),
        4 => Some(IcmpMapping {
            // Port unreachable
            icmp_type: ICMPV4_DEST_UNREACHABLE,
            icmp_code: ICMPV4_DU_PORT_UNREACHABLE,
        }),
        _ => Some(IcmpMapping {
            icmp_type: ICMPV4_DEST_UNREACHABLE,
            icmp_code: ICMPV4_DU_NET_UNREACHABLE,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_translation() {
        let m = icmpv4_to_icmpv6(ICMPV4_ECHO_REQUEST, 0).unwrap();
        assert_eq!(m.icmp_type, ICMPV6_ECHO_REQUEST);

        let m = icmpv4_to_icmpv6(ICMPV4_ECHO_REPLY, 0).unwrap();
        assert_eq!(m.icmp_type, ICMPV6_ECHO_REPLY);

        let m = icmpv6_to_icmpv4(ICMPV6_ECHO_REQUEST, 0).unwrap();
        assert_eq!(m.icmp_type, ICMPV4_ECHO_REQUEST);

        let m = icmpv6_to_icmpv4(ICMPV6_ECHO_REPLY, 0).unwrap();
        assert_eq!(m.icmp_type, ICMPV4_ECHO_REPLY);
    }

    #[test]
    fn test_frag_needed_packet_too_big() {
        let m = icmpv4_to_icmpv6(ICMPV4_DEST_UNREACHABLE, ICMPV4_DU_FRAG_NEEDED).unwrap();
        assert_eq!(m.icmp_type, ICMPV6_PACKET_TOO_BIG);

        let m = icmpv6_to_icmpv4(ICMPV6_PACKET_TOO_BIG, 0).unwrap();
        assert_eq!(m.icmp_type, ICMPV4_DEST_UNREACHABLE);
        assert_eq!(m.icmp_code, ICMPV4_DU_FRAG_NEEDED);
    }

    #[test]
    fn test_roundtrip_echo() {
        let v6 = icmpv4_to_icmpv6(ICMPV4_ECHO_REQUEST, 0).unwrap();
        let v4 = icmpv6_to_icmpv4(v6.icmp_type, v6.icmp_code).unwrap();
        assert_eq!(v4.icmp_type, ICMPV4_ECHO_REQUEST);
    }
}
