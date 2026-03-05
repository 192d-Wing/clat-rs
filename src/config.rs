use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// IPv4 address for the CLAT TUN interface
    pub clat_ipv4_addr: Ipv4Addr,

    /// IPv4 subnets for LAN (e.g., ["192.168.1.0/24", "10.0.0.0/24"])
    pub clat_ipv4_networks: Vec<String>,

    /// /96 IPv6 prefix for CLAT-side embedding (source).
    /// Optional if dhcpv6_pd_prefix is set — the first /96 will be derived automatically.
    pub clat_v6_prefix: Option<String>,

    /// DHCPv6 Prefix Delegation prefix (e.g., "2001:db8:aaaa::/48").
    /// When set and clat_v6_prefix is omitted, the first /96 subnet is used for CLAT translation.
    pub dhcpv6_pd_prefix: Option<String>,

    /// /96 IPv6 prefix for PLAT-side embedding (destination)
    pub plat_v6_prefix: String,

    /// Host network interface for IPv6 uplink
    pub uplink_interface: String,

    /// TUN MTU (default 1400)
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_mtu() -> u16 {
    1400
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents: String = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml_ng::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        // Validate CLAT prefix if provided (it can also be set later via gRPC)
        let _ = self.clat_prefix();
        parse_v6_prefix_96(&self.plat_v6_prefix)?;
        if self.clat_ipv4_networks.is_empty() {
            anyhow::bail!("clat_ipv4_networks must contain at least one subnet");
        }
        for network in &self.clat_ipv4_networks {
            parse_ipv4_cidr(network)?;
        }
        Ok(())
    }

    /// Parse all configured IPv4 networks, returning (network addr, prefix length) pairs.
    pub fn parse_ipv4_networks(&self) -> anyhow::Result<Vec<(Ipv4Addr, u8)>> {
        self.clat_ipv4_networks
            .iter()
            .map(|n| parse_ipv4_cidr(n))
            .collect()
    }

    /// Resolve the CLAT /96 prefix.
    ///
    /// Priority:
    /// 1. Explicit `clat_v6_prefix` if set
    /// 2. First /96 derived from `dhcpv6_pd_prefix`
    /// 3. Error if neither is set
    pub fn clat_prefix(&self) -> anyhow::Result<Ipv6Addr> {
        if let Some(ref explicit) = self.clat_v6_prefix {
            return parse_v6_prefix_96(explicit);
        }
        if let Some(ref pd) = self.dhcpv6_pd_prefix {
            return derive_first_96_from_pd(pd);
        }
        anyhow::bail!("either clat_v6_prefix or dhcpv6_pd_prefix must be set")
    }

    pub fn plat_prefix(&self) -> Ipv6Addr {
        parse_v6_prefix_96(&self.plat_v6_prefix).unwrap()
    }
}

/// Parse a "/96" IPv6 prefix string, returning the prefix address.
fn parse_v6_prefix_96(prefix_str: &str) -> anyhow::Result<Ipv6Addr> {
    let parts: Vec<&str> = prefix_str.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid IPv6 prefix format: {prefix_str}");
    }
    let prefix_len: u8 = parts[1].parse()?;
    if prefix_len != 96 {
        anyhow::bail!("only /96 prefixes are supported, got /{prefix_len}");
    }
    let addr: Ipv6Addr = parts[0].parse()?;
    Ok(addr)
}

/// Derive the first /96 subnet from a DHCPv6-PD prefix.
///
/// For example, "2001:db8:aaaa::/48" -> "2001:db8:aaaa::" (first /96).
/// The PD prefix must be <= /96. The derived /96 uses the same base address
/// with all bits beyond the PD prefix length zeroed (which they already are
/// in a properly formatted prefix).
pub fn derive_first_96_from_pd(pd_str: &str) -> anyhow::Result<Ipv6Addr> {
    let parts: Vec<&str> = pd_str.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid DHCPv6-PD prefix format: {pd_str}");
    }
    let prefix_len: u8 = parts[1].parse()?;
    if prefix_len > 96 {
        anyhow::bail!(
            "DHCPv6-PD prefix must be /96 or shorter to derive a /96 for CLAT, got /{prefix_len}"
        );
    }
    let addr: Ipv6Addr = parts[0].parse()?;

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

    let derived = Ipv6Addr::from(octets);
    log::info!("derived CLAT /96 prefix {derived} from DHCPv6-PD {pd_str}");
    Ok(derived)
}

/// Parse an IPv4 CIDR string, returning (network addr, prefix length).
fn parse_ipv4_cidr(cidr: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid IPv4 network format: {cidr}");
    }
    let addr: Ipv4Addr = parts[0].parse()?;
    let prefix_len: u8 = parts[1].parse()?;
    if prefix_len > 32 {
        anyhow::bail!("invalid IPv4 prefix length: {prefix_len}");
    }
    Ok((addr, prefix_len))
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

    #[test]
    fn test_config_load_valid_explicit_prefix() {
        let yaml = r#"
clat_ipv4_addr: 192.168.1.1
clat_ipv4_networks:
  - "192.168.1.0/24"
clat_v6_prefix: "2001:db8:aaaa::/96"
plat_v6_prefix: "64:ff9b::/96"
uplink_interface: eth0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.mtu, 1400); // default
        let prefix = config.clat_prefix().unwrap();
        assert_eq!(prefix, "2001:db8:aaaa::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_config_load_valid_pd_prefix() {
        let yaml = r#"
clat_ipv4_addr: 192.168.1.1
clat_ipv4_networks:
  - "10.0.0.0/8"
dhcpv6_pd_prefix: "2001:db8:abcd::/48"
plat_v6_prefix: "64:ff9b::/96"
uplink_interface: eth0
mtu: 1280
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.mtu, 1280);
        let prefix = config.clat_prefix().unwrap();
        assert_eq!(prefix, "2001:db8:abcd::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_config_no_prefix_errors() {
        let yaml = r#"
clat_ipv4_addr: 192.168.1.1
clat_ipv4_networks:
  - "192.168.1.0/24"
plat_v6_prefix: "64:ff9b::/96"
uplink_interface: eth0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.clat_prefix().is_err());
    }

    #[test]
    fn test_config_empty_networks_errors() {
        let yaml = r#"
clat_ipv4_addr: 192.168.1.1
clat_ipv4_networks: []
clat_v6_prefix: "2001:db8::/96"
plat_v6_prefix: "64:ff9b::/96"
uplink_interface: eth0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_parse_ipv4_networks() {
        let yaml = r#"
clat_ipv4_addr: 192.168.1.1
clat_ipv4_networks:
  - "192.168.1.0/24"
  - "10.0.0.0/8"
clat_v6_prefix: "2001:db8::/96"
plat_v6_prefix: "64:ff9b::/96"
uplink_interface: eth0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let networks = config.parse_ipv4_networks().unwrap();
        assert_eq!(networks.len(), 2);
        assert_eq!(networks[0], (Ipv4Addr::new(192, 168, 1, 0), 24));
        assert_eq!(networks[1], (Ipv4Addr::new(10, 0, 0, 0), 8));
    }

    #[test]
    fn test_config_plat_prefix() {
        let yaml = r#"
clat_ipv4_addr: 192.168.1.1
clat_ipv4_networks:
  - "192.168.1.0/24"
clat_v6_prefix: "2001:db8::/96"
plat_v6_prefix: "64:ff9b::/96"
uplink_interface: eth0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(
            config.plat_prefix(),
            "64:ff9b::".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn test_config_explicit_prefix_takes_priority() {
        let yaml = r#"
clat_ipv4_addr: 192.168.1.1
clat_ipv4_networks:
  - "192.168.1.0/24"
clat_v6_prefix: "2001:db8:aaaa::/96"
dhcpv6_pd_prefix: "2001:db8:bbbb::/48"
plat_v6_prefix: "64:ff9b::/96"
uplink_interface: eth0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let prefix = config.clat_prefix().unwrap();
        // Explicit clat_v6_prefix should take priority over dhcpv6_pd_prefix
        assert_eq!(prefix, "2001:db8:aaaa::".parse::<Ipv6Addr>().unwrap());
    }
}
