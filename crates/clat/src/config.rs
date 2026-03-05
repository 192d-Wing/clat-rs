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
        nat64_core::prefix::parse_v6_prefix_96(&self.plat_v6_prefix)?;
        if self.clat_ipv4_networks.is_empty() {
            anyhow::bail!("clat_ipv4_networks must contain at least one subnet");
        }
        for network in &self.clat_ipv4_networks {
            nat64_core::prefix::parse_ipv4_cidr(network)?;
        }
        Ok(())
    }

    /// Parse all configured IPv4 networks, returning (network addr, prefix length) pairs.
    pub fn parse_ipv4_networks(&self) -> anyhow::Result<Vec<(Ipv4Addr, u8)>> {
        self.clat_ipv4_networks
            .iter()
            .map(|n| nat64_core::prefix::parse_ipv4_cidr(n).map_err(Into::into))
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
            return Ok(nat64_core::prefix::parse_v6_prefix_96(explicit)?);
        }
        if let Some(ref pd) = self.dhcpv6_pd_prefix {
            let derived = nat64_core::prefix::derive_first_96_from_pd(pd)?;
            log::info!("derived CLAT /96 prefix {derived} from DHCPv6-PD {pd}");
            return Ok(derived);
        }
        anyhow::bail!("either clat_v6_prefix or dhcpv6_pd_prefix must be set")
    }

    pub fn plat_prefix(&self) -> Ipv6Addr {
        nat64_core::prefix::parse_v6_prefix_96(&self.plat_v6_prefix).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
