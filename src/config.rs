use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// IPv4 address for the CLAT TUN interface
    pub clat_ipv4_addr: Ipv4Addr,

    /// IPv4 subnets for LAN (e.g., ["192.168.1.0/24", "10.0.0.0/24"])
    pub clat_ipv4_networks: Vec<String>,

    /// /96 IPv6 prefix for CLAT-side embedding (source)
    pub clat_v6_prefix: String,

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
        self.parse_v6_prefix(&self.clat_v6_prefix)?;
        self.parse_v6_prefix(&self.plat_v6_prefix)?;
        if self.clat_ipv4_networks.is_empty() {
            anyhow::bail!("clat_ipv4_networks must contain at least one subnet");
        }
        for network in &self.clat_ipv4_networks {
            parse_ipv4_cidr(network)?;
        }
        Ok(())
    }

    /// Parse a "/96" IPv6 prefix string, returning the prefix address.
    pub fn parse_v6_prefix(&self, prefix_str: &str) -> anyhow::Result<Ipv6Addr> {
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

    /// Parse all configured IPv4 networks, returning (network addr, prefix length) pairs.
    pub fn parse_ipv4_networks(&self) -> anyhow::Result<Vec<(Ipv4Addr, u8)>> {
        self.clat_ipv4_networks
            .iter()
            .map(|n| parse_ipv4_cidr(n))
            .collect()
    }

    pub fn clat_prefix(&self) -> Ipv6Addr {
        self.parse_v6_prefix(&self.clat_v6_prefix).unwrap()
    }

    pub fn plat_prefix(&self) -> Ipv6Addr {
        self.parse_v6_prefix(&self.plat_v6_prefix).unwrap()
    }
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
