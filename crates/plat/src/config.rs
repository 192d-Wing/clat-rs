use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Deserialize;

use crate::session::SessionTimeouts;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// NAT64 /96 prefix (e.g., "64:ff9b::/96")
    pub nat64_prefix: String,

    /// IPv4 address pool for NAT, in CIDR notation
    pub ipv4_pool: Vec<String>,

    /// IPv6-facing uplink interface
    pub uplink_interface: String,

    /// IPv4-facing egress interface (defaults to uplink_interface)
    pub egress_interface: Option<String>,

    /// Session limits and timeouts
    #[serde(default)]
    pub session: SessionConfig,

    /// Ephemeral port range for NAT pool (default [1024, 65535])
    #[serde(default = "default_port_range")]
    pub port_range: [u16; 2],

    /// MTU (default 1500)
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// gRPC listen address
    #[serde(default = "default_grpc_addr")]
    pub grpc_addr: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionConfig {
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout_secs: u64,
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout_secs: u64,
    #[serde(default = "default_icmp_timeout")]
    pub icmp_timeout_secs: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: default_max_sessions(),
            tcp_timeout_secs: default_tcp_timeout(),
            udp_timeout_secs: default_udp_timeout(),
            icmp_timeout_secs: default_icmp_timeout(),
        }
    }
}

impl SessionConfig {
    pub fn to_timeouts(&self) -> SessionTimeouts {
        SessionTimeouts {
            tcp: std::time::Duration::from_secs(self.tcp_timeout_secs),
            udp: std::time::Duration::from_secs(self.udp_timeout_secs),
            icmp: std::time::Duration::from_secs(self.icmp_timeout_secs),
        }
    }
}

fn default_port_range() -> [u16; 2] {
    [1024, 65535]
}
fn default_mtu() -> u16 {
    1500
}
fn default_grpc_addr() -> String {
    "[::1]:50052".to_string()
}
fn default_max_sessions() -> usize {
    65536
}
fn default_tcp_timeout() -> u64 {
    7200
}
fn default_udp_timeout() -> u64 {
    300
}
fn default_icmp_timeout() -> u64 {
    60
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml_ng::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        nat64_core::prefix::parse_v6_prefix_96(&self.nat64_prefix)?;
        if self.ipv4_pool.is_empty() {
            anyhow::bail!("ipv4_pool must contain at least one CIDR range");
        }
        for cidr in &self.ipv4_pool {
            nat64_core::prefix::parse_ipv4_cidr(cidr)?;
        }
        if self.port_range[0] < 1024 {
            anyhow::bail!(
                "port_range start must be >= 1024, got {}",
                self.port_range[0]
            );
        }
        if self.port_range[0] > self.port_range[1] {
            anyhow::bail!(
                "port_range start ({}) must be <= end ({})",
                self.port_range[0],
                self.port_range[1]
            );
        }
        Ok(())
    }

    pub fn nat64_prefix(&self) -> Ipv6Addr {
        nat64_core::prefix::parse_v6_prefix_96(&self.nat64_prefix).unwrap()
    }

    pub fn parse_ipv4_pool(&self) -> anyhow::Result<Vec<(Ipv4Addr, u8)>> {
        self.ipv4_pool
            .iter()
            .map(|c| nat64_core::prefix::parse_ipv4_cidr(c).map_err(Into::into))
            .collect()
    }

    pub fn egress_interface(&self) -> &str {
        self.egress_interface
            .as_deref()
            .unwrap_or(&self.uplink_interface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_valid() {
        let yaml = r#"
nat64_prefix: "64:ff9b::/96"
ipv4_pool:
  - "198.51.100.0/24"
uplink_interface: eth0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.nat64_prefix(),
            "64:ff9b::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.port_range, [1024, 65535]);
        assert_eq!(config.session.max_sessions, 65536);
        assert_eq!(config.egress_interface(), "eth0");
    }

    #[test]
    fn test_config_with_overrides() {
        let yaml = r#"
nat64_prefix: "2001:db8:64::/96"
ipv4_pool:
  - "203.0.113.0/28"
  - "198.51.100.1/32"
uplink_interface: eth0
egress_interface: eth1
session:
  max_sessions: 1000
  tcp_timeout_secs: 3600
  udp_timeout_secs: 120
  icmp_timeout_secs: 30
mtu: 1280
port_range: [2048, 32767]
grpc_addr: "[::1]:9999"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.session.max_sessions, 1000);
        assert_eq!(config.session.tcp_timeout_secs, 3600);
        assert_eq!(config.mtu, 1280);
        assert_eq!(config.port_range, [2048, 32767]);
        assert_eq!(config.egress_interface(), "eth1");

        let pool = config.parse_ipv4_pool().unwrap();
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_config_empty_pool_errors() {
        let yaml = r#"
nat64_prefix: "64:ff9b::/96"
ipv4_pool: []
uplink_interface: eth0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_bad_prefix_errors() {
        let yaml = r#"
nat64_prefix: "64:ff9b::/64"
ipv4_pool:
  - "198.51.100.0/24"
uplink_interface: eth0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_port_range_start_too_low() {
        let yaml = r#"
nat64_prefix: "64:ff9b::/96"
ipv4_pool:
  - "198.51.100.0/24"
uplink_interface: eth0
port_range: [80, 1024]
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_port_range_inverted() {
        let yaml = r#"
nat64_prefix: "64:ff9b::/96"
ipv4_pool:
  - "198.51.100.0/24"
uplink_interface: eth0
port_range: [50000, 10000]
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_session_config_to_timeouts() {
        let sc = SessionConfig {
            max_sessions: 100,
            tcp_timeout_secs: 60,
            udp_timeout_secs: 30,
            icmp_timeout_secs: 10,
        };
        let t = sc.to_timeouts();
        assert_eq!(t.tcp, std::time::Duration::from_secs(60));
        assert_eq!(t.udp, std::time::Duration::from_secs(30));
        assert_eq!(t.icmp, std::time::Duration::from_secs(10));
    }
}
