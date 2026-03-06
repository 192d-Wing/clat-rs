use std::net::Ipv4Addr;

use tun::Configuration;

/// Create and configure the CLAT TUN device.
pub fn create_tun(
    name: &str,
    addr: Ipv4Addr,
    network: Ipv4Addr,
    prefix_len: u8,
    mtu: u16,
) -> anyhow::Result<tun::AsyncDevice> {
    let mut config = Configuration::default();

    config
        .tun_name(name)
        .address(addr)
        .destination(network)
        .netmask(prefix_to_netmask(prefix_len))
        .mtu(mtu)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&config)?;

    tracing::info!(
        event_type = "lifecycle",
        action = "tun_create",
        device = name,
        address = %addr,
        netmask = %prefix_to_netmask(prefix_len),
        mtu = mtu,
        "created CLAT TUN device"
    );

    Ok(dev)
}

/// Create the IPv6-facing TUN device (uplink side).
///
/// This device carries translated IPv6 packets to/from the network.
/// Routing rules must direct CLAT-prefix and NAT64-prefix traffic
/// through this device.
pub fn create_v6_tun(name: &str, mtu: u16) -> anyhow::Result<tun::AsyncDevice> {
    let mut config = Configuration::default();

    config.tun_name(name).mtu(mtu).up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&config)?;

    tracing::info!(
        event_type = "lifecycle",
        action = "tun_create",
        device = name,
        address_family = "ipv6",
        mtu = mtu,
        "created CLAT IPv6 TUN device"
    );

    Ok(dev)
}

/// Convert a prefix length to a netmask (e.g., 24 -> 255.255.255.0).
fn prefix_to_netmask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask: u32 = !0u32 << (32 - prefix_len);
    Ipv4Addr::from(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
    }
}
