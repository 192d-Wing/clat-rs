use std::net::Ipv4Addr;

use tun::Configuration;

/// Create the IPv6-facing TUN device (uplink side).
///
/// This device receives IPv6 packets destined to the NAT64 prefix
/// and sends translated IPv6 packets back to clients.
/// Routing rules must direct NAT64-prefix traffic into this device.
pub fn create_v6_tun(name: &str, mtu: u16) -> anyhow::Result<tun::AsyncDevice> {
    let mut config = Configuration::default();

    config.tun_name(name).mtu(mtu).up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&config)?;

    log::info!("created IPv6 TUN device '{name}' with mtu {mtu}");
    Ok(dev)
}

/// Create the IPv4-facing TUN device (egress side).
///
/// This device sends translated IPv4 packets out and receives
/// return IPv4 traffic destined to pool addresses.
/// The pool addresses are configured on this interface so the
/// kernel routes return traffic back to us.
pub fn create_v4_tun(
    name: &str,
    pool_addr: Ipv4Addr,
    mtu: u16,
) -> anyhow::Result<tun::AsyncDevice> {
    let mut config = Configuration::default();

    config
        .tun_name(name)
        .address(pool_addr)
        .netmask(Ipv4Addr::new(255, 255, 255, 255))
        .mtu(mtu)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&config)?;

    log::info!("created IPv4 TUN device '{name}' with addr {pool_addr} mtu {mtu}");
    Ok(dev)
}
