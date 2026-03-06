use std::net::Ipv4Addr;

use tun::Configuration;

/// Configuration for privilege dropping after TUN device creation.
#[allow(dead_code)] // Fields read only on Linux via cfg-gated code
pub struct DropPrivileges {
    pub uid: u32,
    pub gid: u32,
}

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
    let clamped = prefix_len.min(32);
    let mask: u32 = !0u32 << (32 - clamped);
    Ipv4Addr::from(mask)
}

/// Drop privileges after TUN devices have been created.
///
/// On Linux, this drops supplementary groups and switches to the specified
/// UID/GID. On non-Linux platforms, this is a no-op.
#[cfg(target_os = "linux")]
pub fn drop_privileges(privs: &DropPrivileges) -> anyhow::Result<()> {
    use std::io;

    let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setgroups(0) failed: {}",
            io::Error::last_os_error()
        ));
    }

    let ret = unsafe { libc::setgid(privs.gid) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setgid({}) failed: {}",
            privs.gid,
            io::Error::last_os_error()
        ));
    }

    let ret = unsafe { libc::setuid(privs.uid) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setuid({}) failed: {}",
            privs.uid,
            io::Error::last_os_error()
        ));
    }

    tracing::info!(
        event_type = "security",
        action = "drop_privileges",
        uid = privs.uid,
        gid = privs.gid,
        "dropped privileges"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn drop_privileges(_privs: &DropPrivileges) -> anyhow::Result<()> {
    tracing::debug!("privilege dropping not supported on this platform");
    Ok(())
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

    #[test]
    fn test_drop_privileges_struct() {
        let privs = DropPrivileges {
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(privs.uid, 1000);
        assert_eq!(privs.gid, 1000);
    }

    #[test]
    fn test_drop_privileges_noop_on_non_linux() {
        let privs = DropPrivileges {
            uid: 65534,
            gid: 65534,
        };
        let result = drop_privileges(&privs);
        assert!(result.is_ok());
    }
}
