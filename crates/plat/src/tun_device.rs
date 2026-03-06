use std::net::Ipv4Addr;

use tun::Configuration;

/// Configuration for privilege dropping after TUN device creation.
#[allow(dead_code)] // Fields read only on Linux via cfg-gated code
pub struct DropPrivileges {
    pub uid: u32,
    pub gid: u32,
}

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

/// Drop privileges after TUN devices have been created.
///
/// On Linux, this drops supplementary groups and switches to the specified
/// UID/GID. This should be called after all privileged operations (TUN
/// creation) are complete but before entering the packet loop.
///
/// On non-Linux platforms, this is a no-op.
#[cfg(target_os = "linux")]
pub fn drop_privileges(privs: &DropPrivileges) -> anyhow::Result<()> {
    use std::io;

    // Drop supplementary groups
    let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setgroups(0) failed: {}",
            io::Error::last_os_error()
        ));
    }

    // Set GID first (must happen before setuid, since setuid drops the
    // ability to change GID)
    let ret = unsafe { libc::setgid(privs.gid) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setgid({}) failed: {}",
            privs.gid,
            io::Error::last_os_error()
        ));
    }

    // Set UID
    let ret = unsafe { libc::setuid(privs.uid) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setuid({}) failed: {}",
            privs.uid,
            io::Error::last_os_error()
        ));
    }

    log::info!("dropped privileges to uid={} gid={}", privs.uid, privs.gid);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn drop_privileges(_privs: &DropPrivileges) -> anyhow::Result<()> {
    log::debug!("privilege dropping not supported on this platform");
    Ok(())
}
