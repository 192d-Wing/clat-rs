use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use crate::config::Config;
use crate::state::SharedState;
use crate::tun_device;

const V4_TUN_NAME: &str = "clat0";
const V6_TUN_NAME: &str = "clat6";
const BUF_SIZE: usize = 65536;

/// Minimum IPv6 header length.
const IPV6_HDR_LEN: usize = 40;

/// Run the main CLAT packet translation loop.
///
/// Uses two TUN devices:
/// - `clat0` (IPv4-facing): receives IPv4 packets from clients
/// - `clat6` (IPv6-facing): sends/receives translated IPv6 packets on the uplink
///
/// Each direction runs as a dedicated task, eliminating select overhead
/// and enabling true parallelism across cores.
///
/// Routing rules must direct NAT64-prefix and CLAT-prefix traffic through `clat6`.
/// If no CLAT prefix is available at startup, waits for one to be set via gRPC.
pub async fn run(config: &Config, state: Arc<SharedState>) -> anyhow::Result<()> {
    let networks: Vec<(Ipv4Addr, u8)> = config.parse_ipv4_networks()?;
    let plat_prefix: Ipv6Addr = config.plat_prefix();

    // Create IPv4-facing TUN device using the first network for the interface address
    let (first_network, first_prefix_len) = networks[0];
    let v4_tun = tun_device::create_tun(
        V4_TUN_NAME,
        config.clat_ipv4_addr,
        first_network,
        first_prefix_len,
        config.mtu,
    )?;

    // Create IPv6-facing TUN device for the uplink
    let v6_tun = tun_device::create_v6_tun(V6_TUN_NAME, config.mtu)?;

    // Log additional networks (routes would be added via ip route in production)
    for (net, prefix) in &networks[1..] {
        tracing::info!("additional CLAT network: {net}/{prefix}");
    }

    let mut prefix_rx = state.subscribe_prefix();

    // Wait for initial prefix if not set
    if state.current_prefix().is_none() {
        tracing::info!("no CLAT prefix configured — waiting for gRPC SetPrefix...");
        loop {
            if prefix_rx.changed().await.is_err() {
                anyhow::bail!("prefix channel closed before a prefix was set");
            }
            if prefix_rx.borrow().is_some() {
                break;
            }
        }
    }

    let clat_prefix = state.current_prefix().unwrap();
    tracing::info!(
        event_type = "lifecycle",
        action = "packet_loop_start",
        v4_tun = V4_TUN_NAME,
        v6_tun = V6_TUN_NAME,
        clat_prefix = %clat_prefix,
        "CLAT packet loop started"
    );
    state.set_translating(true);

    // Split TUN devices into independent reader/writer halves.
    // Each direction gets its own task — no 4-way select overhead per packet.
    let (v4_writer, v4_reader) = v4_tun.split()?;
    let (v6_writer, v6_reader) = v6_tun.split()?;

    let v4_to_v6_handle = tokio::spawn(v4_to_v6_loop(
        v4_reader,
        v6_writer,
        clat_prefix,
        plat_prefix,
        state.subscribe_prefix(),
    ));
    let v6_to_v4_handle = tokio::spawn(v6_to_v4_loop(
        v6_reader,
        v4_writer,
        clat_prefix,
        plat_prefix,
        state.subscribe_prefix(),
    ));

    tokio::select! {
        result = v4_to_v6_handle => {
            if let Ok(Err(e)) = result {
                tracing::warn!("v4→v6 task failed: {e}");
            }
        }
        result = v6_to_v4_handle => {
            if let Ok(Err(e)) = result {
                tracing::warn!("v6→v4 task failed: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!(
                event_type = "lifecycle",
                action = "packet_loop_stop",
                reason = "signal",
                "CLAT received shutdown signal"
            );
        }
    }

    state.set_translating(false);
    Ok(())
}

/// Dedicated v4→v6 translation task.
async fn v4_to_v6_loop(
    mut reader: tun::DeviceReader,
    mut writer: tun::DeviceWriter,
    mut clat_prefix: Ipv6Addr,
    plat_prefix: Ipv6Addr,
    mut prefix_rx: watch::Receiver<Option<Ipv6Addr>>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; BUF_SIZE];
    let mut out = [0u8; BUF_SIZE];

    loop {
        if prefix_rx.has_changed().unwrap_or(false)
            && let Some(new_prefix) = *prefix_rx.borrow_and_update()
            && new_prefix != clat_prefix
        {
            tracing::info!("v4→v6: hot-swapping CLAT prefix: {clat_prefix} -> {new_prefix}");
            clat_prefix = new_prefix;
        }

        let n = reader.read(&mut buf).await?;
        if n == 0 {
            continue;
        }

        if let Some(out_len) =
            nat64_core::translate::ipv4_to_ipv6_buf(&buf[..n], clat_prefix, plat_prefix, &mut out)
        {
            tracing::debug!(
                event_type = "translation",
                direction = "v4_to_v6",
                bytes = out_len,
                "translated IPv4 to IPv6"
            );
            if let Err(e) = writer.write_all(&out[..out_len]).await {
                tracing::warn!("failed to write IPv6 packet to TUN: {e}");
            }
        }
    }
}

/// Dedicated v6→v4 translation task.
async fn v6_to_v4_loop(
    mut reader: tun::DeviceReader,
    mut writer: tun::DeviceWriter,
    mut clat_prefix: Ipv6Addr,
    plat_prefix: Ipv6Addr,
    mut prefix_rx: watch::Receiver<Option<Ipv6Addr>>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; BUF_SIZE];
    let mut out = [0u8; BUF_SIZE];

    loop {
        if prefix_rx.has_changed().unwrap_or(false)
            && let Some(new_prefix) = *prefix_rx.borrow_and_update()
            && new_prefix != clat_prefix
        {
            tracing::info!("v6→v4: hot-swapping CLAT prefix: {clat_prefix} -> {new_prefix}");
            clat_prefix = new_prefix;
        }

        let n = reader.read(&mut buf).await?;
        if n < IPV6_HDR_LEN {
            continue;
        }

        if let Some(out_len) =
            nat64_core::translate::ipv6_to_ipv4_buf(&buf[..n], clat_prefix, plat_prefix, &mut out)
        {
            tracing::debug!(
                event_type = "translation",
                direction = "v6_to_v4",
                bytes = out_len,
                "translated IPv6 to IPv4"
            );
            if let Err(e) = writer.write_all(&out[..out_len]).await {
                tracing::warn!("failed to write IPv4 packet to TUN: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buf_size_constant() {
        assert_eq!(BUF_SIZE, 65536);
    }

    #[test]
    fn test_tun_name_constants() {
        assert_eq!(V4_TUN_NAME, "clat0");
        assert_eq!(V6_TUN_NAME, "clat6");
    }

    #[test]
    fn test_ipv6_hdr_len_constant() {
        assert_eq!(IPV6_HDR_LEN, 40);
    }
}
