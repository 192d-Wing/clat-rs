use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
/// Routing rules must direct NAT64-prefix and CLAT-prefix traffic through `clat6`.
/// If no CLAT prefix is available at startup, waits for one to be set via gRPC.
pub async fn run(config: &Config, state: Arc<SharedState>) -> anyhow::Result<()> {
    let networks: Vec<(Ipv4Addr, u8)> = config.parse_ipv4_networks()?;
    let plat_prefix: Ipv6Addr = config.plat_prefix();

    // Create IPv4-facing TUN device using the first network for the interface address
    let (first_network, first_prefix_len) = networks[0];
    let mut v4_tun = tun_device::create_tun(
        V4_TUN_NAME,
        config.clat_ipv4_addr,
        first_network,
        first_prefix_len,
        config.mtu,
    )?;

    // Create IPv6-facing TUN device for the uplink
    let mut v6_tun = tun_device::create_v6_tun(V6_TUN_NAME, config.mtu)?;

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

    let mut clat_prefix = state.current_prefix().unwrap();
    tracing::info!(
        event_type = "lifecycle",
        action = "packet_loop_start",
        v4_tun = V4_TUN_NAME,
        v6_tun = V6_TUN_NAME,
        clat_prefix = %clat_prefix,
        "CLAT packet loop started"
    );
    state.set_translating(true);

    let mut v4_buf = [0u8; BUF_SIZE];
    let mut v6_buf = [0u8; BUF_SIZE];
    // Pre-allocated output buffers — reused every packet, zero heap allocations
    let mut v6_out = [0u8; BUF_SIZE];
    let mut v4_out = [0u8; BUF_SIZE];

    loop {
        tokio::select! {
            // Watch for prefix updates (hot-swap)
            result = prefix_rx.changed() => {
                if result.is_err() {
                    tracing::warn!("prefix watch channel closed");
                    break;
                }
                if let Some(new_prefix) = *prefix_rx.borrow_and_update()
                    && new_prefix != clat_prefix
                {
                    tracing::info!("hot-swapping CLAT prefix: {clat_prefix} -> {new_prefix}");
                    clat_prefix = new_prefix;
                }
            }

            // Read IPv4 packet from v4 TUN -> translate to IPv6 -> send out v6 TUN
            result = v4_tun.read(&mut v4_buf) => {
                let n = result?;
                if n == 0 {
                    continue;
                }
                let ipv4_packet = &v4_buf[..n];

                if let Some(out_len) = nat64_core::translate::ipv4_to_ipv6_buf(ipv4_packet, clat_prefix, plat_prefix, &mut v6_out)
                {
                    tracing::debug!(
                        event_type = "translation",
                        direction = "v4_to_v6",
                        bytes = out_len,
                        "translated IPv4 to IPv6"
                    );
                    if let Err(e) = v6_tun.write_all(&v6_out[..out_len]).await {
                        tracing::warn!("failed to write IPv6 packet to TUN: {e}");
                    }
                }
            }

            // Read IPv6 packet from v6 TUN -> translate to IPv4 -> write to v4 TUN
            result = v6_tun.read(&mut v6_buf) => {
                let n = result?;
                if n < IPV6_HDR_LEN {
                    continue;
                }
                let ipv6_packet = &v6_buf[..n];

                if let Some(out_len) = nat64_core::translate::ipv6_to_ipv4_buf(ipv6_packet, clat_prefix, plat_prefix, &mut v4_out)
                {
                    tracing::debug!(
                        event_type = "translation",
                        direction = "v6_to_v4",
                        bytes = out_len,
                        "translated IPv6 to IPv4"
                    );
                    if let Err(e) = v4_tun.write_all(&v4_out[..out_len]).await {
                        tracing::warn!("failed to write IPv4 packet to TUN: {e}");
                    }
                }
            }

            // Handle shutdown signal
            _ = tokio::signal::ctrl_c() => {
                tracing::info!(
                    event_type = "lifecycle",
                    action = "packet_loop_stop",
                    reason = "signal",
                    "CLAT received shutdown signal"
                );
                break;
            }
        }
    }

    state.set_translating(false);
    Ok(())
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
