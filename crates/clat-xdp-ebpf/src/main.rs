#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, XskMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;

/// AF_XDP socket map — one entry per NIC RX queue.
#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(64, 0);

/// CLAT /96 prefix stored as three big-endian u32 words.
/// Index 0 = bytes 0-3, index 1 = bytes 4-7, index 2 = bytes 8-11.
/// Written by userspace before attaching the program.
#[map]
static CLAT_PREFIX: Array<u32> = Array::with_max_entries(3, 0);

const ETH_HDR_LEN: usize = 14;
const IPV6_HDR_LEN: usize = 40;
const ETH_P_IPV6: u16 = 0x86DD;

#[xdp]
pub fn clat_xdp(ctx: XdpContext) -> u32 {
    match try_clat_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

/// Inspect incoming frames: if IPv6 destination matches our CLAT /96 prefix,
/// redirect to the AF_XDP socket for this queue. Everything else passes through
/// the normal kernel stack.
#[inline(always)]
fn try_clat_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Need at least Ethernet + IPv6 fixed header
    if data + ETH_HDR_LEN + IPV6_HDR_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check EtherType == IPv6
    let ethertype = unsafe { u16::from_be(core::ptr::read_unaligned((data + 12) as *const u16)) };
    if ethertype != ETH_P_IPV6 {
        return Ok(xdp_action::XDP_PASS);
    }

    // IPv6 destination address starts at byte 24 of the IPv6 header.
    // Compare the first 12 bytes (/96 prefix) as three u32 words.
    let dst_offset = data + ETH_HDR_LEN + 24;

    for i in 0..3u32 {
        let expected = unsafe { CLAT_PREFIX.get(i) }.ok_or(())?;
        let actual =
            unsafe { core::ptr::read_unaligned((dst_offset + (i as usize) * 4) as *const u32) };
        if actual != *expected {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // Prefix matched — redirect to AF_XDP socket for this RX queue
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    info!(ctx, "CLAT prefix match on queue {}", queue_id);
    XSKS_MAP.redirect(queue_id, 0).map_err(|_| ())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
