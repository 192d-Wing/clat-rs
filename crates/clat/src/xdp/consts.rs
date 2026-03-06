// Linux UAPI constants for AF_XDP (from linux/if_xdp.h, linux/socket.h)

pub const AF_XDP: i32 = 44;
pub const SOL_XDP: i32 = 283;
pub const SOCK_RAW: i32 = libc::SOCK_RAW;

// setsockopt options
pub const XDP_MMAP_OFFSETS: i32 = 1;
pub const XDP_RX_RING: i32 = 2;
pub const XDP_TX_RING: i32 = 3;
pub const XDP_UMEM_REG: i32 = 4;
pub const XDP_UMEM_FILL_RING: i32 = 5;
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;

// mmap offsets for ring mapping
pub const XDP_PGOFF_RX_RING: u64 = 0;
pub const XDP_PGOFF_TX_RING: u64 = 0x8000_0000;
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x1_0000_0000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x1_8000_0000;

// Bind flags
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_COPY: u16 = 1 << 1;

// Default sizes
pub const DEFAULT_FRAME_SIZE: u32 = 4096;
pub const DEFAULT_NUM_FRAMES: u32 = 4096;
pub const DEFAULT_RING_SIZE: u32 = 2048;

/// UMEM registration passed to setsockopt(XDP_UMEM_REG).
#[repr(C)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

/// Bind address for AF_XDP sockets.
#[repr(C)]
pub struct SockaddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

/// Ring offset info returned by getsockopt(XDP_MMAP_OFFSETS).
#[repr(C)]
#[derive(Default)]
pub struct XdpRingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

/// Full mmap offsets for all four rings.
#[repr(C)]
#[derive(Default)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffset,
    pub tx: XdpRingOffset,
    pub fr: XdpRingOffset,
    pub cr: XdpRingOffset,
}

/// Packet descriptor in RX/TX rings.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}
