use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use super::consts::*;

/// Shared UMEM region backing AF_XDP packet buffers.
pub struct Umem {
    /// Aligned allocation for packet frames
    area: *mut u8,
    area_len: usize,
    pub frame_size: u32,
    pub num_frames: u32,
    /// Socket that owns the UMEM registration
    fd: OwnedFd,
    pub fill: FillRing,
    pub comp: CompRing,
}

// SAFETY: Umem is only accessed from the single XDP packet thread.
unsafe impl Send for Umem {}

impl Umem {
    /// Allocate UMEM and register it with an AF_XDP socket.
    pub fn new(num_frames: u32, frame_size: u32) -> io::Result<Self> {
        let area_len = (num_frames as usize) * (frame_size as usize);

        // Page-aligned allocation
        let area = unsafe {
            libc::mmap(
                ptr::null_mut(),
                area_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if area == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let area = area.cast::<u8>();

        // Create the AF_XDP socket that owns this UMEM
        let raw_fd = unsafe { libc::socket(AF_XDP, SOCK_RAW, 0) };
        if raw_fd < 0 {
            unsafe { libc::munmap(area.cast(), area_len) };
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // Register UMEM
        let reg = XdpUmemReg {
            addr: area as u64,
            len: area_len as u64,
            chunk_size: frame_size,
            headroom: 0,
            flags: 0,
        };
        setsockopt_raw(fd.as_raw_fd(), XDP_UMEM_REG, &reg)?;

        // Set fill & completion ring sizes
        let ring_size = DEFAULT_RING_SIZE;
        setsockopt_raw(fd.as_raw_fd(), XDP_UMEM_FILL_RING, &ring_size)?;
        setsockopt_raw(fd.as_raw_fd(), XDP_UMEM_COMPLETION_RING, &ring_size)?;

        // Get mmap offsets
        let offsets = get_mmap_offsets(fd.as_raw_fd())?;

        // mmap fill ring
        let fill = unsafe {
            FillRing::mmap(
                fd.as_raw_fd(),
                &offsets.fr,
                ring_size,
                XDP_UMEM_PGOFF_FILL_RING,
            )?
        };

        // mmap completion ring
        let comp = unsafe {
            CompRing::mmap(
                fd.as_raw_fd(),
                &offsets.cr,
                ring_size,
                XDP_UMEM_PGOFF_COMPLETION_RING,
            )?
        };

        Ok(Umem {
            area,
            area_len,
            frame_size,
            num_frames,
            fd,
            fill,
            comp,
        })
    }

    /// Get the raw fd (used when binding XskSockets that share this UMEM).
    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// Pointer to the frame at the given UMEM address.
    ///
    /// # Safety
    /// Caller must ensure `addr` is within bounds and properly aligned.
    pub unsafe fn frame_ptr(&self, addr: u64) -> *mut u8 {
        debug_assert!(
            (addr as usize) < self.area_len,
            "UMEM frame_ptr out of bounds: addr={addr}, area_len={}",
            self.area_len
        );
        unsafe { self.area.add(addr as usize) }
    }

    /// Get a slice for the frame at `addr` with length `len`.
    ///
    /// # Safety
    /// Caller must ensure addr + len is within the UMEM region.
    pub unsafe fn frame_slice(&self, addr: u64, len: u32) -> &[u8] {
        debug_assert!(
            (addr as usize).saturating_add(len as usize) <= self.area_len,
            "UMEM frame_slice out of bounds: addr={addr}, len={len}, area_len={}",
            self.area_len
        );
        unsafe { std::slice::from_raw_parts(self.area.add(addr as usize), len as usize) }
    }

    /// Get a mutable slice for the frame at `addr` with capacity `frame_size`.
    ///
    /// # Safety
    /// Caller must ensure addr is within bounds.
    pub unsafe fn frame_slice_mut(&self, addr: u64) -> &mut [u8] {
        debug_assert!(
            (addr as usize).saturating_add(self.frame_size as usize) <= self.area_len,
            "UMEM frame_slice_mut out of bounds: addr={addr}, frame_size={}, area_len={}",
            self.frame_size,
            self.area_len
        );
        unsafe {
            std::slice::from_raw_parts_mut(self.area.add(addr as usize), self.frame_size as usize)
        }
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.area.cast(), self.area_len);
        }
    }
}

/// AF_XDP socket bound to a specific NIC queue.
pub struct XskSocket {
    pub fd: OwnedFd,
    pub rx: RxRing,
    pub tx: TxRing,
}

// SAFETY: XskSocket is only accessed from the single XDP packet thread.
unsafe impl Send for XskSocket {}

impl XskSocket {
    /// Create an AF_XDP socket, bind it to `ifindex`/`queue_id`, and set up RX/TX rings.
    /// If `umem_fd` is provided, share that UMEM instead of creating a new one.
    pub fn new(umem: &Umem, ifindex: u32, queue_id: u32, zero_copy: bool) -> io::Result<Self> {
        // For the first queue we reuse the UMEM's socket fd.
        // For additional queues we'd create a new socket with shared UMEM.
        // This implementation supports a single queue; multi-queue can extend this.
        let raw_fd = unsafe { libc::socket(AF_XDP, SOCK_RAW, 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let ring_size = DEFAULT_RING_SIZE;
        setsockopt_raw(fd.as_raw_fd(), XDP_RX_RING, &ring_size)?;
        setsockopt_raw(fd.as_raw_fd(), XDP_TX_RING, &ring_size)?;

        let offsets = get_mmap_offsets(fd.as_raw_fd())?;

        let rx =
            unsafe { RxRing::mmap(fd.as_raw_fd(), &offsets.rx, ring_size, XDP_PGOFF_RX_RING)? };
        let tx =
            unsafe { TxRing::mmap(fd.as_raw_fd(), &offsets.tx, ring_size, XDP_PGOFF_TX_RING)? };

        // Bind to interface + queue
        let sxdp = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: if zero_copy { XDP_ZEROCOPY } else { XDP_COPY },
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: umem.fd().as_raw_fd() as u32,
        };

        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&sxdp as *const SockaddrXdp).cast(),
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(XskSocket { fd, rx, tx })
    }

    /// Receive a batch of packets. Returns the number received.
    /// Descriptors are written into `descs[..returned_count]`.
    pub fn recv_batch(&mut self, descs: &mut [XdpDesc]) -> u32 {
        self.rx.recv_batch(descs)
    }

    /// Submit a batch of packets for transmission.
    pub fn send_batch(&mut self, descs: &[XdpDesc]) -> u32 {
        self.tx.send_batch(descs)
    }

    /// Notify the kernel there are TX frames to send (calls sendto).
    pub fn kick_tx(&self) {
        unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                ptr::null(),
                0,
            );
        }
    }

    /// Wake the kernel to deliver RX frames (via poll).
    pub fn wake_rx(&self) {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe {
            libc::poll(&mut pfd, 1, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Ring buffer types
// ---------------------------------------------------------------------------

/// Fill ring: userspace → kernel. Provides UMEM frame addresses for RX.
pub struct FillRing {
    producer: *mut AtomicU32,
    consumer: *const AtomicU32,
    ring: *mut u64,
    mask: u32,
    size: u32,
    mmap_addr: *mut u8,
    mmap_len: usize,
    cached_prod: u32,
}

impl FillRing {
    /// # Safety
    /// `fd` must be a valid AF_XDP socket with UMEM fill ring configured.
    unsafe fn mmap(fd: i32, offset: &XdpRingOffset, size: u32, pgoff: u64) -> io::Result<Self> {
        assert!(size.is_power_of_two(), "ring size must be a power of two");
        let mmap_len = (offset.desc + (size as u64) * std::mem::size_of::<u64>() as u64) as usize;
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff as libc::off_t,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = addr.cast::<u8>();
        Ok(FillRing {
            producer: unsafe { base.add(offset.producer as usize).cast::<AtomicU32>() },
            consumer: unsafe { base.add(offset.consumer as usize).cast::<AtomicU32>() },
            ring: unsafe { base.add(offset.desc as usize).cast::<u64>() },
            mask: size - 1,
            size,
            mmap_addr: base,
            mmap_len,
            cached_prod: 0,
        })
    }

    /// Enqueue frame addresses for the kernel to fill with received packets.
    pub fn submit(&mut self, addrs: &[u64]) -> u32 {
        let prod = self.cached_prod;
        let cons = unsafe { (*self.consumer).load(Ordering::Acquire) };
        let free = self.size - (prod.wrapping_sub(cons));
        let count = (addrs.len() as u32).min(free);

        for (i, &addr) in addrs[..count as usize].iter().enumerate() {
            let idx = (prod + i as u32) & self.mask;
            unsafe { ptr::write(self.ring.add(idx as usize), addr) };
        }

        std::sync::atomic::fence(Ordering::Release);
        self.cached_prod = prod + count;
        unsafe { (*self.producer).store(self.cached_prod, Ordering::Release) };
        count
    }
}

impl Drop for FillRing {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.mmap_addr.cast(), self.mmap_len) };
    }
}

/// Completion ring: kernel → userspace. Returns UMEM frame addresses after TX.
pub struct CompRing {
    producer: *const AtomicU32,
    consumer: *mut AtomicU32,
    ring: *const u64,
    mask: u32,
    #[allow(dead_code)]
    size: u32,
    mmap_addr: *mut u8,
    mmap_len: usize,
    cached_cons: u32,
}

impl CompRing {
    /// # Safety
    /// `fd` must be a valid AF_XDP socket with UMEM completion ring configured.
    unsafe fn mmap(fd: i32, offset: &XdpRingOffset, size: u32, pgoff: u64) -> io::Result<Self> {
        assert!(size.is_power_of_two(), "ring size must be a power of two");
        let mmap_len = (offset.desc + (size as u64) * std::mem::size_of::<u64>() as u64) as usize;
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff as libc::off_t,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = addr.cast::<u8>();
        Ok(CompRing {
            producer: unsafe { base.add(offset.producer as usize).cast::<AtomicU32>() },
            consumer: unsafe { base.add(offset.consumer as usize).cast::<AtomicU32>() },
            ring: unsafe { base.add(offset.desc as usize).cast::<u64>() },
            mask: size - 1,
            size,
            mmap_addr: base,
            mmap_len,
            cached_cons: 0,
        })
    }

    /// Drain completed TX frame addresses back into `out`. Returns count.
    pub fn drain(&mut self, out: &mut Vec<u64>) -> u32 {
        let prod = unsafe { (*self.producer).load(Ordering::Acquire) };
        let cons = self.cached_cons;
        let count = prod.wrapping_sub(cons);
        if count == 0 {
            return 0;
        }

        for i in 0..count {
            let idx = (cons + i) & self.mask;
            let addr = unsafe { ptr::read(self.ring.add(idx as usize)) };
            out.push(addr);
        }

        std::sync::atomic::fence(Ordering::Release);
        self.cached_cons = cons + count;
        unsafe { (*self.consumer).store(self.cached_cons, Ordering::Release) };
        count
    }
}

impl Drop for CompRing {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.mmap_addr.cast(), self.mmap_len) };
    }
}

/// RX ring: kernel → userspace. Provides received packet descriptors.
pub struct RxRing {
    producer: *const AtomicU32,
    consumer: *mut AtomicU32,
    ring: *const XdpDesc,
    mask: u32,
    #[allow(dead_code)]
    size: u32,
    mmap_addr: *mut u8,
    mmap_len: usize,
    cached_cons: u32,
}

impl RxRing {
    /// # Safety
    /// `fd` must be a valid AF_XDP socket with RX ring configured.
    unsafe fn mmap(fd: i32, offset: &XdpRingOffset, size: u32, pgoff: u64) -> io::Result<Self> {
        assert!(size.is_power_of_two(), "ring size must be a power of two");
        let mmap_len =
            (offset.desc + (size as u64) * std::mem::size_of::<XdpDesc>() as u64) as usize;
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff as libc::off_t,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = addr.cast::<u8>();
        Ok(RxRing {
            producer: unsafe { base.add(offset.producer as usize).cast::<AtomicU32>() },
            consumer: unsafe { base.add(offset.consumer as usize).cast::<AtomicU32>() },
            ring: unsafe { base.add(offset.desc as usize).cast::<XdpDesc>() },
            mask: size - 1,
            size,
            mmap_addr: base,
            mmap_len,
            cached_cons: 0,
        })
    }

    fn recv_batch(&mut self, descs: &mut [XdpDesc]) -> u32 {
        let prod = unsafe { (*self.producer).load(Ordering::Acquire) };
        let cons = self.cached_cons;
        let avail = prod.wrapping_sub(cons);
        let count = (descs.len() as u32).min(avail);

        for i in 0..count {
            let idx = (cons + i) & self.mask;
            descs[i as usize] = unsafe { ptr::read(self.ring.add(idx as usize)) };
        }

        std::sync::atomic::fence(Ordering::Release);
        self.cached_cons = cons + count;
        unsafe { (*self.consumer).store(self.cached_cons, Ordering::Release) };
        count
    }
}

impl Drop for RxRing {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.mmap_addr.cast(), self.mmap_len) };
    }
}

/// TX ring: userspace → kernel. Submits packet descriptors for transmission.
pub struct TxRing {
    producer: *mut AtomicU32,
    consumer: *const AtomicU32,
    ring: *mut XdpDesc,
    mask: u32,
    size: u32,
    mmap_addr: *mut u8,
    mmap_len: usize,
    cached_prod: u32,
}

impl TxRing {
    /// # Safety
    /// `fd` must be a valid AF_XDP socket with TX ring configured.
    unsafe fn mmap(fd: i32, offset: &XdpRingOffset, size: u32, pgoff: u64) -> io::Result<Self> {
        assert!(size.is_power_of_two(), "ring size must be a power of two");
        let mmap_len =
            (offset.desc + (size as u64) * std::mem::size_of::<XdpDesc>() as u64) as usize;
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff as libc::off_t,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = addr.cast::<u8>();
        Ok(TxRing {
            producer: unsafe { base.add(offset.producer as usize).cast::<AtomicU32>() },
            consumer: unsafe { base.add(offset.consumer as usize).cast::<AtomicU32>() },
            ring: unsafe { base.add(offset.desc as usize).cast::<XdpDesc>() },
            mask: size - 1,
            size,
            mmap_addr: base,
            mmap_len,
            cached_prod: 0,
        })
    }

    fn send_batch(&mut self, descs: &[XdpDesc]) -> u32 {
        let prod = self.cached_prod;
        let cons = unsafe { (*self.consumer).load(Ordering::Acquire) };
        let free = self.size - (prod.wrapping_sub(cons));
        let count = (descs.len() as u32).min(free);

        for (i, desc) in descs[..count as usize].iter().enumerate() {
            let idx = (prod + i as u32) & self.mask;
            unsafe { ptr::write(self.ring.add(idx as usize), *desc) };
        }

        std::sync::atomic::fence(Ordering::Release);
        self.cached_prod = prod + count;
        unsafe { (*self.producer).store(self.cached_prod, Ordering::Release) };
        count
    }
}

impl Drop for TxRing {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.mmap_addr.cast(), self.mmap_len) };
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setsockopt_raw<T>(fd: i32, opt: i32, val: &T) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            opt,
            (val as *const T).cast(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn get_mmap_offsets(fd: i32) -> io::Result<XdpMmapOffsets> {
    let mut offsets = XdpMmapOffsets::default();
    let mut len = std::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            (&mut offsets as *mut XdpMmapOffsets).cast(),
            &mut len,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(offsets)
    }
}

/// Free frame allocator: simple stack-based allocator for UMEM frame addresses.
pub struct FrameAllocator {
    free: Vec<u64>,
}

impl FrameAllocator {
    /// Initialize with all frames in `[0, num_frames * frame_size)`.
    pub fn new(num_frames: u32, frame_size: u32) -> Self {
        let free = (0..num_frames)
            .map(|i| (i as u64) * (frame_size as u64))
            .collect();
        FrameAllocator { free }
    }

    pub fn alloc(&mut self) -> Option<u64> {
        self.free.pop()
    }

    pub fn free(&mut self, addr: u64) {
        self.free.push(addr);
    }

    pub fn available(&self) -> usize {
        self.free.len()
    }
}
