use std::net::Ipv6Addr;
use std::path::Path;

use aya::Ebpf;
use aya::maps::{Array, XskMap};
use aya::programs::{Xdp, XdpFlags};

/// Loaded XDP program and its BPF maps.
pub struct XdpProgram {
    bpf: Ebpf,
}

impl XdpProgram {
    /// Load the XDP eBPF object file and attach it to the given interface.
    pub fn load_and_attach(
        obj_path: &Path,
        iface: &str,
        clat_prefix: Ipv6Addr,
        zero_copy: bool,
    ) -> anyhow::Result<Self> {
        let mut bpf = Ebpf::load_file(obj_path)?;

        // Set up aya-log forwarding (BPF-side log messages → env_logger)
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            log::warn!("failed to init eBPF logger (non-fatal): {e}");
        }

        // Write the CLAT /96 prefix into the BPF map
        Self::write_prefix(&mut bpf, clat_prefix)?;

        // Load and attach the XDP program
        let program: &mut Xdp = bpf.program_mut("clat_xdp").unwrap().try_into()?;
        program.load()?;

        let flags = if zero_copy {
            XdpFlags::DRV_MODE
        } else {
            XdpFlags::SKB_MODE
        };
        program.attach(iface, flags)?;

        log::info!("XDP program attached to {iface} (flags={flags:?})");

        Ok(XdpProgram { bpf })
    }

    /// Update the CLAT prefix in the running BPF program (hot-swap).
    pub fn update_prefix(&mut self, prefix: Ipv6Addr) -> anyhow::Result<()> {
        Self::write_prefix(&mut self.bpf, prefix)
    }

    /// Get a mutable reference to the XSK map for registering AF_XDP sockets.
    pub fn xsk_map(&mut self) -> anyhow::Result<XskMap<aya::maps::MapData>> {
        let map = self.bpf.take_map("XSKS_MAP").unwrap();
        Ok(XskMap::try_from(map)?)
    }

    fn write_prefix(bpf: &mut Ebpf, prefix: Ipv6Addr) -> anyhow::Result<()> {
        let octets = prefix.octets();
        let words: [u32; 3] = [
            u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
            u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
            u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
        ];

        let mut map: Array<_, u32> = Array::try_from(bpf.map_mut("CLAT_PREFIX").unwrap())?;

        // Store as raw big-endian bytes (the BPF program compares raw memory)
        for (i, &word) in words.iter().enumerate() {
            map.set(i as u32, word.to_be(), 0)?;
        }

        log::info!("CLAT prefix written to BPF map: {prefix}/96");
        Ok(())
    }
}

impl Drop for XdpProgram {
    fn drop(&mut self) {
        log::info!("detaching XDP program");
        // aya automatically detaches on drop
    }
}
