use std::collections::HashSet;
use std::net::Ipv4Addr;

/// Manages a pool of public IPv4 addresses and ephemeral ports for NAT64.
pub struct Ipv4Pool {
    /// Expanded list of usable IPv4 addresses.
    addresses: Vec<Ipv4Addr>,
    /// Inclusive range of ephemeral ports available for mapping.
    port_start: u16,
    port_end: u16,
    /// Currently allocated (address, port, protocol) tuples.
    allocated: HashSet<(Ipv4Addr, u16, u8)>,
    /// Round-robin index for address selection.
    next_addr_idx: usize,
    /// Next port to try per address (simple linear scan).
    next_port: u16,
}

impl Ipv4Pool {
    /// Create a new pool from CIDR ranges.
    ///
    /// `cidrs` are parsed via `nat64_core::prefix::parse_ipv4_cidr`.
    /// `port_range` is the inclusive (start, end) of usable ephemeral ports.
    pub fn new(cidrs: &[(Ipv4Addr, u8)], port_range: (u16, u16)) -> anyhow::Result<Self> {
        let mut addresses = Vec::new();
        for &(network, prefix_len) in cidrs {
            let expanded = expand_cidr(network, prefix_len);
            if expanded.is_empty() {
                anyhow::bail!("CIDR {network}/{prefix_len} expands to zero usable addresses");
            }
            addresses.extend(expanded);
        }
        if addresses.is_empty() {
            anyhow::bail!("IPv4 pool has no addresses");
        }
        Ok(Self {
            addresses,
            port_start: port_range.0,
            port_end: port_range.1,
            allocated: HashSet::new(),
            next_addr_idx: 0,
            next_port: port_range.0,
        })
    }

    /// Allocate a (address, port) pair for the given protocol.
    ///
    /// Returns `None` if the pool is exhausted.
    pub fn allocate(&mut self, protocol: u8) -> Option<(Ipv4Addr, u16)> {
        let num_addrs = self.addresses.len();
        let port_count = (self.port_end - self.port_start + 1) as usize;
        let max_attempts = num_addrs * port_count;

        for _ in 0..max_attempts {
            let addr = self.addresses[self.next_addr_idx];
            let port = self.next_port;

            // Advance to next port/address
            if self.next_port >= self.port_end {
                self.next_port = self.port_start;
                self.next_addr_idx = (self.next_addr_idx + 1) % num_addrs;
            } else {
                self.next_port += 1;
            }

            let key = (addr, port, protocol);
            if !self.allocated.contains(&key) {
                self.allocated.insert(key);
                return Some((addr, port));
            }
        }

        None // Pool exhausted for this protocol
    }

    /// Release a previously allocated (address, port, protocol) tuple.
    pub fn release(&mut self, addr: Ipv4Addr, port: u16, protocol: u8) {
        self.allocated.remove(&(addr, port, protocol));
    }

    /// Number of currently allocated bindings.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Total capacity (addresses * ports_per_addr * 3 protocols roughly).
    /// This is per-protocol, so actual max is addresses * port_range_size per protocol.
    pub fn capacity_per_protocol(&self) -> usize {
        self.addresses.len() * (self.port_end - self.port_start + 1) as usize
    }

    /// Return the list of pool addresses (for status reporting).
    pub fn addresses(&self) -> &[Ipv4Addr] {
        &self.addresses
    }
}

/// Expand a CIDR into individual host addresses.
///
/// For /32: returns just the single address.
/// For /31: returns both addresses (point-to-point, RFC 3021).
/// For /30 and shorter: excludes network and broadcast addresses.
fn expand_cidr(network: Ipv4Addr, prefix_len: u8) -> Vec<Ipv4Addr> {
    if prefix_len >= 32 {
        return vec![network];
    }
    if prefix_len == 31 {
        let base = u32::from(network);
        return vec![Ipv4Addr::from(base), Ipv4Addr::from(base | 1)];
    }

    let base = u32::from(network);
    let host_bits = 32 - prefix_len as u32;
    let count = 1u32 << host_bits;

    // Skip network (first) and broadcast (last)
    (1..count - 1).map(|i| Ipv4Addr::from(base + i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_cidr_slash_32() {
        let addrs = expand_cidr(Ipv4Addr::new(198, 51, 100, 1), 32);
        assert_eq!(addrs, vec![Ipv4Addr::new(198, 51, 100, 1)]);
    }

    #[test]
    fn test_expand_cidr_slash_31() {
        let addrs = expand_cidr(Ipv4Addr::new(198, 51, 100, 0), 31);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], Ipv4Addr::new(198, 51, 100, 0));
        assert_eq!(addrs[1], Ipv4Addr::new(198, 51, 100, 1));
    }

    #[test]
    fn test_expand_cidr_slash_30() {
        let addrs = expand_cidr(Ipv4Addr::new(198, 51, 100, 0), 30);
        // /30 = 4 addresses, minus network and broadcast = 2 usable
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(addrs[1], Ipv4Addr::new(198, 51, 100, 2));
    }

    #[test]
    fn test_expand_cidr_slash_28() {
        let addrs = expand_cidr(Ipv4Addr::new(203, 0, 113, 0), 28);
        // /28 = 16 addresses, minus network and broadcast = 14 usable
        assert_eq!(addrs.len(), 14);
        assert_eq!(addrs[0], Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(addrs[13], Ipv4Addr::new(203, 0, 113, 14));
    }

    #[test]
    fn test_pool_new() {
        let cidrs = vec![(Ipv4Addr::new(198, 51, 100, 0), 30)];
        let pool = Ipv4Pool::new(&cidrs, (1024, 1026)).unwrap();
        assert_eq!(pool.addresses().len(), 2); // .1 and .2
        assert_eq!(pool.capacity_per_protocol(), 6); // 2 addrs * 3 ports
    }

    #[test]
    fn test_pool_new_empty_rejects() {
        let cidrs: Vec<(Ipv4Addr, u8)> = vec![];
        assert!(Ipv4Pool::new(&cidrs, (1024, 65535)).is_err());
    }

    #[test]
    fn test_pool_allocate_and_release() {
        let cidrs = vec![(Ipv4Addr::new(10, 0, 0, 1), 32)];
        let mut pool = Ipv4Pool::new(&cidrs, (5000, 5002)).unwrap();

        let tcp: u8 = 6;

        let a1 = pool.allocate(tcp).unwrap();
        assert_eq!(a1.0, Ipv4Addr::new(10, 0, 0, 1));
        assert!(a1.1 >= 5000 && a1.1 <= 5002);

        let a2 = pool.allocate(tcp).unwrap();
        assert_ne!(a1.1, a2.1); // different port

        let _a3 = pool.allocate(tcp).unwrap();
        // All 3 ports now allocated
        assert_eq!(pool.allocated_count(), 3);

        // Pool exhausted for TCP
        assert!(pool.allocate(tcp).is_none());

        // But UDP can still allocate (different protocol)
        let udp: u8 = 17;
        assert!(pool.allocate(udp).is_some());

        // Release and re-allocate
        pool.release(a1.0, a1.1, tcp);
        assert_eq!(pool.allocated_count(), 3); // 2 tcp + 1 udp
        assert!(pool.allocate(tcp).is_some());
    }

    #[test]
    fn test_pool_multiple_addresses() {
        let cidrs = vec![
            (Ipv4Addr::new(198, 51, 100, 1), 32),
            (Ipv4Addr::new(198, 51, 100, 2), 32),
        ];
        let mut pool = Ipv4Pool::new(&cidrs, (10000, 10001)).unwrap();
        assert_eq!(pool.capacity_per_protocol(), 4); // 2 addrs * 2 ports

        let tcp: u8 = 6;
        let mut allocated = Vec::new();
        for _ in 0..4 {
            allocated.push(pool.allocate(tcp).unwrap());
        }
        assert!(pool.allocate(tcp).is_none());

        // Verify we got both addresses
        let addrs: HashSet<_> = allocated.iter().map(|(a, _)| *a).collect();
        assert!(addrs.contains(&Ipv4Addr::new(198, 51, 100, 1)));
        assert!(addrs.contains(&Ipv4Addr::new(198, 51, 100, 2)));
    }

    #[test]
    fn test_pool_allocated_count() {
        let cidrs = vec![(Ipv4Addr::new(10, 0, 0, 1), 32)];
        let mut pool = Ipv4Pool::new(&cidrs, (1024, 1025)).unwrap();
        assert_eq!(pool.allocated_count(), 0);

        let (addr, port) = pool.allocate(6).unwrap();
        assert_eq!(pool.allocated_count(), 1);

        pool.release(addr, port, 6);
        assert_eq!(pool.allocated_count(), 0);
    }
}
