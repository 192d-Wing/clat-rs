use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::pool::Ipv4Pool;

/// Protocol numbers used as keys.
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;

/// Forward-direction session key: identifies an IPv6 flow entering the PLAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub src_v6: Ipv6Addr,
    pub dst_v6: Ipv6Addr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Reverse-direction lookup key: identifies return IPv4 traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReverseKey {
    pool_addr: Ipv4Addr,
    mapped_port: u16,
    protocol: u8,
}

/// The NAT binding allocated for a session.
#[derive(Debug, Clone)]
pub struct NatBinding {
    pub pool_addr: Ipv4Addr,
    pub mapped_port: u16,
    pub created: Instant,
    pub last_seen: Instant,
}

/// Timeout configuration for different protocols.
#[derive(Debug, Clone)]
pub struct SessionTimeouts {
    pub tcp: Duration,
    pub udp: Duration,
    pub icmp: Duration,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            tcp: Duration::from_secs(7200), // 2 hours
            udp: Duration::from_secs(300),  // 5 minutes
            icmp: Duration::from_secs(60),  // 1 minute
        }
    }
}

impl SessionTimeouts {
    fn timeout_for(&self, protocol: u8) -> Duration {
        match protocol {
            PROTO_TCP => self.tcp,
            PROTO_UDP => self.udp,
            PROTO_ICMP => self.icmp,
            _ => self.udp, // default to UDP timeout for unknown protocols
        }
    }
}

/// Snapshot of a session for reporting (e.g. gRPC ListSessions).
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub key: SessionKey,
    pub binding: NatBinding,
}

/// Stateful NAT64 session table.
///
/// Maps IPv6 flows to allocated IPv4 (address, port) bindings,
/// and provides reverse lookup for return traffic.
pub struct SessionTable {
    /// Forward: IPv6 5-tuple -> NAT binding
    forward: HashMap<SessionKey, NatBinding>,
    /// Reverse: (pool_addr, mapped_port, proto) -> forward key
    reverse: HashMap<ReverseKey, SessionKey>,
    /// Maximum number of sessions allowed.
    max_sessions: usize,
    /// Timeout configuration.
    timeouts: SessionTimeouts,
}

/// Result of looking up or creating a session.
pub enum LookupResult {
    /// An existing session was found and refreshed.
    Existing(NatBinding),
    /// A new session was created.
    Created(NatBinding),
    /// The pool is exhausted or max sessions reached.
    Exhausted,
}

impl SessionTable {
    pub fn new(max_sessions: usize, timeouts: SessionTimeouts) -> Self {
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            max_sessions,
            timeouts,
        }
    }

    /// Look up an existing session without creating a new one.
    ///
    /// If the session exists, its `last_seen` timestamp is refreshed.
    pub fn lookup(&mut self, key: &SessionKey) -> Option<NatBinding> {
        let binding = self.forward.get_mut(key)?;
        binding.last_seen = Instant::now();
        Some(binding.clone())
    }

    /// Look up an existing session or create a new one.
    ///
    /// If the session exists, its `last_seen` timestamp is refreshed.
    /// If it doesn't exist, a new binding is allocated from `pool`.
    pub fn lookup_or_create(&mut self, key: SessionKey, pool: &mut Ipv4Pool) -> LookupResult {
        if let Some(binding) = self.forward.get_mut(&key) {
            binding.last_seen = Instant::now();
            return LookupResult::Existing(binding.clone());
        }

        if self.forward.len() >= self.max_sessions {
            return LookupResult::Exhausted;
        }

        let (pool_addr, mapped_port) = match pool.allocate(key.protocol) {
            Some(pair) => pair,
            None => return LookupResult::Exhausted,
        };

        let now = Instant::now();
        let binding = NatBinding {
            pool_addr,
            mapped_port,
            created: now,
            last_seen: now,
        };

        let rev_key = ReverseKey {
            pool_addr,
            mapped_port,
            protocol: key.protocol,
        };

        self.forward.insert(key, binding.clone());
        self.reverse.insert(rev_key, key);

        LookupResult::Created(binding)
    }

    /// Reverse lookup: find the original IPv6 session key from return IPv4 traffic.
    ///
    /// Refreshes `last_seen` on match.
    pub fn reverse_lookup(
        &mut self,
        pool_addr: Ipv4Addr,
        mapped_port: u16,
        protocol: u8,
    ) -> Option<(SessionKey, NatBinding)> {
        let rev_key = ReverseKey {
            pool_addr,
            mapped_port,
            protocol,
        };
        let fwd_key = self.reverse.get(&rev_key).copied()?;
        let binding = self.forward.get_mut(&fwd_key)?;
        binding.last_seen = Instant::now();
        Some((fwd_key, binding.clone()))
    }

    /// Remove expired sessions and release their pool bindings.
    ///
    /// Returns the number of sessions reaped.
    pub fn reap_expired(&mut self, pool: &mut Ipv4Pool) -> usize {
        let now = Instant::now();
        let mut expired_keys = Vec::new();

        for (key, binding) in &self.forward {
            let timeout = self.timeouts.timeout_for(key.protocol);
            if now.duration_since(binding.last_seen) >= timeout {
                expired_keys.push(*key);
            }
        }

        let count = expired_keys.len();
        for key in expired_keys {
            self.remove_session(&key, pool);
        }
        count
    }

    /// Flush all sessions, releasing all pool bindings.
    ///
    /// Returns the number of sessions flushed.
    pub fn flush_all(&mut self, pool: &mut Ipv4Pool) -> usize {
        let keys: Vec<SessionKey> = self.forward.keys().copied().collect();
        let count = keys.len();
        for key in keys {
            self.remove_session(&key, pool);
        }
        count
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// Whether the table is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Check if a session exists for the given key.
    pub fn has_session(&self, key: &SessionKey) -> bool {
        self.forward.contains_key(key)
    }

    /// Collect session info for status reporting.
    pub fn list_sessions(&self, limit: usize) -> Vec<SessionInfo> {
        let iter = self.forward.iter();
        let iter: Box<dyn Iterator<Item = _>> = if limit > 0 {
            Box::new(iter.take(limit))
        } else {
            Box::new(iter)
        };
        iter.map(|(key, binding)| SessionInfo {
            key: *key,
            binding: binding.clone(),
        })
        .collect()
    }

    fn remove_session(&mut self, key: &SessionKey, pool: &mut Ipv4Pool) {
        if let Some(binding) = self.forward.remove(key) {
            let rev_key = ReverseKey {
                pool_addr: binding.pool_addr,
                mapped_port: binding.mapped_port,
                protocol: key.protocol,
            };
            self.reverse.remove(&rev_key);
            pool.release(binding.pool_addr, binding.mapped_port, key.protocol);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pool() -> Ipv4Pool {
        let cidrs = vec![(Ipv4Addr::new(198, 51, 100, 1), 32)];
        Ipv4Pool::new(&cidrs, (10000, 10100)).unwrap()
    }

    fn tcp_key(src_port: u16) -> SessionKey {
        SessionKey {
            src_v6: "2001:db8::1".parse().unwrap(),
            dst_v6: "64:ff9b::c633:6401".parse().unwrap(),
            protocol: PROTO_TCP,
            src_port,
            dst_port: 80,
        }
    }

    #[test]
    fn test_create_session() {
        let mut pool = test_pool();
        let mut table = SessionTable::new(1000, SessionTimeouts::default());

        let key = tcp_key(12345);
        match table.lookup_or_create(key, &mut pool) {
            LookupResult::Created(binding) => {
                assert_eq!(binding.pool_addr, Ipv4Addr::new(198, 51, 100, 1));
                assert!(binding.mapped_port >= 10000 && binding.mapped_port <= 10100);
            }
            _ => panic!("expected Created"),
        }
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_lookup_existing() {
        let mut pool = test_pool();
        let mut table = SessionTable::new(1000, SessionTimeouts::default());

        let key = tcp_key(12345);
        let binding1 = match table.lookup_or_create(key, &mut pool) {
            LookupResult::Created(b) => b,
            _ => panic!("expected Created"),
        };

        // Second lookup should find existing
        let binding2 = match table.lookup_or_create(key, &mut pool) {
            LookupResult::Existing(b) => b,
            _ => panic!("expected Existing"),
        };

        assert_eq!(binding1.pool_addr, binding2.pool_addr);
        assert_eq!(binding1.mapped_port, binding2.mapped_port);
        assert_eq!(table.len(), 1); // still just one session
    }

    #[test]
    fn test_reverse_lookup() {
        let mut pool = test_pool();
        let mut table = SessionTable::new(1000, SessionTimeouts::default());

        let key = tcp_key(12345);
        let binding = match table.lookup_or_create(key, &mut pool) {
            LookupResult::Created(b) => b,
            _ => panic!("expected Created"),
        };

        let (found_key, found_binding) = table
            .reverse_lookup(binding.pool_addr, binding.mapped_port, PROTO_TCP)
            .expect("reverse lookup should succeed");

        assert_eq!(found_key, key);
        assert_eq!(found_binding.pool_addr, binding.pool_addr);
    }

    #[test]
    fn test_reverse_lookup_miss() {
        let mut pool = test_pool();
        let mut table = SessionTable::new(1000, SessionTimeouts::default());

        // No sessions — reverse lookup should fail
        assert!(
            table
                .reverse_lookup(Ipv4Addr::new(198, 51, 100, 1), 10000, PROTO_TCP)
                .is_none()
        );

        // Create a TCP session
        let key = tcp_key(12345);
        let binding = match table.lookup_or_create(key, &mut pool) {
            LookupResult::Created(b) => b,
            _ => panic!("expected Created"),
        };

        // Wrong protocol should miss
        assert!(
            table
                .reverse_lookup(binding.pool_addr, binding.mapped_port, PROTO_UDP)
                .is_none()
        );

        // Wrong port should miss
        assert!(
            table
                .reverse_lookup(binding.pool_addr, binding.mapped_port + 1, PROTO_TCP)
                .is_none()
        );
    }

    #[test]
    fn test_max_sessions_exhausted() {
        let mut pool = test_pool();
        let mut table = SessionTable::new(2, SessionTimeouts::default());

        let k1 = tcp_key(1000);
        let k2 = tcp_key(1001);
        let k3 = tcp_key(1002);

        assert!(matches!(
            table.lookup_or_create(k1, &mut pool),
            LookupResult::Created(_)
        ));
        assert!(matches!(
            table.lookup_or_create(k2, &mut pool),
            LookupResult::Created(_)
        ));
        // Third should be exhausted (max_sessions = 2)
        assert!(matches!(
            table.lookup_or_create(k3, &mut pool),
            LookupResult::Exhausted
        ));
    }

    #[test]
    fn test_flush_all() {
        let mut pool = test_pool();
        let mut table = SessionTable::new(1000, SessionTimeouts::default());

        for port in 1000..1010 {
            table.lookup_or_create(tcp_key(port), &mut pool);
        }
        assert_eq!(table.len(), 10);
        assert_eq!(pool.allocated_count(), 10);

        let flushed = table.flush_all(&mut pool);
        assert_eq!(flushed, 10);
        assert!(table.is_empty());
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn test_reap_expired() {
        let mut pool = test_pool();
        let timeouts = SessionTimeouts {
            tcp: Duration::from_millis(50),
            udp: Duration::from_millis(10),
            icmp: Duration::from_millis(10),
        };
        let mut table = SessionTable::new(1000, timeouts);

        let key = tcp_key(12345);
        table.lookup_or_create(key, &mut pool);
        assert_eq!(table.len(), 1);

        // Not expired yet
        assert_eq!(table.reap_expired(&mut pool), 0);
        assert_eq!(table.len(), 1);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(table.reap_expired(&mut pool), 1);
        assert!(table.is_empty());
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn test_refresh_prevents_expiry() {
        let mut pool = test_pool();
        let timeouts = SessionTimeouts {
            tcp: Duration::from_millis(80),
            udp: Duration::from_millis(10),
            icmp: Duration::from_millis(10),
        };
        let mut table = SessionTable::new(1000, timeouts);

        let key = tcp_key(12345);
        table.lookup_or_create(key, &mut pool);

        // Wait 50ms then refresh via lookup
        std::thread::sleep(Duration::from_millis(50));
        assert!(matches!(
            table.lookup_or_create(key, &mut pool),
            LookupResult::Existing(_)
        ));

        // Wait another 50ms — 100ms total but last_seen was refreshed at 50ms
        std::thread::sleep(Duration::from_millis(50));
        // Should still be alive (50ms since refresh, timeout is 80ms)
        assert_eq!(table.reap_expired(&mut pool), 0);
        assert_eq!(table.len(), 1);

        // Wait until truly expired
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(table.reap_expired(&mut pool), 1);
    }

    #[test]
    fn test_list_sessions() {
        let mut pool = test_pool();
        let mut table = SessionTable::new(1000, SessionTimeouts::default());

        for port in 1000..1005 {
            table.lookup_or_create(tcp_key(port), &mut pool);
        }

        let all = table.list_sessions(0);
        assert_eq!(all.len(), 5);

        let limited = table.list_sessions(3);
        assert_eq!(limited.len(), 3);
    }

    #[test]
    fn test_different_protocols_independent() {
        let mut pool = test_pool();
        let mut table = SessionTable::new(1000, SessionTimeouts::default());

        let tcp_key = SessionKey {
            src_v6: "2001:db8::1".parse().unwrap(),
            dst_v6: "64:ff9b::c633:6401".parse().unwrap(),
            protocol: PROTO_TCP,
            src_port: 5000,
            dst_port: 80,
        };
        let udp_key = SessionKey {
            protocol: PROTO_UDP,
            ..tcp_key
        };

        let tcp_b = match table.lookup_or_create(tcp_key, &mut pool) {
            LookupResult::Created(b) => b,
            _ => panic!("expected Created"),
        };
        let udp_b = match table.lookup_or_create(udp_key, &mut pool) {
            LookupResult::Created(b) => b,
            _ => panic!("expected Created"),
        };

        assert_eq!(table.len(), 2);

        // Reverse lookups should find their respective sessions
        let (fk, _) = table
            .reverse_lookup(tcp_b.pool_addr, tcp_b.mapped_port, PROTO_TCP)
            .unwrap();
        assert_eq!(fk.protocol, PROTO_TCP);

        let (fk, _) = table
            .reverse_lookup(udp_b.pool_addr, udp_b.mapped_port, PROTO_UDP)
            .unwrap();
        assert_eq!(fk.protocol, PROTO_UDP);
    }
}
