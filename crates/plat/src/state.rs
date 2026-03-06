use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::pool::Ipv4Pool;
use crate::session::{SessionTable, SessionTimeouts};

/// Atomic counters for packet drop/translation metrics.
pub struct PacketMetrics {
    pub v6_to_v4_translated: AtomicU64,
    pub v4_to_v6_translated: AtomicU64,
    pub dropped_bogon_v4: AtomicU64,
    pub dropped_reserved_v6: AtomicU64,
    pub dropped_rate_limited: AtomicU64,
    pub dropped_session_exhausted: AtomicU64,
    pub dropped_prefix_mismatch: AtomicU64,
    pub dropped_invalid_packet: AtomicU64,
}

impl PacketMetrics {
    fn new() -> Self {
        Self {
            v6_to_v4_translated: AtomicU64::new(0),
            v4_to_v6_translated: AtomicU64::new(0),
            dropped_bogon_v4: AtomicU64::new(0),
            dropped_reserved_v6: AtomicU64::new(0),
            dropped_rate_limited: AtomicU64::new(0),
            dropped_session_exhausted: AtomicU64::new(0),
            dropped_prefix_mismatch: AtomicU64::new(0),
            dropped_invalid_packet: AtomicU64::new(0),
        }
    }
}

/// Shared PLAT daemon state, passed to both the gRPC server and the packet loop.
pub struct SharedState {
    prefix_tx: watch::Sender<Option<Ipv6Addr>>,
    prefix_rx: watch::Receiver<Option<Ipv6Addr>>,
    pub uplink_interface: String,
    pub egress_interface: String,
    translating: AtomicBool,
    pub total_translations: AtomicU64,
    /// Session table and pool are behind a single Mutex to avoid lock ordering issues.
    pub nat: Mutex<NatState>,
    /// Security policy for packet validation.
    pub security: SecurityPolicy,
    /// Packet metrics counters.
    pub metrics: PacketMetrics,
}

/// The mutable NAT state protected by a mutex.
pub struct NatState {
    pub sessions: SessionTable,
    pub pool: Ipv4Pool,
    pub rate_limiter: SourceRateLimiter,
}

/// Per-source fixed-window rate limiter for session creation.
pub struct SourceRateLimiter {
    /// (window_start, count) per source IPv6 address.
    counters: HashMap<Ipv6Addr, (Instant, u32)>,
    /// Max new sessions per source per window.
    max_per_window: u32,
    /// Window duration.
    window: Duration,
}

impl SourceRateLimiter {
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            counters: HashMap::new(),
            max_per_window,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check whether a source is allowed to create a new session.
    /// Returns true if allowed (and increments the counter), false if rate-limited.
    pub fn check_and_increment(&mut self, source: Ipv6Addr) -> bool {
        let now = Instant::now();
        let entry = self.counters.entry(source).or_insert((now, 0));

        // Reset window if expired
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }

        if entry.1 >= self.max_per_window {
            return false;
        }

        entry.1 += 1;
        true
    }

    /// Remove stale entries (called during reaping).
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let window = self.window;
        self.counters
            .retain(|_, (start, _)| now.duration_since(*start) < window * 2);
    }
}

/// Bundled security policy settings.
pub struct SecurityPolicy {
    pub reject_bogon_v4_dst: bool,
    pub reject_reserved_v6_src: bool,
}

/// Check if an IPv6 source address is reserved/invalid for NAT64 traffic.
pub fn is_reserved_v6_source(addr: Ipv6Addr) -> bool {
    addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() || is_v4_mapped_v6(addr)
}

/// Check if an IPv4 address is a bogon (should not appear as NAT64 destination).
pub fn is_bogon_v4(addr: Ipv4Addr) -> bool {
    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_broadcast()
        || addr.is_multicast()
        || is_private_v4(addr)
        || is_link_local_v4(addr)
}

fn is_v4_mapped_v6(addr: Ipv6Addr) -> bool {
    let seg = addr.segments();
    seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0xFFFF
}

fn is_private_v4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
}

fn is_link_local_v4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 169 && octets[1] == 254
}

impl SharedState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initial_prefix: Option<Ipv6Addr>,
        uplink_interface: String,
        egress_interface: String,
        pool: Ipv4Pool,
        max_sessions: usize,
        timeouts: SessionTimeouts,
        rate_limiter: SourceRateLimiter,
        security: SecurityPolicy,
    ) -> Self {
        let (prefix_tx, prefix_rx) = watch::channel(initial_prefix);
        Self {
            prefix_tx,
            prefix_rx,
            uplink_interface,
            egress_interface,
            translating: AtomicBool::new(false),
            total_translations: AtomicU64::new(0),
            nat: Mutex::new(NatState {
                sessions: SessionTable::new(max_sessions, timeouts),
                pool,
                rate_limiter,
            }),
            security,
            metrics: PacketMetrics::new(),
        }
    }

    pub fn subscribe_prefix(&self) -> watch::Receiver<Option<Ipv6Addr>> {
        self.prefix_rx.clone()
    }

    pub fn current_prefix(&self) -> Option<Ipv6Addr> {
        *self.prefix_rx.borrow()
    }

    pub fn set_prefix(&self, prefix: Ipv6Addr) {
        let old = self.current_prefix();
        let _ = self.prefix_tx.send(Some(prefix));
        tracing::info!(
            event_type = "config",
            action = "prefix_update",
            new_prefix = %prefix,
            previous_prefix = %old.map(|p| p.to_string()).unwrap_or_else(|| "none".into()),
            "NAT64 prefix updated"
        );
    }

    pub fn is_translating(&self) -> bool {
        self.translating.load(Ordering::Relaxed)
    }

    pub fn set_translating(&self, val: bool) {
        self.translating.store(val, Ordering::Relaxed);
    }

    pub fn increment_translations(&self) {
        self.total_translations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn translation_count(&self) -> u64 {
        self.total_translations.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_pool() -> Ipv4Pool {
        let cidrs = vec![(Ipv4Addr::new(198, 51, 100, 1), 32)];
        Ipv4Pool::new(&cidrs, (1024, 65535)).unwrap()
    }

    fn default_rate_limiter() -> SourceRateLimiter {
        SourceRateLimiter::new(100, 1)
    }

    fn default_security() -> SecurityPolicy {
        SecurityPolicy {
            reject_bogon_v4_dst: true,
            reject_reserved_v6_src: true,
        }
    }

    #[test]
    fn test_new_with_prefix() {
        let prefix: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = SharedState::new(
            Some(prefix),
            "eth0".into(),
            "eth1".into(),
            test_pool(),
            1000,
            SessionTimeouts::default(),
            default_rate_limiter(),
            default_security(),
        );
        assert_eq!(state.current_prefix(), Some(prefix));
        assert!(!state.is_translating());
        assert_eq!(state.translation_count(), 0);
    }

    #[test]
    fn test_set_prefix() {
        let state = SharedState::new(
            None,
            "eth0".into(),
            "eth0".into(),
            test_pool(),
            1000,
            SessionTimeouts::default(),
            default_rate_limiter(),
            default_security(),
        );
        assert_eq!(state.current_prefix(), None);

        let prefix: Ipv6Addr = "64:ff9b::".parse().unwrap();
        state.set_prefix(prefix);
        assert_eq!(state.current_prefix(), Some(prefix));
    }

    #[test]
    fn test_translation_counter() {
        let state = SharedState::new(
            None,
            "eth0".into(),
            "eth0".into(),
            test_pool(),
            1000,
            SessionTimeouts::default(),
            default_rate_limiter(),
            default_security(),
        );
        state.increment_translations();
        state.increment_translations();
        assert_eq!(state.translation_count(), 2);
    }

    #[test]
    fn test_nat_state_accessible() {
        let state = SharedState::new(
            None,
            "eth0".into(),
            "eth0".into(),
            test_pool(),
            1000,
            SessionTimeouts::default(),
            default_rate_limiter(),
            default_security(),
        );
        let nat = state.nat.lock().unwrap();
        assert!(nat.sessions.is_empty());
        assert_eq!(nat.pool.allocated_count(), 0);
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut rl = SourceRateLimiter::new(3, 1);
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(rl.check_and_increment(src));
        assert!(rl.check_and_increment(src));
        assert!(rl.check_and_increment(src));
        assert!(!rl.check_and_increment(src)); // 4th blocked
    }

    #[test]
    fn test_rate_limiter_independent_sources() {
        let mut rl = SourceRateLimiter::new(1, 1);
        let src1: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let src2: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert!(rl.check_and_increment(src1));
        assert!(!rl.check_and_increment(src1));
        assert!(rl.check_and_increment(src2)); // different source OK
    }

    #[test]
    fn test_rate_limiter_window_reset() {
        let mut rl = SourceRateLimiter::new(1, 0); // 0-second window => always expired
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(rl.check_and_increment(src));
        // Window is 0 seconds so next check should reset
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(rl.check_and_increment(src));
    }

    #[test]
    fn test_reserved_v6_source() {
        assert!(is_reserved_v6_source("::1".parse().unwrap())); // loopback
        assert!(is_reserved_v6_source("::".parse().unwrap())); // unspecified
        assert!(is_reserved_v6_source("ff02::1".parse().unwrap())); // multicast
        assert!(is_reserved_v6_source("::ffff:192.168.1.1".parse().unwrap())); // v4-mapped
        assert!(!is_reserved_v6_source("2001:db8::1".parse().unwrap())); // normal
    }

    #[test]
    fn test_bogon_v4() {
        assert!(is_bogon_v4(Ipv4Addr::new(127, 0, 0, 1))); // loopback
        assert!(is_bogon_v4(Ipv4Addr::new(10, 0, 0, 1))); // RFC 1918
        assert!(is_bogon_v4(Ipv4Addr::new(172, 16, 0, 1))); // RFC 1918
        assert!(is_bogon_v4(Ipv4Addr::new(192, 168, 1, 1))); // RFC 1918
        assert!(is_bogon_v4(Ipv4Addr::new(169, 254, 1, 1))); // link-local
        assert!(is_bogon_v4(Ipv4Addr::new(224, 0, 0, 1))); // multicast
        assert!(is_bogon_v4(Ipv4Addr::new(255, 255, 255, 255))); // broadcast
        assert!(is_bogon_v4(Ipv4Addr::new(0, 0, 0, 0))); // unspecified
        assert!(!is_bogon_v4(Ipv4Addr::new(198, 51, 100, 1))); // normal
        assert!(!is_bogon_v4(Ipv4Addr::new(8, 8, 8, 8))); // normal
    }
}
