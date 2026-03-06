use std::net::Ipv6Addr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::watch;

use crate::pool::Ipv4Pool;
use crate::session::{SessionTable, SessionTimeouts};

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
}

/// The mutable NAT state protected by a mutex.
pub struct NatState {
    pub sessions: SessionTable,
    pub pool: Ipv4Pool,
}

impl SharedState {
    pub fn new(
        initial_prefix: Option<Ipv6Addr>,
        uplink_interface: String,
        egress_interface: String,
        pool: Ipv4Pool,
        max_sessions: usize,
        timeouts: SessionTimeouts,
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
            }),
        }
    }

    pub fn subscribe_prefix(&self) -> watch::Receiver<Option<Ipv6Addr>> {
        self.prefix_rx.clone()
    }

    pub fn current_prefix(&self) -> Option<Ipv6Addr> {
        *self.prefix_rx.borrow()
    }

    pub fn set_prefix(&self, prefix: Ipv6Addr) {
        log::info!("NAT64 prefix updated to {prefix}");
        let _ = self.prefix_tx.send(Some(prefix));
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
        );
        let nat = state.nat.lock().unwrap();
        assert!(nat.sessions.is_empty());
        assert_eq!(nat.pool.allocated_count(), 0);
    }
}
