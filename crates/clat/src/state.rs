use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;

/// Shared CLAT daemon state, passed to both the gRPC server and the packet loop.
pub struct SharedState {
    prefix_tx: watch::Sender<Option<Ipv6Addr>>,
    prefix_rx: watch::Receiver<Option<Ipv6Addr>>,
    pub plat_prefix: Ipv6Addr,
    pub uplink_interface: String,
    translating: AtomicBool,
}

impl SharedState {
    pub fn new(
        initial_prefix: Option<Ipv6Addr>,
        plat_prefix: Ipv6Addr,
        uplink_interface: String,
    ) -> Self {
        let (prefix_tx, prefix_rx) = watch::channel(initial_prefix);
        Self {
            prefix_tx,
            prefix_rx,
            plat_prefix,
            uplink_interface,
            translating: AtomicBool::new(false),
        }
    }

    /// Get a new watch receiver for prefix changes.
    pub fn subscribe_prefix(&self) -> watch::Receiver<Option<Ipv6Addr>> {
        self.prefix_rx.clone()
    }

    /// Get the current CLAT prefix.
    pub fn current_prefix(&self) -> Option<Ipv6Addr> {
        *self.prefix_rx.borrow()
    }

    /// Update the CLAT prefix.
    pub fn set_prefix(&self, prefix: Ipv6Addr) {
        tracing::info!("CLAT prefix updated to {prefix}");
        // send() only fails if all receivers are dropped, which won't happen.
        let _ = self.prefix_tx.send(Some(prefix));
    }

    pub fn is_translating(&self) -> bool {
        self.translating.load(Ordering::Acquire)
    }

    pub fn set_translating(&self, val: bool) {
        self.translating.store(val, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_initial_prefix() {
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let plat: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = SharedState::new(Some(prefix), plat, "eth0".to_string());
        assert_eq!(state.current_prefix(), Some(prefix));
        assert_eq!(state.plat_prefix, plat);
        assert!(!state.is_translating());
    }

    #[test]
    fn test_new_without_initial_prefix() {
        let plat: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = SharedState::new(None, plat, "eth0".to_string());
        assert_eq!(state.current_prefix(), None);
    }

    #[test]
    fn test_set_prefix() {
        let plat: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = SharedState::new(None, plat, "eth0".to_string());
        assert_eq!(state.current_prefix(), None);

        let new_prefix: Ipv6Addr = "2001:db8:aaaa::".parse().unwrap();
        state.set_prefix(new_prefix);
        assert_eq!(state.current_prefix(), Some(new_prefix));
    }

    #[test]
    fn test_subscribe_prefix() {
        let plat: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = SharedState::new(None, plat, "eth0".to_string());
        let rx = state.subscribe_prefix();
        assert_eq!(*rx.borrow(), None);

        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        state.set_prefix(prefix);
        assert_eq!(*rx.borrow(), Some(prefix));
    }

    #[test]
    fn test_translating_flag() {
        let plat: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = SharedState::new(None, plat, "eth0".to_string());
        assert!(!state.is_translating());

        state.set_translating(true);
        assert!(state.is_translating());

        state.set_translating(false);
        assert!(!state.is_translating());
    }
}
