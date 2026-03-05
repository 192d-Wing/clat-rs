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
        log::info!("CLAT prefix updated to {prefix}");
        // send() only fails if all receivers are dropped, which won't happen.
        let _ = self.prefix_tx.send(Some(prefix));
    }

    pub fn is_translating(&self) -> bool {
        self.translating.load(Ordering::Relaxed)
    }

    pub fn set_translating(&self, val: bool) {
        self.translating.store(val, Ordering::Relaxed);
    }
}
