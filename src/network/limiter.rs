//! Connection limiting: a global concurrent-session cap and a per-source-IP
//! concurrent-connection cap.
//!
//! Limits are enforced at TCP accept time — before the SSH handshake runs — so
//! a flood of connections from a single host (or in aggregate) is shed cheaply
//! without allocating crypto state. Each accepted connection holds a
//! [`ConnectionGuard`] for its lifetime; the slot is released automatically when
//! the guard is dropped (i.e. when the session ends, for any reason).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The global concurrent-session cap (`max_sessions`) was reached.
    GlobalLimit,
    /// The per-source-IP concurrent-connection cap (`per_ip_connections`) was
    /// reached for this peer.
    PerIpLimit,
}

impl RejectReason {
    /// A short, stable string for structured logs.
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::GlobalLimit => "global_limit",
            RejectReason::PerIpLimit => "per_ip_limit",
        }
    }
}

#[derive(Default)]
struct RegistryInner {
    per_ip: HashMap<IpAddr, usize>,
}

/// Tracks active connections and enforces the configured caps.
pub struct ConnectionRegistry {
    inner: Mutex<RegistryInner>,
    total: AtomicUsize,
    max_sessions: usize,
    per_ip: usize,
}

impl ConnectionRegistry {
    /// Build a registry enforcing `max_sessions` total and `per_ip` per source
    /// IP. Both caps must be greater than zero (validated by config loading).
    pub fn new(max_sessions: usize, per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(RegistryInner::default()),
            total: AtomicUsize::new(0),
            max_sessions,
            per_ip,
        })
    }

    /// Reserve a connection slot for `ip`. On success the returned guard must be
    /// kept alive for the duration of the connection; dropping it frees the
    /// slot. On failure the connection should be closed immediately.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionGuard, RejectReason> {
        if self.total.fetch_update(Ordering::Acquire, Ordering::Relaxed, |x| {
            if x >= self.max_sessions { None } else { Some(x + 1) }
        }).is_err() {
            return Err(RejectReason::GlobalLimit);
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let count = inner.per_ip.entry(ip).or_insert(0);
        if *count >= self.per_ip {
            self.total.fetch_sub(1, Ordering::Release);
            return Err(RejectReason::PerIpLimit);
        }
        *count += 1;
        
        Ok(ConnectionGuard {
            registry: Arc::clone(self),
            ip,
        })
    }

    /// Current number of active connections. Used by the limiter tests.
    #[allow(dead_code)]
    pub fn active(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    fn release(&self, ip: IpAddr) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = inner.per_ip.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                inner.per_ip.remove(&ip);
            }
        }
        drop(inner); // Drop mutex before updating atomic
        self.total.fetch_sub(1, Ordering::Release);
    }
}

/// RAII handle for one reserved connection slot. Releasing happens on drop.
pub struct ConnectionGuard {
    registry: Arc<ConnectionRegistry>,
    ip: IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.registry.release(self.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn enforces_per_ip_cap() {
        let reg = ConnectionRegistry::new(100, 2);
        let _a = reg.try_acquire(ip(1)).expect("first allowed");
        let _b = reg.try_acquire(ip(1)).expect("second allowed");
        assert!(matches!(
            reg.try_acquire(ip(1)),
            Err(RejectReason::PerIpLimit)
        ));
        // A different IP is unaffected.
        let _c = reg.try_acquire(ip(2)).expect("other ip allowed");
        assert_eq!(reg.active(), 3);
    }

    #[test]
    fn enforces_global_cap() {
        let reg = ConnectionRegistry::new(2, 10);
        let _a = reg.try_acquire(ip(1)).expect("first allowed");
        let _b = reg.try_acquire(ip(2)).expect("second allowed");
        assert!(matches!(
            reg.try_acquire(ip(3)),
            Err(RejectReason::GlobalLimit)
        ));
    }

    #[test]
    fn releases_slot_on_drop() {
        let reg = ConnectionRegistry::new(10, 1);
        {
            let _g = reg.try_acquire(ip(1)).expect("allowed");
            assert!(matches!(
                reg.try_acquire(ip(1)),
                Err(RejectReason::PerIpLimit)
            ));
            assert_eq!(reg.active(), 1);
        }
        // Guard dropped — the slot is free again.
        assert_eq!(reg.active(), 0);
        let _g = reg.try_acquire(ip(1)).expect("allowed after release");
        assert_eq!(reg.active(), 1);
    }

    #[test]
    fn per_ip_map_is_pruned_on_release() {
        let reg = ConnectionRegistry::new(10, 5);
        {
            let _g = reg.try_acquire(ip(1)).expect("allowed");
        }
        // After the only connection from an IP closes, its bookkeeping entry is
        // removed so the map cannot grow unbounded under scanning.
        assert_eq!(reg.inner.lock().unwrap().per_ip.len(), 0);
    }
}
