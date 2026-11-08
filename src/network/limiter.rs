use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    GlobalLimit,

    PerIpLimit,
}

impl RejectReason {
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

pub struct ConnectionRegistry {
    inner: Mutex<RegistryInner>,
    total: AtomicUsize,
    max_sessions: usize,
    per_ip: usize,
}

impl ConnectionRegistry {
    pub fn new(max_sessions: usize, per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(RegistryInner::default()),
            total: AtomicUsize::new(0),
            max_sessions,
            per_ip,
        })
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionGuard, RejectReason> {
        if self
            .total
            .fetch_update(Ordering::Acquire, Ordering::Relaxed, |x| {
                if x >= self.max_sessions {
                    None
                } else {
                    Some(x + 1)
                }
            })
            .is_err()
        {
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
        drop(inner);
        self.total.fetch_sub(1, Ordering::Release);
    }
}

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

        assert_eq!(reg.inner.lock().unwrap().per_ip.len(), 0);
    }
}
