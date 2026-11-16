use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

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

pub struct ConnectionRegistry {
    connections_per_ip: Mutex<HashMap<IpAddr, usize>>,
    active_total: AtomicUsize,
    max_sessions: usize,
    max_per_ip: usize,
}

impl ConnectionRegistry {
    pub fn new(max_sessions: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            connections_per_ip: Mutex::new(HashMap::new()),
            active_total: AtomicUsize::new(0),
            max_sessions,
            max_per_ip,
        })
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionGuard, RejectReason> {
        // Key the per-source cap on the /64 for IPv6: a single attacker is
        // routinely assigned a whole /64 (or larger), so keying on the exact
        // address would let them evade `per_ip_connections` by rotating within
        // their block. IPv4 is keyed on the full address.
        let ip = per_source_key(ip);
        if !self.try_reserve_global_slot() {
            return Err(RejectReason::GlobalLimit);
        }

        let mut connections_per_ip = self.lock_connections_per_ip();
        let count = connections_per_ip.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            self.release_global_slot();
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
        self.active_total.load(Ordering::Relaxed)
    }

    fn try_reserve_global_slot(&self) -> bool {
        self.active_total
            .fetch_update(Ordering::Acquire, Ordering::Relaxed, |x| {
                if x >= self.max_sessions {
                    None
                } else {
                    Some(x + 1)
                }
            })
            .is_ok()
    }

    fn release_global_slot(&self) {
        self.active_total.fetch_sub(1, Ordering::Release);
    }

    fn lock_connections_per_ip(&self) -> MutexGuard<'_, HashMap<IpAddr, usize>> {
        self.connections_per_ip
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn release(&self, ip: IpAddr) {
        let mut connections_per_ip = self.lock_connections_per_ip();
        if let Some(count) = connections_per_ip.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                connections_per_ip.remove(&ip);
            }
        }
        drop(connections_per_ip);
        self.release_global_slot();
    }
}

/// Normalise a peer address to the key used for per-source rate limiting.
/// IPv6 addresses collapse to their /64 prefix; IPv4 addresses are unchanged.
///
/// An IPv4 peer reaching a dual-stack listener arrives as `::ffff:a.b.c.d`.
/// Those are unwrapped first: they all sit in one /64, so masking them would
/// put every IPv4 client under a single shared cap.
fn per_source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        v4 => v4,
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

        assert_eq!(reg.connections_per_ip.lock().unwrap().len(), 0);
    }

    fn v6(text: &str) -> IpAddr {
        text.parse().expect("valid address")
    }

    #[test]
    fn ipv6_addresses_in_one_slash_64_share_the_cap() {
        let reg = ConnectionRegistry::new(100, 2);
        let _a = reg.try_acquire(v6("2001:db8:1:2::1")).expect("first");
        let _b = reg.try_acquire(v6("2001:db8:1:2:ffff::9")).expect("second");
        assert!(matches!(
            reg.try_acquire(v6("2001:db8:1:2:a:b:c:d")),
            Err(RejectReason::PerIpLimit)
        ));

        let _c = reg
            .try_acquire(v6("2001:db8:1:3::1"))
            .expect("a neighbouring /64 has its own cap");
    }

    #[test]
    fn ipv4_mapped_peers_are_keyed_on_their_ipv4_address() {
        let reg = ConnectionRegistry::new(100, 1);
        let _a = reg.try_acquire(v6("::ffff:10.0.0.1")).expect("first");
        let _b = reg
            .try_acquire(v6("::ffff:10.0.0.2"))
            .expect("a different IPv4 client is not capped by the first");
        assert!(matches!(
            reg.try_acquire(v6("::ffff:10.0.0.1")),
            Err(RejectReason::PerIpLimit)
        ));
        assert!(
            matches!(reg.try_acquire(ip(1)), Err(RejectReason::PerIpLimit)),
            "the mapped and plain forms of one address share a cap"
        );
    }

    #[test]
    fn a_slash_64_slot_is_released_on_drop() {
        let reg = ConnectionRegistry::new(10, 1);
        {
            let _g = reg.try_acquire(v6("2001:db8::1")).expect("allowed");
        }
        assert_eq!(reg.connections_per_ip.lock().unwrap().len(), 0);
        let _g = reg.try_acquire(v6("2001:db8::2")).expect("allowed again");
    }
}
