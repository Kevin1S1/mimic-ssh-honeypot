//! Per-deployment hardware identity.
//!
//! Every fact the emulated box reports about its hardware — machine id, memory
//! size, CPU model, disk size, MAC address — used to be a compile-time constant.
//! That made two things true at once: every MIMIC deployment was byte-identical
//! to every other, and (once the source is public) the constants themselves are
//! a published detection signature. `cat /etc/machine-id` was a single-command,
//! zero-false-positive check for anyone who had read this file.
//!
//! A `Persona` fixes that by deriving those values from a seed. The seed comes
//! from the sensor's own host key, so:
//!
//! - it is **stable across restarts**, the same property host-key persistence
//!   already protects — a box whose RAM size changes every boot is a worse tell
//!   than one that shares a constant with other installs; and
//! - it is **different per sensor**, because no two deployments share a host
//!   key, so two MIMIC instances no longer look like the same machine.
//!
//! Everything here is pure computation. The seed is derived in `src/network/`,
//! which is the only layer permitted to read the key material it comes from.

/// One deployment's fabricated hardware identity.
///
/// Every emulated command that reports a hardware fact reads it from here, so
/// `/proc/cpuinfo`, `lscpu`, `nproc`, `/proc/meminfo`, `free`, `df`, `dmesg`
/// and `ip addr` cannot drift apart the way independent constants would.
#[derive(Debug, Clone)]
pub struct Persona {
    /// `/etc/machine-id` — 32 lowercase hex characters.
    pub machine_id: String,
    /// `/proc/sys/kernel/random/boot_id` — a UUID, regenerated per boot on a
    /// real box and therefore per process here.
    pub boot_id: String,
    /// Total RAM in kB, as `/proc/meminfo` and `free` report it.
    pub mem_total_kb: u64,
    /// Root filesystem size in 1K blocks, as `df` reports it.
    pub disk_total_kb: u64,
    /// Online CPU count.
    pub cpu_cores: u32,
    /// The CPU this box claims to be.
    pub cpu: CpuModel,
    /// Primary interface MAC, shared by `ip addr` and `ip link`.
    pub mac: String,
    /// Primary interface IPv4 address, in CIDR-less form.
    pub ipv4: String,
    /// The /24 this box sits on, e.g. `10.0.0`.
    pub subnet: String,
}

/// A plausible cloud/VM CPU, with the fields `/proc/cpuinfo` and `lscpu` need
/// to agree on.
#[derive(Debug, Clone, Copy)]
pub struct CpuModel {
    pub name: &'static str,
    pub vendor: &'static str,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub mhz: u32,
    pub cache_kb: u32,
    pub microcode: &'static str,
    pub flags: &'static str,
    pub bugs: &'static str,
}

/// The CPUs a deployment may claim. All are real parts commonly seen backing
/// small cloud instances, so any one of them is unremarkable.
const CPUS: &[CpuModel] = &[
    CpuModel {
        name: "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
        vendor: "GenuineIntel",
        family: 6,
        model: 85,
        stepping: 7,
        mhz: 2500,
        cache_kb: 36608,
        microcode: "0x5003604",
        flags: "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq monitor ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves ida arat pku ospke",
        bugs: "spectre_v1 spectre_v2 spec_store_bypass mds swapgs taa itlb_multihit mmio_stale_data retbleed",
    },
    CpuModel {
        name: "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz",
        vendor: "GenuineIntel",
        family: 6,
        model: 79,
        stepping: 1,
        mhz: 2300,
        cache_kb: 46080,
        microcode: "0xb000038",
        flags: "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq monitor est ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm rdseed adx xsaveopt",
        bugs: "cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit mmio_stale_data retbleed",
    },
    CpuModel {
        name: "AMD EPYC 7571",
        vendor: "AuthenticAMD",
        family: 23,
        model: 1,
        stepping: 2,
        mhz: 2199,
        cache_kb: 512,
        microcode: "0x800126e",
        flags: "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a misalignsse 3dnowprefetch topoext perfctr_core ssbd ibpb vmmcall fsgsbase bmi1 avx2 smep bmi2 rdseed adx smap clflushopt sha_ni xsaveopt xsavec xgetbv1 clzero xsaveerptr arat npt nrip_save",
        bugs: "sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass retbleed smt_rsb",
    },
    CpuModel {
        name: "Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz",
        vendor: "GenuineIntel",
        family: 6,
        model: 85,
        stepping: 7,
        mhz: 3000,
        cache_kb: 36608,
        microcode: "0x5003604",
        flags: "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq monitor ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves arat pku ospke avx512_vnni md_clear flush_l1d arch_capabilities",
        bugs: "spectre_v1 spectre_v2 spec_store_bypass swapgs taa itlb_multihit mmio_stale_data retbleed",
    },
];

/// Memory sizes a small VM plausibly has, in kB. Each is slightly under the
/// round figure, the way a real `MemTotal` sits below installed RAM once the
/// kernel and firmware have taken their reservations.
const MEM_SIZES_KB: &[u64] = &[1009428, 2041208, 4025464, 8148304, 16373612];

/// Root filesystem sizes in 1K blocks, matching common cloud root volumes
/// (8/16/20/32/40/64 GB) after filesystem overhead.
const DISK_SIZES_KB: &[u64] = &[8065444, 16197524, 20263528, 32441516, 40593708, 64891496];

/// SplitMix64 — a small, well-distributed deterministic generator.
///
/// A fixed algorithm written out here rather than pulled from `rand`, because
/// the values must stay identical across `rand` releases: a dependency bump
/// that changed a sensor's memory size or MAC would be exactly the instability
/// this type exists to avoid.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n`. `n` is always a small literal here, so the modulo
    /// bias is far below anything observable.
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn hex(&mut self, chars: usize) -> String {
        let mut s = String::with_capacity(chars);
        while s.len() < chars {
            s.push_str(&format!("{:016x}", self.next()));
        }
        s.truncate(chars);
        s
    }
}

impl Persona {
    /// Derive a deployment identity from `seed`.
    ///
    /// The same seed always yields the same persona, so a sensor keeps its
    /// identity across restarts.
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = SplitMix64(seed);

        let machine_id = rng.hex(32);
        let boot_hex = rng.hex(32);
        let boot_id = format!(
            "{}-{}-{}-{}-{}",
            &boot_hex[0..8],
            &boot_hex[8..12],
            &boot_hex[12..16],
            &boot_hex[16..20],
            &boot_hex[20..32]
        );

        let cpu = CPUS[rng.below(CPUS.len() as u64) as usize];
        // Small instances are overwhelmingly 1-2 vCPU; 4 is the tail.
        let cpu_cores = match rng.below(10) {
            0..=4 => 1,
            5..=8 => 2,
            _ => 4,
        };
        let mem_total_kb = MEM_SIZES_KB[rng.below(MEM_SIZES_KB.len() as u64) as usize];
        let disk_total_kb = DISK_SIZES_KB[rng.below(DISK_SIZES_KB.len() as u64) as usize];

        // Locally-administered unicast MAC, which is what every hypervisor
        // hands a guest: low bit of the first octet clear, next bit set.
        let mac_tail = rng.hex(10);
        let first: u8 = (rng.below(64) as u8) << 2 | 0b10;
        let mac = format!(
            "{:02x}:{}:{}:{}:{}:{}",
            first,
            &mac_tail[0..2],
            &mac_tail[2..4],
            &mac_tail[4..6],
            &mac_tail[6..8],
            &mac_tail[8..10]
        );

        // An RFC 1918 address, drawn from the ranges cloud providers actually
        // hand out so the box looks like it sits behind ordinary NAT.
        let (subnet, host) = match rng.below(3) {
            0 => (
                format!("10.{}.{}", rng.below(256), rng.below(256)),
                rng.below(250) + 4,
            ),
            1 => (
                format!("172.{}.{}", rng.below(16) + 16, rng.below(256)),
                rng.below(250) + 4,
            ),
            _ => (format!("192.168.{}", rng.below(256)), rng.below(250) + 4),
        };
        let ipv4 = format!("{subnet}.{host}");

        Self {
            machine_id,
            boot_id,
            mem_total_kb,
            disk_total_kb,
            cpu_cores,
            cpu,
            mac,
            ipv4,
            subnet,
        }
    }

    /// The persona used by tests and by any caller that has no seed.
    ///
    /// Production always derives one from the host key; this exists so unit
    /// tests get stable, assertable values.
    pub fn sample() -> Self {
        Self::from_seed(0x5EED_1234_5678_9ABC)
    }

    /// Bogomips as the kernel reports them: twice the clock, to two decimals.
    pub fn bogomips(&self) -> String {
        format!("{}.00", self.cpu.mhz * 2)
    }

    /// The broadcast address for this box's /24.
    pub fn broadcast(&self) -> String {
        format!("{}.255", self.subnet)
    }

    /// The default gateway for this box's /24, which is `.1` by convention.
    pub fn gateway(&self) -> String {
        format!("{}.1", self.subnet)
    }
}

impl Default for Persona {
    fn default() -> Self {
        Self::sample()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_always_yields_the_same_persona() {
        let a = Persona::from_seed(42);
        let b = Persona::from_seed(42);
        assert_eq!(a.machine_id, b.machine_id);
        assert_eq!(a.mem_total_kb, b.mem_total_kb);
        assert_eq!(a.mac, b.mac);
        assert_eq!(a.ipv4, b.ipv4);
        assert_eq!(a.cpu.name, b.cpu.name);
    }

    #[test]
    fn different_seeds_yield_different_identities() {
        // The identity fields must actually vary: a persona that collapses to
        // one value for every sensor is the constant it replaced.
        let ids: std::collections::BTreeSet<String> =
            (0..64).map(|s| Persona::from_seed(s).machine_id).collect();
        assert_eq!(ids.len(), 64, "machine ids must be distinct");

        let macs: std::collections::BTreeSet<String> =
            (0..64).map(|s| Persona::from_seed(s).mac).collect();
        assert_eq!(macs.len(), 64, "MACs must be distinct");
    }

    #[test]
    fn machine_id_is_32_lowercase_hex() {
        for seed in 0..32 {
            let id = Persona::from_seed(seed).machine_id;
            assert_eq!(id.len(), 32);
            assert!(id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        }
    }

    #[test]
    fn boot_id_is_uuid_shaped() {
        let boot = Persona::from_seed(7).boot_id;
        let parts: Vec<&str> = boot.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(boot.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    #[test]
    fn mac_is_locally_administered_unicast() {
        // Every hypervisor-assigned MAC has the locally-administered bit set
        // and the multicast bit clear; a guest with a vendor OUI would be odd.
        for seed in 0..32 {
            let mac = Persona::from_seed(seed).mac;
            let first = u8::from_str_radix(&mac[0..2], 16).expect("hex octet");
            assert_eq!(first & 0b11, 0b10, "mac={mac}");
        }
    }

    #[test]
    fn addresses_are_rfc1918() {
        for seed in 0..64 {
            let p = Persona::from_seed(seed);
            let octets: Vec<u32> = p
                .ipv4
                .split('.')
                .map(|o| o.parse().expect("octet"))
                .collect();
            assert_eq!(octets.len(), 4, "ipv4={}", p.ipv4);
            let private = octets[0] == 10
                || (octets[0] == 172 && (16..32).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168);
            assert!(private, "ipv4={} is not RFC1918", p.ipv4);
            // The host part must not collide with the gateway `.1`.
            assert!(octets[3] >= 4, "ipv4={}", p.ipv4);
        }
    }
}
