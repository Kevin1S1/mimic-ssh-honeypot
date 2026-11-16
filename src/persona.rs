#[derive(Debug, Clone)]
pub struct Persona {
    pub machine_id: String,

    pub boot_id: String,

    pub mem_total_kb: u64,

    pub disk_total_kb: u64,

    pub cpu_cores: u32,

    pub cpu: CpuModel,

    pub mac: String,

    pub ipv4: String,

    pub subnet: String,

    pub host_keys: Vec<(String, String)>,

    pub uptime_at_start_secs: i64,

    pub pid_base: u32,
}

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

const SPLITMIX_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
const SPLITMIX_MUL_1: u64 = 0xBF58_476D_1CE4_E5B9;
const SPLITMIX_MUL_2: u64 = 0x94D0_49BB_1331_11EB;

const SAMPLE_SEED: u64 = 0x5EED_1234_5678_9ABC;

const ID_HEX_LEN: usize = 32;
const MAC_TAIL_HEX_LEN: usize = 10;
const MAC_FIRST_OCTET_CHOICES: u64 = 64;
const MAC_LOCALLY_ADMINISTERED: u8 = 0b10;

const OCTET_VALUES: u64 = 256;
const FIRST_HOST_OCTET: u64 = 4;
const HOST_OCTET_CHOICES: u64 = 250;
const PRIVATE_172_FIRST: u64 = 16;
const PRIVATE_172_SPAN: u64 = 16;

const BUFFERS_PER_MILLE: u64 = 13;
const CACHED_PER_MILLE: u64 = 139;
const SRECLAIMABLE_PER_MILLE: u64 = 20;
const FREE_PERCENT: u64 = 73;
const AVAILABLE_PERCENT: u64 = 86;

const SECS_PER_DAY: u64 = 86_400;
const MIN_UPTIME_DAYS: u64 = 1;
const UPTIME_DAY_CHOICES: u64 = 89;

// Session shells get PIDs above every boot-time process, and stay far below
// the kernel's `pid_max` so a long-lived sensor never has to wrap.
const FIRST_PID_BASE: u64 = 1_400;
const PID_BASE_CHOICES: u64 = 28_000;
const PID_STRIDE: u64 = 11;
const PID_MAX: u64 = 4_194_304;

const MEM_SIZES_KB: &[u64] = &[1009428, 2041208, 4025464, 8148304, 16373612];

const DISK_SIZES_KB: &[u64] = &[8065444, 16197524, 20263528, 32441516, 40593708, 64891496];

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(SPLITMIX_GAMMA);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX_MUL_1);
        z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX_MUL_2);
        z ^ (z >> 31)
    }

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
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = SplitMix64(seed);

        let machine_id = rng.hex(ID_HEX_LEN);
        let boot_id = uuid_from_hex(&rng.hex(ID_HEX_LEN));
        let cpu = CPUS[rng.below(CPUS.len() as u64) as usize];
        let cpu_cores = random_core_count(&mut rng);
        let mem_total_kb = MEM_SIZES_KB[rng.below(MEM_SIZES_KB.len() as u64) as usize];
        let disk_total_kb = DISK_SIZES_KB[rng.below(DISK_SIZES_KB.len() as u64) as usize];
        let mac = random_mac(&mut rng);
        let (subnet, host) = random_subnet_and_host(&mut rng);
        let ipv4 = format!("{subnet}.{host}");

        // Drawn last so the fields above keep the values earlier releases
        // derived from the same seed.
        let uptime_at_start_secs = ((rng.below(UPTIME_DAY_CHOICES) + MIN_UPTIME_DAYS)
            * SECS_PER_DAY
            + rng.below(SECS_PER_DAY)) as i64;
        let pid_base = (rng.below(PID_BASE_CHOICES) + FIRST_PID_BASE) as u32;

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
            host_keys: Vec::new(),
            uptime_at_start_secs,
            pid_base,
        }
    }

    pub fn with_host_keys(mut self, keys: Vec<(String, String)>) -> Self {
        self.host_keys = keys;
        self
    }

    pub fn sample() -> Self {
        Self::from_seed(SAMPLE_SEED)
    }

    /// PID of the login shell for the `session`-th connection: stable within
    /// a session, rising from one session to the next, different per sensor.
    pub fn shell_pid(&self, session: u64) -> u32 {
        let base = u64::from(self.pid_base);
        let jitter = SplitMix64(base ^ session.rotate_left(32)).below(PID_STRIDE);
        let offset = session.wrapping_mul(PID_STRIDE).wrapping_add(jitter);
        (base + offset % (PID_MAX - base)) as u32
    }

    pub fn bogomips(&self) -> String {
        format!("{}.00", self.cpu.mhz * 2)
    }

    pub fn broadcast(&self) -> String {
        format!("{}.255", self.subnet)
    }

    pub fn gateway(&self) -> String {
        format!("{}.1", self.subnet)
    }

    pub fn memory(&self) -> MemStats {
        let total = self.mem_total_kb;
        let buffers = total * BUFFERS_PER_MILLE / 1000;
        let cached = total * CACHED_PER_MILLE / 1000;
        let sreclaimable = total * SRECLAIMABLE_PER_MILLE / 1000;
        let free = total * FREE_PERCENT / 100;
        let buff_cache = buffers + cached + sreclaimable;
        MemStats {
            total,
            free,
            available: total * AVAILABLE_PERCENT / 100,
            buffers,
            cached,
            sreclaimable,
            buff_cache,
            shared: SHMEM_KB,
            used: total.saturating_sub(free).saturating_sub(buff_cache),
        }
    }
}

const SHMEM_KB: u64 = 992;

#[derive(Debug, Clone, Copy)]
pub struct MemStats {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub sreclaimable: u64,
    pub buff_cache: u64,
    pub shared: u64,
    pub used: u64,
}

fn uuid_from_hex(hex: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn random_core_count(rng: &mut SplitMix64) -> u32 {
    match rng.below(10) {
        0..=4 => 1,
        5..=8 => 2,
        _ => 4,
    }
}

fn random_mac(rng: &mut SplitMix64) -> String {
    let tail = rng.hex(MAC_TAIL_HEX_LEN);
    let first: u8 = (rng.below(MAC_FIRST_OCTET_CHOICES) as u8) << 2 | MAC_LOCALLY_ADMINISTERED;
    format!(
        "{:02x}:{}:{}:{}:{}:{}",
        first,
        &tail[0..2],
        &tail[2..4],
        &tail[4..6],
        &tail[6..8],
        &tail[8..10]
    )
}

fn random_subnet_and_host(rng: &mut SplitMix64) -> (String, u64) {
    match rng.below(3) {
        0 => (
            format!("10.{}.{}", rng.below(OCTET_VALUES), rng.below(OCTET_VALUES)),
            random_host_octet(rng),
        ),
        1 => (
            format!(
                "172.{}.{}",
                rng.below(PRIVATE_172_SPAN) + PRIVATE_172_FIRST,
                rng.below(OCTET_VALUES)
            ),
            random_host_octet(rng),
        ),
        _ => (
            format!("192.168.{}", rng.below(OCTET_VALUES)),
            random_host_octet(rng),
        ),
    }
}

fn random_host_octet(rng: &mut SplitMix64) -> u64 {
    rng.below(HOST_OCTET_CHOICES) + FIRST_HOST_OCTET
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
        let ids: std::collections::BTreeSet<String> =
            (0..64).map(|s| Persona::from_seed(s).machine_id).collect();
        assert_eq!(ids.len(), 64, "machine ids must be distinct");

        let macs: std::collections::BTreeSet<String> =
            (0..64).map(|s| Persona::from_seed(s).mac).collect();
        assert_eq!(macs.len(), 64, "MACs must be distinct");
    }

    #[test]
    fn existing_identity_fields_are_unchanged_by_the_newer_draws() {
        let p = Persona::from_seed(42);
        assert_eq!(p.machine_id, "bdd732262feb6e9528efe333b266f103");
        assert_eq!(p.mac, "ba:57:05:b8:77:0b");
        assert_eq!(p.ipv4, "192.168.190.152");
    }

    #[test]
    fn uptime_and_pid_differ_between_sensors_but_not_between_runs() {
        let a = Persona::from_seed(42);
        let b = Persona::from_seed(42);
        assert_eq!(a.uptime_at_start_secs, b.uptime_at_start_secs);
        assert_eq!(a.shell_pid(7), b.shell_pid(7));

        let uptimes: std::collections::BTreeSet<i64> = (0..64)
            .map(|s| Persona::from_seed(s).uptime_at_start_secs)
            .collect();
        assert!(uptimes.len() > 60, "uptimes should vary per sensor");
        let pids: std::collections::BTreeSet<u32> = (0..64)
            .map(|s| Persona::from_seed(s).shell_pid(1))
            .collect();
        assert!(pids.len() > 60, "shell PIDs should vary per sensor");

        for seed in 0..64 {
            let p = Persona::from_seed(seed);
            assert!(p.uptime_at_start_secs >= 86_400, "seed {seed}");
            assert!(p.uptime_at_start_secs < 91 * 86_400, "seed {seed}");
        }
    }

    #[test]
    fn shell_pids_rise_with_each_session_and_stay_in_range() {
        let p = Persona::from_seed(42);
        let pids: Vec<u32> = (1..200).map(|s| p.shell_pid(s)).collect();
        assert!(pids.windows(2).all(|w| w[0] < w[1]), "{pids:?}");
        assert!(pids[0] > 1_400);
        assert!(u64::from(p.shell_pid(u64::MAX)) < PID_MAX);
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

            assert!(octets[3] >= 4, "ipv4={}", p.ipv4);
        }
    }
}
