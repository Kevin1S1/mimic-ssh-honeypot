use super::is_root;
use crate::clock;
use crate::commands::CommandResult;
use crate::shell::Shell;

pub(super) const KERNEL_RELEASE: &str = "6.1.0-21-amd64";

const KERNEL_VERSION: &str = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)";

const MACHINE: &str = "x86_64";

const UNAME_LONG_FLAGS: &[(&str, char)] = &[
    ("--all", 'a'),
    ("--kernel-name", 's'),
    ("--nodename", 'n'),
    ("--kernel-release", 'r'),
    ("--kernel-version", 'v'),
    ("--machine", 'm'),
    ("--processor", 'p'),
    ("--hardware-platform", 'i'),
    ("--operating-system", 'o'),
];

#[derive(Default)]
struct UnameFields {
    sysname: bool,
    nodename: bool,
    release: bool,
    version: bool,
    machine: bool,
    operating: bool,
}

impl UnameFields {
    const ALL: Self = Self {
        sysname: true,
        nodename: true,
        release: true,
        version: true,
        machine: true,
        operating: true,
    };

    fn set(&mut self, flag: char) -> bool {
        match flag {
            's' => self.sysname = true,
            'n' => self.nodename = true,
            'r' => self.release = true,
            'v' => self.version = true,
            'm' | 'p' | 'i' => self.machine = true,
            'o' => self.operating = true,
            'a' => *self = Self::ALL,
            _ => return false,
        }
        true
    }

    fn render(&self, hostname: &str) -> String {
        let parts = [
            (self.sysname, "Linux"),
            (self.nodename, hostname),
            (self.release, KERNEL_RELEASE),
            (self.version, KERNEL_VERSION),
            (self.machine, MACHINE),
            (self.operating, "GNU/Linux"),
        ];
        let shown: Vec<&str> = parts
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, value)| *value)
            .collect();
        format!("{}\n", shown.join(" "))
    }
}

pub fn uname(shell: &Shell, args: &[String]) -> CommandResult {
    let mut fields = UnameFields {
        sysname: args.is_empty(),
        ..UnameFields::default()
    };
    for arg in args {
        if let Some(&(_, flag)) = UNAME_LONG_FLAGS
            .iter()
            .find(|(long, _)| *long == arg.as_str())
        {
            fields.set(flag);
        } else if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.starts_with('-')) {
            if let Some(bad) = cluster.chars().find(|&flag| !fields.set(flag)) {
                return CommandResult::err(
                    format!(
                        "uname: invalid option -- '{bad}'\nTry 'uname --help' for more information.\n"
                    ),
                    1,
                );
            }
        } else {
            return CommandResult::err(
                format!("uname: extra operand '{arg}'\nTry 'uname --help' for more information.\n"),
                1,
            );
        }
    }
    CommandResult::ok(fields.render(&shell.hostname))
}

pub fn hostname(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.hostname))
}

pub fn nproc(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.persona.cpu_cores))
}

pub fn lscpu(shell: &Shell, _args: &[String]) -> CommandResult {
    let p = &shell.persona;
    let cpu = &p.cpu;
    let online = if p.cpu_cores == 1 {
        "0".to_string()
    } else {
        format!("0-{}", p.cpu_cores - 1)
    };
    CommandResult::ok(format!(
        "Architecture:             x86_64\n\
         CPU op-mode(s):           32-bit, 64-bit\n\
         Byte Order:               Little Endian\n\
         CPU(s):                   {cores}\n\
         On-line CPU(s) list:      {online}\n\
         Vendor ID:                {vendor}\n\
         Model name:               {name}\n\
         CPU family:               {family}\n\
         Model:                    {model}\n\
         Thread(s) per core:       1\n\
         Core(s) per socket:       {cores}\n\
         Socket(s):                1\n\
         Stepping:                 {stepping}\n\
         BogoMIPS:                 {bogomips}\n\
         Hypervisor vendor:        KVM\n\
         Virtualization type:      full\n",
        cores = p.cpu_cores,
        online = online,
        vendor = cpu.vendor,
        name = cpu.name,
        family = cpu.family,
        model = cpu.model,
        stepping = cpu.stepping,
        bogomips = p.bogomips(),
    ))
}

pub fn uptime(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!(" {}\n", clock::uptime_banner()))
}

pub fn arch(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{MACHINE}\n"))
}

const LSB_FIELDS: &[(char, &str, &str)] = &[
    ('i', "Distributor ID", "Debian"),
    ('d', "Description", "Debian GNU/Linux 12 (bookworm)"),
    ('r', "Release", "12"),
    ('c', "Codename", "bookworm"),
];

pub fn lsb_release(_shell: &Shell, args: &[String]) -> CommandResult {
    let flags: Vec<char> = args
        .iter()
        .filter_map(|arg| arg.strip_prefix('-'))
        .filter(|cluster| !cluster.is_empty() && !cluster.starts_with('-'))
        .flat_map(str::chars)
        .collect();
    let short = flags.contains(&'s');
    let full = flags.contains(&'a') || !LSB_FIELDS.iter().any(|(flag, _, _)| flags.contains(flag));

    let mut out = String::new();
    if full && !short {
        out.push_str("No LSB modules are available.\n");
    }
    for (_, label, value) in LSB_FIELDS
        .iter()
        .filter(|(flag, _, _)| full || flags.contains(flag))
    {
        if short {
            out.push_str(&format!("{value}\n"));
        } else {
            out.push_str(&format!("{label}:\t{value}\n"));
        }
    }
    CommandResult::ok(out)
}

const DMESG_HEAD: &str = "\
[    0.000000] Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)\n\
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-6.1.0-21-amd64 root=UUID=8f3a2b1c-4d5e-6f70-8192-a3b4c5d6e7f8 ro console=tty0 console=ttyS0,115200\n\
[    0.000000] BIOS-provided physical RAM map:\n\
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable\n\
[    0.000000] KVM: setup async PF for cpu 0\n\
[    0.008000] Hypervisor detected: KVM\n";

const DMESG_TAIL: &str = "\
[    0.410000] pci 0000:00:00.0: [8086:1237] type 00 class 0x060000\n\
[    0.512000] virtio_blk virtio1: [vda] 83886080 512-byte logical blocks (42.9 GB/40.0 GiB)\n\
[    0.640000] ata1.00: ATA-8: QEMU HARDDISK, 2.5+, max UDMA/100\n\
[    0.900000] EXT4-fs (sda1): mounted filesystem with ordered data mode. Quota mode: none.\n\
[    1.220000] systemd[1]: systemd 252.22-1~deb12u1 running in system mode\n\
[    1.480000] systemd[1]: Detected virtualization kvm.\n\
[    1.481000] systemd[1]: Detected architecture x86-64.\n\
[    2.310000] e1000: eth0 NIC Link is Up 1000 Mbps Full Duplex\n\
[    2.640000] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready\n";

const KB_PER_GIB: u64 = 1024 * 1024;

// What the kernel holds back before `MemTotal` is counted (its own image and
// early allocations); the boot line reports the installed RAM alongside it.
const DMESG_EARLY_RESERVED_KB: u64 = 17_416;

fn dmesg_buffer(persona: &crate::persona::Persona) -> String {
    let cpu = &persona.cpu;
    let total = persona.memory().total;
    let installed = total.div_ceil(KB_PER_GIB) * KB_PER_GIB;
    let available = total.saturating_sub(DMESG_EARLY_RESERVED_KB);
    format!(
        "{DMESG_HEAD}\
         [    0.020000] smpboot: CPU0: {name} (family: {family:#x}, model: {model:#x}, stepping: {stepping:#x})\n\
         [    0.130000] Memory: {available}K/{installed}K available (14342K kernel code, 2332K rwdata, 9056K rodata, 2792K init, 17416K bss, {reserved}K reserved, 0K cma-reserved)\n\
         {DMESG_TAIL}",
        name = cpu.name,
        family = cpu.family,
        model = cpu.model,
        stepping = cpu.stepping,
        reserved = installed - available,
    )
}

pub fn dmesg(shell: &Shell, _args: &[String]) -> CommandResult {
    if !is_root(shell) {
        return CommandResult::err(
            "dmesg: read kernel buffer failed: Operation not permitted\n",
            1,
        );
    }
    CommandResult::ok(dmesg_buffer(&shell.persona))
}

pub fn date(_shell: &Shell, args: &[String]) -> CommandResult {
    let epoch = clock::now();
    let fmt = args
        .iter()
        .find_map(|a| a.strip_prefix('+'))
        .unwrap_or("%a %b %e %H:%M:%S %Z %Y");
    CommandResult::ok(format!("{}\n", clock::format(epoch, fmt)))
}
