use super::CommandResult;
use crate::clock;
use crate::shell::Shell;
use crate::vfs::snapshot::{USR_BIN, USR_SBIN};

mod interpreter;
mod privilege;
mod process;
mod top;

pub use interpreter::{scp, shell_cmd};
pub use privilege::{su, sudo};

pub use process::{kill, pkill, process_name, process_pid, process_table, ps};
pub use top::{top, TopScreen};

fn is_root(shell: &Shell) -> bool {
    shell.uid == 0
}

const KERNEL_RELEASE: &str = "6.1.0-21-amd64";

const KERNEL_VERSION: &str = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)";

const MACHINE: &str = "x86_64";

pub fn whoami(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.username))
}

pub fn id(shell: &Shell, _args: &[String]) -> CommandResult {
    let line = if shell.uid == 0 {
        "uid=0(root) gid=0(root) groups=0(root)\n".to_string()
    } else {
        format!(
            "uid={uid}({user}) gid={gid}({user}) groups={gid}({user}),27(sudo)\n",
            uid = shell.uid,
            gid = shell.gid,
            user = shell.username,
        )
    };
    CommandResult::ok(line)
}

pub fn uname(shell: &Shell, args: &[String]) -> CommandResult {
    let mut sysname = false;
    let mut nodename = false;
    let mut release = false;
    let mut version = false;
    let mut machine = false;
    let mut operating = false;
    let mut all = false;

    if args.is_empty() {
        sysname = true;
    }
    for arg in args {
        match arg.as_str() {
            "-a" | "--all" => all = true,
            "-s" | "--kernel-name" => sysname = true,
            "-n" | "--nodename" => nodename = true,
            "-r" | "--kernel-release" => release = true,
            "-v" | "--kernel-version" => version = true,
            "-m" | "--machine" | "-p" | "--processor" | "-i" | "--hardware-platform" => {
                machine = true
            }
            "-o" | "--operating-system" => operating = true,
            other if other.starts_with('-') && !other.starts_with("--") => {
                for ch in other[1..].chars() {
                    match ch {
                        's' => sysname = true,
                        'n' => nodename = true,
                        'r' => release = true,
                        'v' => version = true,
                        'm' | 'p' | 'i' => machine = true,
                        'o' => operating = true,
                        'a' => all = true,
                        bad => {
                            return CommandResult::err(
                                format!(
                                    "uname: invalid option -- '{bad}'\nTry 'uname --help' for more information.\n"
                                ),
                                1,
                            );
                        }
                    }
                }
            }
            bad => {
                return CommandResult::err(
                    format!(
                        "uname: extra operand '{bad}'\nTry 'uname --help' for more information.\n"
                    ),
                    1,
                );
            }
        }
    }

    if all {
        return CommandResult::ok(format!(
            "Linux {host} {rel} {ver} {mach} GNU/Linux\n",
            host = shell.hostname,
            rel = KERNEL_RELEASE,
            ver = KERNEL_VERSION,
            mach = MACHINE,
        ));
    }

    let mut parts: Vec<String> = Vec::new();
    if sysname {
        parts.push("Linux".to_string());
    }
    if nodename {
        parts.push(shell.hostname.clone());
    }
    if release {
        parts.push(KERNEL_RELEASE.to_string());
    }
    if version {
        parts.push(KERNEL_VERSION.to_string());
    }
    if machine {
        parts.push(MACHINE.to_string());
    }
    if operating {
        parts.push("GNU/Linux".to_string());
    }
    CommandResult::ok(format!("{}\n", parts.join(" ")))
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

pub fn printf(_shell: &Shell, args: &[String]) -> CommandResult {
    let Some(format) = args.first() else {
        return CommandResult::err("printf: usage: printf [-v var] format [arguments]\n", 2);
    };
    let mut operands = args[1..].iter();
    let mut out = String::new();
    let chars: Vec<char> = format.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '\\' if i + 1 < chars.len() => {
                match chars[i + 1] {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    '0' => out.push('\0'),
                    '\\' => out.push('\\'),

                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
                i += 2;
            }
            '%' if i + 1 < chars.len() => {
                match chars[i + 1] {
                    '%' => out.push('%'),
                    's' => out.push_str(operands.next().map(String::as_str).unwrap_or("")),
                    'd' | 'i' => {
                        let v: i64 = operands
                            .next()
                            .and_then(|a| a.trim().parse().ok())
                            .unwrap_or(0);
                        out.push_str(&v.to_string());
                    }
                    other => {
                        out.push('%');
                        out.push(other);
                    }
                }
                i += 2;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
        if out.len() > super::MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    CommandResult::ok(out)
}

pub fn echo(_shell: &Shell, args: &[String]) -> CommandResult {
    let mut no_newline = false;
    let mut interpret = false;
    let mut idx = 0;

    while idx < args.len() {
        let arg = &args[idx];
        if arg.starts_with('-') && arg.len() > 1 && arg[1..].chars().all(|c| c == 'n' || c == 'e') {
            for ch in arg[1..].chars() {
                match ch {
                    'n' => no_newline = true,
                    'e' => interpret = true,
                    _ => {}
                }
            }
            idx += 1;
        } else {
            break;
        }
    }

    let mut text = args[idx..].join(" ");
    let mut stopped = false;
    if interpret {
        (text, stopped) = interpret_escapes(&text);
    }
    if !no_newline && !stopped {
        text.push('\n');
    }
    CommandResult::ok(text)
}

fn interpret_escapes(s: &str) -> (String, bool) {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('a') => out.push('\x07'),
            Some('b') => out.push('\x08'),
            Some('e') | Some('E') => out.push('\x1b'),
            Some('f') => out.push('\x0c'),
            Some('v') => out.push('\x0b'),

            Some('0') => out.push(take_code(&mut chars, 8, 3).unwrap_or('\0')),
            Some('x') => match take_code(&mut chars, 16, 2) {
                Some(c) => out.push(c),
                None => out.push_str("\\x"),
            },

            Some('c') => return (out, true),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    (out, false)
}

fn take_code(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    radix: u32,
    max: usize,
) -> Option<char> {
    let mut value = 0u32;
    let mut digits = 0;
    while digits < max {
        let Some(d) = chars.peek().and_then(|c| c.to_digit(radix)) else {
            break;
        };
        value = value * radix + d;
        chars.next();
        digits += 1;
    }

    (digits > 0).then(|| char::from(value as u8))
}

pub fn env(shell: &Shell, _args: &[String]) -> CommandResult {
    let mut out = String::new();
    for (key, value) in shell.env.iter() {
        out.push_str(&format!("{key}={value}\n"));
    }
    CommandResult::ok(out)
}

pub fn export(shell: &mut Shell, args: &[String]) -> CommandResult {
    for arg in args {
        if let Some((name, value)) = arg.split_once('=') {
            shell.env.set(name, value);
        }
    }
    CommandResult::empty()
}

pub fn unset(shell: &mut Shell, args: &[String]) -> CommandResult {
    for arg in args {
        shell.env.unset(arg);
    }
    CommandResult::empty()
}

pub fn clear(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok("\x1b[H\x1b[2J\x1b[3J")
}

pub fn free(shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human");
    let mega = args.iter().any(|a| a == "-m");
    let giga = args.iter().any(|a| a == "-g");

    let mem = shell.persona.memory();
    let (total, free_mem, available, buff, used) =
        (mem.total, mem.free, mem.available, mem.buff_cache, mem.used);
    let shared = 992u64;

    let fmt = |kb: u64| -> String {
        if human {
            human_kib(kb)
        } else if mega {
            (kb / 1024).to_string()
        } else if giga {
            (kb / 1024 / 1024).to_string()
        } else {
            kb.to_string()
        }
    };

    let mut out = String::new();
    out.push_str(
        "               total        used        free      shared  buff/cache   available\n",
    );
    out.push_str(&format!(
        "Mem:    {:>12} {:>11} {:>11} {:>11} {:>11} {:>11}\n",
        fmt(total),
        fmt(used),
        fmt(free_mem),
        fmt(shared),
        fmt(buff),
        fmt(available)
    ));
    out.push_str(&format!(
        "Swap:   {:>12} {:>11} {:>11}\n",
        fmt(0),
        fmt(0),
        fmt(0)
    ));
    CommandResult::ok(out)
}

fn human_kib(kb: u64) -> String {
    let bytes = kb as f64 * 1024.0;
    const UNITS: [&str; 5] = ["B", "Ki", "Mi", "Gi", "Ti"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{}B", value as u64)
    } else if value < 10.0 {
        format!("{value:.1}{}", UNITS[unit])
    } else {
        format!("{value:.0}{}", UNITS[unit])
    }
}

pub fn uptime(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!(" {}\n", clock::uptime_banner()))
}

pub const BUILTINS: &[&str] = &[
    "cd", "export", "unset", "history", "exit", "logout", "alias", "source",
];

pub fn history(shell: &mut Shell, args: &[String]) -> CommandResult {
    if args.iter().any(|a| a == "-c") {
        shell.history.clear();
        return CommandResult::empty();
    }
    let mut out = String::new();
    for (i, cmd) in shell.history.iter().enumerate() {
        out.push_str(&format!("{:5}  {}\n", i + 1, cmd));
    }
    CommandResult::ok(out)
}

pub fn which(_shell: &Shell, args: &[String]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::empty();
    }
    let mut out = String::new();
    let mut status = 0;
    for name in args {
        if BUILTINS.contains(&name.as_str()) {
            status = 1;
        } else if let Some(path) = binary_path(name) {
            out.push_str(&format!("{path}\n"));
        } else {
            status = 1;
        }
    }

    CommandResult::streams(out, "", status)
}

fn binary_path(name: &str) -> Option<String> {
    if BUILTINS.contains(&name) {
        return None;
    }
    if USR_BIN.contains(&name) {
        Some(format!("/usr/bin/{name}"))
    } else if USR_SBIN.contains(&name) {
        Some(format!("/usr/sbin/{name}"))
    } else {
        None
    }
}

pub fn w(shell: &Shell, _args: &[String]) -> CommandResult {
    let header = format!(" {}\n", clock::uptime_banner());
    let cols = "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n";
    let row = format!(
        "{user:<8} pts/0    {from:<16} {login}    0.00s  0.02s  0.00s w\n",
        user = truncate(&shell.username, 8),
        from = clock::PREV_LOGIN_FROM,
        login = clock::format(shell.login, "%H:%M"),
    );
    CommandResult::ok(format!("{header}{cols}{row}"))
}

pub fn last(shell: &Shell, _args: &[String]) -> CommandResult {
    let (prev, prev_end) = clock::prev_login();
    let boot = clock::boot_time();
    let user = truncate(&shell.username, 8);
    let from = clock::PREV_LOGIN_FROM;
    let span = prev_end - prev;
    let out = format!(
        "{user:<8} pts/0        {from:<16} {this}   still logged in\n\
         {user:<8} pts/0        {from:<16} {prev} - {prev_end} ({hours:02}:{mins:02})\n\
         reboot   system boot  6.1.0-21-amd64   {boot}   still running\n\
         \n\
         wtmp begins {wtmp}\n",
        this = clock::format(shell.login, "%a %b %e %H:%M"),
        prev = clock::format(prev, "%a %b %e %H:%M"),
        prev_end = clock::format(prev_end, "%H:%M"),
        hours = span / 3600,
        mins = (span % 3600) / 60,
        boot = clock::format(boot, "%a %b %e %H:%M"),
        wtmp = clock::format(boot, "%a %b %e %H:%M:%S %Y"),
    );
    CommandResult::ok(out)
}

pub fn df(shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human-readable");

    let mem = shell.persona.mem_total_kb;
    let disk = shell.persona.disk_total_kb;
    let udev = mem / 2 - 5270;
    let run = mem / 10;
    let shm = mem / 2;
    let used = disk * 16 / 100;
    let avail = disk - used - (disk / 20);
    let pct = (used * 100).div_ceil(disk.max(1));
    let uid = shell.uid;

    let out = if human {
        format!(
            "Filesystem      Size  Used Avail Use% Mounted on\n\
             udev            {udev:>4}     0  {udev:>4}   0% /dev\n\
             tmpfs           {run:>4}  960K  {run:>4}   1% /run\n\
             /dev/sda1       {disk:>4}  {used:>4}  {avail:>4}  {pct}% /\n\
             tmpfs           {shm:>4}     0  {shm:>4}   0% /dev/shm\n\
             tmpfs           5.0M     0  5.0M   0% /run/lock\n\
             tmpfs           {run:>4}     0  {run:>4}   0% /run/user/{uid}\n",
            udev = human_kib(udev),
            run = human_kib(run),
            shm = human_kib(shm),
            disk = human_kib(disk),
            used = human_kib(used),
            avail = human_kib(avail),
            pct = pct,
            uid = uid,
        )
    } else {
        format!(
            "Filesystem     1K-blocks    Used Available Use% Mounted on\n\
             udev          {udev:>10}       0  {udev:>8}   0% /dev\n\
             tmpfs         {run:>10}     960  {run_avail:>8}   1% /run\n\
             /dev/sda1     {disk:>10} {used:>7}  {avail:>8}  {pct}% /\n\
             tmpfs         {shm:>10}       0  {shm:>8}   0% /dev/shm\n\
             tmpfs               5120       0      5120   0% /run/lock\n\
             tmpfs         {run:>10}       0  {run:>8}   0% /run/user/{uid}\n",
            udev = udev,
            run = run,
            run_avail = run - 960,
            disk = disk,
            used = used,
            avail = avail,
            pct = pct,
            shm = shm,
            uid = uid,
        )
    };
    CommandResult::ok(out)
}

pub fn mount(_shell: &Shell, _args: &[String]) -> CommandResult {
    let out = "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n\
        proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n\
        udev on /dev type devtmpfs (rw,nosuid,relatime,size=1015532k,nr_inodes=253883,mode=755)\n\
        devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)\n\
        tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=204120k,mode=755)\n\
        /dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n\
        tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)\n\
        tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k,inode64)\n";
    CommandResult::ok(out)
}

pub fn crontab(shell: &Shell, args: &[String]) -> CommandResult {
    if args.iter().any(|a| a == "-l") {
        return CommandResult::err(format!("no crontab for {}\n", shell.username), 1);
    }
    if args.iter().any(|a| a == "-r" || a == "-e") {
        return CommandResult::empty();
    }
    CommandResult::err(
        "usage:  crontab [-u user] file\n\
         \tcrontab [ -u user ] [ -i ] { -e | -l | -r }\n",
        1,
    )
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn groups(shell: &Shell, _args: &[String]) -> CommandResult {
    let line = if shell.uid == 0 {
        "root".to_string()
    } else {
        format!("{} sudo", shell.username)
    };
    CommandResult::ok(format!("{line}\n"))
}

pub fn arch(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{MACHINE}\n"))
}

pub fn tty(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok("/dev/pts/0\n")
}

pub fn lsb_release(_shell: &Shell, args: &[String]) -> CommandResult {
    let (mut want_i, mut want_d, mut want_r, mut want_c) = (false, false, false, false);
    let mut short = false;
    let mut all = false;

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for ch in arg[1..].chars() {
                match ch {
                    'a' => all = true,
                    's' => short = true,
                    'i' => want_i = true,
                    'd' => want_d = true,
                    'r' => want_r = true,
                    'c' => want_c = true,
                    _ => {}
                }
            }
        }
    }

    let full = all || !(want_i || want_d || want_r || want_c);
    if full {
        want_i = true;
        want_d = true;
        want_r = true;
        want_c = true;
    }

    let mut out = String::new();
    if full && !short {
        out.push_str("No LSB modules are available.\n");
    }
    let mut push = |label: &str, value: &str| {
        if short {
            out.push_str(value);
            out.push('\n');
        } else {
            out.push_str(&format!("{label}:\t{value}\n"));
        }
    };
    if want_i {
        push("Distributor ID", "Debian");
    }
    if want_d {
        push("Description", "Debian GNU/Linux 12 (bookworm)");
    }
    if want_r {
        push("Release", "12");
    }
    if want_c {
        push("Codename", "bookworm");
    }
    CommandResult::ok(out)
}

const DMESG_BUFFER: &str = "\
[    0.000000] Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)\n\
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-6.1.0-21-amd64 root=UUID=8f3a2b1c-4d5e-6f70-8192-a3b4c5d6e7f8 ro console=tty0 console=ttyS0,115200\n\
[    0.000000] BIOS-provided physical RAM map:\n\
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable\n\
[    0.000000] KVM: setup async PF for cpu 0\n\
[    0.008000] Hypervisor detected: KVM\n\
[    0.020000] CPU0: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz (family: 0x6, model: 0x55, stepping: 0x7)\n\
[    0.130000] Memory: 2041208K/2097152K available\n\
[    0.410000] pci 0000:00:00.0: [8086:1237] type 00 class 0x060000\n\
[    0.512000] virtio_blk virtio1: [vda] 83886080 512-byte logical blocks (42.9 GB/40.0 GiB)\n\
[    0.640000] ata1.00: ATA-8: QEMU HARDDISK, 2.5+, max UDMA/100\n\
[    0.900000] EXT4-fs (sda1): mounted filesystem with ordered data mode. Quota mode: none.\n\
[    1.220000] systemd[1]: systemd 252.22-1~deb12u1 running in system mode\n\
[    1.480000] systemd[1]: Detected virtualization kvm.\n\
[    1.481000] systemd[1]: Detected architecture x86-64.\n\
[    2.310000] e1000: eth0 NIC Link is Up 1000 Mbps Full Duplex\n\
[    2.640000] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready\n";

pub fn dmesg(shell: &Shell, _args: &[String]) -> CommandResult {
    if shell.uid != 0 {
        return CommandResult::err(
            "dmesg: read kernel buffer failed: Operation not permitted\n",
            1,
        );
    }
    CommandResult::ok(DMESG_BUFFER)
}

pub fn date(_shell: &Shell, args: &[String]) -> CommandResult {
    let epoch = clock::now();
    let fmt = args
        .iter()
        .find_map(|a| a.strip_prefix('+'))
        .unwrap_or("%a %b %e %H:%M:%S %Z %Y");
    CommandResult::ok(format!("{}\n", clock::format(epoch, fmt)))
}

#[cfg(test)]
mod tests;
