//! Debian 12 (Bookworm) filesystem snapshot.
//!
//! Builds a believable skeleton of `/`, `/etc`, `/home`, `/var`, `/proc`, and
//! the usual top-level directories, populated with realistic content for the
//! files attackers most commonly inspect (`/etc/passwd`, `/etc/os-release`,
//! `/proc/cpuinfo`, ...). Everything is static and in-memory.

use super::Vfs;
use crate::persona::Persona;

/// Binaries in `/usr/bin` — one per non-builtin command the registry serves,
/// so `ls /usr/bin`, `which`, Tab completion, and dispatch all agree.
const USR_BIN: &[&str] = &[
    "apt",
    "apt-get",
    "arch",
    "bash",
    "cat",
    "chmod",
    "clear",
    "cp",
    "crontab",
    "curl",
    "date",
    "df",
    "dmesg",
    "dpkg",
    "echo",
    "env",
    "false",
    "find",
    "free",
    "grep",
    "groups",
    "head",
    "hostname",
    "id",
    "kill",
    "last",
    "ls",
    "lsb_release",
    "lscpu",
    "mkdir",
    "mount",
    "mv",
    "netstat",
    "nproc",
    "ping",
    "pkill",
    "printenv",
    "ps",
    "pwd",
    "rm",
    "rmdir",
    "scp",
    "sh",
    "su",
    "sudo",
    "tail",
    "tar",
    "top",
    "touch",
    "true",
    "tty",
    "uname",
    "uptime",
    "w",
    "wc",
    "wget",
    "which",
    "whoami",
];

/// Binaries in `/usr/sbin`, matching the paths `which` reports for them.
const USR_SBIN: &[&str] = &["ip", "ss"];

/// File contents for `/etc/os-release` on Debian 12.
const OS_RELEASE: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n\
NAME=\"Debian GNU/Linux\"\n\
VERSION_ID=\"12\"\n\
VERSION=\"12 (bookworm)\"\n\
VERSION_CODENAME=bookworm\n\
ID=debian\n\
HOME_URL=\"https://www.debian.org/\"\n\
SUPPORT_URL=\"https://www.debian.org/support\"\n\
BUG_REPORT_URL=\"https://bugs.debian.org/\"\n";

/// File contents for `/etc/passwd` — the standard Debian system accounts plus
/// one regular user (`user`, uid 1000).
const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
sync:x:4:65534:sync:/bin:/bin/sync\n\
games:x:5:60:games:/usr/games:/usr/sbin/nologin\n\
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n\
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n\
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n\
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n\
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
sshd:x:100:65534::/run/sshd:/usr/sbin/nologin\n\
user:x:1000:1000:user,,,:/home/user:/bin/bash\n";

/// File contents for `/etc/group`.
const GROUP: &str = "root:x:0:\n\
daemon:x:1:\n\
bin:x:2:\n\
sys:x:3:\n\
adm:x:4:\n\
tty:x:5:\n\
disk:x:6:\n\
sudo:x:27:user\n\
www-data:x:33:\n\
ssh:x:114:\n\
user:x:1000:\n";

/// `/etc/shadow` — passwords shown as locked/hashed placeholders. The `user`
/// row carries a random-looking (but inert, non-identifying) SHA-512 crypt
/// string rather than an obvious "placeholder"/"honeypot" marker: real
/// permission checks now gate this file (owner/root only), but the content
/// itself must not be a self-outing tell for anyone who does get past that
/// (e.g. via a future privilege-escalation emulation gap).
const SHADOW: &str = "root:!:19000:0:99999:7:::\n\
daemon:*:19000:0:99999:7:::\n\
sshd:!:19000:0:99999:7:::\n\
user:$6$rounds=656000$D1G7H204ckii$Abjn5s.euB1Z/rC2tdRk8fQxF5ucdtUgVpg.H.tPzMNktyVxhqoAclDrdXCw29WpcY68HNAlSzrJwXX1kX/PvS:19000:0:99999:7:::\n";

/// `.bashrc` skeleton shipped by Debian's `bash` package.
const BASHRC: &str = "# ~/.bashrc: executed by bash(1) for non-login shells.\n\
\n\
case $- in\n\
    *i*) ;;\n\
      *) return;;\n\
esac\n\
\n\
HISTCONTROL=ignoreboth\n\
HISTSIZE=1000\n\
HISTFILESIZE=2000\n\
shopt -s checkwinsize\n\
\n\
if [ -x /usr/bin/dircolors ]; then\n\
    alias ls='ls --color=auto'\n\
    alias grep='grep --color=auto'\n\
fi\n\
\n\
alias ll='ls -alF'\n\
alias la='ls -A'\n\
alias l='ls -CF'\n";

/// `.profile` skeleton.
const PROFILE: &str = "# ~/.profile: executed by the command interpreter for login shells.\n\
\n\
if [ -n \"$BASH_VERSION\" ]; then\n\
    if [ -f \"$HOME/.bashrc\" ]; then\n\
\t. \"$HOME/.bashrc\"\n\
    fi\n\
fi\n\
\n\
if [ -d \"$HOME/bin\" ] ; then\n\
    PATH=\"$HOME/bin:$PATH\"\n\
fi\n";

/// `/proc/cpuinfo`, rendered for this deployment's CPU and core count.
///
/// `lscpu`, `nproc` and `dmesg` read the same [`Persona`], so the four cannot
/// disagree about what processor this box has.
pub fn cpuinfo(persona: &Persona) -> String {
    let cpu = &persona.cpu;
    let mut out = String::new();
    for core in 0..persona.cpu_cores {
        out.push_str(&format!(
            "processor\t: {core}\n\
             vendor_id\t: {vendor}\n\
             cpu family\t: {family}\n\
             model\t\t: {model}\n\
             model name\t: {name}\n\
             stepping\t: {stepping}\n\
             microcode\t: {microcode}\n\
             cpu MHz\t\t: {mhz}.000\n\
             cache size\t: {cache} KB\n\
             physical id\t: 0\n\
             siblings\t: {cores}\n\
             core id\t\t: {core}\n\
             cpu cores\t: {cores}\n\
             apicid\t\t: {core}\n\
             initial apicid\t: {core}\n\
             fpu\t\t: yes\n\
             fpu_exception\t: yes\n\
             cpuid level\t: 13\n\
             wp\t\t: yes\n\
             flags\t\t: {flags}\n\
             bugs\t\t: {bugs}\n\
             bogomips\t: {bogomips}\n\
             clflush size\t: 64\n\
             cache_alignment\t: 64\n\
             address sizes\t: 46 bits physical, 48 bits virtual\n\
             power management:\n\n",
            core = core,
            vendor = cpu.vendor,
            family = cpu.family,
            model = cpu.model,
            name = cpu.name,
            stepping = cpu.stepping,
            microcode = cpu.microcode,
            mhz = cpu.mhz,
            cache = cpu.cache_kb,
            cores = persona.cpu_cores,
            flags = cpu.flags,
            bugs = cpu.bugs,
            bogomips = persona.bogomips(),
        ));
    }
    out
}

/// `/proc/meminfo`, with every figure derived from this deployment's
/// `MemTotal` so `free` and `df`'s tmpfs rows stay consistent with it.
pub fn meminfo(persona: &Persona) -> String {
    let total = persona.mem_total_kb;
    // Proportions taken from an idle Debian 12 VM, scaled to this box's RAM.
    let free = total * 73 / 100;
    let available = total * 86 / 100;
    let buffers = total * 13 / 1000;
    let cached = total * 139 / 1000;
    let active = total * 145 / 1000;
    let inactive = total * 72 / 1000;
    let anon = total * 64 / 1000;
    let mapped = total * 36 / 1000;
    let slab = total * 28 / 1000;
    let sreclaim = total * 20 / 1000;
    let sunreclaim = slab - sreclaim;
    format!(
        "MemTotal:        {total} kB\n\
         MemFree:         {free} kB\n\
         MemAvailable:    {available} kB\n\
         Buffers:           {buffers} kB\n\
         Cached:           {cached} kB\n\
         SwapCached:            0 kB\n\
         Active:           {active} kB\n\
         Inactive:         {inactive} kB\n\
         SwapTotal:             0 kB\n\
         SwapFree:              0 kB\n\
         Dirty:                88 kB\n\
         Writeback:             0 kB\n\
         AnonPages:        {anon} kB\n\
         Mapped:            {mapped} kB\n\
         Shmem:               992 kB\n\
         Slab:              {slab} kB\n\
         SReclaimable:      {sreclaim} kB\n\
         SUnreclaim:        {sunreclaim} kB\n"
    )
}

/// `/proc/version`.
const VERSION: &str = "Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)\n";

/// `/etc/hosts`.
const HOSTS_TAIL: &str = "\n\
::1     localhost ip6-localhost ip6-loopback\n\
ff02::1 ip6-allnodes\n\
ff02::2 ip6-allrouters\n";

/// `/etc/hosts` with the loopback alias pointing at the configured hostname,
/// matching how `debconf` writes the file on a fresh Debian install.
fn hosts_file(hostname: &str) -> String {
    format!("127.0.0.1\tlocalhost\n127.0.1.1\t{hostname}\n{HOSTS_TAIL}")
}

/// Build and return a fully populated Debian 12 snapshot for `hostname`.
pub fn build(hostname: &str, persona: &Persona) -> Vfs {
    let mut fs = Vfs::new();
    let root = fs.root();

    // Top-level directories.
    let etc = fs.mkdir(root, "etc", 0o755, 0, 0);
    let home = fs.mkdir(root, "home", 0o755, 0, 0);
    let root_home = fs.mkdir(root, "root", 0o700, 0, 0);
    let proc = fs.mkdir(root, "proc", 0o555, 0, 0);
    let var = fs.mkdir(root, "var", 0o755, 0, 0);
    let usr = fs.mkdir(root, "usr", 0o755, 0, 0);
    let tmp = fs.mkdir(root, "tmp", 0o1777, 0, 0);
    fs.mkdir(root, "boot", 0o755, 0, 0);
    let dev = fs.mkdir(root, "dev", 0o755, 0, 0);
    // ponytail: the VFS has no character-device kind, so /dev/null is a plain
    // empty file — `ls -l` shows `-` where a real one shows `c`. Upgrade when
    // the arena grows a device node kind.
    fs.add_file(dev, "null", Vec::new(), 0o666, 0, 0);
    fs.mkdir(root, "opt", 0o755, 0, 0);
    fs.mkdir(root, "run", 0o755, 0, 0);
    fs.mkdir(root, "srv", 0o755, 0, 0);
    fs.mkdir(root, "sys", 0o555, 0, 0);
    fs.mkdir(root, "mnt", 0o755, 0, 0);
    fs.mkdir(root, "media", 0o755, 0, 0);

    // Usual merged-/usr symlinks.
    fs.add_symlink(root, "bin", "usr/bin");
    fs.add_symlink(root, "sbin", "usr/sbin");
    fs.add_symlink(root, "lib", "usr/lib");
    fs.add_symlink(root, "lib64", "usr/lib64");

    // /usr subtree.
    let usr_bin = fs.mkdir(usr, "bin", 0o755, 0, 0);
    let usr_sbin = fs.mkdir(usr, "sbin", 0o755, 0, 0);
    fs.mkdir(usr, "lib", 0o755, 0, 0);
    fs.mkdir(usr, "lib64", 0o755, 0, 0);
    fs.mkdir(usr, "local", 0o755, 0, 0);
    fs.mkdir(usr, "share", 0o755, 0, 0);
    fs.mkdir(usr, "include", 0o755, 0, 0);
    fs.mkdir(usr, "games", 0o755, 0, 0);
    // The "binaries" behind the emulated commands. This list is exactly what
    // the command registry can run: a name here that the shell then reports as
    // `command not found` (or a command missing from `ls /usr/bin`) is a
    // one-line honeypot check. `binaries_match_the_command_registry` fails the
    // build if the two drift apart.
    for bin in USR_BIN {
        fs.add_file(usr_bin, bin, &b""[..], 0o755, 0, 0);
    }
    for bin in USR_SBIN {
        fs.add_file(usr_sbin, bin, &b""[..], 0o755, 0, 0);
    }

    // /etc files.
    fs.add_file(etc, "os-release", OS_RELEASE, 0o644, 0, 0);
    fs.add_file(etc, "debian_version", "12.5\n", 0o644, 0, 0);
    fs.add_file(etc, "hostname", format!("{hostname}\n"), 0o644, 0, 0);
    fs.add_file(etc, "hosts", hosts_file(hostname), 0o644, 0, 0);
    fs.add_file(etc, "passwd", PASSWD, 0o644, 0, 0);
    fs.add_file(etc, "group", GROUP, 0o644, 0, 0);
    fs.add_file(etc, "shadow", SHADOW, 0o640, 0, 42);
    fs.add_file(
        etc,
        "resolv.conf",
        "nameserver 127.0.0.53\noptions edns0 trust-ad\n",
        0o644,
        0,
        0,
    );
    fs.add_file(etc, "issue", "Debian GNU/Linux 12 \\n \\l\n\n", 0o644, 0, 0);
    // Derived per deployment: a constant here would be a single-command,
    // zero-false-positive check for anyone who has read this source.
    fs.add_file(
        etc,
        "machine-id",
        format!("{}\n", persona.machine_id),
        0o444,
        0,
        0,
    );
    fs.mkdir(etc, "ssh", 0o755, 0, 0);
    fs.mkdir(etc, "apt", 0o755, 0, 0);
    fs.mkdir(etc, "systemd", 0o755, 0, 0);
    fs.mkdir(etc, "network", 0o755, 0, 0);

    // /proc files.
    fs.add_file(proc, "cpuinfo", cpuinfo(persona), 0o444, 0, 0);
    fs.add_file(proc, "meminfo", meminfo(persona), 0o444, 0, 0);
    fs.add_file(proc, "version", VERSION, 0o444, 0, 0);
    // Derived from the same boot anchor as the `uptime`/`top`/`w` banners so
    // `cat /proc/uptime` can't contradict them. The idle field is the busier
    // "0.98 of one core idle" ratio a mostly-quiet single-core box shows.
    //
    // ponytail: a snapshot file is a fixed string, so this is the uptime at
    // session start and does not tick within a session the way the banners do;
    // upgrade when the VFS grows generated files.
    let up = crate::clock::uptime_secs();
    fs.add_file(
        proc,
        "uptime",
        format!("{up}.42 {:.2}\n", up as f64 * 0.9846),
        0o444,
        0,
        0,
    );
    fs.add_file(proc, "loadavg", "0.08 0.03 0.01 1/128 9241\n", 0o444, 0, 0);

    // /var subtree.
    let var_log = fs.mkdir(var, "log", 0o755, 0, 0);
    fs.mkdir(var, "www", 0o755, 0, 0);
    fs.mkdir(var, "cache", 0o755, 0, 0);
    fs.mkdir(var, "lib", 0o755, 0, 0);
    fs.mkdir(var, "spool", 0o755, 0, 0);
    fs.mkdir(var, "tmp", 0o1777, 0, 0);
    fs.mkdir(var, "backups", 0o755, 0, 0);
    fs.add_file(var_log, "wtmp", &b""[..], 0o664, 0, 43);
    fs.add_file(var_log, "lastlog", &b""[..], 0o664, 0, 43);
    fs.add_file(var_log, "auth.log", &b""[..], 0o640, 0, 4);
    fs.add_file(var_log, "syslog", &b""[..], 0o640, 0, 4);

    // /tmp is empty by default.
    let _ = tmp;

    // /root dotfiles.
    fs.add_file(root_home, ".bashrc", BASHRC, 0o644, 0, 0);
    fs.add_file(root_home, ".profile", PROFILE, 0o644, 0, 0);
    fs.add_file(root_home, ".bash_logout", "# ~/.bash_logout\n", 0o644, 0, 0);

    // The standard regular user (uid 1000).
    let user_home = fs.mkdir(home, "user", 0o755, 1000, 1000);
    fs.add_file(user_home, ".bashrc", BASHRC, 0o644, 1000, 1000);
    fs.add_file(user_home, ".profile", PROFILE, 0o644, 1000, 1000);
    fs.add_file(
        user_home,
        ".bash_logout",
        "# ~/.bash_logout\n",
        0o644,
        1000,
        1000,
    );

    // Everything above is part of the box as installed, so it carries the
    // install date rather than the moment this session opened. Nodes the
    // attacker creates later keep the current time `Metadata::new` stamps.
    fs.set_all_mtimes(crate::clock::install_time());
    fs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::nodes::NodeKind;

    fn read(fs: &Vfs, path: &str) -> String {
        let id = fs.resolve(fs.root(), path).expect("path should resolve");
        match &fs.node(id).kind {
            NodeKind::File { contents } => String::from_utf8_lossy(contents).into_owned(),
            _ => panic!("{path} is not a regular file"),
        }
    }

    /// `ls /usr/bin` may only show binaries the shell can actually run, and
    /// every runnable command must be there: `-bash: python3: command not
    /// found` for a file the attacker just saw listed identifies the honeypot
    /// in two commands.
    #[test]
    fn binaries_match_the_command_registry() {
        use std::collections::BTreeSet;

        let listed: BTreeSet<&str> = USR_BIN.iter().chain(USR_SBIN).copied().collect();
        let runnable: BTreeSet<&str> = crate::shell::complete::COMMANDS
            .iter()
            .copied()
            .filter(|name| !crate::commands::system::BUILTINS.contains(name))
            .collect();

        assert_eq!(
            listed.difference(&runnable).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "listed under /usr/bin or /usr/sbin but not runnable"
        );
        assert_eq!(
            runnable.difference(&listed).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "runnable but missing from /usr/bin and /usr/sbin"
        );
    }

    #[test]
    fn hostname_is_consistent_across_files() {
        let fs = build("web-prod-01", &Persona::sample());

        assert_eq!(read(&fs, "/etc/hostname"), "web-prod-01\n");

        let hosts = read(&fs, "/etc/hosts");
        assert!(
            hosts.contains("127.0.1.1\tweb-prod-01\n"),
            "/etc/hosts should alias the configured hostname, got: {hosts:?}"
        );
        assert!(hosts.contains("127.0.0.1\tlocalhost\n"));
    }

    #[test]
    fn proc_uptime_matches_command_banner() {
        let fs = build("srv1", &Persona::sample());
        let first = read(&fs, "/proc/uptime");
        let secs: f64 = first
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("/proc/uptime first field should be a number");
        // Must decode to the same phrase the `uptime`/`top`/`w` banners print.
        assert_eq!(
            crate::clock::uptime_phrase(secs as i64),
            crate::clock::uptime_phrase(crate::clock::uptime_secs())
        );
        // The idle field can never exceed the uptime on a single-core box.
        let idle: f64 = first
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("/proc/uptime second field should be a number");
        assert!(idle < secs, "idle {idle} should be below uptime {secs}");
    }

    /// The snapshot is the box as installed: dated before this process
    /// started, and — unlike a file the attacker creates — never "now".
    #[test]
    fn snapshot_files_carry_the_install_date() {
        let mut fs = build("srv1", &Persona::sample());
        let etc = fs.resolve(fs.root(), "/etc/passwd").expect("/etc/passwd");
        assert_eq!(fs.node(etc).meta.mtime, crate::clock::install_time());
        assert!(fs.node(etc).meta.mtime < crate::clock::now());

        let tmp = fs.resolve(fs.root(), "/tmp").expect("/tmp");
        let fresh = fs.mkdir(tmp, "new", 0o755, 0, 0);
        assert!(fs.node(fresh).meta.mtime >= crate::clock::install_time());
        assert!(fs.node(fresh).meta.mtime > fs.node(etc).meta.mtime);
    }

    #[test]
    fn common_paths_exist_with_expected_content() {
        let fs = build("srv1", &Persona::sample());
        let root = fs.root();

        assert!(read(&fs, "/etc/os-release").contains("bookworm"));
        assert!(read(&fs, "/etc/passwd").contains("user:x:1000:1000:"));
        assert!(read(&fs, "/proc/cpuinfo").contains("model name\t: Intel"));

        // Merged-/usr symlink resolves to a real binary.
        assert!(fs.resolve(root, "/bin/ls").is_some());
    }

    #[test]
    fn shadow_holds_no_real_credentials() {
        let fs = build("srv1", &Persona::sample());
        let shadow = read(&fs, "/etc/shadow");
        assert!(shadow.contains("root:!:"), "root must be locked");
        assert!(
            shadow.contains("$6$"),
            "user row must look like a real SHA-512 crypt hash"
        );
        // The hash content itself must not be a self-identifying tell: no
        // English words like "placeholder"/"honeypot"/"fake"/"dummy" that
        // would instantly out this as a decoy to anyone who reads it (e.g.
        // via `cat /etc/shadow` if a future bug bypasses permission checks).
        let lower = shadow.to_lowercase();
        for tell in ["placeholder", "honeypot", "fake", "dummy", "mimic"] {
            assert!(
                !lower.contains(tell),
                "shadow content must not contain the identifying word {tell:?}"
            );
        }
    }
}
