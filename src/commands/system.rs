//! System and identity commands: `whoami`, `id`, `uname`, `hostname`, `echo`,
//! `env`, `export`, `unset`, `clear`, plus process-table emulation (`ps`,
//! `top`, `kill`, `free`, `uptime`).
//!
//! There is no real process table — every row is fabricated from a static base
//! plus the session's own fake shell PID. `kill` never signals anything; it
//! only validates the target PID against the fake table and returns the message
//! a real shell would.

use super::CommandResult;
use crate::shell::complete::COMMANDS;
use crate::shell::Shell;

/// Emulated kernel release (`uname -r`).
const KERNEL_RELEASE: &str = "6.1.0-21-amd64";
/// Emulated kernel version (`uname -v`).
const KERNEL_VERSION: &str = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)";
/// Emulated machine hardware name (`uname -m`).
const MACHINE: &str = "x86_64";

/// `whoami`
pub fn whoami(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.username))
}

/// `id`
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

/// `uname [OPTION]...`
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

/// `hostname`
pub fn hostname(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.hostname))
}

/// `nproc` — matches the single-core `/proc/cpuinfo` snapshot.
pub fn nproc(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok("1\n")
}

/// `lscpu` — describes the same single-core Xeon presented by `/proc/cpuinfo`.
pub fn lscpu(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(
        "Architecture:             x86_64\n\
         CPU op-mode(s):           32-bit, 64-bit\n\
         Byte Order:               Little Endian\n\
         CPU(s):                   1\n\
         On-line CPU(s) list:      0\n\
         Vendor ID:                GenuineIntel\n\
         Model name:               Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n\
         CPU family:               6\n\
         Model:                    85\n\
         Thread(s) per core:       1\n\
         Core(s) per socket:       1\n\
         Socket(s):                1\n\
         Stepping:                 7\n\
         BogoMIPS:                 5000.00\n\
         Hypervisor vendor:        KVM\n\
         Virtualization type:      full\n",
    )
}

/// `sudo [-u USER] [-l] COMMAND [ARG]...`
///
/// The honeypot never gates this on a real password: the attacker's session
/// credentials were already accepted at login, and `id` already reports
/// membership in the `sudo` group, so denying here would be an inconsistent
/// tell for no forensic benefit. Elevation only lasts for the wrapped
/// command; the caller's uid/gid are restored afterward.
pub fn sudo(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.peek() {
        match arg.as_str() {
            "-l" | "--list" => {
                return CommandResult::ok(format!(
                    "Matching Defaults entries for {user} on {host}:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\nUser {user} may run the following commands on {host}:\n    (ALL : ALL) ALL\n",
                    user = shell.username,
                    host = shell.hostname,
                ));
            }
            "-u" => {
                iter.next();
                iter.next(); // consume the target username
            }
            other if other.starts_with('-') => {
                iter.next();
            }
            _ => break,
        }
    }
    let rest: Vec<String> = iter.cloned().collect();
    if rest.is_empty() {
        return CommandResult::err(
            "usage: sudo -h | -K | -k | -V\n\
             usage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]\n\
             usage: sudo -l [-ABkNnS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]\n\
             usage: sudo [-ABbEHknPS] [-r role] [-t type] [-C fd] [-D directory] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] [VAR=value] [-i | -s] [<command>]\n",
            1,
        );
    }
    let (uid, gid) = (shell.uid, shell.gid);
    shell.uid = 0;
    shell.gid = 0;
    let result = super::dispatch(shell, &rest);
    shell.uid = uid;
    shell.gid = gid;
    result
}

/// `su [-] [USER]`
///
/// Switches the session's effective identity, as a fresh login shell for
/// `USER` (root if omitted). Like `sudo`, this never fails on a real password
/// check for the same reason.
///
/// ponytail: `-c COMMAND` is accepted but ignored beyond still switching
/// identity; add transient (non-persistent) elevation if that distinction
/// ever matters for captured sessions.
pub fn su(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut target: Option<&str> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--command" | "-s" | "--shell" | "-g" | "--group" => {
                iter.next(); // takes a value; accepted, ignored
            }
            other if other.starts_with('-') => {} // "-", "-l", "--login", ...: accepted, no-op
            other => target = Some(other),
        }
    }
    shell.switch_user(target.unwrap_or("root"));
    CommandResult::empty()
}

/// `echo [-ne] [STRING]...`
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
    if interpret {
        text = interpret_escapes(&text);
    }
    if !no_newline {
        text.push('\n');
    }
    CommandResult::ok(text)
}

/// Interpret the backslash escapes `echo -e` understands.
fn interpret_escapes(s: &str) -> String {
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
            Some('0') => out.push('\0'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// `env` / `printenv`
pub fn env(shell: &Shell, _args: &[String]) -> CommandResult {
    let mut out = String::new();
    for (key, value) in shell.env.iter() {
        out.push_str(&format!("{key}={value}\n"));
    }
    CommandResult::ok(out)
}

/// `export [NAME=VALUE]...`
pub fn export(shell: &mut Shell, args: &[String]) -> CommandResult {
    for arg in args {
        if let Some((name, value)) = arg.split_once('=') {
            shell.env.set(name, value);
        }
    }
    CommandResult::empty()
}

/// `unset NAME...`
pub fn unset(shell: &mut Shell, args: &[String]) -> CommandResult {
    for arg in args {
        shell.env.unset(arg);
    }
    CommandResult::empty()
}

/// `clear`
pub fn clear(_shell: &Shell, _args: &[String]) -> CommandResult {
    // ANSI: move cursor home, clear screen, clear scrollback.
    CommandResult::ok("\x1b[H\x1b[2J\x1b[3J")
}

/// One row of the fabricated process table.
struct Proc {
    pid: u32,
    ppid: u32,
    user: String,
    tty: &'static str,
    stat: &'static str,
    /// %CPU.
    cpu: &'static str,
    /// %MEM.
    mem: &'static str,
    /// Virtual size in KiB.
    vsz: u32,
    /// Resident set size in KiB.
    rss: u32,
    time: &'static str,
    start: &'static str,
    cmd: String,
}

/// The static system processes a freshly booted Debian 12 VM shows.
fn base_table() -> Vec<Proc> {
    vec![
        Proc {
            pid: 1,
            ppid: 0,
            user: "root".to_string(),
            tty: "?",
            stat: "Ss",
            cpu: "0.0",
            mem: "0.4",
            vsz: 167404,
            rss: 13072,
            time: "0:02",
            start: "May03",
            cmd: "/sbin/init".to_string(),
        },
        Proc {
            pid: 2,
            ppid: 0,
            user: "root".to_string(),
            tty: "?",
            stat: "S",
            cpu: "0.0",
            mem: "0.0",
            vsz: 0,
            rss: 0,
            time: "0:00",
            start: "May03",
            cmd: "[kthreadd]".to_string(),
        },
        Proc {
            pid: 312,
            ppid: 1,
            user: "root".to_string(),
            tty: "?",
            stat: "Ss",
            cpu: "0.0",
            mem: "0.3",
            vsz: 24684,
            rss: 9216,
            time: "0:01",
            start: "May03",
            cmd: "/lib/systemd/systemd-journald".to_string(),
        },
        Proc {
            pid: 334,
            ppid: 1,
            user: "root".to_string(),
            tty: "?",
            stat: "Ss",
            cpu: "0.0",
            mem: "0.2",
            vsz: 21916,
            rss: 6400,
            time: "0:00",
            start: "May03",
            cmd: "/lib/systemd/systemd-udevd".to_string(),
        },
        Proc {
            pid: 501,
            ppid: 1,
            user: "systemd+".to_string(),
            tty: "?",
            stat: "Ssl",
            cpu: "0.0",
            mem: "0.3",
            vsz: 90264,
            rss: 9088,
            time: "0:00",
            start: "May03",
            cmd: "/lib/systemd/systemd-resolved".to_string(),
        },
        Proc {
            pid: 512,
            ppid: 1,
            user: "root".to_string(),
            tty: "?",
            stat: "Ss",
            cpu: "0.0",
            mem: "0.2",
            vsz: 6892,
            rss: 4992,
            time: "0:00",
            start: "May03",
            cmd: "/usr/sbin/cron -f".to_string(),
        },
        Proc {
            pid: 528,
            ppid: 1,
            user: "message+".to_string(),
            tty: "?",
            stat: "Ss",
            cpu: "0.0",
            mem: "0.2",
            vsz: 8460,
            rss: 4736,
            time: "0:00",
            start: "May03",
            cmd: "/usr/bin/dbus-daemon --system".to_string(),
        },
        Proc {
            pid: 604,
            ppid: 1,
            user: "root".to_string(),
            tty: "?",
            stat: "Ss",
            cpu: "0.0",
            mem: "0.4",
            vsz: 15420,
            rss: 9472,
            time: "0:00",
            start: "May03",
            cmd: "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups".to_string(),
        },
        Proc {
            pid: 611,
            ppid: 1,
            user: "root".to_string(),
            tty: "?",
            stat: "Ssl",
            cpu: "0.0",
            mem: "0.5",
            vsz: 313196,
            rss: 12544,
            time: "0:01",
            start: "May03",
            cmd: "/usr/lib/systemd/systemd-logind".to_string(),
        },
        Proc {
            pid: 1188,
            ppid: 1,
            user: "root".to_string(),
            tty: "tty1",
            stat: "Ss+",
            cpu: "0.0",
            mem: "0.1",
            vsz: 5612,
            rss: 3200,
            time: "0:00",
            start: "May03",
            cmd: "/sbin/agetty -o -p -- \\u --noclear tty1 linux".to_string(),
        },
    ]
}

/// Build the full table including this session's own login chain.
fn session_table(shell: &Shell) -> Vec<Proc> {
    let mut table = base_table();
    let user = shell.username.clone();
    let sshd_pid = shell.pid.saturating_sub(2).max(1000);
    let bash_pid = shell.pid;
    let ps_pid = shell.pid + 1;

    table.push(Proc {
        pid: sshd_pid,
        ppid: 604,
        user: user.clone(),
        tty: "?",
        stat: "Ss",
        cpu: "0.0",
        mem: "0.4",
        vsz: 17668,
        rss: 10880,
        time: "0:00",
        start: "10:14",
        cmd: format!("sshd: {}@pts/0", shell.username),
    });
    table.push(Proc {
        pid: bash_pid,
        ppid: sshd_pid,
        user: user.clone(),
        tty: "pts/0",
        stat: "Ss",
        cpu: "0.0",
        mem: "0.2",
        vsz: 8228,
        rss: 5376,
        time: "0:00",
        start: "10:14",
        cmd: "-bash".to_string(),
    });
    table.push(Proc {
        pid: ps_pid,
        ppid: bash_pid,
        user: user.clone(),
        tty: "pts/0",
        stat: "R+",
        cpu: "0.0",
        mem: "0.1",
        vsz: 10072,
        rss: 3200,
        time: "0:00",
        start: "10:15",
        cmd: "ps aux".to_string(),
    });
    table
}

/// `ps [aux|-ef|...]`
pub fn ps(shell: &Shell, args: &[String]) -> CommandResult {
    let joined: String = args.join("");
    let table = session_table(shell);

    // `ps aux` / `ps -ef` style: show every process. Bare `ps` shows only this
    // session's processes on its tty.
    let show_all = joined.contains('a')
        || joined.contains('e')
        || joined.contains('A')
        || args.iter().any(|a| a == "-ef" || a == "aux");
    let ef = args.iter().any(|a| a == "-ef") || joined.contains('f') && !joined.contains('u');
    let user_fmt = joined.contains('u') || args.iter().any(|a| a == "aux");

    let mut out = String::new();
    if ef {
        out.push_str("UID          PID    PPID  C STIME TTY          TIME CMD\n");
        for p in &table {
            if !show_all && p.tty != "pts/0" {
                continue;
            }
            out.push_str(&format!(
                "{:<8} {:>6} {:>7}  0 {:>5} {:<8} {:>8} {}\n",
                p.user, p.pid, p.ppid, p.start, p.tty, p.time, p.cmd
            ));
        }
    } else if user_fmt {
        out.push_str(
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n",
        );
        for p in &table {
            if !show_all && p.tty != "pts/0" {
                continue;
            }
            out.push_str(&format!(
                "{:<8} {:>5} {:>4} {:>4} {:>6} {:>5} {:<8} {:<4} {:>5} {:>6} {}\n",
                p.user, p.pid, p.cpu, p.mem, p.vsz, p.rss, p.tty, p.stat, p.start, p.time, p.cmd
            ));
        }
    } else {
        out.push_str("    PID TTY          TIME CMD\n");
        for p in &table {
            if !show_all && p.tty != "pts/0" {
                continue;
            }
            out.push_str(&format!(
                "{:>7} {:<12} {:>5} {}\n",
                p.pid,
                p.tty,
                p.time,
                p.cmd.split_whitespace().next().unwrap_or(&p.cmd)
            ));
        }
    }
    CommandResult::ok(out)
}

/// `top` (batch-mode snapshot; the interactive UI is not emulated).
pub fn top(shell: &Shell, _args: &[String]) -> CommandResult {
    let table = session_table(shell);
    let running = table.iter().filter(|p| p.stat.starts_with('R')).count();
    let sleeping = table.len() - running;

    let mut out = String::new();
    out.push_str("top - 10:15:42 up 2 days,  3:21,  1 user,  load average: 0.08, 0.03, 0.01\n");
    out.push_str(&format!(
        "Tasks: {:>3} total,   {} running, {:>3} sleeping,   0 stopped,   0 zombie\n",
        table.len(),
        running,
        sleeping
    ));
    out.push_str(
        "%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.4 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st\n",
    );
    out.push_str("MiB Mem :   1993.4 total,   1468.3 free,    128.7 used,    396.4 buff/cache\n");
    out.push_str("MiB Swap:      0.0 total,      0.0 free,      0.0 used.   1723.6 avail Mem\n");
    out.push('\n');
    out.push_str(
        "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n",
    );
    for p in &table {
        out.push_str(&format!(
            "{:>7} {:<8}  20   0 {:>7} {:>6} {:>6} {} {:>5} {:>5}   {:>7} {}\n",
            p.pid,
            p.user,
            p.vsz,
            p.rss,
            p.rss / 2,
            &p.stat[..1],
            p.cpu,
            p.mem,
            p.time,
            p.cmd.split_whitespace().next().unwrap_or(&p.cmd)
        ));
    }
    CommandResult::ok(out)
}

/// `kill [-SIG] PID...`
pub fn kill(shell: &Shell, args: &[String]) -> CommandResult {
    let mut pids: Vec<&str> = Vec::new();
    let mut list = false;
    for arg in args {
        match arg.as_str() {
            "-l" | "--list" => list = true,
            // Signal specifiers (e.g. -9, -SIGKILL, -s TERM): accepted, ignored.
            s if s.starts_with('-') => {}
            other => pids.push(other),
        }
    }

    if list {
        return CommandResult::ok(
            " 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\t 5) SIGTRAP\n\
             6) SIGABRT\t 7) SIGBUS\t 8) SIGFPE\t 9) SIGKILL\t10) SIGUSR1\n\
            11) SIGSEGV\t12) SIGUSR2\t13) SIGPIPE\t14) SIGALRM\t15) SIGTERM\n",
        );
    }

    if pids.is_empty() {
        return CommandResult::err(
            "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n",
            2,
        );
    }

    let table = session_table(shell);
    let mut out = String::new();
    let mut status = 0;
    for pid_str in pids {
        let Ok(pid) = pid_str.parse::<u32>() else {
            out.push_str(&format!(
                "-bash: kill: {pid_str}: arguments must be process or job IDs\n"
            ));
            status = 1;
            continue;
        };
        match table.iter().find(|p| p.pid == pid) {
            None => {
                out.push_str(&format!("-bash: kill: ({pid}) - No such process\n"));
                status = 1;
            }
            Some(p) => {
                // Non-root may only signal its own processes; system PIDs are
                // owned by root, so an unprivileged attacker is denied.
                if shell.uid != 0 && p.user != shell.username {
                    out.push_str(&format!("-bash: kill: ({pid}) - Operation not permitted\n"));
                    status = 1;
                }
                // Otherwise: silently "succeed" without affecting anything.
            }
        }
    }
    if status == 0 {
        CommandResult::empty()
    } else {
        CommandResult::err(out, status)
    }
}

/// `pkill [-SIGNAL] NAME`
///
/// Matches process names (substring) in the same fake table `ps`/`kill` use,
/// applying the same ownership rule as `kill`. Tab-completion has always
/// offered `pkill`; this closes the gap where it fell through to "command not
/// found".
pub fn pkill(shell: &Shell, args: &[String]) -> CommandResult {
    let names: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();

    if names.is_empty() {
        return CommandResult::err(
            "pkill: no matching criteria specified\nTry `pkill --help' for more information.\n",
            2,
        );
    }

    let table = session_table(shell);
    let mut out = String::new();
    let mut matched_any = false;
    let mut denied = false;
    for name in &names {
        for p in table.iter().filter(|p| p.cmd.contains(name)) {
            if shell.uid != 0 && p.user != shell.username {
                out.push_str(&format!(
                    "pkill: killing pid {} failed: Operation not permitted\n",
                    p.pid
                ));
                denied = true;
            } else {
                matched_any = true;
            }
        }
    }

    if denied {
        CommandResult::err(out, 1)
    } else if matched_any {
        CommandResult::empty()
    } else {
        CommandResult::err("", 1)
    }
}

/// `free [-h|-m|-g]`
pub fn free(_shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human");
    let mega = args.iter().any(|a| a == "-m");
    let giga = args.iter().any(|a| a == "-g");

    // Base figures in KiB.
    let (total, used, free_mem, shared, buff, available) =
        (2041208u64, 131800, 1503544, 992, 313072, 1764920);

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

/// Human-readable size for `free -h` (Gi/Mi/Ki units).
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
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

/// `uptime`
pub fn uptime(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(" 10:15:42 up 2 days,  3:21,  1 user,  load average: 0.08, 0.03, 0.01\n")
}

// --- Reconnaissance commands ---------------------------------------------
//
// The first things an attacker runs after login. Their *absence* is itself a
// tell, so each emulates plausible, internally consistent output. As with the
// process table, all values are fabricated and static (or per-session) so no
// real host detail and no other honeypot session is ever exposed.

/// Shell builtins that `which` reports as not on the PATH.
const BUILTINS: &[&str] = &[
    "cd", "export", "unset", "history", "exit", "logout", "alias", "source",
];

/// `history` — print the session's command history, bash-style.
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

/// `which NAME...`
pub fn which(_shell: &Shell, args: &[String]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::empty();
    }
    let mut out = String::new();
    let mut status = 0;
    for name in args {
        if BUILTINS.contains(&name.as_str()) {
            status = 1; // builtins are not external binaries
        } else if let Some(path) = binary_path(name) {
            out.push_str(&format!("{path}\n"));
        } else {
            status = 1;
        }
    }
    CommandResult::err(out, status)
}

/// Resolve a known command name to the absolute path `which` would print, or
/// `None` if it is not a recognised external binary.
fn binary_path(name: &str) -> Option<String> {
    if !COMMANDS.contains(&name) || BUILTINS.contains(&name) {
        return None;
    }
    let dir = match name {
        "ip" | "ss" => "/usr/sbin",
        _ => "/usr/bin",
    };
    Some(format!("{dir}/{name}"))
}

/// `w` — who is logged on and what they are doing. A single fabricated session
/// for the current user; other connections are never revealed.
pub fn w(shell: &Shell, _args: &[String]) -> CommandResult {
    let header = " 10:15:42 up 2 days,  3:21,  1 user,  load average: 0.08, 0.03, 0.01\n";
    let cols = "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n";
    let row = format!(
        "{user:<8} pts/0    10.0.0.5         10:01    0.00s  0.02s  0.00s w\n",
        user = truncate(&shell.username, 8),
    );
    CommandResult::ok(format!("{header}{cols}{row}"))
}

/// `last` — listing of last logged-in users. Fabricated and static.
pub fn last(shell: &Shell, _args: &[String]) -> CommandResult {
    let out = format!(
        "{user:<8} pts/0        10.0.0.5         Mon Jun 24 10:01   still logged in\n\
         reboot   system boot  6.1.0-21-amd64   Mon Jun 24 07:00   still running\n\
         \n\
         wtmp begins Mon Jun 24 07:00:00 2024\n",
        user = truncate(&shell.username, 8),
    );
    CommandResult::ok(out)
}

/// `df [-h]`
pub fn df(_shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human-readable");
    let out = if human {
        "Filesystem      Size  Used Avail Use% Mounted on\n\
         udev            3.9G     0  3.9G   0% /dev\n\
         tmpfs           789M  960K  788M   1% /run\n\
         /dev/sda1        40G  6.3G   31G  17% /\n\
         tmpfs           3.9G     0  3.9G   0% /dev/shm\n\
         tmpfs           5.0M     0  5.0M   0% /run/lock\n\
         tmpfs           789M     0  789M   0% /run/user/0\n"
    } else {
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n\
         udev             4019216       0   4019216   0% /dev\n\
         tmpfs             807868     960    806908   1% /run\n\
         /dev/sda1       41019672 6552432  32352140  17% /\n\
         tmpfs            4039332       0   4039332   0% /dev/shm\n\
         tmpfs               5120       0      5120   0% /run/lock\n\
         tmpfs             807864       0    807864   0% /run/user/0\n"
    };
    CommandResult::ok(out)
}

/// `mount` — print the (fabricated) mount table.
pub fn mount(_shell: &Shell, _args: &[String]) -> CommandResult {
    let out = "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n\
        proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n\
        udev on /dev type devtmpfs (rw,nosuid,relatime,size=4019216k,nr_inodes=1004804,mode=755)\n\
        devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)\n\
        tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=807868k,mode=755)\n\
        /dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n\
        tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)\n\
        tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k,inode64)\n";
    CommandResult::ok(out)
}

/// `crontab [-l|-e|-r]`
pub fn crontab(shell: &Shell, args: &[String]) -> CommandResult {
    if args.iter().any(|a| a == "-l") {
        return CommandResult::err(format!("no crontab for {}\n", shell.username), 1);
    }
    if args.iter().any(|a| a == "-r" || a == "-e") {
        // Removing/editing a non-existent crontab is a no-op / opens an editor;
        // for an emulated session we simply report nothing.
        return CommandResult::empty();
    }
    CommandResult::err(
        "usage:  crontab [-u user] file\n\
         \tcrontab [ -u user ] [ -i ] { -e | -l | -r }\n",
        1,
    )
}

/// Truncate `s` to at most `n` characters (ASCII usernames), for column
/// alignment.
fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `groups [USER]...` — the group memberships mirrored from `id`.
pub fn groups(shell: &Shell, _args: &[String]) -> CommandResult {
    let line = if shell.uid == 0 {
        "root".to_string()
    } else {
        format!("{} sudo", shell.username)
    };
    CommandResult::ok(format!("{line}\n"))
}

/// `arch` — machine hardware name, matching `uname -m`.
pub fn arch(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{MACHINE}\n"))
}

/// `tty` — the pseudo-terminal this session runs on (matches `ps`/`w`).
pub fn tty(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok("/dev/pts/0\n")
}

/// `lsb_release [-a|-s|-i|-d|-r|-c]` — Debian 12 (bookworm) release info.
///
/// A near-universal fingerprinting step in automated recon; the values match
/// the `/etc/os-release` snapshot the VFS presents.
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
                    _ => {} // -v etc.: accepted, ignored
                }
            }
        }
    }

    // Bare invocation or -a lists every field.
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

/// A static kernel ring buffer for `dmesg`, shown only to root.
const DMESG_BUFFER: &str = "\
[    0.000000] Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)\n\
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-6.1.0-21-amd64 root=UUID=8f3a2b1c-4d5e-6f70-8192-a3b4c5d6e7f8 ro console=tty0 console=ttyS0,115200\n\
[    0.000000] BIOS-provided physical RAM map:\n\
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable\n\
[    0.000000] KVM: setup async PF for cpu 0\n\
[    0.008000] Hypervisor detected: KVM\n\
[    0.020000] CPU0: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz (family: 0x6, model: 0x55, stepping: 0x7)\n\
[    0.130000] Memory: 4019216K/4194304K available\n\
[    0.410000] pci 0000:00:00.0: [8086:1237] type 00 class 0x060000\n\
[    0.512000] virtio_blk virtio1: [vda] 83886080 512-byte logical blocks (42.9 GB/40.0 GiB)\n\
[    0.640000] ata1.00: ATA-8: QEMU HARDDISK, 2.5+, max UDMA/100\n\
[    0.900000] EXT4-fs (sda1): mounted filesystem with ordered data mode. Quota mode: none.\n\
[    1.220000] systemd[1]: systemd 252.22-1~deb12u1 running in system mode\n\
[    1.480000] systemd[1]: Detected virtualization kvm.\n\
[    1.481000] systemd[1]: Detected architecture x86-64.\n\
[    2.310000] e1000: eth0 NIC Link is Up 1000 Mbps Full Duplex\n\
[    2.640000] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready\n";

/// `dmesg` — the kernel ring buffer.
///
/// Debian 12 ships `kernel.dmesg_restrict=1`, so an unprivileged user gets a
/// permission error; only root sees the (fabricated) buffer.
pub fn dmesg(shell: &Shell, _args: &[String]) -> CommandResult {
    if shell.uid != 0 {
        return CommandResult::err(
            "dmesg: read kernel buffer failed: Operation not permitted\n",
            1,
        );
    }
    CommandResult::ok(DMESG_BUFFER)
}

/// Current wall-clock time in unix seconds.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A broken-down UTC timestamp.
struct Tm {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
    /// Days since Sunday, `0..=6`.
    wday: u32,
    /// Days since Jan 1, `0..=365`.
    yday: u32,
}

/// Convert unix seconds to broken-down UTC using Howard Hinnant's civil-date
/// algorithm (valid across the full `i64` range, no external crate).
fn gmtime(secs: i64) -> Tm {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u32;
    let min = ((rem % 3600) / 60) as u32;
    let sec = (rem % 60) as u32;
    // 1970-01-01 was a Thursday (index 4 with Sunday = 0).
    let wday = ((days.rem_euclid(7) + 4) % 7) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    const CUM: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut yday = CUM[(month - 1) as usize] + (day - 1);
    if leap && month > 2 {
        yday += 1;
    }

    Tm {
        year,
        month,
        day,
        hour,
        min,
        sec,
        wday,
        yday,
    }
}

const WDAY: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const WDAY_FULL: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MON: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const MON_FULL: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// Render a `date` `+FORMAT` string against a broken-down time. Supports the
/// specifiers that appear in real-world recon (`%Y %m %d %H %M %S %s %a %A %b
/// %B %e %j %y %p %F %T %Z %n %t %%`); unknown specifiers pass through verbatim.
fn strftime(tm: &Tm, epoch: i64, fmt: &str) -> String {
    let mut out = String::new();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&tm.year.to_string()),
            Some('y') => out.push_str(&format!("{:02}", tm.year.rem_euclid(100))),
            Some('m') => out.push_str(&format!("{:02}", tm.month)),
            Some('d') => out.push_str(&format!("{:02}", tm.day)),
            Some('e') => out.push_str(&format!("{:2}", tm.day)),
            Some('H') => out.push_str(&format!("{:02}", tm.hour)),
            Some('M') => out.push_str(&format!("{:02}", tm.min)),
            Some('S') => out.push_str(&format!("{:02}", tm.sec)),
            Some('s') => out.push_str(&epoch.to_string()),
            Some('j') => out.push_str(&format!("{:03}", tm.yday + 1)),
            Some('a') => out.push_str(WDAY[tm.wday as usize]),
            Some('A') => out.push_str(WDAY_FULL[tm.wday as usize]),
            Some('b') | Some('h') => out.push_str(MON[(tm.month - 1) as usize]),
            Some('B') => out.push_str(MON_FULL[(tm.month - 1) as usize]),
            Some('p') => out.push_str(if tm.hour < 12 { "AM" } else { "PM" }),
            Some('Z') => out.push_str("UTC"),
            Some('F') => out.push_str(&format!("{}-{:02}-{:02}", tm.year, tm.month, tm.day)),
            Some('T') => out.push_str(&format!("{:02}:{:02}:{:02}", tm.hour, tm.min, tm.sec)),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// `date [-u] [+FORMAT]` — the current UTC time.
///
/// The emulated host runs in UTC, so the `-u` flag is a no-op. Setting the
/// clock (`date MMDDhhmm...`) would require root and is accepted as a no-op
/// that echoes the current time back.
///
/// ponytail: read-only clock (uses the real host time, which is realistic for a
/// live box); does not honour a `date STRING` set operand beyond echoing.
pub fn date(_shell: &Shell, args: &[String]) -> CommandResult {
    let epoch = now_unix();
    let tm = gmtime(epoch);
    let fmt = args.iter().find_map(|a| a.strip_prefix('+'));
    let out = match fmt {
        Some(f) => strftime(&tm, epoch, f),
        // Default C-locale form: `Wed Jul  8 12:34:56 UTC 2026`.
        None => strftime(&tm, epoch, "%a %b %e %H:%M:%S %Z %Y"),
    };
    CommandResult::ok(format!("{out}\n"))
}

#[cfg(test)]
mod tests {
    use super::{gmtime, strftime, WDAY};
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn whoami_and_hostname_reflect_identity() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "whoami"), "root\n");
        assert_eq!(run(&mut shell, "hostname"), "debian\n");
    }

    #[test]
    fn id_distinguishes_root_from_user() {
        let mut root = Shell::new("root", "debian");
        assert_eq!(
            run(&mut root, "id"),
            "uid=0(root) gid=0(root) groups=0(root)\n"
        );
        let mut user = Shell::new("attacker", "debian");
        assert_eq!(
            run(&mut user, "id"),
            "uid=1000(attacker) gid=1000(attacker) groups=1000(attacker),27(sudo)\n"
        );
    }

    #[test]
    fn uname_defaults_and_flags() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "uname"), "Linux\n");
        assert_eq!(run(&mut shell, "uname -r"), "6.1.0-21-amd64\n");
        assert_eq!(
            run(&mut shell, "uname -a"),
            "Linux debian 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64 GNU/Linux\n"
        );
        // Combined short flags.
        assert_eq!(run(&mut shell, "uname -sm"), "Linux x86_64\n");
    }

    #[test]
    fn echo_newline_and_escapes() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo hello world"), "hello world\n");
        assert_eq!(run(&mut shell, "echo -n hi"), "hi");
        // Single quotes preserve the backslash so `echo -e` can interpret it.
        assert_eq!(run(&mut shell, r"echo -e 'a\tb'"), "a\tb\n");
        // Without -e, the escape stays literal.
        assert_eq!(run(&mut shell, r"echo 'a\tb'"), "a\\tb\n");
    }

    #[test]
    fn export_unset_and_env_roundtrip() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "export FOO=bar"), "");
        assert_eq!(run(&mut shell, "echo $FOO"), "bar\n");
        assert!(run(&mut shell, "env").contains("FOO=bar\n"));
        assert_eq!(run(&mut shell, "unset FOO"), "");
        assert_eq!(run(&mut shell, "echo $FOO"), "\n");
    }

    #[test]
    fn clear_emits_ansi_reset() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "clear"), "\x1b[H\x1b[2J\x1b[3J");
    }

    #[test]
    fn ps_aux_lists_system_and_session() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "ps aux");
        assert!(out.contains("USER"));
        assert!(out.contains("/sbin/init"));
        assert!(out.contains("sshd"));
        assert!(out.contains("-bash"));
    }

    #[test]
    fn ps_ef_format() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "ps -ef");
        assert!(out.contains("UID"));
        assert!(out.contains("PPID"));
    }

    #[test]
    fn kill_unknown_pid_errors() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("kill 999999");
        assert!(out.text.contains("No such process"));
        assert_eq!(shell.last_status, 1);
    }

    #[test]
    fn kill_system_pid_denied_for_nonroot() {
        let mut shell = Shell::new("attacker", "debian");
        let out = shell.execute("kill 1");
        assert!(out.text.contains("Operation not permitted"));
        assert_eq!(shell.last_status, 1);
    }

    #[test]
    fn top_and_free_render() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "top").contains("Tasks:"));
        assert!(run(&mut shell, "free").contains("Mem:"));
        assert!(run(&mut shell, "free -h").contains("Mi"));
    }

    #[test]
    fn uptime_renders() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "uptime").contains("load average:"));
    }

    #[test]
    fn history_numbers_then_clears() {
        let mut shell = Shell::new("root", "debian");
        shell.record_history("ls");
        shell.record_history("pwd");
        let out = run(&mut shell, "history");
        assert!(out.contains("    1  ls"));
        assert!(out.contains("    2  pwd"));
        run(&mut shell, "history -c");
        assert!(shell.history.is_empty());
    }

    #[test]
    fn which_external_builtin_and_sbin() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "which wget"), "/usr/bin/wget\n");
        assert_eq!(run(&mut shell, "which ip"), "/usr/sbin/ip\n");
        // Builtins are not external binaries: no output, status 1.
        assert_eq!(run(&mut shell, "which cd"), "");
        assert_eq!(shell.last_status, 1);
    }

    #[test]
    fn w_and_last_show_current_user_only() {
        let mut shell = Shell::new("attacker", "debian");
        let w = run(&mut shell, "w");
        assert!(w.contains("load average:"));
        assert!(w.contains("attacker"));
        let last = run(&mut shell, "last");
        assert!(last.contains("attacker"));
        assert!(last.contains("wtmp begins"));
    }

    #[test]
    fn df_human_flag_changes_units() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "df").contains("1K-blocks"));
        assert!(run(&mut shell, "df -h").contains("Size"));
    }

    #[test]
    fn mount_lists_fabricated_table() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "mount").contains("/dev/sda1 on / type ext4"));
    }

    #[test]
    fn crontab_l_reports_none() {
        let mut shell = Shell::new("attacker", "debian");
        assert_eq!(run(&mut shell, "crontab -l"), "no crontab for attacker\n");
        assert_eq!(shell.last_status, 1);
    }

    #[test]
    fn nproc_and_lscpu_match_cpuinfo() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "nproc"), "1\n");
        assert!(run(&mut shell, "lscpu").contains("Xeon(R) Platinum 8259CL"));
    }

    #[test]
    fn sudo_elevates_for_one_command_then_restores() {
        let mut shell = Shell::new("attacker", "debian");
        assert_eq!(shell.uid, 1000);
        // A privileged apt subcommand is denied without sudo...
        assert!(run(&mut shell, "apt update").contains("Permission denied"));
        // ...but succeeds prefixed with sudo, and uid is restored afterward.
        assert!(run(&mut shell, "sudo apt update").contains("Reading package lists"));
        assert_eq!(shell.uid, 1000);
    }

    #[test]
    fn sudo_list_and_bare_usage() {
        let mut shell = Shell::new("attacker", "debian");
        assert!(run(&mut shell, "sudo -l").contains("(ALL : ALL) ALL"));
        assert!(run(&mut shell, "sudo").contains("usage: sudo"));
    }

    #[test]
    fn su_switches_identity_and_home() {
        let mut shell = Shell::new("attacker", "debian");
        assert_eq!(run(&mut shell, "su"), "");
        assert_eq!(shell.username, "root");
        assert_eq!(shell.uid, 0);
        assert_eq!(shell.cwd_path(), "/root");
        // `su attacker` (or any other name) switches back to a normal account.
        assert_eq!(run(&mut shell, "su someoneelse"), "");
        assert_eq!(shell.uid, 1000);
        assert_eq!(shell.cwd_path(), "/home/someoneelse");
    }

    #[test]
    fn pkill_matches_by_name_and_respects_ownership() {
        let mut root = Shell::new("root", "debian");
        assert_eq!(run(&mut root, "pkill bash"), "");
        let mut user = Shell::new("attacker", "debian");
        // The fake table's system processes are owned by root; a non-root
        // session may not "kill" them.
        assert!(run(&mut user, "pkill sshd").contains("Operation not permitted"));
        assert!(run(&mut user, "pkill no-such-process").is_empty());
    }

    #[test]
    fn groups_arch_and_tty_reflect_identity() {
        let mut root = Shell::new("root", "debian");
        assert_eq!(run(&mut root, "groups"), "root\n");
        assert_eq!(run(&mut root, "arch"), "x86_64\n");
        assert_eq!(run(&mut root, "tty"), "/dev/pts/0\n");
        let mut user = Shell::new("attacker", "debian");
        assert_eq!(run(&mut user, "groups"), "attacker sudo\n");
    }

    #[test]
    fn lsb_release_all_and_short_forms() {
        let mut shell = Shell::new("root", "debian");
        let all = run(&mut shell, "lsb_release -a");
        assert!(all.contains("Distributor ID:\tDebian"));
        assert!(all.contains("Description:\tDebian GNU/Linux 12 (bookworm)"));
        assert!(all.contains("Codename:\tbookworm"));
        // Short selectors print just the value.
        assert_eq!(run(&mut shell, "lsb_release -cs"), "bookworm\n");
        assert_eq!(run(&mut shell, "lsb_release -rs"), "12\n");
    }

    #[test]
    fn dmesg_is_root_only() {
        let mut root = Shell::new("root", "debian");
        assert!(run(&mut root, "dmesg").contains("Hypervisor detected: KVM"));
        let mut user = Shell::new("attacker", "debian");
        assert!(run(&mut user, "dmesg").contains("Operation not permitted"));
        assert_eq!(user.last_status, 1);
    }

    #[test]
    fn date_default_and_format_specifiers() {
        let mut shell = Shell::new("root", "debian");
        // Default form: `Wdy Mon DD HH:MM:SS UTC YYYY`.
        let default = run(&mut shell, "date");
        assert!(default.contains("UTC"));
        assert!(default.ends_with('\n'));
        // %F/%T/%s formats are self-consistent with gmtime.
        let f = run(&mut shell, "date +%F");
        assert_eq!(f.matches('-').count(), 2);
        assert_eq!(run(&mut shell, "date +%%"), "%\n");
    }

    #[test]
    fn gmtime_matches_known_epoch() {
        // 1_714_694_400 = 2024-05-03 00:00:00 UTC (a Friday).
        let tm = gmtime(1_714_694_400);
        assert_eq!((tm.year, tm.month, tm.day), (2024, 5, 3));
        assert_eq!((tm.hour, tm.min, tm.sec), (0, 0, 0));
        assert_eq!(WDAY[tm.wday as usize], "Fri");
        assert_eq!(
            strftime(&tm, 1_714_694_400, "%a %b %e %H:%M:%S %Z %Y"),
            "Fri May  3 00:00:00 UTC 2024"
        );
    }
}
