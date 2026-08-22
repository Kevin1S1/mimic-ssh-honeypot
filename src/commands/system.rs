//! System and identity commands: `whoami`, `id`, `uname`, `hostname`, `echo`,
//! `env`, `export`, `unset`, `clear`, plus process-table emulation (`ps`,
//! `top`, `kill`, `free`, `uptime`).
//!
//! There is no real process table — every row is fabricated from a static base
//! plus the session's own fake shell PID. `kill` never signals anything; it
//! only validates the target PID against the fake table and returns the message
//! a real shell would.

use super::CommandResult;
use crate::clock;
use crate::shell::complete::COMMANDS;
use crate::shell::{Pending, Shell};

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

/// `bash`/`sh` — the shell this session already claims to be.
///
/// `-c LINE` runs the line, which is how bot payloads usually arrive
/// (`sh -c "cd /tmp; wget ...; ./x"`). Without `-c` a real shell would start an
/// interactive subshell: since the emulated prompt is identical either way,
/// returning immediately is indistinguishable to the attacker.
pub fn shell_cmd(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" => {
                let Some(line) = iter.next() else {
                    return CommandResult::err("bash: -c: option requires an argument\n", 2);
                };
                let argv = shell.parse_line(line);
                if argv.is_empty() {
                    return CommandResult::ok("");
                }
                return super::dispatch(shell, &argv);
            }
            // Interactive/login flags change nothing here.
            "-i" | "-l" | "-s" | "--login" | "-" => {}
            // ponytail: a script operand runs nothing (an empty script is the
            // honest reading of a VFS file with no executable semantics);
            // upgrade when the VFS can actually interpret file contents.
            _ => return CommandResult::ok(""),
        }
    }
    CommandResult::ok("")
}

/// `scp` run as an interactive command.
///
/// The binary has to exist — uploads to this host succeed, which means the
/// server side runs `scp -t` — but an interactive copy would need a real
/// network, so it fails as a refused connection — a "timed out" that returns
/// instantly would be a tell in itself. Transfer mode (`-t`/`-f`) never reaches
/// this handler: the SSH layer intercepts it before the shell sees it.
pub fn scp(shell: &mut Shell, args: &[String]) -> CommandResult {
    let operands: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if operands.len() < 2 {
        return CommandResult::err(
            "usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n           \
             [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n           \
             [-P port] [-S program] [-X sftp_option] source ... target\n",
            1,
        );
    }

    // A `host:path` operand means a real connection, which this host will never
    // make. It fails as a refused connection rather than a timeout: a timeout
    // that returns instantly is itself a tell.
    if let Some(host) = operands.iter().find_map(|op| {
        op.split_once(':')
            .map(|(h, _)| h.rsplit('@').next().unwrap_or(h))
            .filter(|h| !h.is_empty())
    }) {
        return CommandResult::err(
            format!("ssh: connect to host {host} port 22: Connection refused\nlost connection\n"),
            1,
        );
    }

    // Purely local operands: real scp just copies, so let `cp` do it.
    let argv: Vec<String> = std::iter::once("cp".to_string())
        .chain(operands.into_iter().cloned())
        .collect();
    super::dispatch(shell, &argv)
}

/// `sudo [-u USER] [-l] [-i | -s] COMMAND [ARG]...`
///
/// The honeypot never gates this on a real password: the attacker's session
/// credentials were already accepted at login, and `id` already reports
/// membership in the `sudo` group, so denying here would be an inconsistent
/// tell for no forensic benefit. Elevation only lasts for the wrapped
/// command; the caller's uid/gid are restored afterward.
///
/// `-i` and `-s` with no command are the exception: they are the two common
/// ways an attacker asks for a root *shell*, so they switch the session's
/// identity for good, the way [`su`] does. `-i` is a login shell (root's
/// environment and home); `-s` keeps the directory the caller was in.
pub fn sudo(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut login_shell = false;
    let mut keep_cwd = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.peek() {
        match arg.as_str() {
            "-i" | "--login" => {
                login_shell = true;
                iter.next();
            }
            "-s" | "--shell" => {
                login_shell = true;
                keep_cwd = true;
                iter.next();
            }
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
    if rest.is_empty() && login_shell {
        // A root shell for the rest of the session. `-i` is a login shell, so
        // the switch is all of it. `-s` is not: Debian's sudoers resets the
        // environment but does not set `always_set_home`, so the caller keeps
        // their directory and `$HOME` and only the identity changes.
        let (cwd, home) = (shell.cwd, shell.home);
        shell.switch_user("root");
        if keep_cwd {
            shell.cwd = cwd;
            shell.prev_cwd = cwd;
            shell.home = home;
            let (pwd, home) = (shell.vfs.path_of(cwd), shell.vfs.path_of(home));
            shell.env.set("PWD", &pwd);
            shell.env.set("HOME", &home);
        }
        return CommandResult::empty();
    }
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
/// `USER` (root if omitted). Root may switch to any account with no password,
/// exactly like real `su`; a non-root user is prompted for the target's
/// password first. The honeypot does not gate the switch on a correct password
/// (the attacker already authenticated over SSH, and denying here yields no
/// forensic benefit) — but the attempted password *is* captured, and the
/// realistic `Password:` prompt removes the "instant, password-less root" tell.
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
    let target = target.unwrap_or("root").to_string();

    // Root switches identity without a password, like real `su`.
    if shell.uid == 0 {
        shell.switch_user(&target);
        return CommandResult::empty();
    }

    // A non-root user must be prompted for the target's password. Defer the
    // switch: the network layer collects the password line (echo suppressed)
    // and calls `Shell::resume`, which captures it and performs the switch.
    shell.pending = Some(Pending::SuPassword { target });
    CommandResult::ok("Password: ")
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
    let mut stopped = false;
    if interpret {
        (text, stopped) = interpret_escapes(&text);
    }
    if !no_newline && !stopped {
        text.push('\n');
    }
    CommandResult::ok(text)
}

/// Interpret the backslash escapes `echo -e` understands. The flag is set by
/// `\c`, which ends the output there and takes the trailing newline with it.
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
            // `\0NNN` takes up to three octal digits, `\xHH` up to two hex
            // ones; with no digits at all both are the character itself.
            // ponytail: a command's output is a `String`, so a code above 127
            // becomes that Unicode scalar's UTF-8 bytes where real echo writes
            // the single byte — `echo -e '\xff' | wc -c` reads 3, not 2.
            // Upgrade when command output becomes a byte buffer.
            Some('0') => out.push(take_code(&mut chars, 8, 3).unwrap_or('\0')),
            Some('x') => match take_code(&mut chars, 16, 2) {
                Some(c) => out.push(c),
                None => out.push_str("\\x"),
            },
            // `\c` drops the rest of the output, trailing newline included.
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

/// Read up to `max` digits in `radix` off `chars` and return the character
/// they encode, or `None` if the next character is not a digit in that radix.
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
    // Every value a byte escape can name is a valid `char`.
    (digits > 0).then(|| char::from(value as u8))
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
    /// `ps`'s START column: the boot date for daemons, `HH:MM` for anything
    /// started in the last day.
    start: String,
    cmd: String,
}

/// The system processes a Debian 12 VM shows, all started at boot — so their
/// START column is the boot date, not a date fixed at compile time that a
/// long-running honeypot eventually reports as older than its own uptime.
fn base_table() -> Vec<Proc> {
    let boot = clock::format(clock::boot_time(), "%b%d");
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
            start: boot.clone(),
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
            start: boot.clone(),
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
            start: boot.clone(),
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
            start: boot.clone(),
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
            start: boot.clone(),
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
            start: boot.clone(),
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
            start: boot.clone(),
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
            start: boot.clone(),
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
            start: boot.clone(),
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
            start: boot.clone(),
            cmd: "/sbin/agetty -o -p -- \\u --noclear tty1 linux".to_string(),
        },
    ]
}

/// The command line as typed, which is what `ps`/`top` show for the process
/// doing the asking.
fn invocation(name: &str, args: &[String]) -> String {
    if args.is_empty() {
        name.to_string()
    } else {
        format!("{name} {}", args.join(" "))
    }
}

/// Build the full table including this session's own login chain. `running` is
/// the command asking for the table: it is itself in the process list it
/// prints, so `top` must not report `ps aux` as the process at the top.
fn session_table(shell: &Shell, running: &str) -> Vec<Proc> {
    let mut table = base_table();
    let user = shell.username.clone();
    let sshd_pid = shell.pid.saturating_sub(2).max(1000);
    let bash_pid = shell.pid;
    let ps_pid = shell.pid + 1;
    let login = clock::format(shell.login, "%H:%M");
    let now = clock::format(clock::now(), "%H:%M");

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
        start: login.clone(),
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
        start: login.clone(),
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
        start: now,
        cmd: running.to_string(),
    });
    table
}

/// `ps [aux|-ef|...]`
pub fn ps(shell: &Shell, args: &[String]) -> CommandResult {
    let joined: String = args.join("");
    let table = session_table(shell, &invocation("ps", args));

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

/// One `top` display, able to redraw itself at any later instant.
///
/// The process rows are fixed when the command runs — this box has one session
/// on it, and nothing starts or exits while an attacker watches — but the
/// header carries the clock and the uptime, which are exactly what a viewer
/// checks to see whether the screen is alive. Holding only the rendered rows
/// keeps this free of any borrow on the shell, so the network layer can redraw
/// it on a timer without reaching back into the session.
#[derive(Clone)]
pub struct TopScreen {
    rows: Vec<String>,
    total: usize,
    running: usize,
}

impl TopScreen {
    /// Render the whole display as of now.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("top - {}\n", clock::uptime_banner()));
        out.push_str(&format!(
            "Tasks: {:>3} total,   {} running, {:>3} sleeping,   0 stopped,   0 zombie\n",
            self.total,
            self.running,
            self.total - self.running
        ));
        out.push_str(
            "%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.4 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st\n",
        );
        out.push_str(
            "MiB Mem :   1993.4 total,   1468.3 free,    179.0 used,    346.0 buff/cache\n",
        );
        out.push_str(
            "MiB Swap:      0.0 total,      0.0 free,      0.0 used.   1723.6 avail Mem\n",
        );
        out.push('\n');
        out.push_str(
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n",
        );
        for row in &self.rows {
            out.push_str(row);
        }
        out
    }
}

/// `top [-b] [-n N]`
///
/// On a terminal, real `top` takes the screen and redraws every three seconds
/// until `q`. The display is built here; the holding is the network layer's,
/// which is the only layer allowed to own a timer. Batch mode (`-b`), an
/// iteration count (`-n`), a pipe, and any channel without a terminal all get
/// the one-shot dump instead — the same cases real `top` prints once for.
pub fn top(shell: &mut Shell, args: &[String]) -> CommandResult {
    let table = session_table(shell, &invocation("top", args));
    let running = table.iter().filter(|p| p.stat.starts_with('R')).count();
    let rows = table
        .iter()
        .map(|p| {
            format!(
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
            )
        })
        .collect();
    let screen = TopScreen {
        rows,
        total: table.len(),
        running,
    };

    let batch = args
        .iter()
        .any(|a| a == "-b" || a == "--batch" || (a.starts_with('-') && a.contains('n')));
    if !batch && shell.interactive && shell.stdout_is_tty {
        // The display paints itself once the network layer picks it up, so the
        // command writes nothing: a frame here would be painted twice.
        shell.screen = Some(screen);
        return CommandResult::empty();
    }
    CommandResult::ok(screen.render())
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

    let table = session_table(shell, &invocation("kill", args));
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

    let table = session_table(shell, &invocation("pkill", args));
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

    // Base figures in KiB, matching `/proc/meminfo` and `top`'s header. The
    // columns must add up — `total = used + free + buff/cache` is what a real
    // `free` prints, and a row that doesn't balance is arithmetic anyone can
    // check in one command.
    // buff/cache = Buffers + Cached + SReclaimable, and used is whatever is
    // left, exactly as procps derives them from `/proc/meminfo`.
    let (total, used, free_mem, shared, buff, available) =
        (2041208u64, 183336, 1503544, 992, 354328, 1764920);

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
    } else if value < 10.0 {
        // procps only spends a decimal place where it buys precision: `1.9Gi`,
        // but `992Ki` and `346Mi`. `992.0Ki` is a byte-for-byte mismatch.
        format!("{value:.1}{}", UNITS[unit])
    } else {
        format!("{value:.0}{}", UNITS[unit])
    }
}

/// `uptime`
pub fn uptime(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!(" {}\n", clock::uptime_banner()))
}

// --- Reconnaissance commands ---------------------------------------------
//
// The first things an attacker runs after login. Their *absence* is itself a
// tell, so each emulates plausible, internally consistent output. As with the
// process table, all values are fabricated and static (or per-session) so no
// real host detail and no other honeypot session is ever exposed.

/// Shell builtins that `which` reports as not on the PATH.
pub const BUILTINS: &[&str] = &[
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
    // A name that resolved still prints its path; `which` says nothing about
    // the ones that did not, it only reports them in the exit status.
    CommandResult::streams(out, "", status)
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

/// `last` — listing of recent logins. Fabricated, but anchored to the same
/// boot and previous-login instants PAM's `Last login` banner reports, so the
/// two cannot contradict each other.
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

/// `df [-h]`
pub fn df(_shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human-readable");
    // Every tmpfs size here is derivable from `MemTotal` (2041208 kB) the way
    // the kernel and systemd size them — devtmpfs and /dev/shm at half of RAM,
    // /run and /run/user/<uid> at a tenth. A `df` implying more RAM than
    // `free` reports is a two-command honeypot check.
    let out = if human {
        "Filesystem      Size  Used Avail Use% Mounted on\n\
         udev            992M     0  992M   0% /dev\n\
         tmpfs           200M  960K  199M   1% /run\n\
         /dev/sda1        40G  6.3G   31G  17% /\n\
         tmpfs           997M     0  997M   0% /dev/shm\n\
         tmpfs           5.0M     0  5.0M   0% /run/lock\n\
         tmpfs           200M     0  200M   0% /run/user/0\n"
    } else {
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n\
         udev             1015532       0   1015532   0% /dev\n\
         tmpfs             204120     960    203160   1% /run\n\
         /dev/sda1       41019672 6552432  32352140  17% /\n\
         tmpfs            1020604       0   1020604   0% /dev/shm\n\
         tmpfs               5120       0      5120   0% /run/lock\n\
         tmpfs             204116       0    204116   0% /run/user/0\n"
    };
    CommandResult::ok(out)
}

/// `mount` — print the (fabricated) mount table.
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

/// `date [-u] [+FORMAT]` — the current UTC time.
///
/// The emulated host runs in UTC, so the `-u` flag is a no-op. Setting the
/// clock (`date MMDDhhmm...`) would require root and is accepted as a no-op
/// that echoes the current time back.
///
/// ponytail: read-only clock (uses the real host time, which is realistic for a
/// live box); does not honour a `date STRING` set operand beyond echoing.
pub fn date(_shell: &Shell, args: &[String]) -> CommandResult {
    let epoch = clock::now();
    let fmt = args
        .iter()
        .find_map(|a| a.strip_prefix('+'))
        // Default C-locale form: `Wed Jul  8 12:34:56 UTC 2026`.
        .unwrap_or("%a %b %e %H:%M:%S %Z %Y");
    CommandResult::ok(format!("{}\n", clock::format(epoch, fmt)))
}

#[cfg(test)]
mod tests {
    use crate::clock;
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn sudo_dash_i_and_dash_s_hand_over_a_root_shell() {
        // `-i` is a login shell: root's identity, environment, and home.
        let mut shell = Shell::new("attacker", "debian");
        assert_eq!(run(&mut shell, "sudo -i"), "");
        assert_eq!(shell.last_status, 0);
        assert_eq!(run(&mut shell, "whoami"), "root\n");
        assert_eq!(run(&mut shell, "pwd"), "/root\n");
        assert_eq!(shell.prompt(), "root@debian:~# ");
        assert_eq!(run(&mut shell, "echo $HOME"), "/root\n");

        // `-s` changes the identity but not where the caller stood: Debian's
        // sudoers does not set `always_set_home`, so `$HOME` stays theirs too.
        let mut shell = Shell::new("attacker", "debian");
        run(&mut shell, "cd /tmp");
        assert_eq!(run(&mut shell, "sudo -s"), "");
        assert_eq!(run(&mut shell, "whoami"), "root\n");
        assert_eq!(run(&mut shell, "pwd"), "/tmp\n");
        assert_eq!(shell.prompt(), "root@debian:/tmp# ");
        assert_eq!(run(&mut shell, "echo $HOME"), "/home/attacker\n");

        // A flag with a command still runs just that command as root, without
        // handing over the session.
        let mut shell = Shell::new("attacker", "debian");
        assert_eq!(
            run(&mut shell, "sudo -i id"),
            "uid=0(root) gid=0(root) groups=0(root)\n"
        );
        assert_eq!(run(&mut shell, "whoami"), "attacker\n");

        // Everything else with no command is still the usage block.
        let mut shell = Shell::new("attacker", "debian");
        assert!(run(&mut shell, "sudo").contains("usage: sudo"));
        assert_eq!(run(&mut shell, "whoami"), "attacker\n");
    }

    #[test]
    fn sh_runs_a_command_line_and_bare_shells_are_silent() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "sh -c whoami"), "root\n");
        assert_eq!(run(&mut shell, "bash -c 'echo hi'"), "hi\n");
        // A bare `bash`/`sh` is a subshell: nothing is printed and the next
        // prompt is identical, so the attacker sees what a real one would.
        assert_eq!(run(&mut shell, "bash"), "");
        assert_eq!(shell.last_status, 0);
    }

    #[test]
    fn nested_commands_are_bounded() {
        let mut shell = Shell::new("root", "debian");
        let deep = format!("{}whoami", "sudo ".repeat(40));
        let out = run(&mut shell, &deep);
        assert!(
            out.contains("Resource temporarily unavailable"),
            "expected the nesting cap to refuse, got {out:?}"
        );
        // The counter unwinds: the next command runs normally.
        assert_eq!(run(&mut shell, "whoami"), "root\n");
    }

    #[test]
    fn scp_needs_a_real_network_and_says_so() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "scp").contains("usage: scp"));
        let out = run(&mut shell, "scp /tmp/x root@10.0.0.9:/tmp/");
        assert!(
            out.contains("connect to host 10.0.0.9 port 22: Connection refused"),
            "{out:?}"
        );
        assert_eq!(shell.last_status, 1);
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
        // Double quotes leave a backslash alone unless it escapes one of the
        // four characters that are special inside them, so `echo -e` gets the
        // same string it would in bash.
        assert_eq!(run(&mut shell, "echo -e \"a\\tb\\nc\""), "a\tb\nc\n");
        assert_eq!(run(&mut shell, "echo \"a\\tb\""), "a\\tb\n");
        assert_eq!(run(&mut shell, "echo \"a\\\"b\\\\c\""), "a\"b\\c\n");
        // The rest of the GNU escape table.
        assert_eq!(run(&mut shell, r"echo -e 'x\e[0m'"), "x\x1b[0m\n");
        assert_eq!(run(&mut shell, r"echo -e '\0101\x42\x2'"), "AB\x02\n");
        assert_eq!(run(&mut shell, r"echo -e 'no newline\c'"), "no newline");
        assert_eq!(run(&mut shell, r"echo -e 'keep\q\xzz'"), "keep\\q\\xzz\n");
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
    fn top_takes_the_screen_only_where_a_real_one_would() {
        let mut shell = Shell::new("root", "debian");

        // On a terminal it takes the screen and prints nothing itself: the
        // display paints from the network layer's redraw timer.
        let out = run(&mut shell, "top");
        assert_eq!(out, "");
        let screen = shell.screen.take().expect("top should hold the screen");
        assert!(screen.render().contains("Tasks:"));

        // Batch mode and an iteration count are the one-shot dump.
        for line in ["top -b", "top -bn1", "top -n 1", "top --batch"] {
            assert!(
                run(&mut shell, line).contains("Tasks:"),
                "{line} should print a dump"
            );
            assert!(shell.screen.is_none(), "{line} should not hold the screen");
        }

        // A pipe is not a terminal, and neither is a redirect.
        assert!(
            run(&mut shell, "top | wc -l")
                .trim()
                .parse::<u32>()
                .unwrap()
                > 5
        );
        assert!(shell.screen.is_none(), "a pipe should not hold the screen");
        run(&mut shell, "top > /tmp/t");
        assert!(
            shell.screen.is_none(),
            "a redirect should not hold the screen"
        );

        // Neither is a one-shot `exec`, whatever its stdout is.
        shell.interactive = false;
        assert!(run(&mut shell, "top").contains("Tasks:"));
        assert!(shell.screen.is_none(), "exec should not hold the screen");
        shell.interactive = true;

        // A substitution runs in a subshell with no terminal of its own, so it
        // captures a dump and hands the session back unheld.
        let sub = run(&mut shell, "echo $(top)");
        assert!(sub.contains("Tasks:"));
        assert!(
            shell.screen.is_none(),
            "a substitution should not hold the screen"
        );
    }

    #[test]
    fn top_and_free_render() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "top -b").contains("Tasks:"));
        assert!(run(&mut shell, "free").contains("Mem:"));
        // procps' scaling: a decimal place only below 10, so `1.9Gi` but
        // `346Mi` — never `346.0Mi`.
        let human = run(&mut shell, "free -h");
        assert!(human.contains("1.9Gi"), "unexpected `free -h`: {human}");
        assert!(human.contains("346Mi"), "unexpected `free -h`: {human}");
        assert!(!human.contains(".0Mi"), "unexpected `free -h`: {human}");
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
        // A non-root user is prompted for a password before the switch; the
        // shell defers, exposing a pending prompt the network layer drives.
        assert_eq!(run(&mut shell, "su"), "Password: ");
        assert!(shell.pending.is_some());
        assert_eq!(shell.uid, 1000, "identity is unchanged until a password");
        // Answering the prompt performs the switch and captures the attempt.
        assert_eq!(shell.resume("hunter2").text, "");
        assert!(shell.pending.is_none());
        assert_eq!(shell.username, "root");
        assert_eq!(shell.uid, 0);
        assert_eq!(shell.cwd_path(), "/root");
        assert!(
            matches!(
                shell.captures.first(),
                Some(crate::shell::Capture::SuAuth { target, password })
                    if target == "root" && password == "hunter2"
            ),
            "the attempted password is captured as forensic data"
        );
        // Root switches to any account without a password prompt.
        assert_eq!(run(&mut shell, "su someoneelse"), "");
        assert!(shell.pending.is_none());
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

    /// `date`, `uptime`, `w`, `last` and `ps` all describe the same box. An
    /// attacker comparing any two of them must not find a contradiction — a
    /// login dated before the boot, or a daemon older than the uptime.
    #[test]
    fn the_recon_commands_agree_on_one_timeline() {
        let mut shell = Shell::new("root", "debian");
        let year = clock::format(clock::now(), "%Y");

        // `date` and the `uptime`/`w`/`top` banners share a clock.
        assert!(run(&mut shell, "date").contains(&year));
        let banner = clock::uptime_banner();
        assert!(run(&mut shell, "uptime").contains(&banner));
        assert!(run(&mut shell, "w").contains(&banner));
        assert!(run(&mut shell, "top -b").contains(&banner));

        // `last` reports this year's boot, not a date frozen at compile time.
        let last = run(&mut shell, "last");
        assert!(last.contains(&year), "last should be in {year}: {last}");
        assert!(last.contains("still logged in"));
        assert!(last.contains("wtmp begins"));
        // The previous login `last` lists is the one PAM's banner announces.
        let (prev, _) = clock::prev_login();
        assert!(last.contains(&clock::format(prev, "%a %b %e %H:%M")));

        // Daemons started at boot; nothing claims to predate the box.
        let ps = run(&mut shell, "ps aux");
        assert!(ps.contains(&clock::format(clock::boot_time(), "%b%d")));
        // Snapshot files carry the install date, which is older still.
        let ls = run(&mut shell, "ls -l /etc/passwd");
        assert!(ls.contains(&clock::format(clock::install_time(), "%b %e")));
    }

    /// Real `top` is in its own process list; showing `ps aux` as the running
    /// process says the output came from somewhere else.
    #[test]
    fn top_and_ps_list_themselves_not_each_other() {
        let mut shell = Shell::new("root", "debian");
        let top = run(&mut shell, "top -b");
        assert!(top.contains(" top\n"), "top should list itself: {top}");
        assert!(!top.contains("ps aux"));
        assert!(run(&mut shell, "ps aux").contains("ps aux"));
    }

    /// `free`'s columns must add up the way procps derives them, and agree
    /// with both `/proc/meminfo` and `top`'s header.
    #[test]
    fn the_memory_figures_agree_across_commands() {
        let mut shell = Shell::new("root", "debian");
        let free = run(&mut shell, "free");
        let row = free
            .lines()
            .find(|l| l.starts_with("Mem:"))
            .expect("free should print a Mem: row");
        let cols: Vec<u64> = row
            .split_whitespace()
            .skip(1)
            .filter_map(|f| f.parse().ok())
            .collect();
        let (total, used, free_mem, buff) = (cols[0], cols[1], cols[2], cols[4]);
        assert_eq!(total, used + free_mem + buff);

        // MemTotal is where every other figure comes from.
        let meminfo = run(&mut shell, "cat /proc/meminfo");
        assert!(meminfo.contains(&format!("MemTotal:        {total} kB")));
        // `df`'s tmpfs sizes are halves and tenths of it, so a `df` that
        // implies more RAM than `free` reports cannot happen.
        let df = run(&mut shell, "df");
        assert!(df.contains(&format!("{}", total / 2)), "/dev/shm is RAM/2");
        assert!(df.contains(&format!("{}", total / 10)), "/run is RAM/10");
        // `top`'s header is the same total in MiB.
        assert!(run(&mut shell, "top -b").contains(&format!("{:.1} total", total as f64 / 1024.0)));
    }
}
