use super::is_root;
use crate::clock;
use crate::commands::CommandResult;
use crate::shell::Shell;

pub(super) const SESSION_TTY: &str = "pts/0";
pub(super) const IDLE_CPU_PERCENT: &str = "0.0";
const NO_TTY: &str = "?";
const SSHD_LISTENER_PID: u32 = 604;
const MIN_SESSION_SSHD_PID: u32 = 1000;
pub(super) const CLOCK_TIME_FORMAT: &str = "%H:%M";
const BOOT_DATE_FORMAT: &str = "%b%d";

/// One row of the fabricated process table.
pub(super) struct Proc {
    pub(super) pid: u32,
    pub(super) ppid: u32,
    pub(super) user: String,
    pub(super) tty: &'static str,
    pub(super) stat: &'static str,
    /// %MEM.
    pub(super) mem: &'static str,
    /// Virtual size in KiB.
    pub(super) vsz: u32,
    /// Resident set size in KiB.
    pub(super) rss: u32,
    pub(super) time: &'static str,
    /// `ps`'s START column: the boot date for daemons, `HH:MM` for anything
    /// started in the last day.
    pub(super) start: String,
    pub(super) cmd: String,
}

impl Proc {
    pub(super) fn command_word(&self) -> &str {
        self.cmd.split_whitespace().next().unwrap_or(&self.cmd)
    }
}

struct BootProcess {
    pid: u32,
    ppid: u32,
    user: &'static str,
    tty: &'static str,
    stat: &'static str,
    mem: &'static str,
    vsz: u32,
    rss: u32,
    time: &'static str,
    cmd: &'static str,
}

impl BootProcess {
    fn started_at(&self, start: &str) -> Proc {
        Proc {
            pid: self.pid,
            ppid: self.ppid,
            user: self.user.to_string(),
            tty: self.tty,
            stat: self.stat,
            mem: self.mem,
            vsz: self.vsz,
            rss: self.rss,
            time: self.time,
            start: start.to_string(),
            cmd: self.cmd.to_string(),
        }
    }
}

/// The system processes a Debian 12 VM shows, all started at boot — so their
/// START column is the boot date, not a date fixed at compile time that a
/// long-running honeypot eventually reports as older than its own uptime.
const BOOT_PROCESSES: [BootProcess; 10] = [
    BootProcess {
        pid: 1,
        ppid: 0,
        user: "root",
        tty: NO_TTY,
        stat: "Ss",
        mem: "0.4",
        vsz: 167404,
        rss: 13072,
        time: "0:02",
        cmd: "/sbin/init",
    },
    BootProcess {
        pid: 2,
        ppid: 0,
        user: "root",
        tty: NO_TTY,
        stat: "S",
        mem: "0.0",
        vsz: 0,
        rss: 0,
        time: "0:00",
        cmd: "[kthreadd]",
    },
    BootProcess {
        pid: 312,
        ppid: 1,
        user: "root",
        tty: NO_TTY,
        stat: "Ss",
        mem: "0.3",
        vsz: 24684,
        rss: 9216,
        time: "0:01",
        cmd: "/lib/systemd/systemd-journald",
    },
    BootProcess {
        pid: 334,
        ppid: 1,
        user: "root",
        tty: NO_TTY,
        stat: "Ss",
        mem: "0.2",
        vsz: 21916,
        rss: 6400,
        time: "0:00",
        cmd: "/lib/systemd/systemd-udevd",
    },
    BootProcess {
        pid: 501,
        ppid: 1,
        user: "systemd+",
        tty: NO_TTY,
        stat: "Ssl",
        mem: "0.3",
        vsz: 90264,
        rss: 9088,
        time: "0:00",
        cmd: "/lib/systemd/systemd-resolved",
    },
    BootProcess {
        pid: 512,
        ppid: 1,
        user: "root",
        tty: NO_TTY,
        stat: "Ss",
        mem: "0.2",
        vsz: 6892,
        rss: 4992,
        time: "0:00",
        cmd: "/usr/sbin/cron -f",
    },
    BootProcess {
        pid: 528,
        ppid: 1,
        user: "message+",
        tty: NO_TTY,
        stat: "Ss",
        mem: "0.2",
        vsz: 8460,
        rss: 4736,
        time: "0:00",
        cmd: "/usr/bin/dbus-daemon --system",
    },
    BootProcess {
        pid: SSHD_LISTENER_PID,
        ppid: 1,
        user: "root",
        tty: NO_TTY,
        stat: "Ss",
        mem: "0.4",
        vsz: 15420,
        rss: 9472,
        time: "0:00",
        cmd: "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
    },
    BootProcess {
        pid: 611,
        ppid: 1,
        user: "root",
        tty: NO_TTY,
        stat: "Ssl",
        mem: "0.5",
        vsz: 313196,
        rss: 12544,
        time: "0:01",
        cmd: "/usr/lib/systemd/systemd-logind",
    },
    BootProcess {
        pid: 1188,
        ppid: 1,
        user: "root",
        tty: "tty1",
        stat: "Ss+",
        mem: "0.1",
        vsz: 5612,
        rss: 3200,
        time: "0:00",
        cmd: "/sbin/agetty -o -p -- \\u --noclear tty1 linux",
    },
];

/// The command line as typed, which is what `ps`/`top` show for the process
/// doing the asking.
pub(super) fn invocation(name: &str, args: &[String]) -> String {
    if args.is_empty() {
        name.to_string()
    } else {
        format!("{name} {}", args.join(" "))
    }
}

/// The `(pid, command)` pairs the fabricated process table holds.
///
/// `pidof`, `pgrep` and `killall` all read this, so none of them can disagree
/// with what `ps` prints — three commands inventing their own tables would
/// contradict each other on the first cross-check.
pub fn process_table(shell: &Shell) -> Vec<(u32, String)> {
    session_table(shell, "ps")
        .into_iter()
        .map(|p| (p.pid, p.cmd))
        .collect()
}

/// The executable name a `ps` command line reports, the way `/proc/PID/comm`
/// would: the first word, minus any directory, minus the `sshd: ` title prefix
/// a privilege-separated daemon rewrites its argv to, minus the brackets a
/// kernel thread is shown in.
///
/// Without this, `pidof sshd` misses the one process an attacker is guaranteed
/// to look for — `ps` prints `sshd: /usr/sbin/sshd -D [listener]`, whose first
/// word is `sshd:`.
pub fn process_name(cmd: &str) -> &str {
    let first = cmd.split_whitespace().next().unwrap_or(cmd);
    let first = first.strip_suffix(':').unwrap_or(first);
    let first = first.rsplit('/').next().unwrap_or(first);
    first.trim_start_matches('[').trim_end_matches(']')
}

/// The pid of the first process whose executable name is `name`, if any.
pub fn process_pid(shell: &Shell, name: &str) -> Option<u32> {
    process_table(shell)
        .into_iter()
        .find(|(_, cmd)| process_name(cmd) == name)
        .map(|(pid, _)| pid)
}

/// Build the full table including this session's own login chain. `running` is
/// the command asking for the table: it is itself in the process list it
/// prints, so `top` must not report `ps aux` as the process at the top.
pub(super) fn session_table(shell: &Shell, running: &str) -> Vec<Proc> {
    let boot = clock::format(clock::boot_time(), BOOT_DATE_FORMAT);
    let mut table: Vec<Proc> = BOOT_PROCESSES.iter().map(|p| p.started_at(&boot)).collect();

    let sshd_pid = shell.pid.saturating_sub(2).max(MIN_SESSION_SSHD_PID);
    let bash_pid = shell.pid;
    let login = clock::format(shell.login, CLOCK_TIME_FORMAT);
    let now = clock::format(clock::now(), CLOCK_TIME_FORMAT);
    let user = &shell.username;

    table.push(Proc {
        pid: sshd_pid,
        ppid: SSHD_LISTENER_PID,
        user: user.clone(),
        tty: NO_TTY,
        stat: "Ss",
        mem: "0.4",
        vsz: 17668,
        rss: 10880,
        time: "0:00",
        start: login.clone(),
        cmd: format!("sshd: {user}@{SESSION_TTY}"),
    });
    table.push(Proc {
        pid: bash_pid,
        ppid: sshd_pid,
        user: user.clone(),
        tty: SESSION_TTY,
        stat: "Ss",
        mem: "0.2",
        vsz: 8228,
        rss: 5376,
        time: "0:00",
        start: login,
        cmd: "-bash".to_string(),
    });
    table.push(Proc {
        pid: bash_pid + 1,
        ppid: bash_pid,
        user: user.clone(),
        tty: SESSION_TTY,
        stat: "R+",
        mem: "0.1",
        vsz: 10072,
        rss: 3200,
        time: "0:00",
        start: now,
        cmd: running.to_string(),
    });
    table
}

/// Non-root may only signal its own processes; system PIDs are owned by root,
/// so an unprivileged attacker is denied.
fn may_signal(shell: &Shell, process: &Proc) -> bool {
    is_root(shell) || process.user == shell.username
}

/// `ps [aux|-ef|...]`
pub fn ps(shell: &Shell, args: &[String]) -> CommandResult {
    let joined: String = args.join("");
    // `ps aux` / `ps -ef` style: show every process. Bare `ps` shows only this
    // session's processes on its tty.
    let has_arg = |wanted: &str| args.iter().any(|a| a == wanted);
    let show_all = joined.contains('a') || joined.contains('e') || joined.contains('A');
    let full_format = has_arg("-ef") || joined.contains('f') && !joined.contains('u');
    let user_format = joined.contains('u');

    let (header, row): (&str, fn(&Proc) -> String) = if full_format {
        (
            "UID          PID    PPID  C STIME TTY          TIME CMD\n",
            full_format_row,
        )
    } else if user_format {
        (
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n",
            user_format_row,
        )
    } else {
        ("    PID TTY          TIME CMD\n", default_format_row)
    };

    let mut out = header.to_string();
    let table = session_table(shell, &invocation("ps", args));
    for p in table.iter().filter(|p| show_all || p.tty == SESSION_TTY) {
        out.push_str(&row(p));
    }
    CommandResult::ok(out)
}

fn full_format_row(p: &Proc) -> String {
    format!(
        "{:<8} {:>6} {:>7}  0 {:>5} {:<8} {:>8} {}\n",
        p.user, p.pid, p.ppid, p.start, p.tty, p.time, p.cmd
    )
}

fn user_format_row(p: &Proc) -> String {
    format!(
        "{:<8} {:>5} {:>4} {:>4} {:>6} {:>5} {:<8} {:<4} {:>5} {:>6} {}\n",
        p.user, p.pid, IDLE_CPU_PERCENT, p.mem, p.vsz, p.rss, p.tty, p.stat, p.start, p.time, p.cmd
    )
}

fn default_format_row(p: &Proc) -> String {
    format!(
        "{:>7} {:<12} {:>5} {}\n",
        p.pid,
        p.tty,
        p.time,
        p.command_word()
    )
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
    let errors: String = pids
        .into_iter()
        .filter_map(|target| kill_error(shell, &table, target))
        .collect();
    if errors.is_empty() {
        CommandResult::empty()
    } else {
        CommandResult::err(errors, 1)
    }
}

fn kill_error(shell: &Shell, table: &[Proc], target: &str) -> Option<String> {
    let Ok(pid) = target.parse::<u32>() else {
        return Some(format!(
            "-bash: kill: {target}: arguments must be process or job IDs\n"
        ));
    };
    match table.iter().find(|p| p.pid == pid) {
        None => Some(format!("-bash: kill: ({pid}) - No such process\n")),
        Some(p) if !may_signal(shell, p) => {
            Some(format!("-bash: kill: ({pid}) - Operation not permitted\n"))
        }
        Some(_) => None,
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
            if may_signal(shell, p) {
                matched_any = true;
            } else {
                out.push_str(&format!(
                    "pkill: killing pid {} failed: Operation not permitted\n",
                    p.pid
                ));
                denied = true;
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
