//! Persistence, account, and service commands.
//!
//! What an automated intrusion does *after* it lands. `echo 'root:pass' |
//! chpasswd` is the single most common post-access action in SSH botnet
//! telemetry, `systemctl` is how persistence gets probed, and `sleep` appears in
//! nearly every staging script. None of these touch the real OS: accounts live
//! in the session's `/etc/passwd`, services in a fabricated unit table, and
//! `sleep` returns immediately rather than holding a connection slot.

use super::CommandResult;
use crate::shell::Shell;

/// Read a VFS file as text, or an empty string when it is missing.
fn read_text(shell: &Shell, path: &str) -> String {
    shell
        .vfs
        .resolve(shell.cwd, path)
        .and_then(|id| {
            shell
                .vfs
                .node(id)
                .file_bytes()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        })
        .unwrap_or_default()
}

/// Replace a VFS file's contents, creating it if needed.
fn write_text(shell: &mut Shell, path: &str, text: &str) -> bool {
    let Some((parent, name)) = super::fs::resolve_parent(shell, path) else {
        return false;
    };
    let (uid, gid) = (shell.uid, shell.gid);
    match shell.vfs.child(parent, &name) {
        Some(id) => shell.vfs.write_file(id, text.as_bytes(), false),
        None => {
            if shell.vfs.is_full() {
                return false;
            }
            shell
                .vfs
                .add_file(parent, &name, text.as_bytes().to_vec(), 0o644, uid, gid);
            true
        }
    }
}

/// `sleep NUMBER[SUFFIX]...`
///
/// Returns immediately rather than actually waiting. A honeypot that honoured
/// `sleep 3600` would hold a connection slot for an hour on the attacker's say-so
/// — the sleep is exactly the resource-exhaustion primitive the session caps
/// exist to prevent. The exit status and (absent) output are identical either
/// way, so the only thing an attacker can observe is elapsed wall time.
///
/// ponytail: returns instantly, so timing a `sleep` against the clock detects
/// it. Upgrade when sleeps can be charged against the session deadline rather
/// than a real timer.
pub fn sleep(_shell: &Shell, args: &[String]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::err(
            "sleep: missing operand\nTry 'sleep --help' for more information.\n",
            1,
        );
    }
    for a in args {
        let numeric = a.trim_end_matches(['s', 'm', 'h', 'd']);
        if numeric.parse::<f64>().is_err() {
            return CommandResult::err(format!("sleep: invalid time interval '{a}'\n"), 1);
        }
    }
    CommandResult::empty()
}

/// Replace `user`'s `/etc/shadow` entry with a crypt-shaped placeholder.
///
/// The plaintext never reaches the VFS: it is captured as forensic data and
/// logged, so a later `cat /etc/shadow` shows what a real one would show rather
/// than handing the attacker back their own secret.
pub fn set_shadow_entry(shell: &mut Shell, user: &str) {
    let shadow = read_text(shell, "/etc/shadow");
    let prefix = format!("{user}:");
    let updated: String = shadow
        .lines()
        .map(|l| {
            if l.starts_with(&prefix) {
                format!("{user}:$6$mimic$changed:19999:0:99999:7:::")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    write_text(shell, "/etc/shadow", &format!("{updated}\n"));
}

/// `passwd [USER]`
///
/// Prompts for the new secret the way the real thing does, twice. The shell's
/// [`Pending`](crate::shell::Pending) mechanism collects both answers with echo
/// suppressed — the same path `su` uses — and the second one is where the
/// capture happens.
pub fn passwd(shell: &mut Shell, args: &[String]) -> CommandResult {
    let target = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| shell.username.clone());
    if shell.uid != 0 && target != shell.username {
        return CommandResult::err(
            format!("passwd: You may not view or modify password information for {target}.\n"),
            1,
        );
    }
    if read_text(shell, "/etc/passwd")
        .lines()
        .all(|l| !l.starts_with(&format!("{target}:")))
    {
        return CommandResult::err(format!("passwd: user '{target}' does not exist\n"), 1);
    }
    let banner = format!("Changing password for {target}.\n");
    shell.pending = Some(crate::shell::Pending::NewPassword {
        target,
        first: None,
    });
    CommandResult::ok(format!("{banner}New password: "))
}

/// `chpasswd` — reads `user:password` lines from stdin.
///
/// The most common thing an SSH botnet does once it has a shell: lock the owner
/// out by resetting the password. Captured as credential data, applied only to
/// the session's own `/etc/shadow`.
pub fn chpasswd(shell: &mut Shell, _args: &[String]) -> CommandResult {
    let input = shell.stdin.clone().unwrap_or_default();
    if input.trim().is_empty() {
        return CommandResult::empty();
    }
    if shell.uid != 0 {
        return CommandResult::err("chpasswd: Permission denied.\n", 1);
    }

    let mut errs = String::new();
    let mut status = 0;
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((user, password)) = line.split_once(':') else {
            errs.push_str(&format!("chpasswd: line '{line}' is badly formatted\n"));
            status = 1;
            continue;
        };
        let passwd_file = read_text(shell, "/etc/passwd");
        if !passwd_file
            .lines()
            .any(|l| l.starts_with(&format!("{user}:")))
        {
            errs.push_str(&format!(
                "chpasswd: line '{line}': user '{user}' does not exist\n"
            ));
            status = 1;
            continue;
        }
        // Forensic value is the plaintext, which the shell's capture path logs.
        shell.captures.push(crate::shell::Capture::PasswordChange {
            target: user.to_string(),
            password: password.to_string(),
        });
        set_shadow_entry(shell, user);
    }
    CommandResult::streams(String::new(), errs, status)
}

/// `useradd [-m] [-s SHELL] [-u UID] USER`
pub fn useradd(shell: &mut Shell, args: &[String]) -> CommandResult {
    if shell.uid != 0 {
        return CommandResult::err(
            "useradd: Permission denied.\nuseradd: cannot lock /etc/passwd; try again later.\n",
            1,
        );
    }
    let mut login_shell = "/bin/sh".to_string();
    let mut uid = 1001u32;
    let mut make_home = false;
    let mut name: Option<String> = None;
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-m" | "--create-home" => make_home = true,
            "-s" | "--shell" => {
                if let Some(v) = iter.next() {
                    login_shell = v.clone();
                }
            }
            "-u" | "--uid" => {
                if let Some(v) = iter.next().and_then(|v| v.parse().ok()) {
                    uid = v;
                }
            }
            "-g" | "-G" | "-d" | "-c" | "-p" => {
                iter.next();
            }
            other if other.starts_with('-') => {}
            other => name = Some(other.to_string()),
        }
    }
    let Some(name) = name else {
        return CommandResult::err("useradd: missing operand\n", 2);
    };

    let passwd_file = read_text(shell, "/etc/passwd");
    if passwd_file
        .lines()
        .any(|l| l.starts_with(&format!("{name}:")))
    {
        return CommandResult::err(format!("useradd: user '{name}' already exists\n"), 9);
    }

    let home = format!("/home/{name}");
    let entry = format!("{name}:x:{uid}:{uid}::{home}:{login_shell}\n");
    if !write_text(shell, "/etc/passwd", &format!("{passwd_file}{entry}")) {
        return CommandResult::err("useradd: cannot open /etc/passwd\n", 1);
    }
    let group_file = read_text(shell, "/etc/group");
    write_text(
        shell,
        "/etc/group",
        &format!("{group_file}{name}:x:{uid}:\n"),
    );
    let shadow = read_text(shell, "/etc/shadow");
    write_text(
        shell,
        "/etc/shadow",
        &format!("{shadow}{name}:!:19999:0:99999:7:::\n"),
    );
    if make_home && shell.vfs.mkdir_p(&home, 0o755, uid, uid).is_none() {
        return CommandResult::err(format!("useradd: cannot create directory {home}\n"), 12);
    }
    CommandResult::empty()
}

/// `userdel [-r] USER`
pub fn userdel(shell: &mut Shell, args: &[String]) -> CommandResult {
    if shell.uid != 0 {
        return CommandResult::err("userdel: Permission denied.\n", 1);
    }
    let Some(name) = args.iter().find(|a| !a.starts_with('-')).cloned() else {
        return CommandResult::err("userdel: missing operand\n", 2);
    };
    let passwd_file = read_text(shell, "/etc/passwd");
    let prefix = format!("{name}:");
    if !passwd_file.lines().any(|l| l.starts_with(&prefix)) {
        return CommandResult::err(format!("userdel: user '{name}' does not exist\n"), 6);
    }
    let kept: Vec<&str> = passwd_file
        .lines()
        .filter(|l| !l.starts_with(&prefix))
        .collect();
    write_text(shell, "/etc/passwd", &format!("{}\n", kept.join("\n")));
    CommandResult::empty()
}

/// `groupadd GROUP`
pub fn groupadd(shell: &mut Shell, args: &[String]) -> CommandResult {
    if shell.uid != 0 {
        return CommandResult::err("groupadd: Permission denied.\n", 1);
    }
    let Some(name) = args.iter().find(|a| !a.starts_with('-')).cloned() else {
        return CommandResult::err("groupadd: missing operand\n", 2);
    };
    let group_file = read_text(shell, "/etc/group");
    if group_file
        .lines()
        .any(|l| l.starts_with(&format!("{name}:")))
    {
        return CommandResult::err(format!("groupadd: group '{name}' already exists\n"), 9);
    }
    write_text(
        shell,
        "/etc/group",
        &format!("{group_file}{name}:x:1001:\n"),
    );
    CommandResult::empty()
}

/// The service units this box claims to run. Chosen to match what the rest of
/// the emulation already implies: an sshd is obviously running, and the others
/// are the Debian 12 default set for a minimal cloud image.
const UNITS: &[(&str, &str, &str)] = &[
    ("ssh.service", "OpenBSD Secure Shell server", "running"),
    (
        "cron.service",
        "Regular background program processing daemon",
        "running",
    ),
    ("dbus.service", "D-Bus System Message Bus", "running"),
    ("systemd-journald.service", "Journal Service", "running"),
    ("systemd-logind.service", "User Login Management", "running"),
    (
        "systemd-networkd.service",
        "Network Configuration",
        "running",
    ),
    (
        "systemd-resolved.service",
        "Network Name Resolution",
        "running",
    ),
    (
        "systemd-timesyncd.service",
        "Network Time Synchronization",
        "running",
    ),
    ("rsyslog.service", "System Logging Service", "running"),
    ("getty@tty1.service", "Getty on tty1", "running"),
];

/// `systemctl [SUBCOMMAND] [UNIT]`
///
/// Persistence probing goes through here: `systemctl enable`, then a unit file
/// dropped into `/etc/systemd/system`. Mutating verbs report success — a
/// refusal would end the interaction early and hide what the attacker meant to
/// install — while the state they claim to change is not tracked.
///
/// ponytail: `enable`/`start` report success without changing `is-active`, so
/// a follow-up `systemctl status` on an attacker's own unit contradicts the
/// enable that preceded it. Upgrade when the unit table becomes session state.
pub fn systemctl(shell: &Shell, args: &[String]) -> CommandResult {
    let operands: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let verb = operands.first().copied().unwrap_or("list-units");
    let unit = operands.get(1).copied();

    let full = |u: &str| -> String {
        if u.contains('.') {
            u.to_string()
        } else {
            format!("{u}.service")
        }
    };
    let known = |u: &str| UNITS.iter().find(|(n, _, _)| *n == full(u));

    match verb {
        "list-units" | "list-unit-files" => {
            let mut out =
                String::from("  UNIT                        LOAD   ACTIVE SUB     DESCRIPTION\n");
            for (name, desc, sub) in UNITS {
                out.push_str(&format!("  {name:<27} loaded active {sub:<7} {desc}\n"));
            }
            out.push_str(&format!("\n{} loaded units listed.\n", UNITS.len()));
            CommandResult::ok(out)
        }
        "status" => match unit {
            None => CommandResult::ok(format!(
                "● {}\n    State: running\n     Jobs: 0 queued\n   Failed: 0 units\n",
                shell.hostname
            )),
            Some(u) => match known(u) {
                Some((name, desc, _)) => CommandResult::ok(format!(
                    "● {name} - {desc}\n     \
                     Loaded: loaded (/lib/systemd/system/{name}; enabled; preset: enabled)\n     \
                     Active: active (running) since {}; {} ago\n   \
                     Main PID: 1 (systemd)\n      \
                     Tasks: 1 (limit: 2273)\n     \
                     Memory: 5.4M\n        \
                     CPU: 142ms\n     \
                     CGroup: /system.slice/{name}\n",
                    crate::clock::format(crate::clock::boot_time(), "%a %Y-%m-%d %H:%M:%S %Z"),
                    crate::clock::uptime_phrase(crate::clock::uptime_secs()),
                )),
                None => CommandResult::err(
                    format!(
                        "Unit {}.service could not be found.\n",
                        u.trim_end_matches(".service")
                    ),
                    4,
                ),
            },
        },
        "is-active" => match unit.and_then(known) {
            Some(_) => CommandResult::ok("active\n"),
            None => CommandResult::streams("inactive\n", "", 3),
        },
        "is-enabled" => match unit.and_then(known) {
            Some(_) => CommandResult::ok("enabled\n"),
            None => CommandResult::streams("disabled\n", "", 1),
        },
        // Mutating verbs. Root-only, like the real thing.
        "start" | "stop" | "restart" | "reload" | "enable" | "disable" | "daemon-reload"
        | "mask" | "unmask" => {
            if shell.uid != 0 {
                return CommandResult::err(
                    format!(
                        "Failed to {verb} {}: Interactive authentication required.\n",
                        unit.unwrap_or("unit")
                    ),
                    1,
                );
            }
            match (verb, unit) {
                ("enable", Some(u)) => CommandResult::ok(format!(
                    "Created symlink /etc/systemd/system/multi-user.target.wants/{0} → /lib/systemd/system/{0}.\n",
                    full(u)
                )),
                ("disable", Some(u)) => CommandResult::ok(format!(
                    "Removed \"/etc/systemd/system/multi-user.target.wants/{}\".\n",
                    full(u)
                )),
                _ => CommandResult::empty(),
            }
        }
        other => CommandResult::err(format!("Unknown command verb {other}.\n"), 1),
    }
}

/// `service NAME ACTION` — the SysV wrapper, which scripts still reach for.
pub fn service(shell: &Shell, args: &[String]) -> CommandResult {
    let operands: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    if operands.len() < 2 {
        if operands.first() == Some(&"--status-all") || operands.is_empty() {
            let mut out = String::new();
            for (name, _, _) in UNITS {
                out.push_str(&format!(" [ + ]  {}\n", name.trim_end_matches(".service")));
            }
            return CommandResult::ok(out);
        }
        return CommandResult::err("Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]\n", 1);
    }
    let (name, action) = (operands[0], operands[1]);
    // `service x y` is a thin shim over systemctl on Debian 12.
    systemctl(shell, &[action.to_string(), name.to_string()])
}

/// `chattr [+-=]ATTR FILE...`
///
/// The immutable bit is a favourite persistence trick — `chattr +i` on a
/// dropped binary or on `/etc/passwd` to stop cleanup. Accepted and reported as
/// success; the attribute itself is not modelled.
///
/// ponytail: attributes are not stored, so `lsattr` never shows what `chattr`
/// set. Upgrade when node metadata grows an attribute field.
pub fn chattr(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, files): (Vec<&String>, Vec<&String>) =
        args.iter().partition(|a| a.starts_with(['+', '-', '=']));
    if flags.is_empty() || files.is_empty() {
        return CommandResult::err(
            "Usage: chattr [-pRVf] [-+=aAcCdDeijPsStTuFx] [-v version] files...\n",
            1,
        );
    }
    let mut errs = String::new();
    let mut status = 0;
    for f in files {
        if shell.vfs.resolve(shell.cwd, f).is_none() {
            errs.push_str(&format!(
                "chattr: No such file or directory while trying to stat {f}\n"
            ));
            status = 1;
        }
    }
    CommandResult::streams(String::new(), errs, status)
}

/// `lsattr [FILE]...`
pub fn lsattr(shell: &Shell, args: &[String]) -> CommandResult {
    let files: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let targets: Vec<String> = if files.is_empty() {
        shell
            .vfs
            .entries(shell.cwd)
            .unwrap_or_default()
            .into_iter()
            .map(|(name, _)| format!("./{name}"))
            .collect()
    } else {
        files.into_iter().cloned().collect()
    };
    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;
    for f in targets {
        if shell.vfs.resolve(shell.cwd, &f).is_some() {
            out.push_str(&format!("--------------e------- {f}\n"));
        } else {
            errs.push_str(&format!(
                "lsattr: No such file or directory while trying to stat {f}\n"
            ));
            status = 1;
        }
    }
    CommandResult::streams(out, errs, status)
}

/// `nohup COMMAND [ARG]...`
pub fn nohup(shell: &mut Shell, args: &[String]) -> CommandResult {
    let argv: Vec<String> = args
        .iter()
        .skip_while(|a| a.starts_with('-'))
        .cloned()
        .collect();
    if argv.is_empty() {
        return CommandResult::err("nohup: missing operand\n", 125);
    }
    let mut result = super::dispatch(shell, &argv);
    // Real nohup announces the redirect on stderr before the command runs.
    result.stderr.insert_str(
        0,
        "nohup: ignoring input and appending output to 'nohup.out'\n",
    );
    result
}

/// `sync` — flush the (nonexistent) buffer cache.
///
/// Present because `/etc/passwd` gives the `sync` account `/bin/sync` as its
/// login shell: a box that names a binary in a file an attacker reads and then
/// cannot run it has contradicted itself.
pub fn sync(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::empty()
}

/// `nologin` — the shell `/etc/passwd` gives every system account.
pub fn nologin(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::err("This account is currently not available.\n", 1)
}

/// `getent DATABASE [KEY]...`
pub fn getent(shell: &Shell, args: &[String]) -> CommandResult {
    let operands: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let Some(db) = operands.first() else {
        return CommandResult::err("Usage: getent [OPTION...] database [key ...]\n", 1);
    };
    let file = match *db {
        "passwd" => "/etc/passwd",
        "group" => "/etc/group",
        "shadow" => "/etc/shadow",
        "hosts" => "/etc/hosts",
        other => {
            return CommandResult::err(format!("Unknown database: {other}\n"), 2);
        }
    };
    let text = read_text(shell, file);
    let keys = &operands[1..];
    if keys.is_empty() {
        return CommandResult::ok(text);
    }
    let mut out = String::new();
    for key in keys {
        for line in text.lines() {
            if line.starts_with(&format!("{key}:")) || line.split_whitespace().any(|f| f == *key) {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    let status = i32::from(out.is_empty()) * 2;
    CommandResult::streams(out, String::new(), status)
}

/// `killall NAME...` and `pidof NAME` / `pgrep NAME`, over the same fabricated
/// process table `ps` renders.
pub fn killall(shell: &Shell, args: &[String]) -> CommandResult {
    let names: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if names.is_empty() {
        return CommandResult::err("Usage: killall [OPTION]... [--] NAME...\n", 1);
    }
    let mut errs = String::new();
    let mut status = 0;
    for n in names {
        if super::system::process_pid(shell, n).is_none() {
            errs.push_str(&format!("{n}: no process found\n"));
            status = 1;
        }
    }
    CommandResult::streams(String::new(), errs, status)
}

/// `pidof NAME`
pub fn pidof(shell: &Shell, args: &[String]) -> CommandResult {
    let mut out = String::new();
    for n in args.iter().filter(|a| !a.starts_with('-')) {
        if let Some(pid) = super::system::process_pid(shell, n) {
            out.push_str(&format!("{pid} "));
        }
    }
    if out.is_empty() {
        return CommandResult::streams(String::new(), String::new(), 1);
    }
    CommandResult::ok(format!("{}\n", out.trim_end()))
}

/// `pgrep [-l] PATTERN`
pub fn pgrep(shell: &Shell, args: &[String]) -> CommandResult {
    let long = args.iter().any(|a| a == "-l" || a == "-a");
    let Some(pattern) = args.iter().find(|a| !a.starts_with('-')) else {
        return CommandResult::err("pgrep: no matching criteria specified\n", 2);
    };
    let mut out = String::new();
    for (pid, name) in super::system::process_table(shell) {
        // Real `pgrep` matches the executable name, not the whole command line,
        // so it agrees with `pidof` about what `sshd: /usr/sbin/sshd …` is.
        if super::system::process_name(&name).contains(pattern.as_str()) {
            if long {
                out.push_str(&format!("{pid} {name}\n"));
            } else {
                out.push_str(&format!("{pid}\n"));
            }
        }
    }
    let status = i32::from(out.is_empty());
    CommandResult::streams(out, String::new(), status)
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        let out = shell.execute(line);
        format!("{}{}", out.stdout, out.stderr)
    }

    #[test]
    fn sleep_accepts_durations_and_rejects_junk() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "sleep 5"), "");
        assert_eq!(run(&mut shell, "sleep 0.5"), "");
        assert_eq!(run(&mut shell, "sleep 2m"), "");
        assert!(run(&mut shell, "sleep abc").contains("invalid time interval"));
    }

    /// The single most common post-access action in SSH botnet telemetry.
    #[test]
    fn chpasswd_locks_out_the_owner_and_captures_the_plaintext() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("echo 'root:hunter2' | chpasswd");
        assert_eq!(out.status, 0, "{}", out.stderr);
        assert!(
            shell.captures.iter().any(
                |c| matches!(c, crate::shell::Capture::PasswordChange { target, password }
                    if target == "root" && password == "hunter2")
            ),
            "the plaintext must be captured as forensic data"
        );
        // The emulated shadow file changed, but never holds the plaintext.
        let shadow = run(&mut shell, "cat /etc/shadow");
        assert!(shadow.contains("root:$6$mimic$changed"), "{shadow}");
        assert!(
            !shadow.contains("hunter2"),
            "plaintext must not reach the VFS"
        );
    }

    #[test]
    fn chpasswd_rejects_unknown_users_and_non_root() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("echo 'nosuch:x' | chpasswd");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("does not exist"), "{}", out.stderr);

        let mut user = Shell::new("user", "debian");
        let out = user.execute("echo 'root:x' | chpasswd");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("Permission denied"), "{}", out.stderr);
    }

    #[test]
    fn useradd_creates_a_backdoor_account_visible_to_getent() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "useradd -m -s /bin/bash backdoor"), "");
        let passwd = run(&mut shell, "cat /etc/passwd");
        assert!(
            passwd.contains("backdoor:x:1001:1001::/home/backdoor:/bin/bash"),
            "{passwd}"
        );
        // The account is reachable the way a real one would be.
        assert!(run(&mut shell, "getent passwd backdoor").contains("backdoor"));
        assert!(run(&mut shell, "ls /home").contains("backdoor"));
        // And adding it twice fails the way useradd does.
        let again = shell.execute("useradd backdoor");
        assert_eq!(again.status, 9);
    }

    #[test]
    fn useradd_is_root_only() {
        let mut shell = Shell::new("user", "debian");
        let out = shell.execute("useradd eve");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("Permission denied"), "{}", out.stderr);
    }

    #[test]
    fn systemctl_reports_a_plausible_service_state() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "systemctl is-active ssh").starts_with("active"));
        assert!(run(&mut shell, "systemctl status ssh").contains("OpenBSD Secure Shell server"));
        assert!(run(&mut shell, "systemctl list-units").contains("cron.service"));
        // An unknown unit fails the way systemd's does.
        let missing = shell.execute("systemctl status nosuchthing");
        assert_eq!(missing.status, 4);
        assert!(
            missing.stderr.contains("could not be found"),
            "{}",
            missing.stderr
        );
    }

    #[test]
    fn systemctl_enable_is_root_only_and_reports_the_symlink() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "systemctl enable evil");
        assert!(out.contains("Created symlink"), "{out}");
        assert!(out.contains("evil.service"), "{out}");

        let mut user = Shell::new("user", "debian");
        let denied = user.execute("systemctl enable evil");
        assert_eq!(denied.status, 1);
        assert!(
            denied.stderr.contains("authentication required"),
            "{}",
            denied.stderr
        );
    }

    #[test]
    fn getent_reads_the_emulated_databases() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "getent passwd root").starts_with("root:x:0:0:"));
        assert!(run(&mut shell, "getent group sudo").contains("sudo:x:27"));
        let missing = shell.execute("getent passwd nosuchuser");
        assert_eq!(missing.status, 2);
    }

    #[test]
    fn chattr_and_lsattr_agree_about_what_exists() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "chattr +i /etc/passwd"), "");
        assert!(run(&mut shell, "lsattr /etc/passwd").contains("/etc/passwd"));
        let missing = shell.execute("chattr +i /nope");
        assert_eq!(missing.status, 1);
    }

    /// `/etc/passwd` names both of these as login shells, so a box that cannot
    /// run them contradicts a file every attacker reads.
    #[test]
    fn the_shells_etc_passwd_names_all_exist() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "which sync"), "/usr/bin/sync\n");
        assert_eq!(run(&mut shell, "which nologin"), "/usr/sbin/nologin\n");
        assert_eq!(shell.execute("sync").status, 0);
        let out = shell.execute("nologin");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("not available"), "{}", out.stderr);
    }

    #[test]
    fn pidof_and_pgrep_agree_with_the_process_table() {
        let mut shell = Shell::new("root", "debian");
        // sshd is in the fabricated table, so all three must find it.
        assert!(!run(&mut shell, "pidof sshd").trim().is_empty());
        assert!(!run(&mut shell, "pgrep sshd").trim().is_empty());
        let missing = shell.execute("pidof nosuchdaemon");
        assert_eq!(missing.status, 1);
    }

    /// `passwd` prompts twice, like the real thing, and the plaintext is
    /// captured on the second answer rather than written to the VFS.
    #[test]
    fn passwd_prompts_twice_and_captures_the_secret() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("passwd root");
        assert!(out.stdout.ends_with("New password: "), "{:?}", out.stdout);
        let out = shell.resume("s3cret");
        assert!(
            out.stdout.ends_with("Retype new password: "),
            "{:?}",
            out.stdout
        );
        let out = shell.resume("s3cret");
        assert!(
            out.stdout.contains("updated successfully"),
            "{:?}",
            out.stdout
        );
        assert!(shell.pending.is_none(), "the prompt must be cleared");
        assert!(shell.captures.iter().any(
            |c| matches!(c, crate::shell::Capture::PasswordChange { target, password }
                    if target == "root" && password == "s3cret")
        ));
        let shadow = run(&mut shell, "cat /etc/shadow");
        assert!(shadow.contains("root:$6$mimic$changed"), "{shadow}");
        assert!(
            !shadow.contains("s3cret"),
            "plaintext must not reach the VFS"
        );
    }

    #[test]
    fn passwd_refuses_a_mismatch_and_an_unknown_user() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("passwd root");
        shell.resume("one");
        let out = shell.resume("two");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("do not match"), "{}", out.stderr);
        assert!(shell.captures.is_empty(), "a mismatch captures nothing");

        let out = shell.execute("passwd nosuchuser");
        assert_eq!(out.status, 1);
        assert!(shell.pending.is_none(), "no prompt for a missing account");
    }

    #[test]
    fn nohup_runs_the_command_and_announces_the_redirect() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("nohup echo hi");
        assert_eq!(out.stdout, "hi\n");
        assert!(out.stderr.contains("nohup.out"), "{}", out.stderr);
    }
}
