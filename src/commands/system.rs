use super::CommandResult;
use crate::clock;
use crate::shell::{Pending, Screen, Shell};
use crate::vfs::snapshot::{USR_BIN, USR_SBIN};

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

            "-i" | "-l" | "-s" | "--login" | "-" => {}
            other if other.starts_with('-') => {}

            other => {
                let Some(id) = shell.vfs.resolve(shell.cwd, other) else {
                    return CommandResult::err(
                        format!("bash: {other}: No such file or directory\n"),
                        127,
                    );
                };
                let Some(bytes) = shell.vfs.node(id).file_bytes() else {
                    return CommandResult::err(format!("bash: {other}: Is a directory\n"), 126);
                };
                let text = String::from_utf8_lossy(&bytes).into_owned();
                return run_script(shell, &text);
            }
        }
    }

    match shell.stdin.clone() {
        Some(text) if !text.trim().is_empty() => run_script(shell, &text),
        _ => CommandResult::ok(""),
    }
}

const MAX_SCRIPT_LINES: usize = 4096;

fn run_script(shell: &mut Shell, text: &str) -> CommandResult {
    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;

    let mut collected = std::mem::take(&mut shell.captures);

    for line in text.lines().take(MAX_SCRIPT_LINES) {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let result = shell.execute(line);

        collected.push(crate::shell::Capture::ScriptCommand {
            line: line.to_string(),
            status: result.status,
        });
        collected.append(&mut shell.captures);

        out.push_str(&result.stdout);
        errs.push_str(&result.stderr);
        status = result.status;
        if result.exit {
            break;
        }

        if out.len() + errs.len() > super::MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    shell.captures = collected;
    CommandResult::streams(out, errs, status)
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

    let argv: Vec<String> = std::iter::once("cp".to_string())
        .chain(operands.into_iter().cloned())
        .collect();
    super::dispatch(shell, &argv)
}

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
                iter.next();
            }
            other if other.starts_with('-') => {
                iter.next();
            }
            _ => break,
        }
    }
    let rest: Vec<String> = iter.cloned().collect();
    if rest.is_empty() && login_shell {
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

pub fn su(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut target: Option<&str> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--command" | "-s" | "--shell" | "-g" | "--group" => {
                iter.next();
            }
            other if other.starts_with('-') => {}
            other => target = Some(other),
        }
    }
    let target = target.unwrap_or("root").to_string();

    if shell.uid == 0 {
        shell.switch_user(&target);
        return CommandResult::empty();
    }

    shell.pending = Some(Pending::SuPassword { target });
    CommandResult::ok("Password: ")
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

struct Proc {
    pid: u32,
    ppid: u32,
    user: String,
    tty: &'static str,
    stat: &'static str,

    cpu: &'static str,

    mem: &'static str,

    vsz: u32,

    rss: u32,
    time: &'static str,

    start: String,
    cmd: String,
}

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

fn invocation(name: &str, args: &[String]) -> String {
    if args.is_empty() {
        name.to_string()
    } else {
        format!("{name} {}", args.join(" "))
    }
}

pub fn process_table(shell: &Shell) -> Vec<(u32, String)> {
    session_table(shell, "ps")
        .into_iter()
        .map(|p| (p.pid, p.cmd))
        .collect()
}

pub fn process_name(cmd: &str) -> &str {
    let first = cmd.split_whitespace().next().unwrap_or(cmd);
    let first = first.strip_suffix(':').unwrap_or(first);
    let first = first.rsplit('/').next().unwrap_or(first);
    first.trim_start_matches('[').trim_end_matches(']')
}

pub fn process_pid(shell: &Shell, name: &str) -> Option<u32> {
    process_table(shell)
        .into_iter()
        .find(|(_, cmd)| process_name(cmd) == name)
        .map(|(pid, _)| pid)
}

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

pub fn ps(shell: &Shell, args: &[String]) -> CommandResult {
    let joined: String = args.join("");
    let table = session_table(shell, &invocation("ps", args));

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

#[derive(Clone)]
pub struct TopScreen {
    rows: Vec<String>,
    total: usize,
    running: usize,
}

impl TopScreen {
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
        shell.screen = Some(Screen::Top(screen));
        return CommandResult::empty();
    }
    CommandResult::ok(screen.render())
}

pub fn kill(shell: &Shell, args: &[String]) -> CommandResult {
    let mut pids: Vec<&str> = Vec::new();
    let mut list = false;
    for arg in args {
        match arg.as_str() {
            "-l" | "--list" => list = true,

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
                if shell.uid != 0 && p.user != shell.username {
                    out.push_str(&format!("-bash: kill: ({pid}) - Operation not permitted\n"));
                    status = 1;
                }
            }
        }
    }
    if status == 0 {
        CommandResult::empty()
    } else {
        CommandResult::err(out, status)
    }
}

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

pub fn free(shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human");
    let mega = args.iter().any(|a| a == "-m");
    let giga = args.iter().any(|a| a == "-g");

    let total = shell.persona.mem_total_kb;
    let free_mem = total * 73 / 100;
    let available = total * 86 / 100;
    let shared = 992u64;

    let buff = total * 13 / 1000 + total * 139 / 1000 + total * 20 / 1000;

    let used = total.saturating_sub(free_mem).saturating_sub(buff);

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
mod tests {
    use crate::clock;
    use crate::shell::{Screen, Shell};

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn a_dropped_script_runs_its_body() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/.x");
        shell.execute("printf '#!/bin/sh\\nid\\nwhoami\\n' > /tmp/.x/p.sh");
        let out = shell.execute("sh /tmp/.x/p.sh");
        assert!(out.stdout.contains("uid=0(root)"), "{:?}", out.stdout);
        assert!(out.stdout.contains("root\n"), "{:?}", out.stdout);

        let missing = shell.execute("sh /tmp/nope.sh");
        assert_eq!(missing.status, 127);
    }

    #[test]
    fn a_dropped_script_reports_each_line_it_ran() {
        use crate::shell::Capture;
        let mut shell = Shell::new("root", "debian");
        shell.execute("printf '#!/bin/sh\\nid\\nnosuchcmd\\n' > /tmp/p.sh");
        shell.captures.clear();
        shell.execute("sh /tmp/p.sh");

        let lines: Vec<(String, i32)> = shell
            .captures
            .iter()
            .filter_map(|c| match c {
                Capture::ScriptCommand { line, status } => Some((line.clone(), *status)),
                _ => None,
            })
            .collect();
        assert_eq!(
            lines,
            vec![("id".to_string(), 0), ("nosuchcmd".to_string(), 127)],
            "the shebang is not a command; the 127 is the field that names what \
             to emulate next"
        );
    }

    #[test]
    fn a_script_keeps_every_line_s_captures() {
        use crate::shell::Capture;
        let mut shell = Shell::new("root", "debian");
        shell.execute(
            "printf 'wget http://a.example/one\\nwget http://b.example/two\\n' > /tmp/two.sh",
        );
        shell.captures.clear();
        shell.execute("sh /tmp/two.sh");

        let urls: Vec<String> = shell
            .captures
            .iter()
            .filter_map(|c| match c {
                Capture::Download { url, .. } => Some(url.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            urls,
            vec![
                "http://a.example/one".to_string(),
                "http://b.example/two".to_string()
            ],
            "a line's captures were overwritten by the next line's"
        );
    }

    #[test]
    fn a_self_running_script_hits_the_nesting_cap() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("echo 'sh /tmp/loop.sh' > /tmp/loop.sh");
        let out = shell.execute("sh /tmp/loop.sh");
        assert!(
            out.stderr.contains("Resource temporarily unavailable"),
            "recursion was not bounded: {:?}",
            out.stderr
        );
    }

    #[test]
    fn a_script_runs_at_most_the_line_cap() {
        let mut shell = Shell::new("root", "debian");
        let body = "echo x\n".repeat(super::MAX_SCRIPT_LINES + 500);
        let out = shell.execute(&format!("printf '%s' '{body}' | sh"));
        assert_eq!(
            out.stdout.matches('x').count(),
            super::MAX_SCRIPT_LINES,
            "line cap not applied"
        );
    }

    #[test]
    fn sudo_dash_i_and_dash_s_hand_over_a_root_shell() {
        let mut shell = Shell::new("attacker", "debian");
        assert_eq!(run(&mut shell, "sudo -i"), "");
        assert_eq!(shell.last_status, 0);
        assert_eq!(run(&mut shell, "whoami"), "root\n");
        assert_eq!(run(&mut shell, "pwd"), "/root\n");
        assert_eq!(shell.prompt(), "root@debian:~# ");
        assert_eq!(run(&mut shell, "echo $HOME"), "/root\n");

        let mut shell = Shell::new("attacker", "debian");
        run(&mut shell, "cd /tmp");
        assert_eq!(run(&mut shell, "sudo -s"), "");
        assert_eq!(run(&mut shell, "whoami"), "root\n");
        assert_eq!(run(&mut shell, "pwd"), "/tmp\n");
        assert_eq!(shell.prompt(), "root@debian:/tmp# ");
        assert_eq!(run(&mut shell, "echo $HOME"), "/home/attacker\n");

        let mut shell = Shell::new("attacker", "debian");
        assert_eq!(
            run(&mut shell, "sudo -i id"),
            "uid=0(root) gid=0(root) groups=0(root)\n"
        );
        assert_eq!(run(&mut shell, "whoami"), "attacker\n");

        let mut shell = Shell::new("attacker", "debian");
        assert!(run(&mut shell, "sudo").contains("usage: sudo"));
        assert_eq!(run(&mut shell, "whoami"), "attacker\n");
    }

    #[test]
    fn sh_runs_a_command_line_and_bare_shells_are_silent() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "sh -c whoami"), "root\n");
        assert_eq!(run(&mut shell, "bash -c 'echo hi'"), "hi\n");

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

        assert_eq!(run(&mut shell, "uname -sm"), "Linux x86_64\n");
    }

    #[test]
    fn echo_newline_and_escapes() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo hello world"), "hello world\n");
        assert_eq!(run(&mut shell, "echo -n hi"), "hi");

        assert_eq!(run(&mut shell, r"echo -e 'a\tb'"), "a\tb\n");

        assert_eq!(run(&mut shell, r"echo 'a\tb'"), "a\\tb\n");

        assert_eq!(run(&mut shell, "echo -e \"a\\tb\\nc\""), "a\tb\nc\n");
        assert_eq!(run(&mut shell, "echo \"a\\tb\""), "a\\tb\n");
        assert_eq!(run(&mut shell, "echo \"a\\\"b\\\\c\""), "a\"b\\c\n");

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

        let out = run(&mut shell, "top");
        assert_eq!(out, "");
        let screen = shell.screen.take().expect("top should hold the screen");
        let Screen::Top(top) = screen else {
            panic!("top should hold a Screen::Top");
        };
        assert!(top.render().contains("Tasks:"));

        for line in ["top -b", "top -bn1", "top -n 1", "top --batch"] {
            assert!(
                run(&mut shell, line).contains("Tasks:"),
                "{line} should print a dump"
            );
            assert!(shell.screen.is_none(), "{line} should not hold the screen");
        }

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

        shell.interactive = false;
        assert!(run(&mut shell, "top").contains("Tasks:"));
        assert!(shell.screen.is_none(), "exec should not hold the screen");
        shell.interactive = true;

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

        let human = run(&mut shell, "free -h");
        assert!(!human.contains(".0Mi"), "unexpected `free -h`: {human}");
        assert!(!human.contains(".0Gi"), "unexpected `free -h`: {human}");
        assert!(human.contains("Gi") || human.contains("Mi"), "{human}");
    }

    #[test]
    fn memory_figures_agree_across_commands_for_every_persona() {
        for seed in 0..16u64 {
            let persona = crate::persona::Persona::from_seed(seed);
            let total = persona.mem_total_kb;
            let mut shell = Shell::with_persona("root", "debian", persona);

            let meminfo = run(&mut shell, "cat /proc/meminfo");
            assert!(
                meminfo.contains(&format!("MemTotal:        {total} kB")),
                "seed={seed} meminfo={meminfo}"
            );

            let free_out = run(&mut shell, "free");
            let mem_line = free_out
                .lines()
                .find(|l| l.starts_with("Mem:"))
                .expect("a Mem: row");
            let reported: u64 = mem_line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse().ok())
                .expect("a total column");
            assert_eq!(reported, total, "seed={seed}: free disagrees with meminfo");
        }
    }

    #[test]
    fn cpu_figures_agree_across_commands_for_every_persona() {
        for seed in 0..16u64 {
            let persona = crate::persona::Persona::from_seed(seed);
            let (cores, name) = (persona.cpu_cores, persona.cpu.name);
            let mut shell = Shell::with_persona("root", "debian", persona);

            assert_eq!(run(&mut shell, "nproc").trim(), cores.to_string());

            let lscpu_out = run(&mut shell, "lscpu");
            assert!(lscpu_out.contains(name), "seed={seed}: {lscpu_out}");
            assert!(
                lscpu_out.contains(&format!("CPU(s):                   {cores}")),
                "seed={seed}: {lscpu_out}"
            );

            let cpuinfo = run(&mut shell, "cat /proc/cpuinfo");
            assert!(cpuinfo.contains(name), "seed={seed}");
            assert_eq!(
                cpuinfo.matches("processor\t: ").count(),
                cores as usize,
                "seed={seed}: one cpuinfo block per core"
            );
        }
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

        assert!(run(&mut shell, "apt update").contains("Permission denied"));

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

        assert_eq!(run(&mut shell, "su"), "Password: ");
        assert!(shell.pending.is_some());
        assert_eq!(shell.uid, 1000, "identity is unchanged until a password");

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

        let default = run(&mut shell, "date");
        assert!(default.contains("UTC"));
        assert!(default.ends_with('\n'));

        let f = run(&mut shell, "date +%F");
        assert_eq!(f.matches('-').count(), 2);
        assert_eq!(run(&mut shell, "date +%%"), "%\n");
    }

    #[test]
    fn the_recon_commands_agree_on_one_timeline() {
        let mut shell = Shell::new("root", "debian");
        let year = clock::format(clock::now(), "%Y");

        assert!(run(&mut shell, "date").contains(&year));
        let banner = clock::uptime_banner();
        assert!(run(&mut shell, "uptime").contains(&banner));
        assert!(run(&mut shell, "w").contains(&banner));
        assert!(run(&mut shell, "top -b").contains(&banner));

        let last = run(&mut shell, "last");
        assert!(last.contains(&year), "last should be in {year}: {last}");
        assert!(last.contains("still logged in"));
        assert!(last.contains("wtmp begins"));

        let (prev, _) = clock::prev_login();
        assert!(last.contains(&clock::format(prev, "%a %b %e %H:%M")));

        let ps = run(&mut shell, "ps aux");
        assert!(ps.contains(&clock::format(clock::boot_time(), "%b%d")));

        let ls = run(&mut shell, "ls -l /etc/passwd");
        assert!(ls.contains(&clock::format(clock::install_time(), "%b %e")));
    }

    #[test]
    fn top_and_ps_list_themselves_not_each_other() {
        let mut shell = Shell::new("root", "debian");
        let top = run(&mut shell, "top -b");
        assert!(top.contains(" top\n"), "top should list itself: {top}");
        assert!(!top.contains("ps aux"));
        assert!(run(&mut shell, "ps aux").contains("ps aux"));
    }

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

        let meminfo = run(&mut shell, "cat /proc/meminfo");
        assert!(meminfo.contains(&format!("MemTotal:        {total} kB")));

        let df = run(&mut shell, "df");
        assert!(df.contains(&format!("{}", total / 2)), "/dev/shm is RAM/2");
        assert!(df.contains(&format!("{}", total / 10)), "/run is RAM/10");

        assert!(run(&mut shell, "top -b").contains(&format!("{:.1} total", total as f64 / 1024.0)));
    }
}
