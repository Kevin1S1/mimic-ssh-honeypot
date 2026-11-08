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
use crate::shell::{Pending, Shell};
use crate::vfs::snapshot::{USR_BIN, USR_SBIN};

mod process;
mod top;

pub use process::{kill, pkill, process_name, process_pid, process_table, ps};
pub use top::{top, TopScreen};

fn is_root(shell: &Shell) -> bool {
    shell.uid == 0
}

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
pub fn nproc(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.persona.cpu_cores))
}

/// `lscpu` — describes the same CPU `/proc/cpuinfo` and `nproc` report, drawn
/// from the deployment persona so the three cannot drift apart.
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

/// `bash`/`sh` — the shell this session already claims to be.
///
/// Three ways a payload arrives, all of which now run:
///
/// - `-c LINE`, the classic `sh -c "cd /tmp; wget ...; ./x"`;
/// - piped stdin, which is what `... | base64 -d | sh` and `curl ... | sh`
///   produce — the single most common staging idiom there is;
/// - a script operand, read back out of the VFS, which is what the
///   `wget`-then-`chmod +x`-then-run sequence ends in.
///
/// Each line of a script or of stdin is run through the same shell that would
/// have run it interactively, so the nesting cap and the output cap apply
/// exactly as they do everywhere else.
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
            other if other.starts_with('-') => {}
            // A script operand: read it out of the VFS and run it.
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

    // No `-c` and no operand: a real shell reads its stdin. Over a pipe that is
    // the payload; with no pipe there is nothing to read and it exits.
    match shell.stdin.clone() {
        Some(text) if !text.trim().is_empty() => run_script(shell, &text),
        _ => CommandResult::ok(""),
    }
}

/// How many lines of a script or of piped stdin `sh` will run.
///
/// The output cap alone does not bound this: a script of a million `true` lines
/// produces nothing to truncate and still costs a parse per line. A VFS file
/// can hold 8 MiB, so without a line cap an attacker buys arbitrary CPU for one
/// upload.
const MAX_SCRIPT_LINES: usize = 4096;

/// Run each line of `text` as a shell command, accumulating both streams.
///
/// This is what makes a dropped script observable: the download was already
/// captured, but until the body actually ran, nothing downstream of it — the
/// second-stage fetch, the persistence attempt, the credential change — was
/// ever seen.
fn run_script(shell: &mut Shell, text: &str) -> CommandResult {
    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;
    // `Shell::execute` clears `captures` on entry, so each line would otherwise
    // wipe the one before it — a script that fetched two payloads would log
    // only the second. Accumulate across the whole body and hand the lot back,
    // the way command substitution already does for its subshell.
    let mut collected = std::mem::take(&mut shell.captures);

    for line in text.lines().take(MAX_SCRIPT_LINES) {
        let line = line.trim();
        // Shebangs and comments are not commands.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let result = shell.execute(line);
        // The network layer logs a `command` event per line the *client*
        // submits, and these lines came from a file. Capturing each one is what
        // makes a dropped script observable rather than just its side effects.
        collected.push(crate::shell::Capture::ScriptCommand {
            line: line.to_string(),
            status: result.status,
        });
        collected.append(&mut shell.captures);
        // `stdout` is the pipe view and `text` the terminal-combined one; a
        // script's output is going onward as a stream, so only the former.
        out.push_str(&result.stdout);
        errs.push_str(&result.stderr);
        status = result.status;
        if result.exit {
            break;
        }
        // Bounded like every other accumulated stream.
        if out.len() + errs.len() > super::MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    shell.captures = collected;
    CommandResult::streams(out, errs, status)
}

/// `printf FORMAT [ARG]...`
///
/// Scripts reach for `printf` wherever `echo`'s portability is in doubt, which
/// in practice means anywhere a payload builds a multi-line file.
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
                    // An unknown escape is passed through as written, the way
                    // bash's printf does rather than swallowing the backslash.
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

/// `free [-h|-m|-g]`
pub fn free(shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human");
    let mega = args.iter().any(|a| a == "-m");
    let giga = args.iter().any(|a| a == "-g");

    // Base figures in KiB, matching `/proc/meminfo` and `top`'s header. The
    // columns must add up — `total = used + free + buff/cache` is what a real
    // `free` prints, and a row that doesn't balance is arithmetic anyone can
    // check in one command.
    // buff/cache = Buffers + Cached + SReclaimable, and used is whatever is
    // left, exactly as procps derives them from `/proc/meminfo`.
    // Derived from the persona's `MemTotal` with the same proportions
    // `/proc/meminfo` uses, so the two agree for any deployment.
    let total = shell.persona.mem_total_kb;
    let free_mem = total * 73 / 100;
    let available = total * 86 / 100;
    let shared = 992u64;
    // buff/cache = Buffers + Cached + SReclaimable.
    let buff = total * 13 / 1000 + total * 139 / 1000 + total * 20 / 1000;
    // used is whatever is left, so the row balances by construction.
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
/// `None` if it is not a recognised external binary. Resolves against the
/// listed set (`USR_BIN`/`USR_SBIN` — the same names `ls /usr/bin` shows),
/// not the runnable registry, so `which gzip` finds it even though `gzip`
/// isn't wired into `commands::dispatch`.
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
pub fn df(shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human-readable");
    // Every tmpfs size is derived from the persona's `MemTotal` the way the
    // kernel and systemd size them — devtmpfs and /dev/shm at half of RAM,
    // /run and /run/user/<uid> at a tenth. A `df` implying more RAM than
    // `free` reports is a two-command honeypot check.
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
mod tests;
