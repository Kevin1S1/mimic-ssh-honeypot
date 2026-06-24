//! System and identity commands: `whoami`, `id`, `uname`, `hostname`, `echo`,
//! `env`, `export`, `unset`, `clear`.

use super::CommandResult;
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

#[cfg(test)]
mod tests {
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
}
