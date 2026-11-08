pub mod admin;
pub mod fs;
pub mod net;
pub mod pkg;
pub mod system;
pub mod text;

use crate::shell::Shell;

pub const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub struct CommandResult {
    pub output: String,

    pub stderr: String,

    pub status: i32,

    pub exit: bool,
}

impl CommandResult {
    pub fn ok(output: impl Into<String>) -> Self {
        Self {
            output: output.into(),
            ..Self::default()
        }
    }

    pub fn err(stderr: impl Into<String>, status: i32) -> Self {
        Self {
            stderr: stderr.into(),
            status,
            ..Self::default()
        }
    }

    pub fn streams(output: impl Into<String>, stderr: impl Into<String>, status: i32) -> Self {
        Self {
            output: output.into(),
            stderr: stderr.into(),
            status,
            exit: false,
        }
    }

    pub fn empty() -> Self {
        Self::ok(String::new())
    }

    pub fn exiting(mut self) -> Self {
        self.exit = true;
        self
    }

    fn truncate(&mut self) {
        let budget = MAX_COMMAND_OUTPUT_BYTES;
        truncate_stream(&mut self.output, budget);
        truncate_stream(&mut self.stderr, budget.saturating_sub(self.output.len()));
    }
}

pub(crate) fn truncate_stream(text: &mut String, budget: usize) {
    if text.len() <= budget {
        return;
    }
    let mut cut = budget;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text.push_str("\n... (output truncated)\n");
}

enum CommandHandler {
    Mut(fn(&mut Shell, &[String]) -> CommandResult),
    Read(fn(&Shell, &[String]) -> CommandResult),
}

impl CommandHandler {
    fn run(self, shell: &mut Shell, args: &[String]) -> CommandResult {
        match self {
            CommandHandler::Mut(f) => f(shell, args),
            CommandHandler::Read(f) => f(shell, args),
        }
    }
}

pub const MAX_NESTED_COMMANDS: u32 = 16;

pub const LOGOUT: &str = "logout\n";

pub fn dispatch(shell: &mut Shell, argv: &[String]) -> CommandResult {
    if shell.nesting >= MAX_NESTED_COMMANDS {
        return CommandResult::err("-bash: fork: retry: Resource temporarily unavailable\n", 1);
    }
    shell.nesting += 1;
    let result = dispatch_inner(shell, argv);
    shell.nesting -= 1;
    result
}

fn dispatch_inner(shell: &mut Shell, argv: &[String]) -> CommandResult {
    let cmd = argv[0].as_str();
    let args = &argv[1..];

    let handler = match cmd {
        "ls" | "dir" => CommandHandler::Read(fs::ls),
        "cd" => CommandHandler::Mut(fs::cd),
        "pwd" => CommandHandler::Read(fs::pwd),
        "cat" => CommandHandler::Read(fs::cat),
        "head" => CommandHandler::Read(fs::head),
        "tail" => CommandHandler::Read(fs::tail),
        "wc" => CommandHandler::Read(fs::wc),
        "grep" => CommandHandler::Read(fs::grep),
        "find" => CommandHandler::Read(fs::find),
        "stat" => CommandHandler::Read(fs::stat),
        "du" => CommandHandler::Read(fs::du),

        "base64" => CommandHandler::Read(text::base64),
        "sed" => CommandHandler::Read(text::sed),
        "cut" => CommandHandler::Read(text::cut),
        "tr" => CommandHandler::Read(text::tr),
        "sort" => CommandHandler::Read(text::sort),
        "uniq" => CommandHandler::Read(text::uniq),
        "basename" => CommandHandler::Read(text::basename),
        "dirname" => CommandHandler::Read(text::dirname),
        "rev" => CommandHandler::Read(text::rev),
        "nl" => CommandHandler::Read(text::nl),
        "seq" => CommandHandler::Read(text::seq),
        "tee" => CommandHandler::Mut(text::tee),
        "xargs" => CommandHandler::Mut(text::xargs),
        "awk" | "mawk" => CommandHandler::Read(text::awk),
        "md5sum" => CommandHandler::Read(text::md5sum),
        "sha1sum" => CommandHandler::Read(text::sha1sum),
        "sha256sum" => CommandHandler::Read(text::sha256sum),
        "sha512sum" => CommandHandler::Read(text::sha512sum),

        "touch" => CommandHandler::Mut(fs::touch),
        "mkdir" => CommandHandler::Mut(fs::mkdir),
        "rmdir" => CommandHandler::Mut(fs::rmdir),
        "rm" => CommandHandler::Mut(fs::rm),
        "cp" => CommandHandler::Mut(fs::cp),
        "mv" => CommandHandler::Mut(fs::mv),
        "chmod" => CommandHandler::Mut(fs::chmod),
        "chown" => CommandHandler::Mut(fs::chown),
        "chgrp" => CommandHandler::Mut(fs::chgrp),
        "ln" => CommandHandler::Mut(fs::ln),
        "tar" => CommandHandler::Mut(fs::tar),

        "whoami" => CommandHandler::Read(system::whoami),
        "id" => CommandHandler::Read(system::id),
        "uname" => CommandHandler::Read(system::uname),
        "hostname" => CommandHandler::Read(system::hostname),
        "nproc" => CommandHandler::Read(system::nproc),
        "lscpu" => CommandHandler::Read(system::lscpu),
        "arch" => CommandHandler::Read(system::arch),
        "groups" => CommandHandler::Read(system::groups),
        "tty" => CommandHandler::Read(system::tty),
        "lsb_release" => CommandHandler::Read(system::lsb_release),
        "date" => CommandHandler::Read(system::date),
        "sudo" => CommandHandler::Mut(system::sudo),
        "su" => CommandHandler::Mut(system::su),
        "bash" | "sh" => CommandHandler::Mut(system::shell_cmd),
        "scp" => CommandHandler::Mut(system::scp),
        "echo" => CommandHandler::Read(system::echo),
        "printf" => CommandHandler::Read(system::printf),
        "env" | "printenv" => CommandHandler::Read(system::env),
        "export" => CommandHandler::Mut(system::export),
        "unset" => CommandHandler::Mut(system::unset),
        "clear" => CommandHandler::Read(system::clear),

        "sleep" => CommandHandler::Read(admin::sleep),
        "passwd" => CommandHandler::Mut(admin::passwd),
        "chpasswd" => CommandHandler::Mut(admin::chpasswd),
        "useradd" | "adduser" => CommandHandler::Mut(admin::useradd),
        "userdel" | "deluser" => CommandHandler::Mut(admin::userdel),
        "groupadd" | "addgroup" => CommandHandler::Mut(admin::groupadd),
        "systemctl" => CommandHandler::Read(admin::systemctl),
        "service" => CommandHandler::Read(admin::service),
        "chattr" => CommandHandler::Read(admin::chattr),
        "lsattr" => CommandHandler::Read(admin::lsattr),
        "nohup" => CommandHandler::Mut(admin::nohup),
        "getent" => CommandHandler::Read(admin::getent),
        "killall" => CommandHandler::Read(admin::killall),
        "sync" => CommandHandler::Read(admin::sync),
        "nologin" => CommandHandler::Read(admin::nologin),
        "pidof" => CommandHandler::Read(admin::pidof),
        "pgrep" => CommandHandler::Read(admin::pgrep),

        "ps" => CommandHandler::Read(system::ps),
        "top" => CommandHandler::Mut(system::top),
        "kill" => CommandHandler::Read(system::kill),
        "pkill" => CommandHandler::Read(system::pkill),
        "free" => CommandHandler::Read(system::free),
        "uptime" => CommandHandler::Read(system::uptime),

        "vi" => CommandHandler::Mut(text::vi),
        "nano" => CommandHandler::Mut(text::nano),

        "history" => CommandHandler::Mut(system::history),
        "which" => CommandHandler::Read(system::which),
        "w" => CommandHandler::Read(system::w),
        "last" => CommandHandler::Read(system::last),
        "df" => CommandHandler::Read(system::df),
        "mount" => CommandHandler::Read(system::mount),
        "crontab" => CommandHandler::Read(system::crontab),
        "dmesg" => CommandHandler::Read(system::dmesg),

        "wget" => CommandHandler::Mut(net::wget),
        "curl" => CommandHandler::Mut(net::curl),
        "ping" | "ping6" => CommandHandler::Read(net::ping),
        "netstat" => CommandHandler::Read(net::netstat),
        "ss" => CommandHandler::Read(net::ss),
        "ip" => CommandHandler::Read(net::ip),
        "nc" | "netcat" => CommandHandler::Mut(net::nc),

        "python3" => CommandHandler::Mut(net::python3),
        "perl" => CommandHandler::Mut(net::perl),

        "apt" | "apt-get" => CommandHandler::Read(pkg::apt),
        "dpkg" => CommandHandler::Read(pkg::dpkg),

        "true" => return CommandResult::ok(""),
        "false" => return CommandResult::err("", 1),
        "exit" | "logout" => {
            let farewell = if shell.interactive { LOGOUT } else { "" };
            if args.is_empty() {
                return CommandResult::streams(farewell, "", shell.last_status).exiting();
            }
            if args.len() == 1 {
                if let Ok(n) = args[0].parse::<i64>() {
                    let code = ((n % 256 + 256) % 256) as i32;
                    return CommandResult::streams(farewell, "", code).exiting();
                } else {
                    return CommandResult::streams(
                        farewell,
                        format!("-bash: {cmd}: {}: numeric argument required\n", args[0]),
                        2,
                    )
                    .exiting();
                }
            }
            return CommandResult::err(format!("-bash: {cmd}: too many arguments\n"), 1);
        }

        other => {
            if crate::vfs::snapshot::USR_BIN.contains(&other)
                || crate::vfs::snapshot::USR_SBIN.contains(&other)
            {
                return CommandResult::empty();
            }
            return CommandResult::err(format!("-bash: {other}: command not found\n"), 127);
        }
    };

    let mut result = handler.run(shell, args);
    result.truncate();
    result
}
