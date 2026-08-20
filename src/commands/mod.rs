//! Emulated command registry and dispatch.
//!
//! Every command is a pure Rust function that reads and mutates the in-memory
//! [`Shell`] state and returns a [`CommandResult`]. No real process is ever
//! spawned and no real path is ever touched.

pub mod fs;
pub mod net;
pub mod pkg;
pub mod system;

use crate::shell::Shell;

/// Hard cap on command output to prevent memory-amplification DoS.
///
/// The VFS is node-bounded, but a single command such as `cat` on a large
/// attacker-written file can still amplify into an unbounded `String`. This
/// constant bounds that amplification at the dispatch layer so *every* command
/// is covered without per-command changes. 1 MiB is generous enough that
/// legitimate interactions never hit it, yet small enough to make deliberate
/// memory exhaustion infeasible.
pub const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB

/// The result of running one command.
pub struct CommandResult {
    /// Text written to the client (LF line endings).
    pub output: String,
    /// Process-style exit status.
    pub status: i32,
    /// Whether the session should end after this command.
    pub exit: bool,
}

impl CommandResult {
    /// A successful result (status 0) with the given output.
    pub fn ok(output: impl Into<String>) -> Self {
        Self {
            output: output.into(),
            status: 0,
            exit: false,
        }
    }

    /// A failing result with `status` and the given output.
    pub fn err(output: impl Into<String>, status: i32) -> Self {
        Self {
            output: output.into(),
            status,
            exit: false,
        }
    }

    /// A successful empty result (status 0, no output).
    pub fn empty() -> Self {
        Self::ok(String::new())
    }

    /// Mark this result as ending the session.
    pub fn exiting(mut self) -> Self {
        self.exit = true;
        self
    }

    /// Truncate the output to at most [`MAX_COMMAND_OUTPUT_BYTES`], snapping to
    /// a UTF-8 char boundary and appending a notice. Defence-in-depth: even if a
    /// handler produces too much, dispatch caps it here.
    fn truncate(&mut self) {
        if self.output.len() <= MAX_COMMAND_OUTPUT_BYTES {
            return;
        }
        let mut cut = MAX_COMMAND_OUTPUT_BYTES;
        while cut > 0 && !self.output.is_char_boundary(cut) {
            cut -= 1;
        }
        self.output.truncate(cut);
        self.output.push_str("\n... (output truncated)\n");
    }
}

/// A command handler that either mutates the shell or reads it.
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

/// How deep commands that run other commands (`sudo`, `sh -c`) may nest before
/// the shell refuses. Every level is a real stack frame, and a stack overflow
/// aborts the whole process rather than one session.
const MAX_NESTED_COMMANDS: u32 = 16;

/// Look up `argv[0]` and run the matching command.
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
        // Filesystem reads.
        "ls" | "dir" => CommandHandler::Read(fs::ls),
        "cd" => CommandHandler::Mut(fs::cd),
        "pwd" => CommandHandler::Read(fs::pwd),
        "cat" => CommandHandler::Read(fs::cat),
        "head" => CommandHandler::Read(fs::head),
        "tail" => CommandHandler::Read(fs::tail),
        "wc" => CommandHandler::Read(fs::wc),
        "grep" => CommandHandler::Read(fs::grep),
        "find" => CommandHandler::Read(fs::find),

        // Filesystem mutations (operate on the per-session VFS only).
        "touch" => CommandHandler::Mut(fs::touch),
        "mkdir" => CommandHandler::Mut(fs::mkdir),
        "rmdir" => CommandHandler::Mut(fs::rmdir),
        "rm" => CommandHandler::Mut(fs::rm),
        "cp" => CommandHandler::Mut(fs::cp),
        "mv" => CommandHandler::Mut(fs::mv),
        "chmod" => CommandHandler::Mut(fs::chmod),
        "tar" => CommandHandler::Mut(fs::tar),

        // System / identity commands.
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
        "env" | "printenv" => CommandHandler::Read(system::env),
        "export" => CommandHandler::Mut(system::export),
        "unset" => CommandHandler::Mut(system::unset),
        "clear" => CommandHandler::Read(system::clear),

        // Process-table emulation (no real process is ever signalled).
        "ps" => CommandHandler::Read(system::ps),
        "top" => CommandHandler::Read(system::top),
        "kill" => CommandHandler::Read(system::kill),
        "pkill" => CommandHandler::Read(system::pkill),
        "free" => CommandHandler::Read(system::free),
        "uptime" => CommandHandler::Read(system::uptime),

        // Reconnaissance commands (fabricated, in-memory only).
        "history" => CommandHandler::Mut(system::history),
        "which" => CommandHandler::Read(system::which),
        "w" => CommandHandler::Read(system::w),
        "last" => CommandHandler::Read(system::last),
        "df" => CommandHandler::Read(system::df),
        "mount" => CommandHandler::Read(system::mount),
        "crontab" => CommandHandler::Read(system::crontab),
        "dmesg" => CommandHandler::Read(system::dmesg),

        // Network tools (no real network is ever touched).
        "wget" => CommandHandler::Mut(net::wget),
        "curl" => CommandHandler::Mut(net::curl),
        "ping" | "ping6" => CommandHandler::Read(net::ping),
        "netstat" => CommandHandler::Read(net::netstat),
        "ss" => CommandHandler::Read(net::ss),
        "ip" => CommandHandler::Read(net::ip),

        // Package-manager stubs (in-memory package DB; nothing is ever installed).
        "apt" | "apt-get" => CommandHandler::Read(pkg::apt),
        "dpkg" => CommandHandler::Read(pkg::dpkg),

        "true" => return CommandResult::ok(""),
        "false" => return CommandResult::err("", 1),
        "exit" | "logout" => return CommandResult::ok("logout\n").exiting(),

        other => return CommandResult::err(format!("-bash: {other}: command not found\n"), 127),
    };

    let mut result = handler.run(shell, args);
    result.truncate();
    result
}
