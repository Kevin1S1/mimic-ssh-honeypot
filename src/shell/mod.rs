//! Shell state machine.
//!
//! Holds the per-session shell state — the virtual filesystem, environment,
//! working directory, and identity — and the pure-text operations over it:
//! prompt rendering, variable expansion, and tokenization. Command dispatch is
//! layered on top of this by the command registry; nothing here touches real
//! I/O or runs a real process.

pub mod arith;
pub mod complete;
pub mod env;
pub mod line;
pub mod parser;

use crate::commands;
use crate::persona::Persona;
use crate::vfs::{snapshot, NodeId, Vfs};
use env::Env;

/// The result of running one command line.
///
/// `text` is what a terminal shows — both streams in the order the line
/// produced them — and is what a PTY channel writes, because a real sshd with
/// a pty has only one stream to write to. `stdout` and `stderr` are the same
/// bytes split by descriptor, which is what a channel without a pty needs so
/// stderr can go out as `SSH_EXTENDED_DATA_STDERR`.
#[derive(Default)]
pub struct Output {
    /// Both streams, in terminal order.
    pub text: String,
    /// Text the line wrote to stdout.
    pub stdout: String,
    /// Text the line wrote to stderr.
    pub stderr: String,
    /// Process-style exit status.
    pub status: i32,
    /// Whether the session should end (e.g. after `exit`).
    pub exit: bool,
}

impl Output {
    /// Append one command's two streams, keeping `text` in terminal order.
    ///
    /// ponytail: a command reports both streams as two finished strings, so
    /// within one command stderr is shown before stdout — the order GNU `ls`
    /// and `cat` actually use, since they report an operand they cannot open
    /// before listing the ones they can. Upgrade when a command needs to
    /// interleave the two.
    fn push(&mut self, stdout: &str, stderr: &str) {
        self.text.push_str(stderr);
        self.text.push_str(stdout);
        self.stdout.push_str(stdout);
        self.stderr.push_str(stderr);
    }

    /// A finished [`Output`] holding one write to each stream. Used where a
    /// prompt answers the client directly rather than through a command.
    fn written(stdout: &str, stderr: &str, status: i32) -> Self {
        let mut out = Output {
            status,
            ..Output::default()
        };
        out.push(stdout, stderr);
        out
    }
}

/// A structured event produced by a command that the network layer drains and
/// logs after each line. Keeps the emulation layer free of real I/O while still
/// surfacing forensic events.
#[derive(Debug, Clone)]
pub enum Capture {
    /// An attacker fetched a remote URL (`wget`/`curl`).
    Download {
        /// The tool used (`wget` or `curl`).
        tool: String,
        /// The requested URL.
        url: String,
        /// Where the body was written (a VFS path, or `-` for stdout).
        dest: String,
    },
    /// One line of a script `sh` ran, with the status it returned.
    ///
    /// A `command` event is emitted by the network layer per line the *client*
    /// submits, so a dropped script's body would otherwise be invisible in the
    /// log — the very intelligence running it exists to recover. Routing it
    /// through the capture channel keeps the emulation layer free of the
    /// session id and peer it would need to log directly.
    ScriptCommand {
        /// The line as it appeared in the script.
        line: String,
        /// The status it returned.
        status: i32,
    },
    /// A password set non-interactively (`chpasswd`, `passwd`). Locking the
    /// owner out is the most common thing an SSH botnet does once it lands, so
    /// the new secret is captured the same way a guessed one is.
    PasswordChange {
        /// The account whose password was changed.
        target: String,
        /// The new password, in the clear.
        password: String,
    },
    /// A password entered at an `su` prompt. The attempted secret is captured
    /// as forensic data (a guessed root/target password) before the switch.
    SuAuth {
        /// The account the client tried to become.
        target: String,
        /// The password the client typed at the prompt.
        password: String,
    },
}

/// A follow-up line of input a command is waiting for. While a shell has a
/// pending prompt, the network layer collects the next line (with echo
/// suppressed) and feeds it back via [`Shell::resume`], rather than treating it
/// as a new command.
#[derive(Debug, Clone)]
pub enum Pending {
    /// `su [USER]` is waiting for the target's password before switching.
    SuPassword {
        /// The account to become once a password is supplied.
        target: String,
    },
    /// `passwd [USER]` is collecting a new secret. Real `passwd` asks twice and
    /// refuses if the two differ, so both prompts are emulated: the second one
    /// is where a script that pipes the same line twice succeeds and a typo
    /// fails, which is the behaviour a bot's `passwd` wrapper is written for.
    NewPassword {
        /// The account whose password is being set.
        target: String,
        /// The first answer, once given.
        first: Option<String>,
    },
    /// A here-document (`cat << EOF`) is collecting its body. The line that
    /// opened it runs once a line holds the delimiter and nothing else.
    Heredoc {
        /// The command line with the `<<` operator and delimiter removed.
        command: String,
        /// The line exactly as it was typed, for the capture.
        raw: String,
        /// What ends the body, and how the body is treated.
        doc: parser::Heredoc,
        /// The lines collected so far, each newline-terminated.
        body: String,
    },
}

impl Pending {
    /// Whether the client's answer is echoed back as it is typed. A password
    /// is not; a here-document body is ordinary input and bash's readline
    /// echoes it under its continuation prompt.
    pub fn echoes(&self) -> bool {
        matches!(self, Pending::Heredoc { .. })
    }

    /// The prompt shown while this is outstanding, if the shell draws one.
    /// `su` writes its own; a here-document gets bash's `PS2`.
    pub fn prompt(&self) -> Option<&'static str> {
        match self {
            Pending::SuPassword { .. } | Pending::NewPassword { .. } => None,
            Pending::Heredoc { .. } => Some("> "),
        }
    }
}

/// A full-screen display or terminal hold a command asked to take over with.
/// The network layer takes it after the line runs and owns the redraw timer
/// and keystroke handling — this layer never has a clock or a channel of its
/// own — so each variant only holds what a display needs to compute, never how
/// it is delivered.
#[derive(Clone)]
pub enum Screen {
    /// `top`: repaints on a timer until `q` or Ctrl-C.
    Top(commands::system::TopScreen),
    /// `vi`/`nano`: a read-only view of the target file, held until the
    /// editor's own quit sequence.
    Editor(commands::text::EditorScreen),
    /// `nc -l`: holds the terminal with no display of its own — exactly what a
    /// real listener shows before a client connects — until Ctrl-C or
    /// disconnect.
    Listen,
}

/// Environment variables describing the SSH connection itself. The network
/// layer seeds them; they survive `su`, as they do on a real box, because they
/// belong to the connection rather than to the logged-in identity.
const CONNECTION_VARS: &[&str] = &["SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"];

/// The bit bucket. Writes to it are discarded instead of filling the VFS —
/// `> /dev/null` is in most bot payloads, and a real one never grows.
const DEV_NULL: &str = "/dev/null";

/// An opened redirect target: where a stream's output goes, and whether it adds
/// to what is already there.
#[derive(Debug, Clone)]
struct Sink {
    /// The expanded target path, for error messages.
    path: String,
    /// The node the output lands in, fixed when the target was opened. `None`
    /// is `/dev/null`.
    node: Option<NodeId>,
    /// `>>`: keep the existing contents.
    append: bool,
}

/// Which sink each of a stage's output streams was pointed at. `None` means the
/// stream still reaches the client.
#[derive(Debug, Default)]
struct Sinks {
    /// Target for `>`, `1>`, and the stdout half of `&>`.
    stdout: Option<Sink>,
    /// Target for `2>` and the stderr half of `&>`.
    stderr: Option<Sink>,
    /// `2>&1` while stdout was still the terminal: the two share one
    /// descriptor, so what the command writes to stderr comes back to the
    /// client on stdout — which is what puts it in the pipe that
    /// `cmd 2>&1 | grep` is built around.
    stderr_merged: bool,
    /// `>&2`/`1>&2`, the mirror case.
    stdout_merged: bool,
}

/// The session state a command substitution runs on a copy of, restored when
/// its subshell ends. The filesystem is deliberately not in here: a real
/// subshell shares it with its parent.
struct Subshell {
    env: Env,
    cwd: NodeId,
    prev_cwd: NodeId,
    home: NodeId,
    username: String,
    uid: u32,
    gid: u32,
    pending: Option<Pending>,
    screen: Option<Screen>,
}

/// Per-session shell.
pub struct Shell {
    /// The in-memory Debian filesystem.
    pub vfs: Vfs,
    /// Environment variables.
    pub env: Env,
    /// Current working directory node.
    pub cwd: NodeId,
    /// Home directory node for this session.
    pub home: NodeId,
    /// Previous working directory (for `cd -`).
    pub prev_cwd: NodeId,
    /// Logged-in username.
    pub username: String,
    /// Emulated hostname.
    pub hostname: String,
    /// Effective user id.
    pub uid: u32,
    /// Effective group id.
    pub gid: u32,
    /// Exit status of the last command (for `$?`).
    pub last_status: i32,
    /// Fake shell PID (for `$$`).
    pub pid: u32,
    /// When this session logged in, unix seconds. `w`, `last` and `ps` report
    /// it, so it has to be the real login instant rather than a fixed time of
    /// day that contradicts the clock `date` returns.
    pub login: i64,
    /// Current command-nesting depth (`sudo`, `sh -c`, ...), bounded by the
    /// command registry so a deeply nested line cannot overflow the stack.
    pub nesting: u32,
    /// Bytes of command-substitution output the current line may still splice
    /// into itself. Reset per top-level line; see [`Shell::substitute`].
    subst_budget: usize,
    /// Stderr written by substitutions while the current stage's words were
    /// expanded. Expansion happens before the command's redirections are
    /// applied, so this text goes to the shell's own stderr — `2>` on the
    /// command does not catch it — and is drained by [`Shell::run_pipeline`].
    subst_stderr: String,
    /// Standard input for the running command: the previous pipeline stage's
    /// output, or `None` outside a pipeline.
    pub stdin: Option<String>,
    /// Whether the running command's output goes to the terminal. False for a
    /// stage whose output is piped onward — commands that format differently
    /// off a terminal (`ls`) check this.
    pub stdout_is_tty: bool,
    /// Whether this is an interactive shell. False for a one-shot `exec` and
    /// for a shell channel with no terminal — bash reads a pipe
    /// non-interactively, and the difference is observable: only an
    /// interactive login shell announces `logout` on its way out.
    pub interactive: bool,
    /// Submitted command lines this session, exposed by the `history` builtin.
    /// Bounded to keep per-session memory predictable.
    pub history: Vec<String>,
    /// Captures (downloads, ...) produced by the last command, awaiting logging
    /// by the network layer. Cleared at the start of every command line.
    pub captures: Vec<Capture>,
    /// An interactive prompt a command is waiting on (e.g. `su` reading a
    /// password). `None` between commands.
    pub pending: Option<Pending>,
    /// A full-screen display a command asked to hold the terminal with (`top`,
    /// `vi`/`nano`, `nc -l`). The network layer takes it after the line runs.
    pub screen: Option<Screen>,
    /// How many command substitutions are open around the running command. A
    /// substitution captures its body's stdout through a pipe, so nothing
    /// inside one is writing to a terminal however the stage itself looks.
    subst_depth: u32,
    /// This deployment's fabricated hardware identity. Every command that
    /// reports a hardware fact reads it from here, so `lscpu`, `free`, `df`,
    /// `dmesg` and `/proc` cannot contradict each other.
    pub persona: Persona,
    /// A here-document body waiting to become the next pipeline's stdin.
    heredoc_stdin: Option<String>,
    /// A completed here-document, opening line and body together, waiting for
    /// the network layer to log it as the one command it was.
    pub heredoc_log: Option<String>,
}

impl Shell {
    /// Construct a fresh shell for `username` on a freshly built Debian
    /// snapshot, using the default persona.
    ///
    /// Production goes through [`Shell::with_persona`] so each sensor gets its
    /// own hardware identity; this is the convenience form for tests and any
    /// caller with no seed to derive one from.
    pub fn new(username: &str, hostname: &str) -> Self {
        Self::with_persona(username, hostname, Persona::sample())
    }

    /// Construct a fresh shell whose emulated hardware comes from `persona`.
    ///
    /// `root` (and the empty username) get uid 0 and `/root`; any other user is
    /// treated as a normal account (uid 1000) with a home under `/home`,
    /// created on demand.
    pub fn with_persona(username: &str, hostname: &str, persona: Persona) -> Self {
        let mut vfs = snapshot::build(hostname, &persona);
        let user = if username.is_empty() {
            "root"
        } else {
            username
        };

        let (uid, gid, home_path) = if user == "root" {
            (0, 0, "/root".to_string())
        } else {
            (1000, 1000, format!("/home/{user}"))
        };

        // Ensure the home directory exists (attackers may log in as any name).
        let home = ensure_home(&mut vfs, &home_path, uid, gid);
        let env = Env::login(user, &home_path, hostname);

        Self {
            vfs,
            env,
            cwd: home,
            home,
            prev_cwd: home,
            username: user.to_string(),
            hostname: hostname.to_string(),
            uid,
            gid,
            last_status: 0,
            pid: 1337,
            login: crate::clock::now(),
            nesting: 0,
            subst_budget: commands::MAX_COMMAND_OUTPUT_BYTES,
            subst_stderr: String::new(),
            stdin: None,
            stdout_is_tty: true,
            interactive: true,
            screen: None,
            subst_depth: 0,
            heredoc_stdin: None,
            heredoc_log: None,
            persona,
            history: Vec::new(),
            captures: Vec::new(),
            pending: None,
        }
    }

    /// Maximum command lines retained for the `history` builtin.
    pub const MAX_HISTORY: usize = 1000;

    /// Record a submitted command line in the session history (bounded).
    pub fn record_history(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        self.history.push(line.to_string());
        if self.history.len() > Self::MAX_HISTORY {
            let overflow = self.history.len() - Self::MAX_HISTORY;
            self.history.drain(0..overflow);
        }
    }

    /// The absolute path of the current working directory.
    pub fn cwd_path(&self) -> String {
        self.vfs.path_of(self.cwd)
    }

    /// The interactive prompt string (no trailing newline).
    pub fn prompt(&self) -> String {
        let sigil = if self.uid == 0 { '#' } else { '$' };
        let cwd = self.cwd_path();
        let home = self.vfs.path_of(self.home);
        let display = if cwd == home {
            "~".to_string()
        } else if let Some(rest) = cwd.strip_prefix(&format!("{home}/")) {
            format!("~/{rest}")
        } else {
            cwd
        };
        format!("{}@{}:{}{} ", self.username, self.hostname, display, sigil)
    }

    /// Expand variables in `line` and split it into argument words — the argv
    /// the command layer dispatches on. Expansion runs first so an unquoted
    /// `$VAR` value is still word-split by the tokenizer; the quoting in the
    /// value itself is escaped on the way through, so it stays data.
    pub fn parse_line(&mut self, line: &str) -> Vec<String> {
        let expanded = self.expand(line);
        parser::tokenize(&expanded)
    }

    /// Expand `$VAR`, `${VAR}`, `$?`, `$$`, `$(…)`, `` `…` `` and `$((…))` in
    /// `line`, respecting the quoting around each one: single quotes suppress
    /// expansion entirely, double quotes suppress the word splitting the
    /// tokenizer would otherwise do, and a backslash protects the character
    /// after it.
    fn expand(&mut self, line: &str) -> String {
        self.expand_with(line, Expansion::Words)
    }

    /// The body of [`Shell::expand`], parameterised by what its result feeds.
    fn expand_with(&mut self, line: &str, mode: Expansion) -> String {
        let mut out = String::new();
        let mut in_single = false;
        let mut in_double = false;
        // A here-document body is a command's stdin, not shell source: quotes
        // in it are ordinary characters, so the quote state never leaves
        // `false` and every expanded value is emitted exactly as it is.
        let words = mode == Expansion::Words;
        let mut chars = line.char_indices().peekable();

        while let Some((i, c)) = chars.next() {
            // A substitution is one word however much it holds, so it is
            // recognised before the character-by-character rules below.
            if !in_single && (c == '$' || c == '`') {
                if let Some(subst) = parser::substitution_at(line, i) {
                    let body = &line[subst.body.0..subst.body.1];
                    let value = if subst.arithmetic {
                        self.arithmetic(body)
                    } else {
                        self.substitute(body)
                    };
                    emit(&mut out, mode, &value, in_double);
                    while chars.peek().is_some_and(|(j, _)| *j < subst.end) {
                        chars.next();
                    }
                    continue;
                }
            }
            match c {
                '\\' if !in_single => {
                    if words {
                        // The escape reaches the tokenizer intact, so whatever
                        // it protects stays data — including a `$` that would
                        // expand.
                        out.push(c);
                        if let Some((_, next)) = chars.next() {
                            out.push(next);
                        }
                    } else if matches!(chars.peek(), Some((_, '$' | '`' | '\\'))) {
                        // In a body a backslash protects only what could still
                        // expand; before anything else it is a plain character.
                        let (_, next) = chars.next().expect("peeked");
                        out.push(next);
                    } else {
                        out.push(c);
                    }
                }
                '\'' if words && !in_double => {
                    in_single = !in_single;
                    out.push(c);
                }
                '"' if words && !in_single => {
                    in_double = !in_double;
                    out.push(c);
                }
                '$' if !in_single => match chars.peek().map(|&(_, n)| n) {
                    Some('?') => {
                        chars.next();
                        emit(&mut out, mode, &self.last_status.to_string(), in_double);
                    }
                    Some('$') => {
                        chars.next();
                        emit(&mut out, mode, &self.pid.to_string(), in_double);
                    }
                    Some('#') => {
                        chars.next();
                        emit(&mut out, mode, "0", in_double);
                    }
                    Some('0') => {
                        chars.next();
                        emit(&mut out, mode, "-bash", in_double);
                    }
                    Some('*') | Some('@') => {
                        chars.next();
                        emit(&mut out, mode, "", in_double);
                    }
                    Some(d) if d.is_ascii_digit() => {
                        chars.next();
                        emit(&mut out, mode, "", in_double);
                    }
                    Some('{') => {
                        chars.next();
                        let mut name = String::new();
                        for (_, n) in chars.by_ref() {
                            if n == '}' {
                                break;
                            }
                            name.push(n);
                        }
                        let val = match name.as_str() {
                            "#" => "0".to_string(),
                            "0" => "-bash".to_string(),
                            "?" => self.last_status.to_string(),
                            "$" => self.pid.to_string(),
                            "*" | "@" => String::new(),
                            _ if !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()) => {
                                String::new()
                            }
                            _ => self.env.get(&name).unwrap_or("").to_string(),
                        };
                        emit(&mut out, mode, &val, in_double);
                    }
                    Some(n) if n.is_alphabetic() || n == '_' => {
                        let mut name = String::new();
                        while let Some(&(_, n)) = chars.peek() {
                            if n.is_alphanumeric() || n == '_' {
                                name.push(n);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        emit(&mut out, mode, self.env.get(&name).unwrap_or(""), in_double);
                    }
                    _ => out.push('$'),
                },
                c => out.push(c),
            }
        }
        out
    }

    /// Run a substitution's body and return the text bash would splice into the
    /// line: the command's *stdout* with its trailing newlines stripped.
    /// Anything the body wrote to stderr is not part of the value — it is held
    /// for the outer line to emit, so `echo $(ls /nosuch)` reports the error
    /// and echoes an empty argument, exactly as bash does.
    ///
    /// The body is a command line of its own — `$(cd /tmp; ls | wc -l)` — so it
    /// runs through [`Shell::execute`], in a subshell: what it changes about the
    /// session itself (working directory, environment, identity) is discarded
    /// when it ends, while what it writes to the filesystem stays, exactly as a
    /// real subshell's fork boundary falls. It also cannot end the session
    /// (bash's subshell exit does not log the parent out), whatever it captured
    /// is added to the outer line's captures rather than replacing them, and
    /// both the nesting depth and the per-line output budget bound what it can
    /// spend.
    fn substitute(&mut self, body: &str) -> String {
        // Every level here is a stack frame that `dispatch`'s cap never sees:
        // the descent runs through expansion, before any command is reached.
        if self.nesting >= commands::MAX_NESTED_COMMANDS {
            return String::new();
        }
        self.nesting += 1;
        self.subst_depth += 1;
        let session = Subshell {
            env: self.env.clone(),
            cwd: self.cwd,
            prev_cwd: self.prev_cwd,
            home: self.home,
            username: self.username.clone(),
            uid: self.uid,
            gid: self.gid,
            pending: self.pending.clone(),
            screen: self.screen.clone(),
        };
        let saved = std::mem::take(&mut self.captures);
        let output = self.execute(body);
        let inner = std::mem::replace(&mut self.captures, saved);
        self.captures.extend(inner);
        self.env = session.env;
        self.cwd = session.cwd;
        self.prev_cwd = session.prev_cwd;
        self.home = session.home;
        self.username = session.username;
        self.uid = session.uid;
        self.gid = session.gid;
        self.pending = session.pending;
        // A substitution runs in a subshell with no terminal of its own, so
        // `echo $(top)` captures a dump and does not take the screen.
        self.screen = session.screen;
        self.nesting -= 1;
        self.subst_depth -= 1;

        // Held stderr is capped like any other stream: a line has room for
        // hundreds of substitutions, and each one's stderr is only bounded on
        // its own.
        self.subst_stderr.push_str(&output.stderr);
        commands::truncate_stream(&mut self.subst_stderr, commands::MAX_COMMAND_OUTPUT_BYTES);
        let mut value = output.stdout;
        if output.exit {
            // `logout` is what an interactive shell prints on its way out; a
            // subshell that exits prints nothing.
            if let Some(rest) = value.strip_suffix(commands::LOGOUT) {
                value.truncate(rest.len());
            }
        }
        while value.ends_with('\n') {
            value.pop();
        }

        // One command's output is already capped, but a line has room for
        // hundreds of substitutions; the budget bounds their sum the way
        // `execute` bounds a chained line's.
        if value.len() > self.subst_budget {
            let mut cut = self.subst_budget;
            while cut > 0 && !value.is_char_boundary(cut) {
                cut -= 1;
            }
            value.truncate(cut);
        }
        self.subst_budget -= value.len();
        value
    }

    /// Evaluate an `$((…))` body and return the number it comes to.
    ///
    /// The body is expanded first, so `$((x + $(echo 1)))` works, and bare
    /// names resolve against the environment. A malformed expression or a
    /// division by zero comes to zero rather than the syntax error bash prints,
    /// because expansion has no channel to fail on.
    // ponytail: no arithmetic syntax errors; upgrade when expansion can report
    // a failure back to the command line.
    fn arithmetic(&mut self, body: &str) -> String {
        if self.nesting >= commands::MAX_NESTED_COMMANDS {
            return "0".to_string();
        }
        self.nesting += 1;
        let expanded = self.expand(body);
        self.nesting -= 1;
        arith::eval(&self.env, &expanded).unwrap_or(0).to_string()
    }

    /// Switch this session's effective identity to `user` (`su`), as if a
    /// fresh login shell for that account. Mirrors [`Shell::new`]'s
    /// root/non-root split so `su`, `su root`, and `su <name>` all land the
    /// attacker in a believable home directory with a matching environment.
    pub fn switch_user(&mut self, user: &str) {
        let user = if user.is_empty() { "root" } else { user };
        let (uid, gid, home_path) = if user == "root" {
            (0, 0, "/root".to_string())
        } else {
            (1000, 1000, format!("/home/{user}"))
        };
        let home = ensure_home(&mut self.vfs, &home_path, uid, gid);
        // `su` inherits the connection environment from the caller's shell —
        // only the login variables are rebuilt for the new identity.
        let connection: Vec<(&str, String)> = CONNECTION_VARS
            .iter()
            .filter_map(|key| self.env.get(key).map(|value| (*key, value.to_string())))
            .collect();
        self.env = Env::login(user, &home_path, &self.hostname);
        for (key, value) in connection {
            self.env.set(key, &value);
        }
        self.username = user.to_string();
        self.uid = uid;
        self.gid = gid;
        self.cwd = home;
        self.home = home;
        self.prev_cwd = home;
    }

    /// Complete a [`Pending`] interactive prompt with the line the client just
    /// entered (e.g. the password for `su`). Clears the pending state and
    /// returns the resulting output.
    pub fn resume(&mut self, input: &str) -> Output {
        match self.pending.take() {
            Some(Pending::SuPassword { target }) => {
                // Capture the attempted password as forensic data, then switch.
                // The honeypot keeps the attacker engaged rather than gating on
                // a real credential (same rationale as `sudo`/`su`), but a
                // realistic `Password:` prompt still has to appear first.
                self.captures.push(Capture::SuAuth {
                    target: target.clone(),
                    password: input.to_string(),
                });
                self.switch_user(&target);
                Output::default()
            }
            Some(Pending::NewPassword {
                target,
                first: None,
            }) => {
                self.pending = Some(Pending::NewPassword {
                    target,
                    first: Some(input.to_string()),
                });
                Output::written("Retype new password: ", "", 0)
            }
            Some(Pending::NewPassword {
                target,
                first: Some(first),
            }) => {
                if first != input {
                    return Output::written(
                        "",
                        "Sorry, passwords do not match.\n\
                         passwd: Authentication token manipulation error\n\
                         passwd: password unchanged\n",
                        1,
                    );
                }
                // The plaintext is the forensic value; the emulated shadow file
                // only ever holds a crypt-shaped placeholder.
                self.captures.push(Capture::PasswordChange {
                    target: target.clone(),
                    password: first.clone(),
                });
                commands::admin::set_shadow_entry(self, &target);
                Output::written("passwd: password updated successfully\n", "", 0)
            }
            Some(Pending::Heredoc {
                command,
                raw,
                doc,
                mut body,
            }) => {
                let line = if doc.strip_tabs {
                    input.trim_start_matches('\t')
                } else {
                    input
                };
                if line == doc.delimiter {
                    return self.run_heredoc(&command, &raw, &doc, body);
                }
                body.push_str(line);
                body.push('\n');
                // The body grows a line at a time from the client, so it is
                // capped like every other buffer an attacker can drive.
                commands::truncate_stream(&mut body, commands::MAX_COMMAND_OUTPUT_BYTES);
                self.pending = Some(Pending::Heredoc {
                    command,
                    raw,
                    doc,
                    body,
                });
                Output::default()
            }
            None => Output::default(),
        }
    }

    /// End a here-document at end-of-input rather than at its delimiter.
    ///
    /// A script that stops mid-body still runs the command with what it has,
    /// and bash warns on the way — so `ssh host 'cat << EOF'`, which can never
    /// supply a body, behaves the way `bash -c` does with the same string.
    pub fn finish_heredoc_at_eof(&mut self) -> Option<Output> {
        let Some(Pending::Heredoc {
            command,
            raw,
            doc,
            body,
        }) = self.pending.take()
        else {
            return None;
        };
        let mut out = self.run_heredoc(&command, &raw, &doc, body);
        let warning = format!(
            "-bash: warning: here-document delimited by end-of-file (wanted `{}')\n",
            doc.delimiter
        );
        out.text.insert_str(0, &warning);
        out.stderr.insert_str(0, &warning);
        Some(out)
    }

    /// Run the line a here-document was opened on, with the collected body as
    /// its stdin.
    fn run_heredoc(
        &mut self,
        command: &str,
        raw: &str,
        doc: &parser::Heredoc,
        body: String,
    ) -> Output {
        self.pending = None;
        // The body *is* the payload — a dropped script, a crontab, a key — so
        // the capture records the document whole rather than a bare `cat` with
        // the interesting part missing. Logged here, once, when it closes:
        // the body lines are not commands and are never logged as such.
        self.heredoc_log = Some(format!("{raw}\n{body}{}", doc.delimiter));
        // An unquoted delimiter leaves the body subject to expansion, which is
        // how `cat << EOF` interpolates `$HOME`; a quoted one takes it as-is.
        let text = if doc.expand {
            self.expand_with(&body, Expansion::Literal)
        } else {
            body
        };
        self.heredoc_stdin = Some(text);
        let out = self.execute(command);
        // A command that ignored stdin leaves the body behind; it belongs to
        // this line only.
        self.heredoc_stdin = None;
        out
    }

    /// Run one segment as a pipeline: each stage's *stdout* becomes the next
    /// stage's stdin, and only the last stage's stdout reaches the client.
    /// Every stage's stderr reaches the client, the way a real pipeline shares
    /// one terminal between all of them — `cat /nope | wc -l` prints the error
    /// and counts nothing, rather than counting the error.
    /// Returns `None` if the segment held no command at all.
    ///
    /// Filters (`cat`, `grep`, `head`, `tail`, `wc`) read [`Shell::stdin`] when
    /// they get no file operand, exactly as they read real stdin. A stage that
    /// ignores stdin — `ls`, say — behaves as it would in a real pipeline: the
    /// upstream output is simply discarded.
    fn run_pipeline(&mut self, segment: &str) -> Option<commands::CommandResult> {
        let stages = parser::split_pipeline(segment);
        let last_stage = stages.len() - 1;
        // A here-document body is the first stage's stdin, exactly as a pipe
        // from an upstream stage would be.
        let mut piped: Option<String> = self.heredoc_stdin.take();
        let mut last: Option<commands::CommandResult> = None;
        let mut stderr = String::new();

        for (i, stage) in stages.iter().enumerate() {
            let (text, redirects) = match parser::split_redirects(stage) {
                Ok(split) => split,
                Err(message) => return Some(commands::CommandResult::err(message, 2)),
            };
            // Words are expanded before the targets are opened, so
            // `echo $(cat f) > f` reads `f` before the redirect truncates it —
            // the order bash performs the two in.
            let argv = self.parse_line(&text);
            let sinks = match self.open_redirects(&redirects) {
                Ok(sinks) => sinks,
                // bash opens the targets before it runs the command, so a
                // redirect that cannot be opened means nothing runs at all.
                Err(message) => return Some(commands::CommandResult::err(message, 1)),
            };
            // Expanding the words above may have run a substitution that wrote
            // to stderr; that happened before this command's redirections, so
            // it goes straight to the terminal rather than through the sinks.
            stderr.push_str(&std::mem::take(&mut self.subst_stderr));
            commands::truncate_stream(&mut stderr, commands::MAX_COMMAND_OUTPUT_BYTES);
            // A stage that is nothing but a redirect (`> f`) still opens it.
            if argv.is_empty() {
                continue;
            }
            self.stdin = piped.take();
            self.stdout_is_tty = i == last_stage && sinks.stdout.is_none() && self.subst_depth == 0;
            let result = commands::dispatch(self, &argv);
            self.stdin = None;
            self.stdout_is_tty = true;
            let mut result = self.route_output(result, &sinks);
            stderr.push_str(&std::mem::take(&mut result.stderr));
            commands::truncate_stream(&mut stderr, commands::MAX_COMMAND_OUTPUT_BYTES);
            piped = Some(result.output.clone());
            last = Some(result);
        }
        // Every stage's stderr rides out on the last stage's result, which is
        // the one the segment reports. A segment that ran no command at all
        // still reports what expanding it wrote.
        match last.as_mut() {
            Some(result) => result.stderr = stderr,
            None if !stderr.is_empty() => {
                return Some(commands::CommandResult::streams("", stderr, 0))
            }
            None => {}
        }
        last
    }

    /// Create or truncate every redirect target, resolving which sink each
    /// stream ends up pointing at. Returns the bash error text for the first
    /// target that cannot be opened.
    fn open_redirects(&mut self, redirects: &[parser::Redirect]) -> Result<Sinks, String> {
        let mut sinks = Sinks::default();
        for redirect in redirects {
            // `>&1` and `2>&2` point a stream at itself, which changes nothing.
            if matches!(&redirect.target, parser::Target::Dup(s) if *s == redirect.stream) {
                continue;
            }
            // A dup against a stream that is still the terminal cannot be
            // resolved to a sink: it means "come back on that stream instead",
            // which only the routing below can honour.
            let mut merged = false;
            let sink = match &redirect.target {
                parser::Target::File { path, append } => {
                    // The target word is expanded like any other, so
                    // `> $HOME/f` and `> "my file"` land where bash puts them.
                    // An unset or multi-word target is a redirect bash cannot
                    // resolve to one file, and it says so.
                    let mut words = self.parse_line(path);
                    if words.len() != 1 {
                        return Err(format!("-bash: {path}: ambiguous redirect\n"));
                    }
                    let path = words.remove(0);
                    let node = self.open_redirect(&path, *append)?;
                    Some(Sink {
                        path,
                        node,
                        append: *append,
                    })
                }
                // `2>&1` points a stream at whatever the other one already
                // reached; when that one is still the terminal there is no
                // sink to share, only the stream it comes back on.
                parser::Target::Dup(parser::Stream::Stdout) => {
                    merged = sinks.stdout.is_none();
                    sinks.stdout.clone()
                }
                // The parser only builds `Dup` from descriptor 1 or 2.
                parser::Target::Dup(_) => {
                    merged = sinks.stderr.is_none();
                    sinks.stderr.clone()
                }
            };
            // Redirects apply left to right, so a later one pointing the same
            // stream at a file undoes an earlier dup — which is the whole
            // difference between `> f 2>&1` and `2>&1 > f`.
            match redirect.stream {
                parser::Stream::Stdout => {
                    sinks.stdout = sink;
                    sinks.stdout_merged = merged;
                }
                parser::Stream::Stderr => {
                    sinks.stderr = sink;
                    sinks.stderr_merged = merged;
                }
                parser::Stream::Both => {
                    sinks.stdout = sink.clone();
                    sinks.stderr = sink;
                    sinks.stdout_merged = merged;
                    sinks.stderr_merged = merged;
                }
            }
        }
        Ok(sinks)
    }

    /// Create `path` if it is missing and truncate it unless `append`, the way
    /// opening a redirect target does, without writing anything yet. Returns
    /// the node the write will land in — `None` for `/dev/null` — so the write
    /// goes where the open did even if the command moves the working directory
    /// out from under the path, exactly as an already-open descriptor does.
    fn open_redirect(&mut self, path: &str, append: bool) -> Result<Option<NodeId>, String> {
        let (parent, name) = commands::fs::resolve_parent(self, path)
            .ok_or_else(|| format!("-bash: {path}: No such file or directory\n"))?;

        if let Some(existing) = self.vfs.child(parent, &name) {
            // Matched by node, not by path, so `cd /dev && echo x > null` is
            // swallowed too rather than filling the bit bucket up.
            if Some(existing) == self.vfs.resolve(self.vfs.root(), DEV_NULL) {
                return Ok(None);
            }
            let meta = &self.vfs.node(existing).meta;
            if meta.is_dir() {
                return Err(format!("-bash: {path}: Is a directory\n"));
            }
            if !meta.writable_by(self.uid, self.gid) {
                return Err(format!("-bash: {path}: Permission denied\n"));
            }
            if !append && !self.vfs.write_file(existing, &[], false) {
                return Err(format!("-bash: {path}: No space left on device\n"));
            }
            return Ok(Some(existing));
        }

        if !self.vfs.node(parent).meta.writable_by(self.uid, self.gid) {
            return Err(format!("-bash: {path}: Permission denied\n"));
        }
        let (uid, gid) = (self.uid, self.gid);
        let id = self
            .vfs
            .add_file(parent, &name, Vec::new(), 0o644, uid, gid);
        if id == parent {
            // The node cap refused the file; say so rather than reporting a
            // write that never happened.
            return Err(format!("-bash: {path}: No space left on device\n"));
        }
        Ok(Some(id))
    }

    /// Send each of a command's streams to whichever sink it was redirected
    /// to, returning what is left for the client.
    fn route_output(
        &mut self,
        mut result: commands::CommandResult,
        sinks: &Sinks,
    ) -> commands::CommandResult {
        // The streams go out in the order [`Output::push`] shows them, so
        // `> f 2>&1` — where both descriptors are dups of one open file — puts
        // the same bytes in the file that a terminal would have shown, and the
        // second write follows the first rather than truncating it, exactly as
        // one shared file offset does.
        let mut written = None;
        let mut failure = None;
        if let Some(sink) = sinks.stderr.as_ref() {
            let text = std::mem::take(&mut result.stderr);
            failure = self.divert(sink, &text, &mut written);
        }
        if let Some(sink) = sinks.stdout.as_ref() {
            let text = std::mem::take(&mut result.output);
            failure = self.divert(sink, &text, &mut written).or(failure);
        }
        // A refused write is reported to the client, like a full disk.
        if let Some(message) = failure {
            result.stderr.push_str(&message);
            result.status = 1;
        }
        // A stream duplicated onto one still reaching the client comes back on
        // that one instead, so `2>&1` puts the error where a pipe can see it.
        if sinks.stderr_merged {
            let mut merged = std::mem::take(&mut result.stderr);
            merged.push_str(&result.output);
            result.output = merged;
        }
        if sinks.stdout_merged {
            let stdout = std::mem::take(&mut result.output);
            result.stderr.push_str(&stdout);
        }
        result
    }

    /// Write one stream into its sink, recording the node it landed in so a
    /// second stream pointed at the same file appends after it instead of
    /// truncating what the first one wrote.
    fn divert(&mut self, sink: &Sink, text: &str, written: &mut Option<NodeId>) -> Option<String> {
        if text.is_empty() {
            return None;
        }
        let append = sink.append || (sink.node.is_some() && sink.node == *written);
        *written = sink.node;
        self.write_redirect(sink, text.as_bytes(), append).err()
    }

    /// Write `data` into an already-opened sink. A sink with no node is
    /// `/dev/null`, which swallows it.
    fn write_redirect(&mut self, sink: &Sink, data: &[u8], append: bool) -> Result<(), String> {
        let Some(node) = sink.node else {
            return Ok(());
        };
        if !self.vfs.write_file(node, data, append) {
            return Err(format!("-bash: {}: No space left on device\n", sink.path));
        }
        Ok(())
    }

    /// Run one command line: cut off any `#` comment, split what is left on
    /// `;`, `&&`, and `||`, then for each segment expand variables, tokenize,
    /// dispatch to the command registry, and record the resulting `$?`. Empty
    /// lines — and comment-only ones — are no-ops that leave `$?` alone.
    pub fn execute(&mut self, line: &str) -> Output {
        self.captures.clear();
        // A substitution runs its body through here too; the budget belongs to
        // the line the attacker typed, so only that one refills it.
        if self.nesting == 0 {
            self.subst_budget = commands::MAX_COMMAND_OUTPUT_BYTES;
            // Every path that expands words drains this, but clearing it here
            // means a caller that expands outside a pipeline (a prompt, a
            // completion) cannot leave text to surface on the next line.
            self.subst_stderr.clear();

            // A here-document needs the lines that follow, which only the
            // network layer can read, so the line is parked and the body is
            // collected through `resume`. Nested runs — a substitution, an
            // `sh -c` — have no further input to read, so they never park.
            if let Some((doc, command)) = parser::split_heredoc(parser::strip_comment(line)) {
                self.pending = Some(Pending::Heredoc {
                    command,
                    raw: line.to_string(),
                    doc,
                    body: String::new(),
                });
                return Output::default();
            }
        }

        let mut out = Output::default();
        let mut status = 0;
        let mut ran = false;

        for segment in parser::split_segments(parser::strip_comment(line)) {
            if segment.text.trim().is_empty() {
                if segment.run_if != parser::Separator::Always {
                    // `&& cmd` with nothing in front of it, as bash sees it.
                    let mut syntax = Output {
                        status: 2,
                        ..Output::default()
                    };
                    syntax.push("", "-bash: syntax error near unexpected token `&&'\n");
                    return syntax;
                }
                continue;
            }
            let should_run = match segment.run_if {
                parser::Separator::Always => true,
                parser::Separator::AndIf => status == 0,
                parser::Separator::OrIf => status != 0,
            };
            if !should_run {
                continue;
            }

            let Some(result) = self.run_pipeline(segment.text) else {
                continue;
            };
            ran = true;
            status = result.status;
            self.last_status = status;
            out.push(&result.output, &result.stderr);
            if result.exit {
                out.exit = true;
                break;
            }
            // The per-command cap bounds one command; a chained line has to be
            // bounded as a whole, or `cat big; cat big; ...` multiplies it by
            // the number of segments the line has room for. The two streams
            // share the budget, so splitting the output between them does not
            // buy an attacker a second helping.
            if out.text.len() >= commands::MAX_COMMAND_OUTPUT_BYTES {
                let budget = commands::MAX_COMMAND_OUTPUT_BYTES;
                commands::truncate_stream(&mut out.text, budget);
                commands::truncate_stream(&mut out.stdout, budget);
                commands::truncate_stream(&mut out.stderr, budget);
                break;
            }
        }

        if ran {
            out.status = status;
        }
        out
    }
}

/// What an expansion's result feeds, which decides whether the characters a
/// tokenizer would take as syntax have to be escaped on the way out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expansion {
    /// Argument words for the command layer.
    Words,
    /// A here-document body: a command's stdin, never shell source.
    Literal,
}

/// Append an expanded value under the rules of `mode`.
fn emit(out: &mut String, mode: Expansion, value: &str, in_double: bool) {
    match mode {
        Expansion::Words => push_value(out, value, in_double),
        Expansion::Literal => out.push_str(value),
    }
}

/// Append an expansion's result to the line the tokenizer will read, escaping
/// the characters it would otherwise take as syntax.
///
/// What a variable holds is data, not shell source: a quote or a backslash in
/// a value is a character the command receives, never quoting that re-parses
/// the rest of the line. Whitespace is deliberately left alone, so an unquoted
/// value still splits into words and a quoted one does not — the one part of
/// the value bash does act on. `in_double` only spares the single quote, which
/// the tokenizer already treats as an ordinary character inside double quotes.
fn push_value(out: &mut String, value: &str, in_double: bool) {
    for c in value.chars() {
        match c {
            '\\' | '"' => out.push('\\'),
            '\'' if !in_double => out.push('\\'),
            _ => {}
        }
        out.push(c);
    }
}

/// Ensure `home_path` exists in `vfs`, creating it with skeleton dotfiles if
/// the account is one the snapshot does not ship. Returns the home node id, or
/// the root when the arena is too full to create it — which is what real sshd
/// does after "Could not chdir to home directory".
fn ensure_home(vfs: &mut Vfs, home_path: &str, uid: u32, gid: u32) -> NodeId {
    if let Some(id) = vfs.resolve(vfs.root(), home_path) {
        return id;
    }
    let Some(home) = vfs.mkdir_p(home_path, 0o755, uid, gid) else {
        return vfs.root();
    };
    vfs.add_file(home, ".bashrc", &b"# ~/.bashrc\n"[..], 0o644, uid, gid);
    vfs.add_file(home, ".profile", &b"# ~/.profile\n"[..], 0o644, uid, gid);
    home
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_starts_in_root_home() {
        let shell = Shell::new("root", "debian");
        assert_eq!(shell.cwd_path(), "/root");
        assert_eq!(shell.uid, 0);
        assert_eq!(shell.prompt(), "root@debian:~# ");
    }

    #[test]
    fn unknown_user_gets_created_home() {
        let shell = Shell::new("attacker", "debian");
        assert_eq!(shell.cwd_path(), "/home/attacker");
        assert_eq!(shell.uid, 1000);
        assert_eq!(shell.prompt(), "attacker@debian:~$ ");
    }

    #[test]
    fn prompt_abbreviates_paths_under_home() {
        let mut shell = Shell::new("root", "debian");
        // Move cwd outside home: absolute path is shown verbatim.
        shell.cwd = shell.vfs.resolve(shell.vfs.root(), "/etc").unwrap();
        assert_eq!(shell.prompt(), "root@debian:/etc# ");
    }

    #[test]
    fn parse_line_expands_variables() {
        let mut shell = Shell::new("root", "debian");
        shell.last_status = 7;
        assert_eq!(shell.parse_line("echo $USER"), vec!["echo", "root"]);
        assert_eq!(shell.parse_line("echo ${HOME}"), vec!["echo", "/root"]);
        assert_eq!(shell.parse_line("echo $?"), vec!["echo", "7"]);
        assert_eq!(shell.parse_line("echo $$"), vec!["echo", "1337"]);
        assert_eq!(shell.parse_line("echo $#"), vec!["echo", "0"]);
        assert_eq!(shell.parse_line("echo $0"), vec!["echo", "-bash"]);
        assert_eq!(shell.parse_line("echo $1 $2"), vec!["echo"]);
        assert_eq!(
            shell.parse_line("echo ${#} ${0} ${1}"),
            vec!["echo", "0", "-bash"]
        );
        // Unset variables expand to nothing.
        assert_eq!(shell.parse_line("echo $NOPE end"), vec!["echo", "end"]);
    }

    #[test]
    fn single_quotes_suppress_expansion() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.parse_line("echo '$USER'"), vec!["echo", "$USER"]);
    }

    #[test]
    fn double_quotes_expand_and_hold_a_single_quote() {
        let mut shell = Shell::new("root", "debian");
        // The apostrophe is an ordinary character inside double quotes, so it
        // must not turn the rest of the line into a single-quoted string.
        assert_eq!(
            shell.parse_line(r#"echo "it's $USER""#),
            vec!["echo", "it's root"]
        );
        assert_eq!(shell.execute(r#"echo "it's $USER""#).text, "it's root\n");
    }

    #[test]
    fn a_backslash_protects_the_dollar_it_precedes() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.parse_line(r"echo \$USER"), vec!["echo", "$USER"]);
        assert_eq!(shell.parse_line(r#"echo "\$USER""#), vec!["echo", "$USER"]);
        // An escaped backslash is data; the `$` after it still expands.
        assert_eq!(shell.parse_line(r"echo \\$USER"), vec!["echo", r"\root"]);
    }

    #[test]
    fn an_expanded_value_is_data_not_syntax() {
        let mut shell = Shell::new("root", "debian");
        shell.execute(r#"export Q="a'b""#);
        shell.execute(r#"export D='a"b'"#);
        shell.execute(r"export B='a\b'");
        shell.execute("export S='a  b'");

        // Quotes and backslashes arriving in a value are characters the
        // command receives, not quoting that re-parses the word.
        assert_eq!(shell.execute("echo $Q").text, "a'b\n");
        assert_eq!(shell.execute(r#"echo "$D""#).text, "a\"b\n");
        assert_eq!(shell.execute("echo $B").text, "a\\b\n");
        // A value cannot open a quote that swallows what follows it.
        assert_eq!(shell.execute("echo $D tail").text, "a\"b tail\n");

        // Word splitting is the one thing that still applies to an unquoted
        // value, and double quotes still suppress it.
        assert_eq!(shell.parse_line("echo $S"), vec!["echo", "a", "b"]);
        assert_eq!(shell.parse_line(r#"echo "$S""#), vec!["echo", "a  b"]);
    }

    #[test]
    fn command_substitution_runs_the_body() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.execute("echo $(whoami)").text, "root\n");
        assert_eq!(shell.execute("echo `whoami`").text, "root\n");
        // The whole line the body holds runs, separators, pipes and all.
        assert_eq!(shell.execute("echo $(cd /tmp; pwd)").text, "/tmp\n");
        assert_eq!(shell.execute("echo $(echo a b c | wc -w)").text, "3\n");
        // Trailing newlines go, inner ones stay.
        assert_eq!(shell.execute(r#"echo "[$(echo hi)]""#).text, "[hi]\n");
        assert_eq!(
            shell.execute(r#"echo "[$(echo one; echo two)]""#).text,
            "[one\ntwo]\n"
        );
        // Nested substitutions expand innermost first.
        assert_eq!(shell.execute("echo $(echo $(whoami))").text, "root\n");
        // Quoting suppresses it exactly as it suppresses `$VAR`.
        assert_eq!(shell.execute("echo '$(whoami)'").text, "$(whoami)\n");
        assert_eq!(shell.execute(r"echo \$(whoami)").text, "$(whoami)\n");
        assert_eq!(shell.execute("echo '`whoami`'").text, "`whoami`\n");
    }

    #[test]
    fn substitution_output_is_data_not_syntax() {
        let mut shell = Shell::new("root", "debian");
        // Separators arrive after the line was split, so they stay arguments:
        // a substitution cannot smuggle in a second command.
        assert_eq!(
            shell.execute("echo $(echo 'a; touch /tmp/pwned')").text,
            "a; touch /tmp/pwned\n"
        );
        assert!(shell.vfs.resolve(shell.vfs.root(), "/tmp/pwned").is_none());
        // Nor a redirect, a pipe, a quote or a further expansion.
        assert_eq!(
            shell.execute("echo $(echo 'a > /tmp/out | b')").text,
            "a > /tmp/out | b\n"
        );
        assert!(shell.vfs.resolve(shell.vfs.root(), "/tmp/out").is_none());
        assert_eq!(shell.execute(r#"echo $(echo "it's")"#).text, "it's\n");
        assert_eq!(shell.execute("echo $(echo '$USER')").text, "$USER\n");
        // The words are expanded before the redirect target is truncated.
        shell.execute("echo before > /tmp/f");
        shell.execute("echo $(cat /tmp/f) > /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "before\n");

        // Word splitting is the one thing that still applies, and only unquoted.
        assert_eq!(
            shell.parse_line("echo $(echo 'a  b')"),
            vec!["echo", "a", "b"]
        );
        assert_eq!(
            shell.parse_line(r#"echo "$(echo 'a  b')""#),
            vec!["echo", "a  b"]
        );
    }

    #[test]
    fn a_substitution_is_a_subshell_not_the_session() {
        let mut shell = Shell::new("root", "debian");
        // `exit` in a subshell ends the subshell, silently.
        let out = shell.execute("echo $(exit)");
        assert!(!out.exit);
        assert_eq!(out.text, "\n");
        // What it changes about the session goes with it; what it wrote stays.
        shell.execute("echo $(cd /tmp; export MARK=1; touch /tmp/left-behind)");
        assert_eq!(shell.cwd_path(), "/root");
        assert_eq!(shell.execute("echo $MARK").text, "\n");
        assert!(shell
            .vfs
            .resolve(shell.vfs.root(), "/tmp/left-behind")
            .is_some());
        // The outer command's status is what the line reports.
        assert_eq!(shell.execute("echo $(false)").status, 0);
        assert_eq!(shell.execute("echo $?").text, "0\n");
    }

    #[test]
    fn a_substitution_keeps_the_captures_around_it() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("wget http://example.com/one -O /tmp/one; echo $(wget http://example.com/two -O /tmp/two)");
        let urls: Vec<&str> = shell
            .captures
            .iter()
            .filter_map(|capture| match capture {
                Capture::Download { url, .. } => Some(url.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            urls,
            vec!["http://example.com/one", "http://example.com/two"]
        );
    }

    #[test]
    fn arithmetic_expansion_evaluates_the_expression() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.execute("echo $((2+3*4))").text, "14\n");
        assert_eq!(shell.execute("echo $(( (2+3)*4 ))").text, "20\n");
        // A `>` inside it is a comparison, not a redirect.
        assert_eq!(shell.execute("echo $((3>2))").text, "1\n");
        assert!(shell.vfs.resolve(shell.vfs.root(), "/root/2").is_none());
        // Names resolve with or without the `$`, and a substitution nests.
        shell.execute("export N=20");
        assert_eq!(shell.execute("echo $((N+$N))").text, "40\n");
        assert_eq!(shell.execute("echo $((1+$(echo 2)))").text, "3\n");
        // Quoting suppresses it, as it does every other expansion.
        assert_eq!(shell.execute("echo '$((1+1))'").text, "$((1+1))\n");
    }

    #[test]
    fn escapes_in_a_value_reach_echo_e() {
        let mut shell = Shell::new("root", "debian");
        shell.execute(r"export T='a\tb'");
        // The backslash survives expansion, so `-e` has a `\t` to interpret
        // and plain `echo` prints it as written.
        assert_eq!(shell.execute("echo -e $T").text, "a\tb\n");
        assert_eq!(shell.execute("echo $T").text, "a\\tb\n");
    }

    #[test]
    fn execute_reports_command_status() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.execute("true").status, 0);
        assert_eq!(shell.execute("false").status, 1);
        assert_eq!(shell.execute("missing-command").status, 127);

        let mut fresh = Shell::new("root", "debian");
        let exit_default = fresh.execute("exit");
        assert_eq!(exit_default.status, 0);
        assert!(exit_default.exit);
        assert_eq!(exit_default.text, "logout\n");

        let exit_code = shell.execute("exit 42");
        assert_eq!(exit_code.status, 42);
        assert!(exit_code.exit);
        assert_eq!(exit_code.text, "logout\n");

        let exit_chained = shell.execute("false; exit");
        assert_eq!(exit_chained.status, 1);
        assert!(exit_chained.exit);
        assert_eq!(exit_chained.text, "logout\n");

        let exit_nan = shell.execute("exit abc");
        assert_eq!(exit_nan.status, 2);
        assert!(exit_nan.exit);
        assert!(exit_nan
            .text
            .contains("-bash: exit: abc: numeric argument required\nlogout\n"));

        let exit_too_many = shell.execute("exit 1 2");
        assert_eq!(exit_too_many.status, 1);
        assert!(!exit_too_many.exit);
        assert_eq!(exit_too_many.text, "-bash: exit: too many arguments\n");
    }

    #[test]
    fn parse_line_honours_quoting_and_escapes() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(
            shell.parse_line(r#"echo "a b"  c"#),
            vec!["echo", "a b", "c"]
        );
        assert_eq!(shell.parse_line(r"echo a\ b"), vec!["echo", "a b"]);
        assert!(shell.parse_line("   ").is_empty());
    }

    #[test]
    fn chained_commands_run_in_order_and_honour_status() {
        let mut shell = Shell::new("root", "debian");

        // `;` runs everything, in order.
        let out = shell.execute("echo one; echo two; echo three");
        assert_eq!(out.text, "one\ntwo\nthree\n");
        assert_eq!(out.status, 0);

        // `&&` stops at the first failure, `||` only runs after one.
        assert_eq!(shell.execute("false && echo nope").text, "");
        assert_eq!(shell.execute("false || echo yes").text, "yes\n");
        assert_eq!(shell.execute("true && echo yes").text, "yes\n");
        assert_eq!(shell.execute("true || echo nope").text, "");

        // $? reflects the last command that actually ran.
        assert_eq!(shell.execute("false && echo nope; echo $?").text, "1\n");

        // State changes carry across segments within one line.
        let out = shell.execute("cd /tmp; mkdir -p a/b; find /tmp -type d");
        assert_eq!(out.text, "/tmp\n/tmp/a\n/tmp/a/b\n");

        // A separator inside quotes is data, not an operator.
        assert_eq!(shell.execute("echo 'a; b'").text, "a; b\n");
        assert_eq!(shell.execute(r"echo a\;b").text, "a;b\n");

        // And one that arrives via a variable stays data too.
        shell.execute("export EVIL='x; echo pwned'");
        assert_eq!(shell.execute("echo $EVIL").text, "x; echo pwned\n");
    }

    #[test]
    fn comments_are_not_commands() {
        let mut shell = Shell::new("root", "debian");

        // A comment-only line runs nothing and leaves `$?` alone.
        shell.execute("false");
        let out = shell.execute("# just looking");
        assert_eq!(out.text, "");
        assert_eq!(shell.execute("echo $?").text, "1\n");

        // A trailing comment is cut off the command, and takes the rest of the
        // line with it.
        assert_eq!(shell.execute("echo a # b").text, "a\n");
        assert_eq!(shell.execute("echo a # b; echo c").text, "a\n");
        assert_eq!(shell.execute("echo a; # b").text, "a\n");

        // A `#` that does not start a word is an ordinary character — dropping
        // a shebang script is the payload this must not break.
        assert_eq!(shell.execute("echo a#b").text, "a#b\n");
        assert_eq!(shell.execute("echo '#!/bin/sh' > /tmp/x").text, "");
        assert_eq!(shell.execute("cat /tmp/x").text, "#!/bin/sh\n");
        assert_eq!(shell.execute(r##"echo "# kept""##).text, "# kept\n");
        assert_eq!(shell.execute(r"echo \# kept").text, "# kept\n");

        // Comments are cut before expansion, so one arriving in a variable's
        // value is data, not a comment.
        shell.execute("export C='# x'");
        assert_eq!(shell.execute("echo $C").text, "# x\n");
    }

    #[test]
    fn pipelines_feed_stdin_to_the_next_stage() {
        let mut shell = Shell::new("root", "debian");

        // Only the last stage's output reaches the client.
        assert_eq!(
            shell.execute("cat /etc/passwd | grep sshd").text,
            "sshd:x:100:65534::/run/sshd:/usr/sbin/nologin\n"
        );
        assert_eq!(shell.execute("cat /etc/passwd | wc -l").text, "15\n");
        assert_eq!(
            shell.execute("cat /etc/passwd | head -n 1").text,
            "root:x:0:0:root:/root:/bin/bash\n"
        );
        assert_eq!(
            shell.execute("cat /etc/passwd | grep bash | wc -l").text,
            "2\n"
        );

        // The pipeline's status is the last stage's.
        shell.execute("cat /etc/passwd | grep nosuchuser");
        assert_eq!(shell.last_status, 1);

        // A stage that ignores stdin behaves as it would in a real pipeline.
        assert_eq!(shell.execute("cat /etc/passwd | whoami").text, "root\n");

        // ls drops its column layout when its output is a pipe, so downstream
        // stages see one name per line. `[` sorts first once the /usr/bin
        // density from coreutils lands.
        assert_eq!(
            shell.execute("ls /usr/bin | head -n 2").text,
            "[\naddpart\n"
        );
        assert!(shell.execute("ls /usr/bin").text.lines().count() == 1);

        // A quoted pipe is data, and `||` is still a separator.
        assert_eq!(shell.execute("echo 'a | b'").text, "a | b\n");
        assert_eq!(shell.execute("false || echo fallback").text, "fallback\n");

        // Chaining and piping compose.
        assert_eq!(
            shell
                .execute("cd /tmp && cat /etc/passwd | grep -c bash")
                .text,
            "2\n"
        );
    }

    #[test]
    fn redirection_writes_output_into_the_filesystem() {
        let mut shell = Shell::new("root", "debian");

        // `>` takes the output off the terminal and into a new file.
        let out = shell.execute("echo hello > /tmp/f");
        assert_eq!(out.text, "");
        assert_eq!(out.status, 0);
        assert_eq!(shell.execute("cat /tmp/f").text, "hello\n");

        // `>>` appends, `>` truncates.
        shell.execute("echo second >> /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "hello\nsecond\n");
        shell.execute("echo third > /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "third\n");

        // A redirected stage is not a terminal, so `ls` writes one name a line.
        shell.execute("mkdir -p /tmp/d && touch /tmp/d/a /tmp/d/b");
        shell.execute("ls /tmp/d > /tmp/names");
        assert_eq!(shell.execute("cat /tmp/names").text, "a\nb\n");

        // The target is expanded like any other word.
        shell.execute("echo home > $HOME/f");
        assert_eq!(shell.execute("cat /root/f").text, "home\n");

        // A `>` arriving in a variable's value is data, not an operator.
        shell.execute("export EVIL='x > /tmp/pwned'");
        assert_eq!(shell.execute("echo $EVIL").text, "x > /tmp/pwned\n");
        assert!(shell
            .execute("cat /tmp/pwned")
            .text
            .contains("No such file or directory"));

        // Redirection composes with chaining and pipes.
        shell.execute("cat /etc/passwd | grep bash > /tmp/shells");
        assert!(shell
            .execute("wc -l /tmp/shells")
            .text
            .contains("2 /tmp/shells"));

        // `> FILE` with no command still truncates the file.
        shell.execute("> /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "");
    }

    /// Feed a heredoc's body to a shell that has parked one, a line at a time,
    /// returning the output of the line that opened it.
    fn feed(shell: &mut Shell, lines: &[&str]) -> Output {
        let mut last = Output::default();
        for line in lines {
            assert!(
                shell.pending.is_some(),
                "shell stopped collecting at {line}"
            );
            last = shell.resume(line);
        }
        assert!(shell.pending.is_none(), "body never ended");
        last
    }

    #[test]
    fn a_heredoc_collects_its_body_and_feeds_it_as_stdin() {
        let mut shell = Shell::new("root", "debian");

        // The opening line runs nothing and prints nothing: it waits.
        let opened = shell.execute("cat << EOF");
        assert_eq!(opened.text, "");
        assert!(shell.pending.is_some(), "no here-document was opened");

        assert_eq!(
            feed(&mut shell, &["one", "two", "EOF"]).stdout,
            "one\ntwo\n"
        );

        // The capture gets the document whole — the body is the payload — and
        // gets it once, when the document closes.
        assert_eq!(
            shell
                .heredoc_log
                .take()
                .expect("nothing left for the capture"),
            "cat << EOF\none\ntwo\nEOF"
        );

        // The rest of the line still applies: redirects, pipes and chaining.
        shell.execute("cat << EOF > /tmp/f");
        feed(&mut shell, &["written", "EOF"]);
        assert_eq!(shell.execute("cat /tmp/f").stdout, "written\n");

        shell.execute("cat << EOF | wc -l");
        assert_eq!(feed(&mut shell, &["a", "b", "c", "EOF"]).stdout, "3\n");

        // An unquoted delimiter expands the body; a quoted one does not, and
        // the quotes are not part of the delimiter either way.
        shell.execute("export NAME=world");
        shell.execute("cat << EOF");
        assert_eq!(feed(&mut shell, &["hi $NAME", "EOF"]).stdout, "hi world\n");
        shell.execute("cat << 'EOF'");
        assert_eq!(feed(&mut shell, &["hi $NAME", "EOF"]).stdout, "hi $NAME\n");

        // A body is stdin, not shell source: its quotes are ordinary bytes.
        shell.execute("cat << 'EOF'");
        assert_eq!(
            feed(&mut shell, &[r#"a "b" 'c' \d"#, "EOF"]).stdout,
            "a \"b\" 'c' \\d\n"
        );

        // `<<-` strips leading tabs from the body and from the terminator.
        shell.execute("cat <<- EOF");
        assert_eq!(
            feed(&mut shell, &["\tindented", "\tEOF"]).stdout,
            "indented\n"
        );

        // A line that merely contains the delimiter does not end the body.
        shell.execute("cat << EOF");
        assert_eq!(
            feed(&mut shell, &["EOF and more", "EOF"]).stdout,
            "EOF and more\n"
        );
    }

    #[test]
    fn a_heredoc_operator_is_only_one_where_bash_sees_one() {
        let mut shell = Shell::new("root", "debian");

        // A shift is not a here-document: the line runs rather than parking to
        // collect a body. (What `$((…))` makes of `<<` is the arithmetic
        // evaluator's business, and it does not implement shifts.)
        shell.execute("echo $((1 << 4))");
        assert!(shell.pending.is_none(), "a shift opened a here-document");

        // Nor is one inside quotes, or arriving in a value.
        assert_eq!(shell.execute("echo 'a << b'").stdout, "a << b\n");
        assert!(shell.pending.is_none());
        shell.execute("export EVIL='x << EOF'");
        assert_eq!(shell.execute("echo $EVIL").stdout, "x << EOF\n");
        assert!(shell.pending.is_none());

        // A body that never ends is closed at end-of-input, with the command
        // run on what arrived and bash's warning on stderr.
        shell.execute("cat << EOF");
        shell.resume("half a body");
        let out = shell.finish_heredoc_at_eof().expect("a document was open");
        assert_eq!(out.stdout, "half a body\n");
        assert!(
            out.stderr
                .contains("here-document delimited by end-of-file"),
            "missing warning: {:?}",
            out.stderr
        );
        assert!(shell.pending.is_none());
        assert!(shell.finish_heredoc_at_eof().is_none(), "closed twice");
    }

    #[test]
    fn the_two_streams_stay_apart() {
        let mut shell = Shell::new("root", "debian");

        // A command that only reports on failure writes to stderr alone, so
        // `2>/dev/null` silences it and stdout stays empty.
        let out = shell.execute("nosuchcmd");
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, "-bash: nosuchcmd: command not found\n");
        assert_eq!(out.status, 127);
        assert_eq!(shell.execute("nosuchcmd 2> /dev/null").stderr, "");

        // A command that walks several operands splits what it wrote: the
        // listing on stdout, the operand it could not open on stderr.
        shell.execute("mkdir -p /tmp/d && touch /tmp/d/a");
        let out = shell.execute("ls /tmp/d /nope");
        assert_eq!(out.stdout, "/tmp/d:\na\n");
        assert_eq!(
            out.stderr,
            "ls: cannot access '/nope': No such file or directory\n"
        );
        // The terminal still shows both, errors first, as GNU ls prints them.
        assert_eq!(out.text, format!("{}{}", out.stderr, out.stdout));

        // A substitution captures stdout only: the error reaches the terminal
        // and `echo` is left with an empty argument.
        let out = shell.execute("echo $(ls /nope)");
        assert_eq!(out.stdout, "\n");
        assert_eq!(
            out.stderr,
            "ls: cannot access '/nope': No such file or directory\n"
        );
        // The command's own redirection cannot catch it — bash expands the
        // words before it applies them.
        let out = shell.execute("echo $(ls /nope) 2> /dev/null");
        assert!(out.stderr.contains("No such file or directory"));

        // Only stdout is what a pipe carries, so the error goes to the
        // terminal and the next stage counts nothing.
        let out = shell.execute("cat /nope | wc -l");
        assert_eq!(out.stdout, "0\n");
        assert_eq!(out.stderr, "cat: /nope: No such file or directory\n");

        // `2>&1` with stdout still on the terminal makes the two share one
        // descriptor, so the error comes back on stdout — which is what puts
        // it into the pipe that `cmd 2>&1 | grep` is built around.
        let out = shell.execute("ls /nope 2>&1");
        assert_eq!(
            out.stdout,
            "ls: cannot access '/nope': No such file or directory\n"
        );
        assert_eq!(out.stderr, "");
        assert_eq!(shell.execute("ls /nope 2>&1 | wc -l").stdout, "1\n");
        // The mirror case sends stdout to stderr instead, and a stream pointed
        // at itself changes nothing.
        let out = shell.execute("echo oops >&2");
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, "oops\n");
        let out = shell.execute("echo fine >&1");
        assert_eq!(out.stdout, "fine\n");
        assert_eq!(out.stderr, "");

        // Redirects apply left to right: `2>&1 > f` duplicates stderr onto the
        // terminal first, then moves stdout to the file, so the error is still
        // on the terminal — the classic difference from `> f 2>&1`.
        shell.execute("ls /nope 2>&1 > /tmp/only-out");
        let out = shell.execute("ls /nope 2>&1 > /tmp/only-out");
        assert!(out.stdout.contains("No such file or directory"));
        assert_eq!(shell.execute("cat /tmp/only-out").stdout, "");
    }

    #[test]
    fn redirection_routes_errors_and_reports_refused_targets() {
        let mut shell = Shell::new("root", "debian");

        // A failing command's message is stderr: it stays on the terminal with
        // a plain `>`, and the target is still created.
        let out = shell.execute("ls /nope > /tmp/out");
        assert!(out.text.contains("No such file or directory"));
        assert_eq!(out.status, 2);
        assert_eq!(shell.execute("cat /tmp/out").text, "");

        // `2>` catches it, and `&>` catches whichever stream is written.
        assert_eq!(shell.execute("ls /nope 2> /tmp/err").text, "");
        assert!(shell
            .execute("cat /tmp/err")
            .text
            .contains("No such file or directory"));
        assert_eq!(shell.execute("ls /nope &> /tmp/both").text, "");
        assert_eq!(shell.execute("echo ok &> /tmp/both").text, "");
        assert_eq!(shell.execute("cat /tmp/both").text, "ok\n");

        // `> f 2>&1` sends both to the same file; `2>&1` alone changes nothing.
        assert_eq!(shell.execute("ls /nope > /tmp/all 2>&1").text, "");
        assert!(shell
            .execute("cat /tmp/all")
            .text
            .contains("No such file or directory"));
        // Both descriptors share the file, so the second stream written lands
        // after the first instead of truncating it, and the file holds what a
        // terminal would have shown.
        shell.execute("mkdir -p /tmp/d2 && touch /tmp/d2/a");
        shell.execute("ls /nope /tmp/d2 > /tmp/mix 2>&1");
        assert_eq!(
            shell.execute("cat /tmp/mix").text,
            "ls: cannot access '/nope': No such file or directory\n/tmp/d2:\na\n"
        );
        assert!(shell
            .execute("ls /nope 2>&1")
            .text
            .contains("No such file or directory"));

        // /dev/null discards without growing, however it is reached.
        assert_eq!(shell.execute("echo noise > /dev/null").text, "");
        assert_eq!(shell.execute("cat /dev/null").text, "");
        shell.execute("cd /dev && echo noise > null");
        assert_eq!(shell.execute("cat /dev/null").text, "");
        shell.execute("cd /tmp");

        // A missing directory, and a target that is a directory.
        let out = shell.execute("echo x > /nope/f");
        assert_eq!(out.text, "-bash: /nope/f: No such file or directory\n");
        assert_eq!(out.status, 1);
        assert_eq!(
            shell.execute("echo x > /tmp").text,
            "-bash: /tmp: Is a directory\n"
        );

        // The command does not run when its target cannot be opened.
        assert!(shell.execute("mkdir /tmp/unreached > /nope/f").status == 1);
        assert!(shell
            .execute("ls /tmp/unreached")
            .text
            .contains("No such file or directory"));

        // An unprivileged user cannot redirect into root's home.
        let mut user = Shell::new("attacker", "debian");
        let out = user.execute("echo x > /root/f");
        assert_eq!(out.text, "-bash: /root/f: Permission denied\n");
        assert_eq!(out.status, 1);

        // A target that expands to no word, or to several, is ambiguous — it
        // must not become a file literally named `$UNSET`.
        assert_eq!(
            shell.execute("echo x > $UNSET").text,
            "-bash: $UNSET: ambiguous redirect\n"
        );
        shell.execute("export TWO='a b'");
        assert_eq!(
            shell.execute("echo x > $TWO").text,
            "-bash: $TWO: ambiguous redirect\n"
        );
        assert!(!shell.execute("ls -a /").text.contains('$'));
    }

    #[test]
    fn a_redirect_refused_by_the_vfs_cap_is_reported() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("cd /tmp");

        // Fill the arena to within less than one command's output of the byte
        // cap, then redirect a full command's output into it: the write cannot
        // land, and the client has to be told rather than shown a silent
        // success — the trap `wget` fell into before it reported short writes.
        let big = "A".repeat(7 * 1024 * 1024 + 512 * 1024);
        {
            let cwd = shell.cwd;
            shell
                .vfs
                .add_file(cwd, "big", big.into_bytes(), 0o644, 0, 0);
        }
        assert!(
            shell.execute("cat /tmp/big").text.len() > commands::MAX_COMMAND_OUTPUT_BYTES / 2,
            "the fill file was itself refused, so the cap is never reached"
        );

        let out = shell.execute("cat /tmp/big > /tmp/copy");
        assert!(
            out.text.contains("No space left on device"),
            "silently dropped the write: {:?}",
            out.text
        );
        assert_ne!(out.status, 0);
    }

    #[test]
    fn a_chained_line_is_output_bounded_as_a_whole() {
        let mut shell = Shell::new("root", "debian");
        let big = "A".repeat(200_000);
        shell.execute("cd /tmp");
        {
            let cwd = shell.cwd;
            shell
                .vfs
                .add_file(cwd, "big", big.into_bytes(), 0o644, 0, 0);
        }

        let line = std::iter::repeat_n("cat /tmp/big", 40)
            .collect::<Vec<_>>()
            .join("; ");
        let out = shell.execute(&line);

        assert!(
            out.text.len() <= commands::MAX_COMMAND_OUTPUT_BYTES + 64,
            "chained line produced {} bytes",
            out.text.len()
        );
        assert!(out.text.ends_with("... (output truncated)\n"));
    }

    #[test]
    fn su_rebuilds_the_login_env_but_keeps_the_connection_vars() {
        let mut shell = Shell::new("root", "debian");
        shell
            .env
            .set("SSH_CONNECTION", "10.0.0.5 54321 10.0.0.9 22");
        shell.env.set("SSH_TTY", "/dev/pts/0");

        shell.switch_user("user");

        assert_eq!(shell.env.get("USER"), Some("user"));
        assert_eq!(shell.env.get("HOME"), Some("/home/user"));
        assert_eq!(
            shell.env.get("SSH_CONNECTION"),
            Some("10.0.0.5 54321 10.0.0.9 22")
        );
        assert_eq!(shell.env.get("SSH_TTY"), Some("/dev/pts/0"));
    }

    #[test]
    fn history_skips_blank_and_is_bounded() {
        let mut shell = Shell::new("root", "debian");
        shell.record_history("   ");
        assert!(shell.history.is_empty());
        for i in 0..(Shell::MAX_HISTORY + 50) {
            shell.record_history(&format!("cmd{i}"));
        }
        assert_eq!(shell.history.len(), Shell::MAX_HISTORY);
        assert_eq!(shell.history.last().unwrap(), "cmd1049");
    }
}
