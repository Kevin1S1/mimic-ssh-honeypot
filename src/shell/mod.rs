//! Shell state machine.
//!
//! Holds the per-session shell state — the virtual filesystem, environment,
//! working directory, and identity — and the pure-text operations over it:
//! prompt rendering, variable expansion, and tokenization. Command dispatch is
//! layered on top of this by the command registry; nothing here touches real
//! I/O or runs a real process.

pub mod complete;
pub mod env;
pub mod line;
pub mod parser;

use crate::commands;
use crate::vfs::{snapshot, NodeId, Vfs};
use env::Env;

/// The result of running one command line.
pub struct Output {
    /// Text to write back to the client.
    pub text: String,
    /// Process-style exit status.
    pub status: i32,
    /// Whether the session should end (e.g. after `exit`).
    pub exit: bool,
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
}

/// Environment variables describing the SSH connection itself. The network
/// layer seeds them; they survive `su`, as they do on a real box, because they
/// belong to the connection rather than to the logged-in identity.
const CONNECTION_VARS: &[&str] = &["SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"];

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
    /// Current command-nesting depth (`sudo`, `sh -c`, ...), bounded by the
    /// command registry so a deeply nested line cannot overflow the stack.
    pub nesting: u32,
    /// Submitted command lines this session, exposed by the `history` builtin.
    /// Bounded to keep per-session memory predictable.
    pub history: Vec<String>,
    /// Captures (downloads, ...) produced by the last command, awaiting logging
    /// by the network layer. Cleared at the start of every command line.
    pub captures: Vec<Capture>,
    /// An interactive prompt a command is waiting on (e.g. `su` reading a
    /// password). `None` between commands.
    pub pending: Option<Pending>,
}

impl Shell {
    /// Construct a fresh shell for `username` on a freshly built Debian
    /// snapshot. `root` (and the empty username) get uid 0 and `/root`; any
    /// other user is treated as a normal account (uid 1000) with a home under
    /// `/home`, created on demand.
    pub fn new(username: &str, hostname: &str) -> Self {
        let mut vfs = snapshot::build(hostname);
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
            nesting: 0,
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
    /// the command layer dispatches on. Expansion runs first so `$VAR` values
    /// are subject to quoting/word-splitting by the tokenizer.
    pub fn parse_line(&self, line: &str) -> Vec<String> {
        parser::tokenize(&self.expand(line))
    }

    /// Expand `$VAR`, `${VAR}`, `$?`, and `$$` in `line`, respecting single
    /// quotes (which suppress expansion).
    fn expand(&self, line: &str) -> String {
        let mut out = String::new();
        let mut in_single = false;
        let mut chars = line.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '\'' => {
                    in_single = !in_single;
                    out.push(c);
                }
                '$' if !in_single => match chars.peek() {
                    Some('?') => {
                        chars.next();
                        out.push_str(&self.last_status.to_string());
                    }
                    Some('$') => {
                        chars.next();
                        out.push_str(&self.pid.to_string());
                    }
                    Some('{') => {
                        chars.next();
                        let mut name = String::new();
                        for n in chars.by_ref() {
                            if n == '}' {
                                break;
                            }
                            name.push(n);
                        }
                        out.push_str(self.env.get(&name).unwrap_or(""));
                    }
                    Some(&n) if n.is_alphabetic() || n == '_' => {
                        let mut name = String::new();
                        while let Some(&n) = chars.peek() {
                            if n.is_alphanumeric() || n == '_' {
                                name.push(n);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        out.push_str(self.env.get(&name).unwrap_or(""));
                    }
                    _ => out.push('$'),
                },
                c => out.push(c),
            }
        }
        out
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
                Output {
                    text: String::new(),
                    status: 0,
                    exit: false,
                }
            }
            None => Output {
                text: String::new(),
                status: 0,
                exit: false,
            },
        }
    }

    /// Run one command line: split it on `;`, `&&`, and `||`, then for each
    /// segment expand variables, tokenize, dispatch to the command registry,
    /// and record the resulting `$?`. Empty lines are no-ops.
    pub fn execute(&mut self, line: &str) -> Output {
        self.captures.clear();

        let mut text = String::new();
        let mut status = 0;
        let mut exit = false;
        let mut ran = false;

        for segment in parser::split_segments(line) {
            if segment.text.trim().is_empty() {
                if segment.run_if != parser::Separator::Always {
                    // `&& cmd` with nothing in front of it, as bash sees it.
                    return Output {
                        text: "-bash: syntax error near unexpected token `&&'\n".to_string(),
                        status: 2,
                        exit: false,
                    };
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

            let argv = self.parse_line(segment.text);
            if argv.is_empty() {
                continue;
            }
            let result = commands::dispatch(self, &argv);
            ran = true;
            status = result.status;
            self.last_status = status;
            text.push_str(&result.output);
            if result.exit {
                exit = true;
                break;
            }
            // The per-command cap bounds one command; a chained line has to be
            // bounded as a whole, or `cat big; cat big; ...` multiplies it by
            // the number of segments the line has room for.
            if text.len() >= commands::MAX_COMMAND_OUTPUT_BYTES {
                let mut cut = commands::MAX_COMMAND_OUTPUT_BYTES;
                while cut > 0 && !text.is_char_boundary(cut) {
                    cut -= 1;
                }
                text.truncate(cut);
                text.push_str("\n... (output truncated)\n");
                break;
            }
        }

        if !ran {
            return Output {
                text,
                status: 0,
                exit,
            };
        }
        Output { text, status, exit }
    }
}

/// Ensure `home_path` exists in `vfs`, creating it with skeleton dotfiles if
/// the account is one the snapshot does not ship. Returns the home node id.
fn ensure_home(vfs: &mut Vfs, home_path: &str, uid: u32, gid: u32) -> NodeId {
    if let Some(id) = vfs.resolve(vfs.root(), home_path) {
        return id;
    }
    let home = vfs.mkdir_p(home_path, 0o755, uid, gid);
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
        // Unset variables expand to nothing.
        assert_eq!(shell.parse_line("echo $NOPE end"), vec!["echo", "end"]);
    }

    #[test]
    fn single_quotes_suppress_expansion() {
        let shell = Shell::new("root", "debian");
        assert_eq!(shell.parse_line("echo '$USER'"), vec!["echo", "$USER"]);
    }

    #[test]
    fn execute_reports_command_status() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.execute("true").status, 0);
        assert_eq!(shell.execute("false").status, 1);
        assert_eq!(shell.execute("missing-command").status, 127);
    }

    #[test]
    fn parse_line_honours_quoting_and_escapes() {
        let shell = Shell::new("root", "debian");
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
