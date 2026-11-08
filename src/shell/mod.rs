pub mod arith;
pub mod complete;
pub mod env;
pub mod line;
pub mod parser;

use crate::commands;
use crate::persona::Persona;
use crate::vfs::{snapshot, NodeId, Vfs};
use env::Env;

#[derive(Default)]
pub struct Output {
    pub text: String,

    pub stdout: String,

    pub stderr: String,

    pub status: i32,

    pub exit: bool,
}

impl Output {
    fn push(&mut self, stdout: &str, stderr: &str) {
        self.text.push_str(stderr);
        self.text.push_str(stdout);
        self.stdout.push_str(stdout);
        self.stderr.push_str(stderr);
    }

    fn written(stdout: &str, stderr: &str, status: i32) -> Self {
        let mut out = Output {
            status,
            ..Output::default()
        };
        out.push(stdout, stderr);
        out
    }
}

#[derive(Debug, Clone)]
pub enum Capture {
    Download {
        tool: String,

        url: String,

        dest: String,
    },

    ScriptCommand {
        line: String,

        status: i32,
    },

    PasswordChange {
        target: String,

        password: String,
    },

    SuAuth {
        target: String,

        password: String,
    },
}

#[derive(Debug, Clone)]
pub enum Pending {
    SuPassword {
        target: String,
    },

    NewPassword {
        target: String,

        first: Option<String>,
    },

    Heredoc {
        command: String,

        raw: String,

        doc: parser::Heredoc,

        body: String,
    },
}

impl Pending {
    pub fn echoes(&self) -> bool {
        matches!(self, Pending::Heredoc { .. })
    }

    pub fn prompt(&self) -> Option<&'static str> {
        match self {
            Pending::SuPassword { .. } | Pending::NewPassword { .. } => None,
            Pending::Heredoc { .. } => Some("> "),
        }
    }
}

#[derive(Clone)]
pub enum Screen {
    Top(commands::system::TopScreen),

    Editor(commands::text::EditorScreen),

    Listen,
}

const CONNECTION_VARS: &[&str] = &["SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"];

const DEV_NULL: &str = "/dev/null";

#[derive(Debug, Clone)]
struct Sink {
    path: String,

    node: Option<NodeId>,

    append: bool,
}

#[derive(Debug, Default)]
struct Sinks {
    stdout: Option<Sink>,

    stderr: Option<Sink>,

    stderr_merged: bool,

    stdout_merged: bool,
}

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

pub struct Shell {
    pub vfs: Vfs,

    pub env: Env,

    pub cwd: NodeId,

    pub home: NodeId,

    pub prev_cwd: NodeId,

    pub username: String,

    pub hostname: String,

    pub uid: u32,

    pub gid: u32,

    pub last_status: i32,

    pub pid: u32,

    pub login: i64,

    pub nesting: u32,

    subst_budget: usize,

    subst_stderr: String,

    pub stdin: Option<String>,

    pub stdout_is_tty: bool,

    pub interactive: bool,

    pub history: Vec<String>,

    pub captures: Vec<Capture>,

    pub pending: Option<Pending>,

    pub screen: Option<Screen>,

    subst_depth: u32,

    pub persona: Persona,

    heredoc_stdin: Option<String>,

    pub heredoc_log: Option<String>,
}

impl Shell {
    pub fn new(username: &str, hostname: &str) -> Self {
        Self::with_persona(username, hostname, Persona::sample())
    }

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

    pub const MAX_HISTORY: usize = 1000;

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

    pub fn cwd_path(&self) -> String {
        self.vfs.path_of(self.cwd)
    }

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

    pub fn parse_line(&mut self, line: &str) -> Vec<String> {
        let expanded = self.expand(line);
        parser::tokenize(&expanded)
    }

    fn expand(&mut self, line: &str) -> String {
        self.expand_with(line, Expansion::Words)
    }

    fn expand_with(&mut self, line: &str, mode: Expansion) -> String {
        let mut out = String::new();
        let mut in_single = false;
        let mut in_double = false;

        let words = mode == Expansion::Words;
        let mut chars = line.char_indices().peekable();

        while let Some((i, c)) = chars.next() {
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
                        out.push(c);
                        if let Some((_, next)) = chars.next() {
                            out.push(next);
                        }
                    } else if matches!(chars.peek(), Some((_, '$' | '`' | '\\'))) {
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

    fn substitute(&mut self, body: &str) -> String {
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

        self.screen = session.screen;
        self.nesting -= 1;
        self.subst_depth -= 1;

        self.subst_stderr.push_str(&output.stderr);
        commands::truncate_stream(&mut self.subst_stderr, commands::MAX_COMMAND_OUTPUT_BYTES);
        let mut value = output.stdout;
        if output.exit {
            if let Some(rest) = value.strip_suffix(commands::LOGOUT) {
                value.truncate(rest.len());
            }
        }
        while value.ends_with('\n') {
            value.pop();
        }

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

    fn arithmetic(&mut self, body: &str) -> String {
        if self.nesting >= commands::MAX_NESTED_COMMANDS {
            return "0".to_string();
        }
        self.nesting += 1;
        let expanded = self.expand(body);
        self.nesting -= 1;
        arith::eval(&self.env, &expanded).unwrap_or(0).to_string()
    }

    pub fn switch_user(&mut self, user: &str) {
        let user = if user.is_empty() { "root" } else { user };
        let (uid, gid, home_path) = if user == "root" {
            (0, 0, "/root".to_string())
        } else {
            (1000, 1000, format!("/home/{user}"))
        };
        let home = ensure_home(&mut self.vfs, &home_path, uid, gid);

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

    pub fn resume(&mut self, input: &str) -> Output {
        match self.pending.take() {
            Some(Pending::SuPassword { target }) => {
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

    fn run_heredoc(
        &mut self,
        command: &str,
        raw: &str,
        doc: &parser::Heredoc,
        body: String,
    ) -> Output {
        self.pending = None;

        self.heredoc_log = Some(format!("{raw}\n{body}{}", doc.delimiter));

        let text = if doc.expand {
            self.expand_with(&body, Expansion::Literal)
        } else {
            body
        };
        self.heredoc_stdin = Some(text);
        let out = self.execute(command);

        self.heredoc_stdin = None;
        out
    }

    fn run_pipeline(&mut self, segment: &str) -> Option<commands::CommandResult> {
        let stages = parser::split_pipeline(segment);
        let last_stage = stages.len() - 1;

        let mut piped: Option<String> = self.heredoc_stdin.take();
        let mut last: Option<commands::CommandResult> = None;
        let mut stderr = String::new();

        for (i, stage) in stages.iter().enumerate() {
            let (text, redirects) = match parser::split_redirects(stage) {
                Ok(split) => split,
                Err(message) => return Some(commands::CommandResult::err(message, 2)),
            };

            let argv = self.parse_line(&text);
            let sinks = match self.open_redirects(&redirects) {
                Ok(sinks) => sinks,

                Err(message) => return Some(commands::CommandResult::err(message, 1)),
            };

            stderr.push_str(&std::mem::take(&mut self.subst_stderr));
            commands::truncate_stream(&mut stderr, commands::MAX_COMMAND_OUTPUT_BYTES);

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

        match last.as_mut() {
            Some(result) => result.stderr = stderr,
            None if !stderr.is_empty() => {
                return Some(commands::CommandResult::streams("", stderr, 0))
            }
            None => {}
        }
        last
    }

    fn open_redirects(&mut self, redirects: &[parser::Redirect]) -> Result<Sinks, String> {
        let mut sinks = Sinks::default();
        for redirect in redirects {
            if matches!(&redirect.target, parser::Target::Dup(s) if *s == redirect.stream) {
                continue;
            }

            let mut merged = false;
            let sink = match &redirect.target {
                parser::Target::File { path, append } => {
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

                parser::Target::Dup(parser::Stream::Stdout) => {
                    merged = sinks.stdout.is_none();
                    sinks.stdout.clone()
                }

                parser::Target::Dup(_) => {
                    merged = sinks.stderr.is_none();
                    sinks.stderr.clone()
                }
            };

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

    fn open_redirect(&mut self, path: &str, append: bool) -> Result<Option<NodeId>, String> {
        let (parent, name) = commands::fs::resolve_parent(self, path)
            .ok_or_else(|| format!("-bash: {path}: No such file or directory\n"))?;

        if let Some(existing) = self.vfs.child(parent, &name) {
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
            return Err(format!("-bash: {path}: No space left on device\n"));
        }
        Ok(Some(id))
    }

    fn route_output(
        &mut self,
        mut result: commands::CommandResult,
        sinks: &Sinks,
    ) -> commands::CommandResult {
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

        if let Some(message) = failure {
            result.stderr.push_str(&message);
            result.status = 1;
        }

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

    fn divert(&mut self, sink: &Sink, text: &str, written: &mut Option<NodeId>) -> Option<String> {
        if text.is_empty() {
            return None;
        }
        let append = sink.append || (sink.node.is_some() && sink.node == *written);
        *written = sink.node;
        self.write_redirect(sink, text.as_bytes(), append).err()
    }

    fn write_redirect(&mut self, sink: &Sink, data: &[u8], append: bool) -> Result<(), String> {
        let Some(node) = sink.node else {
            return Ok(());
        };
        if !self.vfs.write_file(node, data, append) {
            return Err(format!("-bash: {}: No space left on device\n", sink.path));
        }
        Ok(())
    }

    pub fn execute(&mut self, line: &str) -> Output {
        self.captures.clear();

        if self.nesting == 0 {
            self.subst_budget = commands::MAX_COMMAND_OUTPUT_BYTES;

            self.subst_stderr.clear();

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
                    let mut syntax = Output {
                        status: 2,
                        ..Output::default()
                    };
                    syntax.push("", "-bash: syntax error near unexpected token `&&'\n");
                    return syntax;
                }
                continue;
            }
            if !segment.run_if.admits(status) {
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expansion {
    Words,

    Literal,
}

fn emit(out: &mut String, mode: Expansion, value: &str, in_double: bool) {
    match mode {
        Expansion::Words => push_value(out, value, in_double),
        Expansion::Literal => out.push_str(value),
    }
}

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

        assert_eq!(shell.parse_line(r"echo \\$USER"), vec!["echo", r"\root"]);
    }

    #[test]
    fn an_expanded_value_is_data_not_syntax() {
        let mut shell = Shell::new("root", "debian");
        shell.execute(r#"export Q="a'b""#);
        shell.execute(r#"export D='a"b'"#);
        shell.execute(r"export B='a\b'");
        shell.execute("export S='a  b'");

        assert_eq!(shell.execute("echo $Q").text, "a'b\n");
        assert_eq!(shell.execute(r#"echo "$D""#).text, "a\"b\n");
        assert_eq!(shell.execute("echo $B").text, "a\\b\n");

        assert_eq!(shell.execute("echo $D tail").text, "a\"b tail\n");

        assert_eq!(shell.parse_line("echo $S"), vec!["echo", "a", "b"]);
        assert_eq!(shell.parse_line(r#"echo "$S""#), vec!["echo", "a  b"]);
    }

    #[test]
    fn command_substitution_runs_the_body() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.execute("echo $(whoami)").text, "root\n");
        assert_eq!(shell.execute("echo `whoami`").text, "root\n");

        assert_eq!(shell.execute("echo $(cd /tmp; pwd)").text, "/tmp\n");
        assert_eq!(shell.execute("echo $(echo a b c | wc -w)").text, "3\n");

        assert_eq!(shell.execute(r#"echo "[$(echo hi)]""#).text, "[hi]\n");
        assert_eq!(
            shell.execute(r#"echo "[$(echo one; echo two)]""#).text,
            "[one\ntwo]\n"
        );

        assert_eq!(shell.execute("echo $(echo $(whoami))").text, "root\n");

        assert_eq!(shell.execute("echo '$(whoami)'").text, "$(whoami)\n");
        assert_eq!(shell.execute(r"echo \$(whoami)").text, "$(whoami)\n");
        assert_eq!(shell.execute("echo '`whoami`'").text, "`whoami`\n");
    }

    #[test]
    fn substitution_output_is_data_not_syntax() {
        let mut shell = Shell::new("root", "debian");

        assert_eq!(
            shell.execute("echo $(echo 'a; touch /tmp/pwned')").text,
            "a; touch /tmp/pwned\n"
        );
        assert!(shell.vfs.resolve(shell.vfs.root(), "/tmp/pwned").is_none());

        assert_eq!(
            shell.execute("echo $(echo 'a > /tmp/out | b')").text,
            "a > /tmp/out | b\n"
        );
        assert!(shell.vfs.resolve(shell.vfs.root(), "/tmp/out").is_none());
        assert_eq!(shell.execute(r#"echo $(echo "it's")"#).text, "it's\n");
        assert_eq!(shell.execute("echo $(echo '$USER')").text, "$USER\n");

        shell.execute("echo before > /tmp/f");
        shell.execute("echo $(cat /tmp/f) > /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "before\n");

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

        let out = shell.execute("echo $(exit)");
        assert!(!out.exit);
        assert_eq!(out.text, "\n");

        shell.execute("echo $(cd /tmp; export MARK=1; touch /tmp/left-behind)");
        assert_eq!(shell.cwd_path(), "/root");
        assert_eq!(shell.execute("echo $MARK").text, "\n");
        assert!(shell
            .vfs
            .resolve(shell.vfs.root(), "/tmp/left-behind")
            .is_some());

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

        assert_eq!(shell.execute("echo $((3>2))").text, "1\n");
        assert!(shell.vfs.resolve(shell.vfs.root(), "/root/2").is_none());

        shell.execute("export N=20");
        assert_eq!(shell.execute("echo $((N+$N))").text, "40\n");
        assert_eq!(shell.execute("echo $((1+$(echo 2)))").text, "3\n");

        assert_eq!(shell.execute("echo '$((1+1))'").text, "$((1+1))\n");
    }

    #[test]
    fn escapes_in_a_value_reach_echo_e() {
        let mut shell = Shell::new("root", "debian");
        shell.execute(r"export T='a\tb'");

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

        let out = shell.execute("echo one; echo two; echo three");
        assert_eq!(out.text, "one\ntwo\nthree\n");
        assert_eq!(out.status, 0);

        assert_eq!(shell.execute("false && echo nope").text, "");
        assert_eq!(shell.execute("false || echo yes").text, "yes\n");
        assert_eq!(shell.execute("true && echo yes").text, "yes\n");
        assert_eq!(shell.execute("true || echo nope").text, "");

        assert_eq!(shell.execute("false && echo nope; echo $?").text, "1\n");

        let out = shell.execute("cd /tmp; mkdir -p a/b; find /tmp -type d");
        assert_eq!(out.text, "/tmp\n/tmp/a\n/tmp/a/b\n");

        assert_eq!(shell.execute("echo 'a; b'").text, "a; b\n");
        assert_eq!(shell.execute(r"echo a\;b").text, "a;b\n");

        shell.execute("export EVIL='x; echo pwned'");
        assert_eq!(shell.execute("echo $EVIL").text, "x; echo pwned\n");
    }

    #[test]
    fn comments_are_not_commands() {
        let mut shell = Shell::new("root", "debian");

        shell.execute("false");
        let out = shell.execute("# just looking");
        assert_eq!(out.text, "");
        assert_eq!(shell.execute("echo $?").text, "1\n");

        assert_eq!(shell.execute("echo a # b").text, "a\n");
        assert_eq!(shell.execute("echo a # b; echo c").text, "a\n");
        assert_eq!(shell.execute("echo a; # b").text, "a\n");

        assert_eq!(shell.execute("echo a#b").text, "a#b\n");
        assert_eq!(shell.execute("echo '#!/bin/sh' > /tmp/x").text, "");
        assert_eq!(shell.execute("cat /tmp/x").text, "#!/bin/sh\n");
        assert_eq!(shell.execute(r##"echo "# kept""##).text, "# kept\n");
        assert_eq!(shell.execute(r"echo \# kept").text, "# kept\n");

        shell.execute("export C='# x'");
        assert_eq!(shell.execute("echo $C").text, "# x\n");
    }

    #[test]
    fn pipelines_feed_stdin_to_the_next_stage() {
        let mut shell = Shell::new("root", "debian");

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

        shell.execute("cat /etc/passwd | grep nosuchuser");
        assert_eq!(shell.last_status, 1);

        assert_eq!(shell.execute("cat /etc/passwd | whoami").text, "root\n");

        assert_eq!(
            shell.execute("ls /usr/bin | head -n 2").text,
            "[\naddpart\n"
        );
        assert!(shell.execute("ls /usr/bin").text.lines().count() == 1);

        assert_eq!(shell.execute("echo 'a | b'").text, "a | b\n");
        assert_eq!(shell.execute("false || echo fallback").text, "fallback\n");

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

        let out = shell.execute("echo hello > /tmp/f");
        assert_eq!(out.text, "");
        assert_eq!(out.status, 0);
        assert_eq!(shell.execute("cat /tmp/f").text, "hello\n");

        shell.execute("echo second >> /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "hello\nsecond\n");
        shell.execute("echo third > /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "third\n");

        shell.execute("mkdir -p /tmp/d && touch /tmp/d/a /tmp/d/b");
        shell.execute("ls /tmp/d > /tmp/names");
        assert_eq!(shell.execute("cat /tmp/names").text, "a\nb\n");

        shell.execute("echo home > $HOME/f");
        assert_eq!(shell.execute("cat /root/f").text, "home\n");

        shell.execute("export EVIL='x > /tmp/pwned'");
        assert_eq!(shell.execute("echo $EVIL").text, "x > /tmp/pwned\n");
        assert!(shell
            .execute("cat /tmp/pwned")
            .text
            .contains("No such file or directory"));

        shell.execute("cat /etc/passwd | grep bash > /tmp/shells");
        assert!(shell
            .execute("wc -l /tmp/shells")
            .text
            .contains("2 /tmp/shells"));

        shell.execute("> /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "");
    }

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

        let opened = shell.execute("cat << EOF");
        assert_eq!(opened.text, "");
        assert!(shell.pending.is_some(), "no here-document was opened");

        assert_eq!(
            feed(&mut shell, &["one", "two", "EOF"]).stdout,
            "one\ntwo\n"
        );

        assert_eq!(
            shell
                .heredoc_log
                .take()
                .expect("nothing left for the capture"),
            "cat << EOF\none\ntwo\nEOF"
        );

        shell.execute("cat << EOF > /tmp/f");
        feed(&mut shell, &["written", "EOF"]);
        assert_eq!(shell.execute("cat /tmp/f").stdout, "written\n");

        shell.execute("cat << EOF | wc -l");
        assert_eq!(feed(&mut shell, &["a", "b", "c", "EOF"]).stdout, "3\n");

        shell.execute("export NAME=world");
        shell.execute("cat << EOF");
        assert_eq!(feed(&mut shell, &["hi $NAME", "EOF"]).stdout, "hi world\n");
        shell.execute("cat << 'EOF'");
        assert_eq!(feed(&mut shell, &["hi $NAME", "EOF"]).stdout, "hi $NAME\n");

        shell.execute("cat << 'EOF'");
        assert_eq!(
            feed(&mut shell, &[r#"a "b" 'c' \d"#, "EOF"]).stdout,
            "a \"b\" 'c' \\d\n"
        );

        shell.execute("cat <<- EOF");
        assert_eq!(
            feed(&mut shell, &["\tindented", "\tEOF"]).stdout,
            "indented\n"
        );

        shell.execute("cat << EOF");
        assert_eq!(
            feed(&mut shell, &["EOF and more", "EOF"]).stdout,
            "EOF and more\n"
        );
    }

    #[test]
    fn a_heredoc_operator_is_only_one_where_bash_sees_one() {
        let mut shell = Shell::new("root", "debian");

        shell.execute("echo $((1 << 4))");
        assert!(shell.pending.is_none(), "a shift opened a here-document");

        assert_eq!(shell.execute("echo 'a << b'").stdout, "a << b\n");
        assert!(shell.pending.is_none());
        shell.execute("export EVIL='x << EOF'");
        assert_eq!(shell.execute("echo $EVIL").stdout, "x << EOF\n");
        assert!(shell.pending.is_none());

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

        let out = shell.execute("nosuchcmd");
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, "-bash: nosuchcmd: command not found\n");
        assert_eq!(out.status, 127);
        assert_eq!(shell.execute("nosuchcmd 2> /dev/null").stderr, "");

        shell.execute("mkdir -p /tmp/d && touch /tmp/d/a");
        let out = shell.execute("ls /tmp/d /nope");
        assert_eq!(out.stdout, "/tmp/d:\na\n");
        assert_eq!(
            out.stderr,
            "ls: cannot access '/nope': No such file or directory\n"
        );

        assert_eq!(out.text, format!("{}{}", out.stderr, out.stdout));

        let out = shell.execute("echo $(ls /nope)");
        assert_eq!(out.stdout, "\n");
        assert_eq!(
            out.stderr,
            "ls: cannot access '/nope': No such file or directory\n"
        );

        let out = shell.execute("echo $(ls /nope) 2> /dev/null");
        assert!(out.stderr.contains("No such file or directory"));

        let out = shell.execute("cat /nope | wc -l");
        assert_eq!(out.stdout, "0\n");
        assert_eq!(out.stderr, "cat: /nope: No such file or directory\n");

        let out = shell.execute("ls /nope 2>&1");
        assert_eq!(
            out.stdout,
            "ls: cannot access '/nope': No such file or directory\n"
        );
        assert_eq!(out.stderr, "");
        assert_eq!(shell.execute("ls /nope 2>&1 | wc -l").stdout, "1\n");

        let out = shell.execute("echo oops >&2");
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, "oops\n");
        let out = shell.execute("echo fine >&1");
        assert_eq!(out.stdout, "fine\n");
        assert_eq!(out.stderr, "");

        shell.execute("ls /nope 2>&1 > /tmp/only-out");
        let out = shell.execute("ls /nope 2>&1 > /tmp/only-out");
        assert!(out.stdout.contains("No such file or directory"));
        assert_eq!(shell.execute("cat /tmp/only-out").stdout, "");
    }

    #[test]
    fn redirection_routes_errors_and_reports_refused_targets() {
        let mut shell = Shell::new("root", "debian");

        let out = shell.execute("ls /nope > /tmp/out");
        assert!(out.text.contains("No such file or directory"));
        assert_eq!(out.status, 2);
        assert_eq!(shell.execute("cat /tmp/out").text, "");

        assert_eq!(shell.execute("ls /nope 2> /tmp/err").text, "");
        assert!(shell
            .execute("cat /tmp/err")
            .text
            .contains("No such file or directory"));
        assert_eq!(shell.execute("ls /nope &> /tmp/both").text, "");
        assert_eq!(shell.execute("echo ok &> /tmp/both").text, "");
        assert_eq!(shell.execute("cat /tmp/both").text, "ok\n");

        assert_eq!(shell.execute("ls /nope > /tmp/all 2>&1").text, "");
        assert!(shell
            .execute("cat /tmp/all")
            .text
            .contains("No such file or directory"));

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

        assert_eq!(shell.execute("echo noise > /dev/null").text, "");
        assert_eq!(shell.execute("cat /dev/null").text, "");
        shell.execute("cd /dev && echo noise > null");
        assert_eq!(shell.execute("cat /dev/null").text, "");
        shell.execute("cd /tmp");

        let out = shell.execute("echo x > /nope/f");
        assert_eq!(out.text, "-bash: /nope/f: No such file or directory\n");
        assert_eq!(out.status, 1);
        assert_eq!(
            shell.execute("echo x > /tmp").text,
            "-bash: /tmp: Is a directory\n"
        );

        assert!(shell.execute("mkdir /tmp/unreached > /nope/f").status == 1);
        assert!(shell
            .execute("ls /tmp/unreached")
            .text
            .contains("No such file or directory"));

        let mut user = Shell::new("attacker", "debian");
        let out = user.execute("echo x > /root/f");
        assert_eq!(out.text, "-bash: /root/f: Permission denied\n");
        assert_eq!(out.status, 1);

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
