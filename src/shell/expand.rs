use std::iter::Peekable;
use std::str::CharIndices;

use super::env::Env;
use super::{arith, floor_char_boundary, parser, push_capped, Output, Pending, Screen, Shell};
use crate::commands;
use crate::vfs::NodeId;

const SHELL_NAME: &str = "-bash";
const POSITIONAL_COUNT: &str = "0";

type Chars<'a> = Peekable<CharIndices<'a>>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Expansion {
    Words,

    Literal,
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

impl Subshell {
    fn save(shell: &Shell) -> Self {
        Self {
            env: shell.env.clone(),
            cwd: shell.cwd,
            prev_cwd: shell.prev_cwd,
            home: shell.home,
            username: shell.username.clone(),
            uid: shell.uid,
            gid: shell.gid,
            pending: shell.pending.clone(),
            screen: shell.screen.clone(),
        }
    }

    fn restore(self, shell: &mut Shell) {
        shell.env = self.env;
        shell.cwd = self.cwd;
        shell.prev_cwd = self.prev_cwd;
        shell.home = self.home;
        shell.username = self.username;
        shell.uid = self.uid;
        shell.gid = self.gid;
        shell.pending = self.pending;

        shell.screen = self.screen;
    }
}

impl Shell {
    pub(super) fn expand(&mut self, line: &str) -> String {
        self.expand_with(line, Expansion::Words)
    }

    pub(super) fn expand_with(&mut self, line: &str, mode: Expansion) -> String {
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
                    while chars.next_if(|(j, _)| *j < subst.end).is_some() {}
                    continue;
                }
            }
            match c {
                '\\' if !in_single => push_escape(&mut out, &mut chars, mode),
                '\'' if words && !in_double => {
                    in_single = !in_single;
                    out.push(c);
                }
                '"' if words && !in_single => {
                    in_double = !in_double;
                    out.push(c);
                }
                '$' if !in_single => match self.parameter(&mut chars) {
                    Some(value) => emit(&mut out, mode, &value, in_double),
                    None => out.push('$'),
                },
                c => out.push(c),
            }
        }
        out
    }

    fn parameter(&self, chars: &mut Chars) -> Option<String> {
        let &(_, first) = chars.peek()?;
        if first == '{' {
            chars.next();
            let name: String = chars
                .by_ref()
                .map(|(_, c)| c)
                .take_while(|&c| c != '}')
                .collect();
            return Some(self.named_parameter(&name));
        }
        if let Some(value) = self.special_parameter(&first.to_string()) {
            chars.next();
            return Some(value);
        }
        if !is_name_start(first) {
            return None;
        }
        let mut name = String::new();
        while let Some((_, c)) = chars.next_if(|&(_, c)| c.is_alphanumeric() || c == '_') {
            name.push(c);
        }
        Some(self.named_parameter(&name))
    }

    fn named_parameter(&self, name: &str) -> String {
        self.special_parameter(name)
            .unwrap_or_else(|| self.env.get(name).unwrap_or("").to_string())
    }

    fn special_parameter(&self, name: &str) -> Option<String> {
        let value = match name {
            "#" => POSITIONAL_COUNT.to_string(),
            "0" => SHELL_NAME.to_string(),
            "?" => self.last_status.to_string(),
            "$" => self.pid.to_string(),
            "*" | "@" => String::new(),
            _ if is_positional(name) => String::new(),
            _ => return None,
        };
        Some(value)
    }

    fn substitute(&mut self, body: &str) -> String {
        if self.nesting >= commands::MAX_NESTED_COMMANDS {
            return String::new();
        }
        let output = self.run_in_subshell(body);

        push_capped(&mut self.subst_stderr, &output.stderr);
        let value = substitution_value(output);
        self.spend_substitution_budget(value)
    }

    fn run_in_subshell(&mut self, body: &str) -> Output {
        self.nesting += 1;
        self.subst_depth += 1;
        let session = Subshell::save(self);
        let outer_captures = std::mem::take(&mut self.captures);
        let output = self.execute(body);
        let inner_captures = std::mem::replace(&mut self.captures, outer_captures);
        self.captures.extend(inner_captures);
        session.restore(self);
        self.nesting -= 1;
        self.subst_depth -= 1;
        output
    }

    fn spend_substitution_budget(&mut self, mut value: String) -> String {
        value.truncate(floor_char_boundary(&value, self.subst_budget));
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
}

fn substitution_value(output: Output) -> String {
    let mut value = output.stdout;
    if output.exit {
        if let Some(rest) = value.strip_suffix(commands::LOGOUT) {
            value.truncate(rest.len());
        }
    }
    let trimmed = value.trim_end_matches('\n').len();
    value.truncate(trimmed);
    value
}

fn is_name_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_positional(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_digit())
}

fn push_escape(out: &mut String, chars: &mut Chars, mode: Expansion) {
    match mode {
        Expansion::Words => {
            out.push('\\');
            if let Some((_, next)) = chars.next() {
                out.push(next);
            }
        }
        Expansion::Literal => match chars.next_if(|&(_, c)| matches!(c, '$' | '`' | '\\')) {
            Some((_, next)) => out.push(next),
            None => out.push('\\'),
        },
    }
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
